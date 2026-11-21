//! OSDP readers: the controller side of the Open Supervised Device Protocol.
//!
//! One `OsdpBus` is one RS-485 line with one or more readers on it, each at its own address.
//! The protocol itself (framing, checksums, polling, the encrypted secure channel) is
//! LibOSDP, through the `libosdp` crate; this module is the thin layer between it and the
//! rest of the controller. Nothing outside this file names a LibOSDP type except the
//! `Channel` a caller supplies for the wire.
//!
//! A card presented at a reader comes out of `OsdpBus::poll` as a `CardRead`, the same
//! thing the Wiegand collector produces, and goes through `card_read::handle` like any
//! other.
//!
//! After each card the reader is told what to show and sound (`OsdpBus::feedback`): green
//! and one beep for a grant, red flashes and three beeps for anything else. A reader going
//! quiet or coming back, and its tamper and power reports, are queued as events
//! (`reader_online`, `reader_offline`, `reader_tamper`, `reader_tamper_restored`,
//! `reader_power_failure`, `reader_power_restored`), once per change.
//!
//! `run` serves the readers the configuration names, over the board's RS-485 serial port
//! (`SerialWire`). With no OSDP reader configured it does nothing.
//!
//! Secure channel. A reader set to use it gets a key of its own, made on this controller
//! and kept only here (`osdp_reader_keys` in the controller database; never sent to the
//! server, never in a command, result, event or log). The key is handed over the standard
//! way: the reader is put in its install mode, the controller opens one session under the
//! default key every OSDP reader accepts in that mode, and sends the real key (KEYSET).
//! That is only allowed for a few minutes after the server asks for it (`enroll_command`).
//! Until the reader has its key nothing it sends is acted on, and afterwards it is run
//! enforced: its own key or nothing. A secure reader with no key stays off; it is never
//! run in the clear. The key is protected by file permissions only, like the controller's
//! own secret, not by hardware.

use anyhow::{Context, Result, bail};
use libosdp::{
    Channel, ControlPanel, ControlPanelBuilder, OsdpCommand, OsdpCommandBuzzer, OsdpCommandLed, OsdpEvent,
    OsdpEventCardRead, OsdpFlag, OsdpLedColor, OsdpLedParams, OsdpStatusReport, OsdpStatusReportType, PdInfoBuilder,
};
use std::sync::mpsc::{Receiver, channel};
use tracing::warn;

use super::card_read::{CardRead, ReadSource};

/// The longest card the controller will accept from a reader, as for Wiegand.
const MAX_CARD_BITS: usize = 128;

/// One OSDP reader on a bus.
#[derive(Clone, PartialEq, Eq)]
pub struct OsdpReader {
    /// Reader port this reader stands for (port number minus one), as in `CardRead`.
    pub channel: u8,
    /// OSDP address on the bus, 0 to 126.
    pub address: u8,
    /// Line speed the reader is set to.
    pub baud_rate: u32,
    /// Secure-channel key. With a key the reader must talk encrypted; without one the
    /// exchange is plain.
    pub secure_channel_key: Option<[u8; 16]>,
    /// The reader has not taken the key yet. The controller may then open one session
    /// with the default key every OSDP reader accepts in its install mode, to hand the
    /// real key over. Nothing the reader sends is acted on until that is done.
    pub enrolling: bool,
}

/// The key is never printed.
impl std::fmt::Debug for OsdpReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsdpReader")
            .field("channel", &self.channel)
            .field("address", &self.address)
            .field("baud_rate", &self.baud_rate)
            .field("has_key", &self.secure_channel_key.is_some())
            .field("enrolling", &self.enrolling)
            .finish()
    }
}

/// Whether a reader is answering, and whether the exchange is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderLink {
    pub channel: u8,
    pub online: bool,
    pub secure: bool,
}

/// What the reader shows and sounds after a card was presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feedback {
    /// Steady green for a second and one beep.
    Granted,
    /// Three red flashes and three short beeps.
    Denied,
}

/// Something a reader reported about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderStatus {
    pub channel: u8,
    /// The reader's cover or mounting switch reports interference.
    pub tamper: bool,
    /// The reader reports a problem with its power.
    pub power_failure: bool,
}

/// The light and buzzer commands for `feedback`. Both are temporary: the reader returns
/// to its own idle state afterwards, so nothing here has to know what that is.
fn feedback_commands(feedback: Feedback) -> (OsdpCommandLed, OsdpCommandBuzzer) {
    // Durations are in tenths of a second.
    let (color, on, off, total, beeps, beep_on, beep_off) = match feedback {
        Feedback::Granted => (OsdpLedColor::Green, 10, 0, 10, 1, 2, 1),
        Feedback::Denied => (OsdpLedColor::Red, 1, 1, 6, 3, 1, 1),
    };
    let led = OsdpCommandLed {
        reader: 0,
        led_number: 0,
        temporary: OsdpLedParams {
            control_code: 2, // set the temporary state and start its timer
            on_count: on,
            off_count: off,
            on_color: color,
            off_color: OsdpLedColor::None,
            timer_count: total,
        },
        permanent: OsdpLedParams::default(), // control code 0: leave the idle state alone
    };
    let buzzer = OsdpCommandBuzzer { reader: 0, control_code: 2, on_count: beep_on, off_count: beep_off, rep_count: beeps };
    (led, buzzer)
}

/// The tamper and power flags from a reader's local status report.
fn local_status(report: &OsdpStatusReport) -> Option<(bool, bool)> {
    if report.type_ != OsdpStatusReportType::Local || report.nr_entries < 2 {
        return None;
    }
    Some((report.report[0] != 0, report.report[1] != 0))
}

/// The readers on one RS-485 line.
pub struct OsdpBus {
    panel: ControlPanel,
    /// Reader port for each reader, in the order LibOSDP numbers them.
    channels: Vec<u8>,
    /// Whether each reader has a secure-channel key, and whether it is still to take it.
    keyed: Vec<bool>,
    enrolling: Vec<bool>,
    events: Receiver<(i32, OsdpEvent)>,
    /// Status reports received and not yet collected with `take_status`.
    status: Vec<ReaderStatus>,
}

impl OsdpBus {
    /// Start talking to `readers` over `wire`.
    pub fn open(wire: Box<dyn Channel>, readers: &[OsdpReader]) -> Result<Self> {
        if readers.is_empty() {
            bail!("an OSDP bus needs at least one reader");
        }
        let mut infos = Vec::with_capacity(readers.len());
        for (index, reader) in readers.iter().enumerate() {
            if reader.address > 126 {
                bail!("OSDP address {} is out of range (0 to 126)", reader.address);
            }
            if readers[..index].iter().any(|other| other.address == reader.address) {
                bail!("OSDP address {} is used twice on one bus", reader.address);
            }
            if readers[..index].iter().any(|other| other.channel == reader.channel) {
                bail!("reader port {} is used twice on one bus", reader.channel + 1);
            }
            let mut info = PdInfoBuilder::new()
                .name(&format!("reader-{}", reader.channel + 1))
                .context("OSDP reader name")?
                .address(i32::from(reader.address))
                .context("OSDP reader address")?
                .baud_rate(i32::try_from(reader.baud_rate).context("OSDP baud rate")?)
                .context("OSDP baud rate")?;
            if let Some(key) = reader.secure_channel_key {
                info = info.secure_channel_key(key);
                // Enforced, the default key is never used and a reader that will not talk
                // encrypted with its own key stays offline.
                if !reader.enrolling {
                    info = info.flag(OsdpFlag::EnforceSecure);
                }
            }
            infos.push(info);
        }

        let mut panel = ControlPanelBuilder::new()
            .add_channel(wire, infos)
            .build()
            .context("start the OSDP control panel")?;
        let (sender, events) = channel();
        panel.set_event_callback(move |reader, event| {
            // The receiver lives as long as the bus; a failed send only means it is gone.
            let _ = sender.send((reader, event));
            0
        });

        Ok(Self {
            panel,
            channels: readers.iter().map(|r| r.channel).collect(),
            keyed: readers.iter().map(|r| r.secure_channel_key.is_some()).collect(),
            enrolling: readers.iter().map(|r| r.secure_channel_key.is_some() && r.enrolling).collect(),
            events,
            status: Vec::new(),
        })
    }

    /// Do one round of protocol work and return the cards presented since the last call.
    /// Call it often (every 10 to 50 ms); it never blocks.
    pub fn poll(&mut self) -> Vec<CardRead> {
        self.panel.refresh();
        let mut reads = Vec::new();
        while let Ok((reader, event)) = self.events.try_recv() {
            let Some(&channel) = usize::try_from(reader).ok().and_then(|i| self.channels.get(i)) else {
                warn!(target: "indagate_osdp", reader, "event from an unknown OSDP reader ignored");
                continue;
            };
            // A reader that has a key is only listened to over its own encrypted session.
            // While the key is still being handed over the session may be plain or under
            // the public default key, so nothing it sends is acted on.
            let index = reader as usize;
            if self.keyed[index] && (self.enrolling[index] || !self.panel.is_sc_active(reader)) {
                if matches!(event, OsdpEvent::CardRead(_)) {
                    warn!(
                        target: "indagate_osdp",
                        reader = channel + 1,
                        "card read ignored: the reader's encrypted session is not established"
                    );
                }
                continue;
            }
            match event {
                OsdpEvent::CardRead(card) => match card_bits(&card) {
                    Some(bits) => reads.push(CardRead { channel, bits, source: ReadSource::Osdp }),
                    None => warn!(
                        target: "indagate_osdp",
                        reader = channel + 1,
                        bits = card.nr_bits,
                        "OSDP card read with an unusable bit count ignored"
                    ),
                },
                OsdpEvent::Status(report) => {
                    if let Some((tamper, power_failure)) = local_status(&report) {
                        self.status.push(ReaderStatus { channel, tamper, power_failure });
                    }
                }
                // Key presses and manufacturer replies are not used.
                _ => {}
            }
        }
        reads
    }

    /// What the readers reported about themselves since the last call.
    pub fn take_status(&mut self) -> Vec<ReaderStatus> {
        std::mem::take(&mut self.status)
    }

    /// Show and sound the result of a card read at the reader on `channel`. A reader with
    /// no light or no buzzer simply does not get that half; neither failure matters to
    /// the decision, which has already been made.
    pub fn feedback(&mut self, channel: u8, feedback: Feedback) {
        let Some(reader) = self.channels.iter().position(|c| *c == channel) else { return };
        let (led, buzzer) = feedback_commands(feedback);
        for (what, command) in [("light", OsdpCommand::Led(led)), ("buzzer", OsdpCommand::Buzzer(buzzer))] {
            if let Err(err) = self.panel.send_command(reader as i32, command) {
                tracing::debug!(target: "indagate_osdp", reader = channel + 1, what, error = %err, "reader feedback not sent");
            }
        }
    }

    /// The state of each reader's link.
    pub fn links(&self) -> Vec<ReaderLink> {
        self.channels
            .iter()
            .enumerate()
            .map(|(index, &channel)| {
                let reader = index as i32;
                ReaderLink {
                    channel,
                    online: self.panel.is_online(reader),
                    secure: self.panel.is_sc_active(reader),
                }
            })
            .collect()
    }
}

/// The card's bits, one per element, from an OSDP card-read report.
///
/// OSDP packs the bits into bytes, first bit in the top of the first byte, with a count of
/// how many are valid.
fn card_bits(card: &OsdpEventCardRead) -> Option<Vec<u8>> {
    let count = card.nr_bits;
    if count == 0 || count > MAX_CARD_BITS || count > card.data.len() * 8 {
        return None;
    }
    Some((0..count).map(|i| (card.data[i / 8] >> (7 - i % 8)) & 1).collect())
}

// ---------- the serial line ----------

/// The board's RS-485 serial port as the wire LibOSDP talks over.
///
/// The port is opened raw, 8 data bits, no parity, one stop bit, and never blocks. The
/// kernel is asked to drive the transceiver's direction (RS-485 mode, sending while RTS is
/// raised); on a port where that is not available the request is skipped and logged, since
/// some boards switch direction in hardware.
pub struct SerialWire {
    port: std::fs::File,
}

/// `struct serial_rs485` from the Linux serial interface.
#[repr(C)]
#[derive(Default)]
struct SerialRs485 {
    flags: u32,
    delay_rts_before_send: u32,
    delay_rts_after_send: u32,
    padding: [u32; 5],
}
const TIOCSRS485: libc::c_ulong = 0x542F;
const SER_RS485_ENABLED: u32 = 1;
const SER_RS485_RTS_ON_SEND: u32 = 1 << 1;

fn speed_constant(baud_rate: u32) -> Option<libc::speed_t> {
    Some(match baud_rate {
        9600 => libc::B9600,
        19200 => libc::B19200,
        38400 => libc::B38400,
        57600 => libc::B57600,
        115200 => libc::B115200,
        230400 => libc::B230400,
        _ => return None,
    })
}

impl SerialWire {
    pub fn open(path: &str, baud_rate: u32) -> Result<Self> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;

        let speed = speed_constant(baud_rate).with_context(|| format!("unsupported line speed {baud_rate}"))?;
        let port = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("open serial port {path}"))?;
        let fd = port.as_raw_fd();

        // SAFETY: `fd` is an open descriptor owned by `port` for the whole block, and each
        // call is given a properly sized, initialised structure.
        unsafe {
            let mut settings: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut settings) != 0 {
                bail!("{path} is not a serial port: {}", std::io::Error::last_os_error());
            }
            libc::cfmakeraw(&mut settings);
            settings.c_cflag |= libc::CLOCAL | libc::CREAD;
            settings.c_cflag &= !(libc::CSTOPB | libc::PARENB | libc::CRTSCTS);
            settings.c_cc[libc::VMIN] = 0;
            settings.c_cc[libc::VTIME] = 0;
            if libc::cfsetispeed(&mut settings, speed) != 0 || libc::cfsetospeed(&mut settings, speed) != 0 {
                bail!("set line speed on {path}: {}", std::io::Error::last_os_error());
            }
            if libc::tcsetattr(fd, libc::TCSANOW, &settings) != 0 {
                bail!("configure {path}: {}", std::io::Error::last_os_error());
            }
            libc::tcflush(fd, libc::TCIOFLUSH);

            let rs485 = SerialRs485 { flags: SER_RS485_ENABLED | SER_RS485_RTS_ON_SEND, ..Default::default() };
            if libc::ioctl(fd, TIOCSRS485, &rs485) != 0 {
                warn!(
                    target: "indagate_osdp",
                    port = path,
                    error = %std::io::Error::last_os_error(),
                    "the serial port did not accept RS-485 mode; relying on the board to switch direction"
                );
            }
        }
        Ok(Self { port })
    }
}

impl Channel for SerialWire {
    fn get_id(&self) -> i32 {
        use std::os::fd::AsRawFd;
        self.port.as_raw_fd()
    }

    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, libosdp::ChannelError> {
        use std::io::Read;
        match self.port.read(buf) {
            Ok(count) => Ok(count),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, libosdp::ChannelError> {
        use std::io::Write;
        match self.port.write(buf) {
            Ok(count) => Ok(count),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    /// Throw away anything received and not yet read.
    fn flush(&mut self) -> std::result::Result<(), libosdp::ChannelError> {
        use std::os::fd::AsRawFd;
        // SAFETY: the descriptor is open for as long as `self.port` lives.
        unsafe { libc::tcflush(self.port.as_raw_fd(), libc::TCIFLUSH) };
        Ok(())
    }

    fn close(&mut self) -> std::result::Result<(), libosdp::ChannelError> {
        Ok(())
    }
}

// ---------- running the readers ----------

/// How often the bus is serviced.
const POLL_EVERY: std::time::Duration = std::time::Duration::from_millis(20);
/// How often the reader settings are checked for a change.
const SETTINGS_CHECK_EVERY: std::time::Duration = std::time::Duration::from_secs(3);
/// How long to wait before trying again after the bus could not be started.
const RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a reader's encrypted session must hold, while its key is being handed over,
/// before the key counts as taken. A session under the public default key lasts only the
/// moment it takes to send the real key, so one that holds is under the real key.
const SECURE_HELD_FOR: std::time::Duration = std::time::Duration::from_secs(5);

/// Serve the OSDP readers the controller is configured with, for as long as it runs.
///
/// With no OSDP reader configured this only checks, every few seconds, whether one has
/// appeared. When the settings or a reader's key change the bus is closed and started
/// again. A card presented at a reader goes through the same decision as any other.
///
/// A reader set to use the secure channel runs only once it has a key: handed over during
/// a time-limited enrolment (`enroll_command`), then enforced from that point on.
pub async fn run(serial_port: &str, db_path: &str, relay_tx: tokio::sync::mpsc::Sender<crate::hal::relay_worker::RelayCommand>) {
    let _ = DATABASE_PATH.set(db_path.to_string());
    let db = match crate::storage::ControllerDatabase::open(db_path) {
        Ok(db) => db,
        Err(err) => {
            tracing::error!(target: "indagate_osdp", error = %err, "Unable to open the database for OSDP readers");
            return;
        }
    };
    let current_plan = |db: &crate::storage::ControllerDatabase| {
        plan(&db.osdp_readers().unwrap_or_default(), |channel| db.osdp_reader_key(channel).ok().flatten(), chrono::Utc::now())
    };
    let mut last_waiting: Vec<u8> = Vec::new();
    loop {
        let (readers, waiting) = current_plan(&db);
        if waiting != last_waiting {
            for channel in &waiting {
                tracing::warn!(
                    target: "indagate_osdp",
                    reader = channel + 1,
                    "OSDP reader is set to use the secure channel and has no key yet; it stays off until it is enrolled"
                );
            }
            last_waiting = waiting.clone();
        }
        if readers.is_empty() {
            tokio::time::sleep(SETTINGS_CHECK_EVERY).await;
            continue;
        }
        let mut bus = match open_bus(serial_port, &readers) {
            Ok(bus) => bus,
            Err(err) => {
                tracing::error!(target: "indagate_osdp", error = %err, "OSDP readers could not be started; READERS OFFLINE");
                tokio::time::sleep(RETRY_AFTER).await;
                continue;
            }
        };
        tracing::info!(target: "indagate_osdp", readers = readers.len(), port = serial_port, "OSDP readers started");

        let started = std::time::Instant::now();
        let mut watches: Vec<ReaderWatch> = readers.iter().map(|_| ReaderWatch::default()).collect();
        let mut secure_since: Vec<Option<std::time::Instant>> = readers.iter().map(|_| None).collect();
        let mut settings_checked = std::time::Instant::now();
        'bus: loop {
            for read in bus.poll() {
                let channel = read.channel;
                let outcome = super::card_read::handle(read, &db, &relay_tx).await;
                bus.feedback(channel, feedback_for(outcome));
            }
            // A reader going quiet, coming back, or reporting tamper or a power problem
            // is recorded as an event, once per change.
            for (index, link) in bus.links().into_iter().enumerate() {
                if let Some(event) = watches[index].link_event(link.online, started.elapsed()) {
                    tracing::info!(target: "indagate_osdp", reader = link.channel + 1, event, secure = link.secure, "OSDP reader link changed");
                    super::card_read::queue_event(
                        &db,
                        event,
                        link.channel,
                        serde_json::json!({ "reader": link.channel + 1, "source": "osdp", "secure_channel": link.secure }),
                    );
                }
                // A reader being given its key: once its encrypted session holds, the key
                // is recorded as taken and the bus restarts with that reader enforced.
                if readers[index].enrolling {
                    if !link.secure {
                        secure_since[index] = None;
                    } else if secure_since[index].get_or_insert_with(std::time::Instant::now).elapsed() >= SECURE_HELD_FOR {
                        match db.osdp_mark_enrolled(link.channel) {
                            Ok(()) => {
                                tracing::info!(target: "indagate_osdp", reader = link.channel + 1, "OSDP reader has taken its secure-channel key");
                                super::card_read::queue_event(
                                    &db,
                                    "reader_secure_channel_enrolled",
                                    link.channel,
                                    serde_json::json!({ "reader": link.channel + 1, "source": "osdp" }),
                                );
                                break 'bus;
                            }
                            Err(err) => tracing::error!(target: "indagate_osdp", error = %err, "could not record the reader's key as taken"),
                        }
                    }
                }
            }
            for status in bus.take_status() {
                let Some(watch) = bus_index(&bus, status.channel).and_then(|i| watches.get_mut(i)) else { continue };
                for event in watch.status_events(status.tamper, status.power_failure) {
                    tracing::warn!(target: "indagate_osdp", reader = status.channel + 1, event, "OSDP reader status changed");
                    super::card_read::queue_event(
                        &db,
                        event,
                        status.channel,
                        serde_json::json!({ "reader": status.channel + 1, "source": "osdp" }),
                    );
                }
            }
            if settings_checked.elapsed() >= SETTINGS_CHECK_EVERY {
                settings_checked = std::time::Instant::now();
                let (now_readers, now_waiting) = current_plan(&db);
                if now_readers != readers {
                    // An enrolment that ran out of time without the reader taking its key.
                    for reader in readers.iter().filter(|r| r.enrolling) {
                        if now_waiting.contains(&reader.channel) {
                            tracing::warn!(target: "indagate_osdp", reader = reader.channel + 1, "OSDP reader enrolment ran out of time");
                            super::card_read::queue_event(
                                &db,
                                "reader_secure_channel_enroll_expired",
                                reader.channel,
                                serde_json::json!({ "reader": reader.channel + 1, "source": "osdp" }),
                            );
                        }
                    }
                    tracing::info!(target: "indagate_osdp", "OSDP reader settings changed; restarting the bus");
                    break;
                }
            }
            tokio::time::sleep(POLL_EVERY).await;
        }
    }
}

/// How each configured reader is to be run right now, and the reader ports that must wait
/// because they are set to use the secure channel and have no usable key.
///
/// `configured` is (channel, address, line speed, secure channel required).
fn plan(
    configured: &[(u8, u8, u32, bool)],
    key_of: impl Fn(u8) -> Option<crate::storage::OsdpReaderKey>,
    now: chrono::DateTime<chrono::Utc>,
) -> (Vec<OsdpReader>, Vec<u8>) {
    let mut readers = Vec::new();
    let mut waiting = Vec::new();
    for &(channel, address, baud_rate, secure) in configured {
        let reader = |secure_channel_key, enrolling| OsdpReader { channel, address, baud_rate, secure_channel_key, enrolling };
        if !secure {
            readers.push(reader(None, false));
            continue;
        }
        match key_of(channel) {
            Some(key) if key.active => readers.push(reader(Some(key.key), false)),
            Some(key) if key.enroll_until.is_some_and(|until| now < until) => readers.push(reader(Some(key.key), true)),
            // No key, or one whose hand-over time has passed: never run in the clear.
            _ => waiting.push(channel),
        }
    }
    (readers, waiting)
}

// ---------- commands from the server ----------

/// Where the controller's database is, for the commands below (set when `run` starts).
static DATABASE_PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// How long a key may be handed over for after an enrolment is asked for.
const ENROLL_WINDOW_SECONDS: i64 = 600;
const ENROLL_WINDOW_RANGE: std::ops::RangeInclusive<i64> = 60..=3600;

fn command_database() -> Result<crate::storage::ControllerDatabase> {
    let path = DATABASE_PATH.get().context("OSDP readers are not running on this controller")?;
    crate::storage::ControllerDatabase::open(path)
}

/// The reader port a command names (`reader_number`, 1 upward) as a channel.
fn command_channel(payload: &serde_json::Value) -> Result<u8> {
    payload
        .get("reader_number")
        .and_then(serde_json::Value::as_u64)
        .filter(|n| (1..=4).contains(n))
        .map(|n| n as u8 - 1)
        .context("reader_number must be a reader port from 1 to 4")
}

/// Command `osdp_reader_enroll`: make a secure-channel key for a reader and hand it over
/// during the next few minutes. The reader must be put in its install mode (see its
/// manual) while that time runs. Payload: `reader_number`, optional `window_seconds`.
pub fn enroll_command(payload: &serde_json::Value) -> Result<serde_json::Value> {
    enroll(&command_database()?, payload, chrono::Utc::now())
}

/// Command `osdp_reader_forget_key`: forget the key held for a reader, for when the
/// reader was replaced or reset. Payload: `reader_number`.
pub fn forget_key_command(payload: &serde_json::Value) -> Result<serde_json::Value> {
    forget_key(&command_database()?, payload)
}

fn enroll(
    db: &crate::storage::ControllerDatabase,
    payload: &serde_json::Value,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<serde_json::Value> {
    let channel = command_channel(payload)?;
    let window = match payload.get("window_seconds") {
        None | Some(serde_json::Value::Null) => ENROLL_WINDOW_SECONDS,
        Some(value) => value
            .as_i64()
            .filter(|seconds| ENROLL_WINDOW_RANGE.contains(seconds))
            .context("window_seconds must be from 60 to 3600")?,
    };
    match db.osdp_readers()?.into_iter().find(|reader| reader.0 == channel) {
        None => bail!("reader {} is not an enabled OSDP reader", channel + 1),
        Some((_, _, _, false)) => bail!("reader {} is not set to use the secure channel", channel + 1),
        Some(_) => {}
    }
    let key = match db.osdp_reader_key(channel)? {
        Some(held) if held.active => bail!(
            "reader {} already has a key; if the reader was replaced or reset, forget its key first",
            channel + 1
        ),
        // Asked again before the reader took it: the same key, with more time.
        Some(held) => held.key,
        None => {
            use ring::rand::SecureRandom;
            let mut key = [0u8; 16];
            ring::rand::SystemRandom::new().fill(&mut key).map_err(|_| anyhow::anyhow!("no random source for a key"))?;
            key
        }
    };
    let until = now + chrono::Duration::seconds(window);
    db.osdp_begin_enrollment(channel, key, until)?;
    Ok(serde_json::json!({
        "message": "put the reader in its install mode now; the key is handed over when it answers",
        "reader_number": channel + 1,
        "enroll_until": until.to_rfc3339(),
    }))
}

fn forget_key(db: &crate::storage::ControllerDatabase, payload: &serde_json::Value) -> Result<serde_json::Value> {
    let channel = command_channel(payload)?;
    let had_key = db.osdp_forget_key(channel)?;
    Ok(serde_json::json!({
        "message": if had_key { "key forgotten; the reader stays off until it is enrolled again" } else { "no key was held for this reader" },
        "reader_number": channel + 1,
        "had_key": had_key,
    }))
}

/// How long a reader may take to answer after the bus starts before it is recorded as
/// offline. Bringing a reader online takes a second or two.
const OFFLINE_AFTER_START: std::time::Duration = std::time::Duration::from_secs(15);

fn bus_index(bus: &OsdpBus, channel: u8) -> Option<usize> {
    bus.channels.iter().position(|c| *c == channel)
}

/// Anything but a grant sounds and shows as a refusal, an unreadable card included.
fn feedback_for(outcome: super::card_read::ReadOutcome) -> Feedback {
    match outcome {
        super::card_read::ReadOutcome::Granted { .. } => Feedback::Granted,
        _ => Feedback::Denied,
    }
}

/// What has already been recorded about one reader, so each change is recorded once.
#[derive(Debug, Default)]
struct ReaderWatch {
    online: Option<bool>,
    tamper: Option<bool>,
    power_failure: Option<bool>,
}

impl ReaderWatch {
    /// The event to record for the reader's link state, if it is news.
    fn link_event(&mut self, online: bool, since_start: std::time::Duration) -> Option<&'static str> {
        match (self.online, online) {
            (Some(true), true) | (Some(false), false) => None,
            (_, true) => {
                self.online = Some(true);
                Some("reader_online")
            }
            (Some(true), false) => {
                self.online = Some(false);
                Some("reader_offline")
            }
            // Never seen yet: give it time to answer before calling it offline.
            (None, false) if since_start >= OFFLINE_AFTER_START => {
                self.online = Some(false);
                Some("reader_offline")
            }
            (None, false) => None,
        }
    }

    /// The events to record for a status report. The first report from a healthy reader
    /// records nothing.
    fn status_events(&mut self, tamper: bool, power_failure: bool) -> Vec<&'static str> {
        let mut events = Vec::new();
        if self.tamper.unwrap_or(false) != tamper {
            events.push(if tamper { "reader_tamper" } else { "reader_tamper_restored" });
        }
        if self.power_failure.unwrap_or(false) != power_failure {
            events.push(if power_failure { "reader_power_failure" } else { "reader_power_restored" });
        }
        self.tamper = Some(tamper);
        self.power_failure = Some(power_failure);
        events
    }
}

/// One bus needs one line speed.
fn open_bus(serial_port: &str, readers: &[OsdpReader]) -> Result<OsdpBus> {
    let baud_rate = readers[0].baud_rate;
    if readers.iter().any(|reader| reader.baud_rate != baud_rate) {
        bail!("the OSDP readers on one line are set to different speeds");
    }
    let wire = SerialWire::open(serial_port, baud_rate)?;
    OsdpBus::open(Box::new(wire), readers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal::card_read::{self, ReadOutcome};
    use crate::hal::relay_worker::RelayCommand;
    use crate::storage::ControllerDatabase;
    use libosdp::{ChannelError, PdCapEntity, PdCapability, PeripheralDevice};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    /// One end of a wire held in memory: what one end writes, the other reads.
    struct MemoryWire {
        id: i32,
        outgoing: Arc<Mutex<VecDeque<u8>>>,
        incoming: Arc<Mutex<VecDeque<u8>>>,
    }

    fn memory_wire() -> (MemoryWire, MemoryWire) {
        let a = Arc::new(Mutex::new(VecDeque::new()));
        let b = Arc::new(Mutex::new(VecDeque::new()));
        (
            MemoryWire { id: 1, outgoing: a.clone(), incoming: b.clone() },
            MemoryWire { id: 2, outgoing: b, incoming: a },
        )
    }

    impl Channel for MemoryWire {
        fn get_id(&self) -> i32 {
            self.id
        }
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, ChannelError> {
            let mut incoming = self.incoming.lock().unwrap();
            let count = buf.len().min(incoming.len());
            for slot in buf.iter_mut().take(count) {
                *slot = incoming.pop_front().unwrap();
            }
            Ok(count)
        }
        fn write(&mut self, buf: &[u8]) -> Result<usize, ChannelError> {
            self.outgoing.lock().unwrap().extend(buf.iter().copied());
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<(), ChannelError> {
            Ok(())
        }
        fn close(&mut self) -> Result<(), ChannelError> {
            Ok(())
        }
    }

    const KEY: [u8; 16] = [
        0x94, 0x4b, 0x8e, 0xdd, 0xcb, 0xaa, 0x2b, 0x5f, 0xe2, 0xb0, 0x14, 0x8d, 0x1b, 0x2f, 0x95, 0xc9,
    ];

    /// A valid 26-bit card as bits, and as OSDP packs it.
    fn card_26(facility: u8, card: u16) -> (Vec<u8>, Vec<u8>) {
        let mut bits = vec![0u8; 26];
        for i in 0..8 {
            bits[1 + i] = (facility >> (7 - i)) & 1;
        }
        for i in 0..16 {
            bits[9 + i] = ((card >> (15 - i)) & 1) as u8;
        }
        let first: usize = bits[1..13].iter().map(|b| *b as usize).sum();
        let second: usize = bits[13..25].iter().map(|b| *b as usize).sum();
        bits[0] = (first % 2) as u8;
        bits[25] = ((second + 1) % 2) as u8;
        let mut packed = vec![0u8; 4];
        for (i, bit) in bits.iter().enumerate() {
            packed[i / 8] |= bit << (7 - i % 8);
        }
        (bits, packed)
    }

    /// A simulated reader (LibOSDP in its reader role) at `address`, which presents `card`
    /// once the controller has brought it online. Runs until `stop` is set.
    fn simulated_reader(
        wire: MemoryWire,
        address: i32,
        key: Option<[u8; 16]>,
        card: Vec<u8>,
        card_bit_count: usize,
        stop: Arc<AtomicBool>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut info = PdInfoBuilder::new()
                .name("simulated")
                .unwrap()
                .address(address)
                .unwrap()
                .baud_rate(9600)
                .unwrap()
                .capability(PdCapability::CommunicationSecurity(PdCapEntity::new(1, 1)));
            if let Some(key) = key {
                info = info.secure_channel_key(key);
            }
            let mut reader = PeripheralDevice::new(info, Box::new(wire)).expect("simulated reader");
            reader.set_command_callback(|_| 0);
            let mut presented = false;
            while !stop.load(Ordering::Relaxed) {
                reader.refresh();
                if !presented && reader.is_online() && (key.is_none() || reader.is_sc_active()) {
                    let event = OsdpEventCardRead::new_wiegand(card_bit_count, card.clone()).unwrap();
                    reader.notify_event(OsdpEvent::CardRead(event)).expect("present card");
                    presented = true;
                }
                thread::sleep(Duration::from_millis(5));
            }
        })
    }

    /// Poll the bus until it yields a card read, or give up after ten seconds.
    fn wait_for_read(bus: &mut OsdpBus) -> Option<CardRead> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(read) = bus.poll().into_iter().next() {
                return Some(read);
            }
            thread::sleep(Duration::from_millis(5));
        }
        None
    }

    fn reader_on_port_one(key: Option<[u8; 16]>) -> OsdpReader {
        OsdpReader { channel: 0, address: 7, baud_rate: 9600, secure_channel_key: key, enrolling: false }
    }

    #[test]
    fn unpacks_card_bits_first_bit_first() {
        let (bits, packed) = card_26(5, 22271);
        let event = OsdpEventCardRead::new_wiegand(26, packed).unwrap();
        assert_eq!(card_bits(&event), Some(bits));
    }

    #[test]
    fn refuses_unusable_bit_counts() {
        let mut event = OsdpEventCardRead::new_wiegand(8, vec![0xff]).unwrap();
        event.nr_bits = 0;
        assert_eq!(card_bits(&event), None);
        event.nr_bits = 9; // more than the data holds
        assert_eq!(card_bits(&event), None);
        let mut long = OsdpEventCardRead::new_raw(vec![0; 32]);
        long.nr_bits = 129;
        assert_eq!(card_bits(&long), None);
    }

    #[test]
    fn refuses_a_bus_with_clashing_readers() {
        let reader = reader_on_port_one(None);
        let (wire, _other) = memory_wire();
        assert!(OsdpBus::open(Box::new(wire), &[]).is_err());
        let (wire, _other) = memory_wire();
        let same_address = OsdpReader { channel: 1, ..reader.clone() };
        assert!(OsdpBus::open(Box::new(wire), &[reader.clone(), same_address]).is_err());
        let (wire, _other) = memory_wire();
        let same_port = OsdpReader { address: 8, ..reader.clone() };
        assert!(OsdpBus::open(Box::new(wire), &[reader.clone(), same_port]).is_err());
        let (wire, _other) = memory_wire();
        let bad_address = OsdpReader { address: 127, ..reader };
        assert!(OsdpBus::open(Box::new(wire), &[bad_address]).is_err());
    }

    #[test]
    fn a_card_at_an_encrypted_reader_arrives_as_a_card_read() {
        let (controller_end, reader_end) = memory_wire();
        let (bits, packed) = card_26(5, 22271);
        let stop = Arc::new(AtomicBool::new(false));
        let reader = simulated_reader(reader_end, 7, Some(KEY), packed, 26, stop.clone());

        let mut bus = OsdpBus::open(Box::new(controller_end), &[reader_on_port_one(Some(KEY))]).unwrap();
        let read = wait_for_read(&mut bus);
        let links = bus.links();
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();

        let read = read.expect("a card read within ten seconds");
        assert_eq!(read.channel, 0);
        assert_eq!(read.source, ReadSource::Osdp);
        assert_eq!(read.bits, bits);
        assert_eq!(links, vec![ReaderLink { channel: 0, online: true, secure: true }]);
    }

    #[test]
    fn a_reader_set_up_without_a_key_talks_plain() {
        let (controller_end, reader_end) = memory_wire();
        let (bits, packed) = card_26(5, 22271);
        let stop = Arc::new(AtomicBool::new(false));
        let reader = simulated_reader(reader_end, 7, None, packed, 26, stop.clone());

        let mut bus = OsdpBus::open(Box::new(controller_end), &[reader_on_port_one(None)]).unwrap();
        let read = wait_for_read(&mut bus);
        let links = bus.links();
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();

        assert_eq!(read.expect("a card read within ten seconds").bits, bits);
        assert_eq!(links, vec![ReaderLink { channel: 0, online: true, secure: false }]);
    }

    #[test]
    fn a_reader_with_the_wrong_key_never_delivers_a_card() {
        let (controller_end, reader_end) = memory_wire();
        let (_, packed) = card_26(5, 22271);
        let stop = Arc::new(AtomicBool::new(false));
        let mut wrong = KEY;
        wrong[0] ^= 0xff;
        let reader = simulated_reader(reader_end, 7, Some(wrong), packed, 26, stop.clone());

        let mut bus = OsdpBus::open(Box::new(controller_end), &[reader_on_port_one(Some(KEY))]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut reads = Vec::new();
        while Instant::now() < deadline {
            reads.extend(bus.poll());
            thread::sleep(Duration::from_millis(5));
        }
        let links = bus.links();
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();

        assert!(reads.is_empty(), "no card read without the right key");
        assert!(!links[0].secure);
    }

    #[test]
    fn a_keyed_controller_does_not_accept_a_reader_talking_plain() {
        let (controller_end, reader_end) = memory_wire();
        let (_, packed) = card_26(5, 22271);
        let stop = Arc::new(AtomicBool::new(false));
        // The reader has no key, so the best it can offer is a plain exchange.
        let reader = simulated_reader(reader_end, 7, None, packed, 26, stop.clone());

        let mut bus = OsdpBus::open(Box::new(controller_end), &[reader_on_port_one(Some(KEY))]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut reads = Vec::new();
        while Instant::now() < deadline {
            reads.extend(bus.poll());
            thread::sleep(Duration::from_millis(5));
        }
        let links = bus.links();
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();

        assert!(reads.is_empty(), "no card read over a plain exchange when a key is set");
        assert!(!links[0].secure);
    }

    /// The controlling end of a pseudo-terminal, standing in for the far end of the cable.
    struct TerminalEnd(std::fs::File);

    impl Channel for TerminalEnd {
        fn get_id(&self) -> i32 {
            9
        }
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, ChannelError> {
            use std::io::Read;
            match self.0.read(buf) {
                Ok(count) => Ok(count),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => Err(e.into()),
            }
        }
        fn write(&mut self, buf: &[u8]) -> Result<usize, ChannelError> {
            use std::io::Write;
            match self.0.write(buf) {
                Ok(count) => Ok(count),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => Err(e.into()),
            }
        }
        fn flush(&mut self) -> Result<(), ChannelError> {
            Ok(())
        }
        fn close(&mut self) -> Result<(), ChannelError> {
            Ok(())
        }
    }

    /// A pseudo-terminal: its controlling end, the path of the end that behaves like a
    /// serial port, and that end held open so the pair stays connected.
    fn pseudo_terminal() -> (TerminalEnd, String, std::fs::File) {
        use std::os::fd::FromRawFd;
        let (mut controlling, mut port) = (0, 0);
        let mut name = [0 as libc::c_char; 128];
        // SAFETY: the pointers are to live locals of the sizes openpty expects; the two
        // descriptors it returns are owned by the `File`s made from them just below.
        unsafe {
            let made = libc::openpty(&mut controlling, &mut port, name.as_mut_ptr(), std::ptr::null(), std::ptr::null());
            assert_eq!(made, 0, "openpty");
            let flags = libc::fcntl(controlling, libc::F_GETFL);
            libc::fcntl(controlling, libc::F_SETFL, flags | libc::O_NONBLOCK);
            let path = std::ffi::CStr::from_ptr(name.as_ptr()).to_string_lossy().into_owned();
            (TerminalEnd(std::fs::File::from_raw_fd(controlling)), path, std::fs::File::from_raw_fd(port))
        }
    }

    #[test]
    fn a_card_arrives_over_a_real_serial_port() {
        let (far_end, port_path, _held_open) = pseudo_terminal();
        // The controller opens the port the way it opens the board's RS-485 port.
        let wire = SerialWire::open(&port_path, 9600).expect("open the serial port");
        let (bits, packed) = card_26(5, 22271);
        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let stop = stop.clone();
            thread::spawn(move || {
                let info = PdInfoBuilder::new()
                    .name("simulated")
                    .unwrap()
                    .address(7)
                    .unwrap()
                    .baud_rate(9600)
                    .unwrap()
                    .capability(PdCapability::CommunicationSecurity(PdCapEntity::new(1, 1)));
                let mut reader = PeripheralDevice::new(info, Box::new(far_end)).expect("simulated reader");
                reader.set_command_callback(|_| 0);
                let mut presented = false;
                while !stop.load(Ordering::Relaxed) {
                    reader.refresh();
                    if !presented && reader.is_online() {
                        let event = OsdpEventCardRead::new_wiegand(26, packed.clone()).unwrap();
                        reader.notify_event(OsdpEvent::CardRead(event)).expect("present card");
                        presented = true;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            })
        };

        let mut bus = OsdpBus::open(Box::new(wire), &[reader_on_port_one(None)]).unwrap();
        let read = wait_for_read(&mut bus);
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();

        assert_eq!(read.expect("a card read within ten seconds").bits, bits);
    }

    #[test]
    fn the_serial_port_refuses_what_is_not_a_serial_port_or_an_odd_speed() {
        assert!(SerialWire::open("/dev/null", 9600).is_err());
        assert!(SerialWire::open("/nonexistent/port", 9600).is_err());
        let (_far_end, port_path, _held_open) = pseudo_terminal();
        assert!(SerialWire::open(&port_path, 1200).is_err());
    }

    #[test]
    fn readers_on_one_line_must_share_a_speed() {
        let slow = OsdpReader { channel: 0, address: 1, baud_rate: 9600, secure_channel_key: None, enrolling: false };
        let fast = OsdpReader { channel: 1, address: 2, baud_rate: 115200, ..slow.clone() };
        let error = open_bus("/nonexistent/port", &[slow, fast]).err().unwrap().to_string();
        assert!(error.contains("different speeds"), "{error}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_card_at_an_osdp_reader_opens_its_door() {
        let (controller_end, reader_end) = memory_wire();
        let (_, packed) = card_26(5, 22271);
        let stop = Arc::new(AtomicBool::new(false));
        let reader = simulated_reader(reader_end, 7, Some(KEY), packed, 26, stop.clone());

        let mut bus = OsdpBus::open(Box::new(controller_end), &[reader_on_port_one(Some(KEY))]).unwrap();
        let read = wait_for_read(&mut bus);
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();
        let read = read.expect("a card read within ten seconds");

        let db = ControllerDatabase::open(":memory:").unwrap();
        db.connection()
            .execute_batch(
                r#"
                INSERT INTO reader_config (reader_number, reader_id, enabled, door_channel, protocol, osdp_address, osdp_baud_rate)
                    VALUES (1, 'reader1', 1, 0, 'osdp', 7, 9600);
                UPDATE door_config SET unlock_ms = 3000 WHERE channel = 0;
                INSERT INTO credentials (id, facility_code, card_code, enabled, holder_name)
                    VALUES ('card', 5, 22271, 1, 'Test');
                INSERT INTO access_levels (id, name, enabled) VALUES ('level1', 'Level', 1);
                INSERT INTO credential_access_levels VALUES ('card', 'level1');
                INSERT INTO access_level_doors VALUES ('level1', 0, 'always');
                INSERT INTO schedules (id, name, timezone, definition_json)
                    VALUES ('always', 'Always', 'America/New_York', '{"always":true}');
                "#,
            )
            .unwrap();
        let (relay_tx, mut relay_rx) = tokio::sync::mpsc::channel(4);

        let outcome = card_read::handle(read, &db, &relay_tx).await;

        assert_eq!(outcome, ReadOutcome::Granted { relay_command_queued: true });
        match relay_rx.try_recv().expect("a relay command") {
            RelayCommand::Pulse { channel, duration_ms, .. } => assert_eq!((channel, duration_ms), (0, 3000)),
            _ => panic!("expected a pulse"),
        }
    }

    #[test]
    fn a_grant_is_steady_green_and_one_beep() {
        let (led, buzzer) = feedback_commands(Feedback::Granted);
        assert_eq!(led.temporary.control_code, 2);
        assert_eq!(led.temporary.on_color, OsdpLedColor::Green);
        assert_eq!((led.temporary.on_count, led.temporary.off_count, led.temporary.timer_count), (10, 0, 10));
        assert_eq!(led.permanent.control_code, 0, "the reader's idle light is left alone");
        assert_eq!((buzzer.control_code, buzzer.rep_count), (2, 1));
    }

    #[test]
    fn a_refusal_is_three_red_flashes_and_three_beeps() {
        let (led, buzzer) = feedback_commands(Feedback::Denied);
        assert_eq!(led.temporary.on_color, OsdpLedColor::Red);
        assert_eq!((led.temporary.on_count, led.temporary.off_count, led.temporary.timer_count), (1, 1, 6));
        assert_eq!(led.permanent.control_code, 0);
        assert_eq!((buzzer.control_code, buzzer.rep_count), (2, 3));
    }

    #[test]
    fn only_a_grant_sounds_like_a_grant() {
        assert_eq!(feedback_for(ReadOutcome::Granted { relay_command_queued: true }), Feedback::Granted);
        assert_eq!(feedback_for(ReadOutcome::Granted { relay_command_queued: false }), Feedback::Granted);
        for refused in [ReadOutcome::Denied, ReadOutcome::InvalidFrame, ReadOutcome::InvalidParity, ReadOutcome::EngineError] {
            assert_eq!(feedback_for(refused), Feedback::Denied);
        }
    }

    #[test]
    fn a_reader_link_is_recorded_once_per_change() {
        let soon = Duration::from_secs(1);
        let late = OFFLINE_AFTER_START;
        let mut watch = ReaderWatch::default();
        assert_eq!(watch.link_event(false, soon), None, "a reader gets time to answer");
        assert_eq!(watch.link_event(true, soon), Some("reader_online"));
        assert_eq!(watch.link_event(true, late), None);
        assert_eq!(watch.link_event(false, late), Some("reader_offline"));
        assert_eq!(watch.link_event(false, late), None);
        assert_eq!(watch.link_event(true, late), Some("reader_online"));

        let mut never_answered = ReaderWatch::default();
        assert_eq!(never_answered.link_event(false, soon), None);
        assert_eq!(never_answered.link_event(false, late), Some("reader_offline"));
        assert_eq!(never_answered.link_event(false, late), None);
    }

    #[test]
    fn reader_status_is_recorded_once_per_change() {
        let mut watch = ReaderWatch::default();
        assert!(watch.status_events(false, false).is_empty(), "a healthy first report is not news");
        assert_eq!(watch.status_events(true, false), vec!["reader_tamper"]);
        assert!(watch.status_events(true, false).is_empty());
        assert_eq!(watch.status_events(false, true), vec!["reader_tamper_restored", "reader_power_failure"]);
        assert_eq!(watch.status_events(false, false), vec!["reader_power_restored"]);

        let mut starts_tampered = ReaderWatch::default();
        assert_eq!(starts_tampered.status_events(true, true), vec!["reader_tamper", "reader_power_failure"]);
    }

    #[test]
    fn only_a_local_status_report_carries_tamper_and_power() {
        let mut report = OsdpStatusReport { type_: OsdpStatusReportType::Local, nr_entries: 2, report: [0; 64] };
        assert_eq!(local_status(&report), Some((false, false)));
        report.report[0] = 1;
        assert_eq!(local_status(&report), Some((true, false)));
        report.report[1] = 1;
        assert_eq!(local_status(&report), Some((true, true)));
        report.nr_entries = 1;
        assert_eq!(local_status(&report), None);
        let inputs = OsdpStatusReport { type_: OsdpStatusReportType::Input, nr_entries: 2, report: [1; 64] };
        assert_eq!(local_status(&inputs), None);
    }

    /// A simulated reader with a light and a buzzer. It records the commands it is sent,
    /// and reports tamper once it is online.
    fn reader_with_light_and_buzzer(
        wire: MemoryWire,
        received: Arc<Mutex<Vec<OsdpCommand>>>,
        stop: Arc<AtomicBool>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let info = PdInfoBuilder::new()
                .name("simulated")
                .unwrap()
                .address(7)
                .unwrap()
                .baud_rate(9600)
                .unwrap()
                .capability(PdCapability::LedControl(PdCapEntity::new(1, 1)))
                .capability(PdCapability::AudibleOutput(PdCapEntity::new(1, 1)));
            let mut reader = PeripheralDevice::new(info, Box::new(wire)).expect("simulated reader");
            reader.set_command_callback(move |command| {
                received.lock().unwrap().push(command.clone());
                0
            });
            let mut reported = false;
            while !stop.load(Ordering::Relaxed) {
                reader.refresh();
                if !reported && reader.is_online() {
                    let mut report = [0u8; 64];
                    report[0] = 1; // tamper
                    let status = OsdpStatusReport { type_: OsdpStatusReportType::Local, nr_entries: 2, report };
                    reader.notify_event(OsdpEvent::Status(status)).expect("report tamper");
                    reported = true;
                }
                thread::sleep(Duration::from_millis(5));
            }
        })
    }

    #[test]
    fn the_reader_gets_its_light_and_buzzer_and_its_tamper_is_heard() {
        let (controller_end, reader_end) = memory_wire();
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let reader = reader_with_light_and_buzzer(reader_end, received.clone(), stop.clone());
        let mut bus = OsdpBus::open(Box::new(controller_end), &[reader_on_port_one(None)]).unwrap();

        // Wait for the tamper report, which also proves the reader is online.
        let mut status = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while status.is_empty() && Instant::now() < deadline {
            bus.poll();
            status = bus.take_status();
            thread::sleep(Duration::from_millis(5));
        }
        bus.feedback(0, Feedback::Granted);
        bus.feedback(5, Feedback::Granted); // no reader on that port: ignored
        let deadline = Instant::now() + Duration::from_secs(10);
        while received.lock().unwrap().len() < 2 && Instant::now() < deadline {
            bus.poll();
            thread::sleep(Duration::from_millis(5));
        }
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();

        assert_eq!(status, vec![ReaderStatus { channel: 0, tamper: true, power_failure: false }]);
        assert!(bus.take_status().is_empty(), "a report is handed over once");
        let (led, buzzer) = feedback_commands(Feedback::Granted);
        let received = received.lock().unwrap();
        assert!(received.contains(&OsdpCommand::Led(led)), "light command not received: {received:?}");
        assert!(received.contains(&OsdpCommand::Buzzer(buzzer)), "buzzer command not received: {received:?}");
        assert_eq!(received.len(), 2);
    }

    // ---------- secure channel: handing a reader its key ----------

    impl MemoryWire {
        /// Another handle on the same end of the wire, for a bus opened after the first
        /// one is closed.
        fn again(&self) -> MemoryWire {
            MemoryWire { id: self.id, outgoing: self.outgoing.clone(), incoming: self.incoming.clone() }
        }
        fn drain(&self) {
            self.outgoing.lock().unwrap().clear();
            self.incoming.lock().unwrap().clear();
        }
    }

    /// Poll `bus` until the reader's encrypted session has held for a second, or `limit`
    /// passes. Returns whether it did, and every card read handed out meanwhile.
    fn wait_for_secure(bus: &mut OsdpBus, limit: Duration) -> (bool, Vec<CardRead>) {
        let deadline = Instant::now() + limit;
        let mut reads = Vec::new();
        let mut since: Option<Instant> = None;
        while Instant::now() < deadline {
            reads.extend(bus.poll());
            if bus.links()[0].secure {
                if since.get_or_insert_with(Instant::now).elapsed() >= Duration::from_secs(1) {
                    return (true, reads);
                }
            } else {
                since = None;
            }
            thread::sleep(Duration::from_millis(5));
        }
        (false, reads)
    }

    #[test]
    fn a_new_reader_is_given_its_key_and_from_then_on_answers_only_to_it() {
        let (controller_end, reader_end) = memory_wire();
        let (_, packed) = card_26(5, 22271);
        let stop = Arc::new(AtomicBool::new(false));
        // A reader with no key of its own: in its install mode, as it comes out of the box.
        // It presents a card as soon as it is online, before it has been given a key.
        let reader = simulated_reader(reader_end, 7, None, packed, 26, stop.clone());

        // Enrolment: the controller holds a key the reader does not have yet.
        let enrolling = OsdpReader { enrolling: true, ..reader_on_port_one(Some(KEY)) };
        let mut bus = OsdpBus::open(Box::new(controller_end.again()), &[enrolling]).unwrap();
        let (handed_over, reads_meanwhile) = wait_for_secure(&mut bus, Duration::from_secs(15));
        drop(bus);
        controller_end.drain();

        // Afterwards the reader is run enforced: no default key, encrypted or nothing.
        let mut bus = OsdpBus::open(Box::new(controller_end.again()), &[reader_on_port_one(Some(KEY))]).unwrap();
        let (secure_with_its_key, _) = wait_for_secure(&mut bus, Duration::from_secs(15));
        drop(bus);
        controller_end.drain();

        // And it is no longer in install mode: another key cannot be pushed onto it.
        let mut other_key = KEY;
        other_key[0] ^= 0xff;
        let takeover = OsdpReader { enrolling: true, ..reader_on_port_one(Some(other_key)) };
        let mut bus = OsdpBus::open(Box::new(controller_end.again()), &[takeover]).unwrap();
        let (taken_over, _) = wait_for_secure(&mut bus, Duration::from_secs(4));

        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();

        assert!(handed_over, "the reader never came up encrypted during enrolment");
        assert!(reads_meanwhile.is_empty(), "a card read during the hand-over was acted on: {reads_meanwhile:?}");
        assert!(secure_with_its_key, "the reader did not answer to the key it was given");
        assert!(!taken_over, "a second key was accepted by a reader that already has one");
    }

    fn held(active: bool, until_seconds_from_now: Option<i64>, now: chrono::DateTime<chrono::Utc>) -> crate::storage::OsdpReaderKey {
        crate::storage::OsdpReaderKey {
            key: KEY,
            active,
            enroll_until: until_seconds_from_now.map(|s| now + chrono::Duration::seconds(s)),
        }
    }

    #[test]
    fn a_secure_reader_runs_only_with_a_key_and_never_in_the_clear() {
        let now = chrono::Utc::now();
        let configured = [(0, 1, 9600, false), (1, 2, 9600, true), (2, 3, 9600, true), (3, 4, 9600, true)];
        let (readers, waiting) = plan(
            &configured,
            |channel| match channel {
                1 => Some(held(true, None, now)),      // has taken its key
                2 => Some(held(false, Some(60), now)), // being handed its key
                _ => None,                             // secure, never enrolled
            },
            now,
        );
        assert_eq!(waiting, vec![3]);
        let summary: Vec<(u8, bool, bool)> = readers.iter().map(|r| (r.channel, r.secure_channel_key.is_some(), r.enrolling)).collect();
        assert_eq!(summary, vec![(0, false, false), (1, true, false), (2, true, true)]);

        // Once the hand-over time has passed the reader waits again rather than run plain.
        let (readers, waiting) = plan(&[(2, 3, 9600, true)], |_| Some(held(false, Some(-1), now)), now);
        assert!(readers.is_empty());
        assert_eq!(waiting, vec![2]);
    }

    fn database_with_reader(secure: bool) -> ControllerDatabase {
        let db = ControllerDatabase::open(":memory:").unwrap();
        db.connection()
            .execute(
                "INSERT INTO reader_config (reader_number, reader_id, enabled, door_channel, protocol, osdp_address, osdp_baud_rate, osdp_secure)
                 VALUES (1, 'reader1', 1, 0, 'osdp', 7, 9600, ?1)",
                [i64::from(secure)],
            )
            .unwrap();
        db
    }

    #[test]
    fn enrolment_makes_a_key_once_and_never_reveals_it() {
        let db = database_with_reader(true);
        let now = chrono::Utc::now();
        let payload = serde_json::json!({ "reader_number": 1 });

        let result = enroll(&db, &payload, now).unwrap();
        let mut fields: Vec<&String> = result.as_object().unwrap().keys().collect();
        fields.sort();
        assert_eq!(fields, ["enroll_until", "message", "reader_number"], "the result holds no key");
        let first = db.osdp_reader_key(0).unwrap().unwrap();
        assert!(!first.active);
        assert_eq!(first.enroll_until.unwrap().timestamp(), (now + chrono::Duration::seconds(600)).timestamp());
        assert_ne!(first.key, [0u8; 16]);

        // Asked again before the reader took it: the same key, more time.
        let later = now + chrono::Duration::seconds(120);
        enroll(&db, &serde_json::json!({ "reader_number": 1, "window_seconds": 900 }), later).unwrap();
        let second = db.osdp_reader_key(0).unwrap().unwrap();
        assert_eq!(second.key, first.key);
        assert_eq!(second.enroll_until.unwrap().timestamp(), (later + chrono::Duration::seconds(900)).timestamp());

        // Once the reader has it, a new enrolment is refused and the key is kept.
        db.osdp_mark_enrolled(0).unwrap();
        let refused = enroll(&db, &payload, now).unwrap_err().to_string();
        assert!(refused.contains("already has a key"), "{refused}");
        let kept = db.osdp_reader_key(0).unwrap().unwrap();
        assert!(kept.active);
        assert_eq!(kept.key, first.key);
        db.osdp_begin_enrollment(0, [9; 16], now).unwrap();
        assert_eq!(db.osdp_reader_key(0).unwrap().unwrap().key, first.key, "a taken key is never overwritten");

        // Forgetting it lets the reader be enrolled again, with a different key.
        assert_eq!(forget_key(&db, &payload).unwrap()["had_key"], true);
        assert_eq!(forget_key(&db, &payload).unwrap()["had_key"], false);
        enroll(&db, &payload, now).unwrap();
        assert_ne!(db.osdp_reader_key(0).unwrap().unwrap().key, first.key);
    }

    #[test]
    fn enrolment_is_refused_for_the_wrong_reader_or_a_bad_request() {
        let now = chrono::Utc::now();
        let plain = database_with_reader(false);
        let error = enroll(&plain, &serde_json::json!({ "reader_number": 1 }), now).unwrap_err().to_string();
        assert!(error.contains("not set to use the secure channel"), "{error}");

        let db = database_with_reader(true);
        let error = enroll(&db, &serde_json::json!({ "reader_number": 2 }), now).unwrap_err().to_string();
        assert!(error.contains("not an enabled OSDP reader"), "{error}");
        for bad in [serde_json::json!({}), serde_json::json!({ "reader_number": 0 }), serde_json::json!({ "reader_number": 5 }), serde_json::json!({ "reader_number": "1" })] {
            assert!(enroll(&db, &bad, now).is_err(), "{bad}");
            assert!(forget_key(&db, &bad).is_err(), "{bad}");
        }
        for bad_window in [0, 59, 3601, -5] {
            assert!(enroll(&db, &serde_json::json!({ "reader_number": 1, "window_seconds": bad_window }), now).is_err());
        }
        assert!(db.osdp_reader_key(0).unwrap().is_none(), "a refused request leaves no key behind");
    }

    #[test]
    fn a_reader_description_never_prints_its_key() {
        let printed = format!("{:?}", reader_on_port_one(Some(KEY)));
        assert!(printed.contains("has_key: true"), "{printed}");
        assert!(!printed.contains("148") && !printed.contains("0x94"), "{printed}");
    }
}
