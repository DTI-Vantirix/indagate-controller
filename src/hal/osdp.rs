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
    Channel, ControlPanel, ControlPanelBuilder, OsdpCommand, OsdpCommandBuzzer, OsdpCommandKeyset, OsdpCommandLed, OsdpEvent,
    OsdpEventCardRead, OsdpFlag, OsdpLedColor, OsdpLedParams, OsdpStatusReport, OsdpStatusReportType, PdInfoBuilder,
};
use std::sync::mpsc::{Receiver, channel};
use tracing::warn;

use super::card_read::{CardRead, ReadSource};
use super::reader_lights::{LightColor, ReaderLights};

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
    /// A change of this reader's key that is under way. The bus itself ignores it; it
    /// tells whoever runs the bus what to do next.
    pub key_change: KeyChange,
}

/// Where a change of a reader's key stands.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyChange {
    #[default]
    None,
    /// Run with the current key and, once the encrypted session is up, send this new one.
    Send([u8; 16]),
    /// The new key was sent: this session runs with the new key to see whether it took.
    VerifyNew,
    /// The new key was sent but did not answer: this session tries the old key again.
    VerifyOld,
}

impl KeyChange {
    fn name(self) -> &'static str {
        match self {
            KeyChange::None => "none",
            KeyChange::Send(_) => "send",
            KeyChange::VerifyNew => "verify_new",
            KeyChange::VerifyOld => "verify_old",
        }
    }
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
            .field("key_change", &self.key_change.name())
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
    feedback_in(feedback, OsdpLedColor::Green, OsdpLedColor::Red)
}

/// The same, as a reader's light settings want it: their colours, and no command at all
/// for a light set to off or a buzzer set to stay quiet.
fn feedback_with(feedback: Feedback, lights: Option<&ReaderLights>) -> (Option<OsdpCommandLed>, Option<OsdpCommandBuzzer>) {
    let Some(lights) = lights else {
        let (led, buzzer) = feedback_commands(feedback);
        return (Some(led), Some(buzzer));
    };
    let (led, buzzer) = feedback_in(feedback, osdp_color(lights.granted), osdp_color(lights.denied));
    let (color, beep) = match feedback {
        Feedback::Granted => (lights.granted, lights.beep_granted),
        Feedback::Denied => (lights.denied, lights.beep_denied),
    };
    ((color != LightColor::Off).then_some(led), beep.then_some(buzzer))
}

fn osdp_color(color: LightColor) -> OsdpLedColor {
    match color {
        LightColor::Off => OsdpLedColor::None,
        LightColor::Red => OsdpLedColor::Red,
        LightColor::Green => OsdpLedColor::Green,
        LightColor::Amber => OsdpLedColor::Amber,
        LightColor::Blue => OsdpLedColor::Blue,
    }
}

/// The command that sets the light a reader rests on: steady, or flashing slowly. It
/// leaves a result being shown at that moment alone; the reader returns to this after it.
fn resting_command(color: LightColor, flashing: bool) -> OsdpCommandLed {
    OsdpCommandLed {
        reader: 0,
        led_number: 0,
        temporary: OsdpLedParams::default(), // control code 0: leave the result being shown alone
        permanent: OsdpLedParams {
            control_code: 1, // set the permanent state
            on_count: if flashing { 5 } else { 10 },
            off_count: if flashing { 5 } else { 0 },
            on_color: osdp_color(color),
            off_color: OsdpLedColor::None,
            timer_count: 0,
        },
    }
}

fn feedback_in(feedback: Feedback, granted: OsdpLedColor, denied: OsdpLedColor) -> (OsdpCommandLed, OsdpCommandBuzzer) {
    // Durations are in tenths of a second.
    let (color, on, off, total, beeps, beep_on, beep_off) = match feedback {
        Feedback::Granted => (granted, 10, 0, 10, 1, 2, 1),
        Feedback::Denied => (denied, 1, 1, 6, 3, 1, 1),
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

    /// Send the reader on `channel` a new secure-channel key, over its current encrypted
    /// session. The reader then expects the new key; this bus keeps talking to it, but
    /// whoever runs the bus should reopen it with the new key to confirm the change took.
    pub fn set_key(&mut self, channel: u8, key: [u8; 16]) -> Result<()> {
        let reader = self.channels.iter().position(|c| *c == channel).context("no such reader on this bus")?;
        if !self.panel.is_sc_active(reader as i32) {
            bail!("the reader's encrypted session is not up");
        }
        self.panel
            .send_command(reader as i32, OsdpCommand::KeySet(OsdpCommandKeyset::new_scbk(key)))
            .map_err(|err| anyhow::anyhow!("the key could not be sent: {err}"))
    }

    /// Show and sound the result of a card read at the reader on `channel`. A reader with
    /// no light or no buzzer simply does not get that half; neither failure matters to
    /// the decision, which has already been made.
    pub fn feedback(&mut self, channel: u8, feedback: Feedback, lights: Option<&ReaderLights>) {
        let Some(reader) = self.channels.iter().position(|c| *c == channel) else { return };
        let (led, buzzer) = feedback_with(feedback, lights);
        for (what, command) in [("light", led.map(OsdpCommand::Led)), ("buzzer", buzzer.map(OsdpCommand::Buzzer))] {
            let Some(command) = command else { continue };
            if let Err(err) = self.panel.send_command(reader as i32, command) {
                tracing::debug!(target: "indagate_osdp", reader = channel + 1, what, error = %err, "reader feedback not sent");
            }
        }
    }

    /// Set the light the reader on `channel` rests on between cards.
    pub fn resting_light(&mut self, channel: u8, color: LightColor, flashing: bool) -> Result<()> {
        let reader = self.channels.iter().position(|c| *c == channel).context("no such reader on this bus")?;
        self.panel
            .send_command(reader as i32, OsdpCommand::Led(resting_command(color, flashing)))
            .map_err(|err| anyhow::anyhow!("the light command could not be sent: {err}"))
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
/// How long to wait before sending a light command again after one could not go out.
const LIGHT_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(1);
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
    // While it is not known which of two keys a reader holds, sessions take turns with
    // them; this counts the turns for each reader port.
    let mut turns: std::collections::HashMap<u8, u32> = std::collections::HashMap::new();
    let event = |db: &crate::storage::ControllerDatabase, name: &str, channel: u8| {
        super::card_read::queue_event(db, name, channel, serde_json::json!({ "reader": channel + 1, "source": "osdp" }));
    };
    let mut last_waiting: Vec<u8> = Vec::new();
    // What has been recorded about each reader port. Kept across restarts of the bus, so
    // a reader that answers again straight after one is not recorded as lost and found.
    let mut watches: std::collections::HashMap<u8, ReaderWatch> = std::collections::HashMap::new();
    // How many times in a row the bus was reopened for a reader that is not answering.
    let mut quiet_retries: u32 = 0;
    loop {
        for channel in expire_key_changes(&db, chrono::Utc::now()) {
            tracing::warn!(target: "indagate_osdp", reader = channel + 1, "OSDP reader key change ran out of time before it could start");
            event(&db, "reader_secure_channel_rotate_expired", channel);
        }
        let current_plan = |db: &crate::storage::ControllerDatabase, turns: &std::collections::HashMap<u8, u32>| {
            plan(
                &db.osdp_readers().unwrap_or_default(),
                |channel| db.osdp_reader_key(channel).ok().flatten(),
                |channel| turns.get(&channel).copied().unwrap_or(0),
                chrono::Utc::now(),
            )
        };
        let (readers, waiting) = current_plan(&db, &turns);
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
        watches.retain(|channel, _| readers.iter().any(|reader| reader.channel == *channel));
        let mut secure_since: Vec<Option<std::time::Instant>> = readers.iter().map(|_| None).collect();
        let mut key_sent_at: Vec<Option<std::time::Instant>> = readers.iter().map(|_| None).collect();
        let mut settings_checked = std::time::Instant::now();
        // Each reader's door and light settings, the resting light it was last told to
        // show, and when a light command last failed to go out.
        let mut lights = db.osdp_reader_lights().unwrap_or_default();
        let mut shown: Vec<Option<(LightColor, bool)>> = readers.iter().map(|_| None).collect();
        let mut light_failed: Vec<Option<std::time::Instant>> = readers.iter().map(|_| None).collect();
        'bus: loop {
            for read in bus.poll() {
                let channel = read.channel;
                let outcome = super::card_read::handle(read, &db, &relay_tx).await;
                bus.feedback(channel, feedback_for(outcome), lights.get(&channel).and_then(|(_, lights)| lights.as_ref()));
            }
            for (index, link) in bus.links().into_iter().enumerate() {
                // A reader going quiet or coming back is recorded as an event, once per change.
                if let Some(name) = watches.entry(link.channel).or_default().link_event(link.online, std::time::Instant::now()) {
                    // A reader that lost power has forgotten its light: tell it again.
                    shown[index] = None;
                    tracing::info!(target: "indagate_osdp", reader = link.channel + 1, event = name, secure = link.secure, "OSDP reader link changed");
                    super::card_read::queue_event(
                        &db,
                        name,
                        link.channel,
                        serde_json::json!({ "reader": link.channel + 1, "source": "osdp", "secure_channel": link.secure }),
                    );
                }
                let reader = &readers[index];
                // The resting light follows the door: sent when it changes, not every round.
                if let Some(&(door, Some(settings))) = lights.get(&link.channel) {
                    let wanted = settings.resting(super::relay_worker::door_state(door));
                    if link.online
                        && !reader.enrolling
                        && shown[index] != Some(wanted)
                        && light_failed[index].is_none_or(|at| at.elapsed() >= LIGHT_RETRY_AFTER)
                    {
                        match bus.resting_light(link.channel, wanted.0, wanted.1) {
                            Ok(()) => {
                                shown[index] = Some(wanted);
                                light_failed[index] = None;
                            }
                            Err(err) => {
                                tracing::debug!(target: "indagate_osdp", reader = link.channel + 1, error = %err, "reader light not set; will try again");
                                light_failed[index] = Some(std::time::Instant::now());
                            }
                        }
                    }
                }
                let held = if link.secure {
                    Some(secure_since[index].get_or_insert_with(std::time::Instant::now).elapsed())
                } else {
                    secure_since[index] = None;
                    None
                };
                // What to do about a key being handed over or changed (see `key_step`).
                match key_step(reader, held, started.elapsed(), key_sent_at[index].map(|at| at.elapsed())) {
                    KeyStep::Wait => {}
                    KeyStep::Enrolled => match db.osdp_mark_enrolled(link.channel) {
                        Ok(()) => {
                            tracing::info!(target: "indagate_osdp", reader = link.channel + 1, "OSDP reader has taken its secure-channel key");
                            event(&db, "reader_secure_channel_enrolled", link.channel);
                            break 'bus;
                        }
                        Err(err) => tracing::error!(target: "indagate_osdp", error = %err, "could not record the reader's key as taken"),
                    },
                    KeyStep::SendNew(key) => {
                        // Recorded as sent before it is sent: if the controller stops in
                        // between, both keys are still tried afterwards.
                        if db.osdp_rotation_sent(link.channel, true).is_ok() {
                            match bus.set_key(link.channel, key) {
                                Ok(()) => {
                                    tracing::info!(target: "indagate_osdp", reader = link.channel + 1, "new secure-channel key sent to the OSDP reader");
                                    key_sent_at[index] = Some(std::time::Instant::now());
                                }
                                Err(err) => {
                                    tracing::warn!(target: "indagate_osdp", reader = link.channel + 1, error = %err, "new key not sent; will try again");
                                    let _ = db.osdp_rotation_sent(link.channel, false);
                                }
                            }
                        }
                    }
                    // The key was sent a moment ago: reopen the bus to see which key answers.
                    KeyStep::Reopen => break 'bus,
                    KeyStep::NewKeyWorks => {
                        if db.osdp_commit_rotation(link.channel).is_ok() {
                            turns.remove(&link.channel);
                            tracing::info!(target: "indagate_osdp", reader = link.channel + 1, "OSDP reader answers to its new secure-channel key");
                            event(&db, "reader_secure_channel_rotated", link.channel);
                            break 'bus;
                        }
                    }
                    KeyStep::OldKeyStillWorks => {
                        // The reader did not take the new key. Back to before it was sent;
                        // it is sent again if there is still time, otherwise given up.
                        if db.osdp_rotation_sent(link.channel, false).is_ok() {
                            turns.remove(&link.channel);
                            tracing::warn!(target: "indagate_osdp", reader = link.channel + 1, "OSDP reader did not take its new key; it still answers to the old one");
                            break 'bus;
                        }
                    }
                    KeyStep::TryOtherKey => {
                        *turns.entry(link.channel).or_insert(0) += 1;
                        break 'bus;
                    }
                }
            }
            // Tamper and power reports, once per change.
            for status in bus.take_status() {
                let watch = watches.entry(status.channel).or_default();
                for name in watch.status_events(status.tamper, status.power_failure) {
                    tracing::warn!(target: "indagate_osdp", reader = status.channel + 1, event = name, "OSDP reader status changed");
                    event(&db, name, status.channel);
                }
            }
            // A reader that is not answering. LibOSDP leaves one that failed alone for
            // five minutes; a bus that is opened afresh tries every reader at once. So the
            // bus is reopened: soon the first time, then less often, because the other
            // readers on the line have to reconnect each time (a second or two). A key
            // change in progress times its own sessions and is left to it.
            if bus.links().iter().all(|link| link.online) {
                quiet_retries = 0;
            } else if readers.iter().all(|reader| reader.key_change == KeyChange::None)
                && started.elapsed() >= quiet_retry_after(quiet_retries)
            {
                quiet_retries = quiet_retries.saturating_add(1);
                tracing::debug!(target: "indagate_osdp", attempt = quiet_retries, "an OSDP reader is not answering; reopening the bus to try it again");
                break;
            }
            if settings_checked.elapsed() >= SETTINGS_CHECK_EVERY {
                settings_checked = std::time::Instant::now();
                let (now_readers, now_waiting) = current_plan(&db, &turns);
                if now_readers != readers {
                    // An enrolment that ran out of time without the reader taking its key.
                    for reader in readers.iter().filter(|r| r.enrolling) {
                        if now_waiting.contains(&reader.channel) {
                            tracing::warn!(target: "indagate_osdp", reader = reader.channel + 1, "OSDP reader enrolment ran out of time");
                            event(&db, "reader_secure_channel_enroll_expired", reader.channel);
                        }
                    }
                    tracing::info!(target: "indagate_osdp", "OSDP reader settings changed; restarting the bus");
                    break;
                }
                if !expire_key_changes_pending(&db, chrono::Utc::now()).is_empty() {
                    break;
                }
                // Light settings change without restarting the bus.
                let now_lights = db.osdp_reader_lights().unwrap_or_default();
                if now_lights != lights {
                    for (index, reader) in readers.iter().enumerate() {
                        let had = lights.get(&reader.channel).is_some_and(|(_, lights)| lights.is_some());
                        let has = now_lights.get(&reader.channel).is_some_and(|(_, lights)| lights.is_some());
                        // Settings taken away: the light goes dark between cards, as it
                        // was before the controller started setting it.
                        if had && !has {
                            let _ = bus.resting_light(reader.channel, LightColor::Off, false);
                        }
                        shown[index] = None;
                    }
                    lights = now_lights;
                }
            }
            tokio::time::sleep(POLL_EVERY).await;
        }
    }
}

/// How long after a new key is sent before the bus is reopened to see which key answers.
const REOPEN_AFTER_KEY_SENT: std::time::Duration = std::time::Duration::from_secs(3);
/// How long a session waits for a key to answer before the other key gets its turn.
const KEY_TURN: std::time::Duration = std::time::Duration::from_secs(20);
/// How long the encrypted session must be up before a new key is sent over it.
const SEND_KEY_AFTER: std::time::Duration = std::time::Duration::from_secs(2);

/// What to do next about a reader's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyStep {
    Wait,
    /// A reader being enrolled has taken its key.
    Enrolled,
    /// Send this new key over the current session.
    SendNew([u8; 16]),
    /// The new key was sent; close the bus and reopen it to confirm.
    Reopen,
    NewKeyWorks,
    OldKeyStillWorks,
    /// The key this session uses did not answer; let the other have a turn.
    TryOtherKey,
}

impl std::fmt::Debug for KeyChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Decide the next step from how the reader is being run and what has been seen:
/// `secure_for` is how long its encrypted session has been up without a break (if it is),
/// `session_age` how long this bus has been open, `sent_ago` how long since a new key was
/// sent in this session.
fn key_step(
    reader: &OsdpReader,
    secure_for: Option<std::time::Duration>,
    session_age: std::time::Duration,
    sent_ago: Option<std::time::Duration>,
) -> KeyStep {
    let held = |needed| secure_for.is_some_and(|up| up >= needed);
    if reader.enrolling {
        return if held(SECURE_HELD_FOR) { KeyStep::Enrolled } else { KeyStep::Wait };
    }
    match reader.key_change {
        KeyChange::None => KeyStep::Wait,
        KeyChange::Send(key) => match sent_ago {
            None if held(SEND_KEY_AFTER) => KeyStep::SendNew(key),
            None => KeyStep::Wait,
            Some(ago) if ago >= REOPEN_AFTER_KEY_SENT => KeyStep::Reopen,
            Some(_) => KeyStep::Wait,
        },
        KeyChange::VerifyNew if held(SECURE_HELD_FOR) => KeyStep::NewKeyWorks,
        KeyChange::VerifyOld if held(SECURE_HELD_FOR) => KeyStep::OldKeyStillWorks,
        // Not up yet. While the session is up but has not held long enough, keep waiting.
        KeyChange::VerifyNew | KeyChange::VerifyOld => {
            if secure_for.is_none() && session_age >= KEY_TURN { KeyStep::TryOtherKey } else { KeyStep::Wait }
        }
    }
}

/// Key changes that were asked for, never sent, and have run out of time.
fn expire_key_changes_pending(db: &crate::storage::ControllerDatabase, now: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
    db.osdp_readers()
        .unwrap_or_default()
        .into_iter()
        .map(|reader| reader.0)
        .filter(|&channel| {
            db.osdp_reader_key(channel).ok().flatten().is_some_and(|key| {
                key.next_key.is_some() && !key.rotate_sent && key.rotate_until.is_none_or(|until| now >= until)
            })
        })
        .collect()
}

/// Give those up, and say which reader ports they were for.
fn expire_key_changes(db: &crate::storage::ControllerDatabase, now: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
    expire_key_changes_pending(db, now)
        .into_iter()
        .filter(|&channel| db.osdp_cancel_rotation(channel).unwrap_or(false))
        .collect()
}

/// How each configured reader is to be run right now, and the reader ports that must wait
/// because they are set to use the secure channel and have no usable key.
///
/// `configured` is (channel, address, line speed, secure channel required). `turn_of` is
/// how many times a reader whose key is uncertain has had the other key tried.
fn plan(
    configured: &[(u8, u8, u32, bool)],
    key_of: impl Fn(u8) -> Option<crate::storage::OsdpReaderKey>,
    turn_of: impl Fn(u8) -> u32,
    now: chrono::DateTime<chrono::Utc>,
) -> (Vec<OsdpReader>, Vec<u8>) {
    let mut readers = Vec::new();
    let mut waiting = Vec::new();
    for &(channel, address, baud_rate, secure) in configured {
        let reader = |secure_channel_key, enrolling, key_change| OsdpReader {
            channel,
            address,
            baud_rate,
            secure_channel_key,
            enrolling,
            key_change,
        };
        if !secure {
            readers.push(reader(None, false, KeyChange::None));
            continue;
        }
        match key_of(channel) {
            Some(key) if key.active => readers.push(match key.next_key {
                None => reader(Some(key.key), false, KeyChange::None),
                Some(next) if !key.rotate_sent => reader(Some(key.key), false, KeyChange::Send(next)),
                // Sent: the reader holds one of the two. The new one is tried first.
                Some(next) if turn_of(channel) % 2 == 0 => reader(Some(next), false, KeyChange::VerifyNew),
                Some(_) => reader(Some(key.key), false, KeyChange::VerifyOld),
            }),
            Some(key) if key.enroll_until.is_some_and(|until| now < until) => {
                readers.push(reader(Some(key.key), true, KeyChange::None))
            }
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

/// Command `osdp_reader_rotate_key`: change the key of a reader that already has one.
/// The new key is sent over the reader's current encrypted session, so the reader must be
/// connected; nothing has to be done at the reader. Payload: `reader_number`, optional
/// `window_seconds` (how long to wait for the reader to be connected).
pub fn rotate_key_command(payload: &serde_json::Value) -> Result<serde_json::Value> {
    rotate_key(&command_database()?, payload, chrono::Utc::now())
}

fn rotate_key(
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
    match db.osdp_reader_key(channel)? {
        Some(held) if held.active => {}
        Some(_) => bail!("reader {} has not taken its first key yet; finish enrolling it first", channel + 1),
        None => bail!("reader {} has no key to change; enroll it first", channel + 1),
    }
    use ring::rand::SecureRandom;
    let mut next = [0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut next).map_err(|_| anyhow::anyhow!("no random source for a key"))?;
    let until = now + chrono::Duration::seconds(window);
    // A change already under way keeps its own new key; only its time is extended.
    db.osdp_begin_rotation(channel, next, until)?;
    Ok(serde_json::json!({
        "message": "the new key is sent to the reader over its encrypted link as soon as it is connected",
        "reader_number": channel + 1,
        "rotate_until": until.to_rfc3339(),
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

/// How long a reader that was answering may be quiet before it is recorded as offline.
/// Long enough to cover the bus being reopened, short enough to be news.
const OFFLINE_AFTER_QUIET: std::time::Duration = std::time::Duration::from_secs(6);

/// How long a bus with a reader that is not answering runs before it is reopened to try
/// that reader again: 10 seconds, then 20, 40, and once a minute from then on.
fn quiet_retry_after(retries: u32) -> std::time::Duration {
    std::time::Duration::from_secs((10u64 << retries.min(3)).min(60))
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
    /// Since when the reader has not been answering, while it is not.
    quiet_since: Option<std::time::Instant>,
    tamper: Option<bool>,
    power_failure: Option<bool>,
}

impl ReaderWatch {
    /// The event to record for the reader's link state at `now`, if it is news.
    ///
    /// Going quiet is news only once it has lasted: a reader never seen gets
    /// `OFFLINE_AFTER_START` to answer, and one that was answering gets
    /// `OFFLINE_AFTER_QUIET`, which covers the bus being reopened.
    fn link_event(&mut self, online: bool, now: std::time::Instant) -> Option<&'static str> {
        if online {
            self.quiet_since = None;
            if self.online == Some(true) {
                return None;
            }
            self.online = Some(true);
            return Some("reader_online");
        }
        let quiet_for = now.saturating_duration_since(*self.quiet_since.get_or_insert(now));
        let allowed = match self.online {
            Some(false) => return None,
            Some(true) => OFFLINE_AFTER_QUIET,
            None => OFFLINE_AFTER_START,
        };
        if quiet_for < allowed {
            return None;
        }
        self.online = Some(false);
        Some("reader_offline")
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
        OsdpReader { channel: 0, address: 7, baud_rate: 9600, secure_channel_key: key, enrolling: false, key_change: KeyChange::None }
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
        let slow = OsdpReader { channel: 0, address: 1, baud_rate: 9600, secure_channel_key: None, enrolling: false, key_change: KeyChange::None };
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
    fn light_settings_choose_the_colours_and_the_beeps() {
        let lights: ReaderLights = serde_json::from_value(serde_json::json!({
            "granted": "blue", "denied": "amber", "beep_granted": false
        }))
        .unwrap();
        let (led, buzzer) = feedback_with(Feedback::Granted, Some(&lights));
        assert_eq!(led.unwrap().temporary.on_color, OsdpLedColor::Blue);
        assert!(buzzer.is_none(), "the buzzer stays quiet on a grant");
        let (led, buzzer) = feedback_with(Feedback::Denied, Some(&lights));
        assert_eq!(led.unwrap().temporary.on_color, OsdpLedColor::Amber);
        assert!(buzzer.is_some());

        // A light set to off gets no command at all.
        let dark: ReaderLights = serde_json::from_value(serde_json::json!({ "denied": "off" })).unwrap();
        assert!(feedback_with(Feedback::Denied, Some(&dark)).0.is_none());

        // Without settings a reader gets what it always got.
        let (led, buzzer) = feedback_commands(Feedback::Granted);
        assert_eq!(feedback_with(Feedback::Granted, None), (Some(led), Some(buzzer)));
    }

    #[test]
    fn the_resting_light_is_permanent_and_leaves_a_result_alone() {
        let steady = resting_command(LightColor::Red, false);
        assert_eq!(steady.temporary.control_code, 0);
        assert_eq!(steady.permanent.control_code, 1);
        assert_eq!(steady.permanent.on_color, OsdpLedColor::Red);
        assert_eq!(steady.permanent.off_count, 0, "steady: never off");

        let flashing = resting_command(LightColor::Amber, true);
        assert_eq!((flashing.permanent.on_count, flashing.permanent.off_count), (5, 5));
        assert_eq!(flashing.permanent.off_color, OsdpLedColor::None);

        assert_eq!(resting_command(LightColor::Off, false).permanent.on_color, OsdpLedColor::None);
    }

    #[test]
    fn light_settings_are_kept_per_osdp_reader() {
        let db = ControllerDatabase::open(":memory:").unwrap();
        db.connection()
            .execute_batch(
                r#"
                INSERT INTO reader_config (reader_number, reader_id, enabled, door_channel, protocol, osdp_address, lights)
                    VALUES (1, 'reader1', 1, 2, 'osdp', 1, '{"locked":"red","unlocked":"green","granted":"green","denied":"red","lockdown":"amber","beep_granted":true,"beep_denied":false}');
                INSERT INTO reader_config (reader_number, reader_id, enabled, door_channel, protocol, osdp_address)
                    VALUES (2, 'reader2', 1, 1, 'osdp', 2);
                INSERT INTO reader_config (reader_number, reader_id, enabled, door_channel) VALUES (3, 'reader3', 1, 3);
                "#,
            )
            .unwrap();
        let lights = db.osdp_reader_lights().unwrap();
        assert_eq!(lights.len(), 2, "the Wiegand reader is not listed");
        let (door, settings) = lights[&0];
        assert_eq!(door, 2);
        let settings = settings.unwrap();
        assert_eq!(settings.lockdown, LightColor::Amber);
        assert!(!settings.beep_denied);
        assert_eq!(lights[&1], (1, None));
    }

    #[test]
    fn a_reader_link_is_recorded_once_per_change() {
        let start = Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let mut watch = ReaderWatch::default();
        assert_eq!(watch.link_event(false, at(0)), None, "a reader gets time to answer");
        assert_eq!(watch.link_event(true, at(1)), Some("reader_online"));
        assert_eq!(watch.link_event(true, at(20)), None);
        // Quiet for a moment, as when the bus is reopened: not news.
        assert_eq!(watch.link_event(false, at(21)), None);
        assert_eq!(watch.link_event(false, at(23)), None);
        assert_eq!(watch.link_event(true, at(24)), None, "it never counted as offline");
        // Quiet for longer: offline, once.
        assert_eq!(watch.link_event(false, at(30)), None);
        assert_eq!(watch.link_event(false, at(30) + OFFLINE_AFTER_QUIET), Some("reader_offline"));
        assert_eq!(watch.link_event(false, at(60)), None);
        assert_eq!(watch.link_event(true, at(61)), Some("reader_online"));

        let mut never_answered = ReaderWatch::default();
        assert_eq!(never_answered.link_event(false, at(0)), None);
        assert_eq!(never_answered.link_event(false, at(1)), None);
        assert_eq!(never_answered.link_event(false, at(0) + OFFLINE_AFTER_START), Some("reader_offline"));
        assert_eq!(never_answered.link_event(false, at(600)), None);
    }

    #[test]
    fn a_quiet_reader_is_tried_again_soon_and_then_less_often() {
        let seconds: Vec<u64> = (0..6).map(|retries| quiet_retry_after(retries).as_secs()).collect();
        assert_eq!(seconds, vec![10, 20, 40, 60, 60, 60]);
        assert_eq!(quiet_retry_after(u32::MAX).as_secs(), 60);
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
        bus.feedback(0, Feedback::Granted, None);
        bus.feedback(5, Feedback::Granted, None); // no reader on that port: ignored
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
            next_key: None,
            rotate_until: None,
            rotate_sent: false,
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
            |_| 0,
            now,
        );
        assert_eq!(waiting, vec![3]);
        let summary: Vec<(u8, bool, bool)> = readers.iter().map(|r| (r.channel, r.secure_channel_key.is_some(), r.enrolling)).collect();
        assert_eq!(summary, vec![(0, false, false), (1, true, false), (2, true, true)]);

        // Once the hand-over time has passed the reader waits again rather than run plain.
        let (readers, waiting) = plan(&[(2, 3, 9600, true)], |_| Some(held(false, Some(-1), now)), |_| 0, now);
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

    // ---------- secure channel: changing a reader's key ----------

    const NEW_KEY: [u8; 16] = [
        0x11, 0x5a, 0x0c, 0xe7, 0x38, 0x90, 0xbd, 0x44, 0x6f, 0x02, 0xd1, 0x7b, 0xa6, 0x3e, 0xc8, 0x59,
    ];

    #[test]
    fn a_reader_changes_to_a_new_key_sent_over_its_encrypted_session() {
        let (controller_end, reader_end) = memory_wire();
        let (_, packed) = card_26(5, 22271);
        let stop = Arc::new(AtomicBool::new(false));
        let reader = simulated_reader(reader_end, 7, Some(KEY), packed, 26, stop.clone());

        // Up under the current key, then the new key is sent.
        let mut bus = OsdpBus::open(Box::new(controller_end.again()), &[reader_on_port_one(Some(KEY))]).unwrap();
        let (up, _) = wait_for_secure(&mut bus, Duration::from_secs(15));
        let sent = bus.set_key(0, NEW_KEY);
        let no_such_reader = bus.set_key(3, NEW_KEY);
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            bus.poll();
            thread::sleep(Duration::from_millis(5));
        }
        drop(bus);
        controller_end.drain();

        // The reader now answers to the new key...
        let mut bus = OsdpBus::open(Box::new(controller_end.again()), &[reader_on_port_one(Some(NEW_KEY))]).unwrap();
        let (new_key_works, _) = wait_for_secure(&mut bus, Duration::from_secs(15));
        drop(bus);
        controller_end.drain();

        // ...and no longer to the old one.
        let mut bus = OsdpBus::open(Box::new(controller_end.again()), &[reader_on_port_one(Some(KEY))]).unwrap();
        let (old_key_works, _) = wait_for_secure(&mut bus, Duration::from_secs(4));

        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();

        assert!(up, "the reader never came up under its current key");
        assert!(sent.is_ok(), "{sent:?}");
        assert!(no_such_reader.is_err());
        assert!(new_key_works, "the reader does not answer to the key it was sent");
        assert!(!old_key_works, "the reader still answers to the key that was replaced");
    }

    #[test]
    fn a_new_key_is_not_sent_to_a_reader_whose_encrypted_session_is_down() {
        let (controller_end, _nobody_listening) = memory_wire();
        let mut bus = OsdpBus::open(Box::new(controller_end), &[reader_on_port_one(Some(KEY))]).unwrap();
        bus.poll();
        let error = bus.set_key(0, NEW_KEY).unwrap_err().to_string();
        assert!(error.contains("not up"), "{error}");
    }

    fn changing(sent: bool, now: chrono::DateTime<chrono::Utc>) -> crate::storage::OsdpReaderKey {
        crate::storage::OsdpReaderKey {
            next_key: Some(NEW_KEY),
            rotate_until: Some(now + chrono::Duration::seconds(600)),
            rotate_sent: sent,
            ..held(true, None, now)
        }
    }

    #[test]
    fn a_key_change_keeps_both_keys_until_one_is_seen_to_work() {
        let now = chrono::Utc::now();
        let configured = [(0, 7, 9600, true)];
        let run = |sent: bool, turn: u32| {
            let (readers, waiting) = plan(&configured, |_| Some(changing(sent, now)), |_| turn, now);
            assert!(waiting.is_empty());
            (readers[0].secure_channel_key.unwrap(), readers[0].key_change, readers[0].enrolling)
        };
        // Not sent yet: the current key, with the new one to send.
        assert_eq!(run(false, 0), (KEY, KeyChange::Send(NEW_KEY), false));
        assert_eq!(run(false, 7), (KEY, KeyChange::Send(NEW_KEY), false));
        // Sent: the reader may hold either, so they take turns, the new one first.
        assert_eq!(run(true, 0), (NEW_KEY, KeyChange::VerifyNew, false));
        assert_eq!(run(true, 1), (KEY, KeyChange::VerifyOld, false));
        assert_eq!(run(true, 2), (NEW_KEY, KeyChange::VerifyNew, false));
    }

    #[test]
    fn each_step_of_a_key_change_waits_for_what_it_needs() {
        let s = Duration::from_secs;
        let with = |key_change| OsdpReader { key_change, ..reader_on_port_one(Some(KEY)) };

        let quiet = with(KeyChange::None);
        assert_eq!(key_step(&quiet, Some(s(60)), s(60), None), KeyStep::Wait);

        let enrolling = OsdpReader { enrolling: true, ..reader_on_port_one(Some(KEY)) };
        assert_eq!(key_step(&enrolling, Some(s(4)), s(30), None), KeyStep::Wait);
        assert_eq!(key_step(&enrolling, Some(s(5)), s(30), None), KeyStep::Enrolled);
        assert_eq!(key_step(&enrolling, None, s(300), None), KeyStep::Wait);

        let send = with(KeyChange::Send(NEW_KEY));
        assert_eq!(key_step(&send, None, s(60), None), KeyStep::Wait, "nothing is sent without an encrypted session");
        assert_eq!(key_step(&send, Some(s(1)), s(60), None), KeyStep::Wait);
        assert_eq!(key_step(&send, Some(s(2)), s(60), None), KeyStep::SendNew(NEW_KEY));
        assert_eq!(key_step(&send, Some(s(9)), s(60), Some(s(1))), KeyStep::Wait, "sent once, not again");
        assert_eq!(key_step(&send, None, s(60), Some(s(3))), KeyStep::Reopen);

        let verify_new = with(KeyChange::VerifyNew);
        assert_eq!(key_step(&verify_new, Some(s(4)), s(10), None), KeyStep::Wait);
        assert_eq!(key_step(&verify_new, Some(s(5)), s(10), None), KeyStep::NewKeyWorks);
        assert_eq!(key_step(&verify_new, None, s(19), None), KeyStep::Wait);
        assert_eq!(key_step(&verify_new, None, s(20), None), KeyStep::TryOtherKey);
        assert_eq!(key_step(&verify_new, Some(s(1)), s(25), None), KeyStep::Wait, "a session that just came up gets to prove itself");

        let verify_old = with(KeyChange::VerifyOld);
        assert_eq!(key_step(&verify_old, Some(s(5)), s(10), None), KeyStep::OldKeyStillWorks);
        assert_eq!(key_step(&verify_old, None, s(20), None), KeyStep::TryOtherKey);
    }

    #[test]
    fn a_key_change_is_asked_for_recorded_and_never_loses_a_key() {
        let db = database_with_reader(true);
        let now = chrono::Utc::now();
        let payload = serde_json::json!({ "reader_number": 1 });

        // Only a reader that has taken its first key can have it changed.
        let error = rotate_key(&db, &payload, now).unwrap_err().to_string();
        assert!(error.contains("no key to change"), "{error}");
        enroll(&db, &payload, now).unwrap();
        let error = rotate_key(&db, &payload, now).unwrap_err().to_string();
        assert!(error.contains("has not taken its first key"), "{error}");
        db.osdp_mark_enrolled(0).unwrap();
        let original = db.osdp_reader_key(0).unwrap().unwrap().key;

        let result = rotate_key(&db, &payload, now).unwrap();
        let mut fields: Vec<&String> = result.as_object().unwrap().keys().collect();
        fields.sort();
        assert_eq!(fields, ["message", "reader_number", "rotate_until"], "the result holds no key");
        let started = db.osdp_reader_key(0).unwrap().unwrap();
        let next = started.next_key.expect("a new key is held");
        assert_eq!(started.key, original, "the current key is untouched");
        assert_ne!(next, original);
        assert!(!started.rotate_sent);

        // Asked again: the same new key, more time.
        rotate_key(&db, &serde_json::json!({ "reader_number": 1, "window_seconds": 900 }), now).unwrap();
        let again = db.osdp_reader_key(0).unwrap().unwrap();
        assert_eq!(again.next_key, Some(next));
        assert_eq!(again.rotate_until.unwrap().timestamp(), (now + chrono::Duration::seconds(900)).timestamp());

        // Out of time before it was ever sent: given up, current key kept.
        assert!(expire_key_changes(&db, now + chrono::Duration::seconds(899)).is_empty());
        assert_eq!(expire_key_changes(&db, now + chrono::Duration::seconds(901)), vec![0]);
        let after = db.osdp_reader_key(0).unwrap().unwrap();
        assert_eq!((after.key, after.next_key), (original, None));

        // Once sent, running out of time gives up nothing: the reader may hold the new key.
        rotate_key(&db, &payload, now).unwrap();
        let next = db.osdp_reader_key(0).unwrap().unwrap().next_key.unwrap();
        db.osdp_rotation_sent(0, true).unwrap();
        assert!(expire_key_changes(&db, now + chrono::Duration::days(30)).is_empty());
        assert!(!db.osdp_cancel_rotation(0).unwrap());
        let sent = db.osdp_reader_key(0).unwrap().unwrap();
        assert_eq!((sent.key, sent.next_key, sent.rotate_sent), (original, Some(next), true));

        // The new key is seen to work: it becomes the key, and the change is over.
        db.osdp_commit_rotation(0).unwrap();
        let done = db.osdp_reader_key(0).unwrap().unwrap();
        assert_eq!((done.key, done.next_key, done.rotate_sent, done.active), (next, None, false, true));
    }
}
