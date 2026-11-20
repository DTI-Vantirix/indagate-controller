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
//! Not wired into the running controller yet: that needs reader settings from the server
//! and the board's serial port, which come in later steps.
#![allow(dead_code)]

use anyhow::{Context, Result, bail};
use libosdp::{Channel, ControlPanel, ControlPanelBuilder, OsdpEvent, OsdpEventCardRead, OsdpFlag, PdInfoBuilder};
use std::sync::mpsc::{Receiver, channel};
use tracing::warn;

use super::card_read::{CardRead, ReadSource};

/// The longest card the controller will accept from a reader, as for Wiegand.
const MAX_CARD_BITS: usize = 128;

/// One OSDP reader on a bus.
#[derive(Debug, Clone)]
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
}

/// Whether a reader is answering, and whether the exchange is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderLink {
    pub channel: u8,
    pub online: bool,
    pub secure: bool,
}

/// The readers on one RS-485 line.
pub struct OsdpBus {
    panel: ControlPanel,
    /// Reader port for each reader, in the order LibOSDP numbers them.
    channels: Vec<u8>,
    events: Receiver<(i32, OsdpEvent)>,
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
                info = info.flag(OsdpFlag::EnforceSecure).secure_channel_key(key);
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

        Ok(Self { panel, channels: readers.iter().map(|r| r.channel).collect(), events })
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
            if let OsdpEvent::CardRead(card) = event {
                match card_bits(&card) {
                    Some(bits) => reads.push(CardRead { channel, bits, source: ReadSource::Osdp }),
                    None => warn!(
                        target: "indagate_osdp",
                        reader = channel + 1,
                        bits = card.nr_bits,
                        "OSDP card read with an unusable bit count ignored"
                    ),
                }
            }
        }
        reads
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
        OsdpReader { channel: 0, address: 7, baud_rate: 9600, secure_channel_key: key }
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
                INSERT INTO reader_config (reader_number, reader_id, enabled, door_channel)
                    VALUES (1, 'reader1', 1, 0);
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
}
