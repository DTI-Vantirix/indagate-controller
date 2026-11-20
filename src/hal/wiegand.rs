use chrono::Utc;
use rusqlite::params;
use serde_json::json;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::access::engine::{self, AccessDecision};
use crate::storage::NexusDatabase;

use super::profile::{BoardProfile, GpioLine};
use super::relay_worker::RelayCommand;

#[derive(Debug)]
struct ReaderState {
    channel: u8,
    bits: Vec<u8>,
    last_bit_at: Option<Instant>,
}

fn chip_index(chip: &str) -> Option<u32> {
    chip.strip_prefix("gpiochip")?.parse::<u32>().ok()
}

fn legacy_gpio(line: &GpioLine) -> Option<u32> {
    chip_index(line.chip).map(|index| (index * 32) + line.line)
}

fn validate_26(bits: &[u8]) -> bool {
    if bits.len() != 26 {
        return false;
    }

    let first_12_ones = bits[1..13].iter().filter(|&&b| b == 1).count();

    let second_12_ones = bits[13..25].iter().filter(|&&b| b == 1).count();

    let leading_parity = bits[0] as usize;
    let trailing_parity = bits[25] as usize;

    let first_even = (first_12_ones + leading_parity) % 2 == 0;

    let second_odd = (second_12_ones + trailing_parity) % 2 == 1;

    first_even && second_odd
}

fn decode_26(bits: &[u8]) -> Option<(u8, u16, u32, bool)> {
    if bits.len() != 26 {
        return None;
    }

    let mut facility: u8 = 0;

    for &bit in &bits[1..9] {
        facility = (facility << 1) | bit;
    }

    let mut card: u16 = 0;

    for &bit in &bits[9..25] {
        card = (card << 1) | bit as u16;
    }

    let mut full: u32 = 0;

    for &bit in bits {
        full = (full << 1) | bit as u32;
    }

    Some((facility, card, full, validate_26(bits)))
}

fn bit_string(bits: &[u8]) -> String {
    bits.iter()
        .map(|b| if *b == 0 { '0' } else { '1' })
        .collect()
}

fn queue_event(db: &NexusDatabase, event_type: &str, channel: u8, payload: serde_json::Value) {
    let result = db.connection().execute(
        r#"
        INSERT INTO event_queue
        (
            id,
            event_type,
            channel,
            payload_json,
            occurred_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            Uuid::new_v4().to_string(),
            event_type,
            channel,
            payload.to_string(),
            Utc::now().to_rfc3339(),
        ],
    );

    if let Err(e) = result {
        warn!(
            event_type = event_type,
            channel = channel,
            error = %e,
            "Unable to queue Nexus event"
        );
    }
}

async fn finish_frame(
    reader: &mut ReaderState,
    db: &NexusDatabase,
    relay_tx: &mpsc::Sender<RelayCommand>,
) {
    if reader.bits.is_empty() {
        return;
    }

    let bits = std::mem::take(&mut reader.bits);
    let raw_bits = bit_string(&bits);

    let Some((facility, card, full, parity_valid)) = decode_26(&bits) else {
        warn!(
            target: "nexus_wiegand",
            reader = reader.channel + 1,
            channel = reader.channel,
            bits = bits.len(),
            raw_bits = %raw_bits,
            "Invalid Wiegand frame length"
        );

        queue_event(
            db,
            "wiegand_invalid_frame",
            reader.channel,
            json!({
                "reader": reader.channel + 1,
                "bits": bits.len(),
                "raw_bits": raw_bits,
                "reason": "invalid_frame_length"
            }),
        );

        reader.last_bit_at = None;
        return;
    };

    if !parity_valid {
        warn!(
            target: "nexus_wiegand",
            reader = reader.channel + 1,
            channel = reader.channel,
            facility_code = facility,
            card_code = card,
            raw_bits = %raw_bits,
            "Credential rejected: invalid Wiegand parity"
        );

        queue_event(
            db,
            "access_deny",
            reader.channel,
            json!({
                "reader": reader.channel + 1,
                "facility_code": facility,
                "card_code": card,
                "full_code": full,
                "raw_bits": raw_bits,
                "parity_valid": false,
                "decision": "Deny",
                "reason": "invalid_parity"
            }),
        );

        reader.last_bit_at = None;
        return;
    }

    match engine::evaluate(db.connection(), facility, card, reader.channel) {
        Ok(result) => {
            let event_type = match result.decision {
                AccessDecision::Grant => "access_grant",
                AccessDecision::Deny => "access_deny",
            };

            let mut relay_command_queued = false;
            let mut unlock_ms: Option<u64> = None;

            if matches!(result.decision, AccessDecision::Grant) {
                match db.door_unlock_ms(reader.channel) {
                    Ok(Some(duration)) => {
                        unlock_ms = Some(duration);

                        match relay_tx
                            .send(RelayCommand::Pulse {
                                channel: reader.channel,
                                duration_ms: duration,
                                response: None,
                            })
                            .await
                        {
                            Ok(()) => {
                                relay_command_queued = true;
                            }

                            Err(e) => {
                                error!(
                                    target: "nexus_access",
                                    channel = reader.channel,
                                    error = %e,
                                    "Access GRANT could not be sent to relay worker"
                                );
                            }
                        }
                    }

                    Ok(None) => {
                        error!(
                            target: "nexus_access",
                            channel = reader.channel,
                            "Access GRANT has no enabled door configuration"
                        );
                    }

                    Err(e) => {
                        error!(
                            target: "nexus_access",
                            channel = reader.channel,
                            error = %e,
                            "Unable to load door unlock duration"
                        );
                    }
                }
            }

            info!(
                target: "nexus_access",
                reader = reader.channel + 1,
                channel = reader.channel,
                facility_code = facility,
                card_code = card,
                decision = ?result.decision,
                reason = %result.reason,
                holder = ?result.holder_name,
                unlock_ms = ?unlock_ms,
                relay_command_queued = relay_command_queued,
                "ACCESS DECISION"
            );

            queue_event(
                db,
                event_type,
                reader.channel,
                json!({
                    "reader": reader.channel + 1,
                    "facility_code": facility,
                    "card_code": card,
                    "full_code": full,
                    "raw_bits": raw_bits,
                    "parity_valid": true,
                    "decision": result.decision,
                    "reason": result.reason,
                    "credential_id": result.credential_id,
                    "holder_name": result.holder_name,
                    "unlock_ms": unlock_ms,
                    "relay_command_queued": relay_command_queued
                }),
            );
        }

        Err(e) => {
            warn!(
                target: "nexus_access",
                reader = reader.channel + 1,
                channel = reader.channel,
                facility_code = facility,
                card_code = card,
                error = %e,
                "Access engine failure"
            );

            queue_event(
                db,
                "access_error",
                reader.channel,
                json!({
                    "reader": reader.channel + 1,
                    "facility_code": facility,
                    "card_code": card,
                    "reason": "access_engine_error"
                }),
            );
        }
    }

    reader.last_bit_at = None;
}

// SA-16I: production Wiegand collection uses kernel GPIO falling-edge events.
// The old 250 us tokio sleep + sequential sysfs reads missed short reader pulses.
// This dedicated blocking worker ONLY assembles frames; access evaluation and
// relay dispatch stay in the existing async consumer below.
const EDGE_MAX_BITS: usize = 128;
const EDGE_GAP: Duration = Duration::from_millis(30);
const EDGE_POLL_TIMEOUT_MS: i32 = 2;

struct EdgeLine {
    file: File,
    reader_index: usize,
    bit: u8,
    gpio: u32,
}

#[derive(Default)]
struct EdgeBuffer {
    bits: Vec<u8>,
    last: Option<Instant>,
    min_gap_us: Option<u128>,
    max_gap_us: Option<u128>,
    overflow: bool,
}

struct EdgeFrame {
    channel: u8,
    bits: Vec<u8>,
    min_gap_us: Option<u128>,
    max_gap_us: Option<u128>,
    overflow: bool,
}

impl EdgeBuffer {
    fn push(&mut self, bit: u8, at: Instant) {
        if let Some(last) = self.last {
            let delta = at.saturating_duration_since(last).as_micros();
            self.min_gap_us = Some(self.min_gap_us.map_or(delta, |v| v.min(delta)));
            self.max_gap_us = Some(self.max_gap_us.map_or(delta, |v| v.max(delta)));
        }
        if self.bits.len() < EDGE_MAX_BITS {
            self.bits.push(bit);
        } else {
            self.overflow = true;
        }
        self.last = Some(at);
    }

    fn finish_if_quiet(&mut self, channel: u8, now: Instant) -> Option<EdgeFrame> {
        let last = self.last?;
        if now.saturating_duration_since(last) < EDGE_GAP {
            return None;
        }
        self.last = None;
        Some(EdgeFrame {
            channel,
            bits: std::mem::take(&mut self.bits),
            min_gap_us: self.min_gap_us.take(),
            max_gap_us: self.max_gap_us.take(),
            overflow: std::mem::take(&mut self.overflow),
        })
    }
}

fn rearm_edge(file: &mut File) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut buf = [0u8; 8];
    let n = file.read(&mut buf)?;
    if n == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "empty GPIO value"));
    }
    Ok(())
}

fn open_edge_line(gpio: u32, reader_index: usize, bit: u8) -> Result<EdgeLine, String> {
    let base = format!("/sys/class/gpio/gpio{gpio}");
    let direction = fs::read_to_string(format!("{base}/direction"))
        .map_err(|e| format!("GPIO {gpio} direction: {e}"))?;
    if direction.trim() != "in" {
        return Err(format!("GPIO {gpio} must already be configured as input, got {}", direction.trim()));
    }
    let edge_path = format!("{base}/edge");
    let edge = fs::read_to_string(&edge_path)
        .map_err(|e| format!("GPIO {gpio} edge configuration: {e}"))?;
    if edge.trim() != "falling" {
        // Bench controller: configure falling edges, never change GPIO direction or outputs.
        fs::write(&edge_path, b"falling")
            .map_err(|e| format!("GPIO {gpio} enable falling edges: {e}"))?;
        let observed = fs::read_to_string(&edge_path)
            .map_err(|e| format!("GPIO {gpio} verify falling edge: {e}"))?;
        if observed.trim() != "falling" {
            return Err(format!("GPIO {gpio}: cannot enable falling edge (got {})", observed.trim()));
        }
        info!(target: "nexus_wiegand", gpio, "Enabled GPIO falling-edge notifications");
    }
    let mut file = OpenOptions::new().read(true).open(format!("{base}/value"))
        .map_err(|e| format!("GPIO {gpio} open event input: {e}"))?;
    rearm_edge(&mut file).map_err(|e| format!("GPIO {gpio} event arm: {e}"))?;
    Ok(EdgeLine { file, reader_index, bit, gpio })
}

fn collect_edge_frames(
    profile: BoardProfile,
    frames_tx: mpsc::Sender<EdgeFrame>,
) -> Result<(), String> {
    let mut lines = Vec::<EdgeLine>::new();
    for (index, reader) in profile.readers.iter().enumerate() {
        let d0 = legacy_gpio(&reader.d0)
            .ok_or_else(|| format!("reader {} invalid D0 profile", reader.channel + 1))?;
        let d1 = legacy_gpio(&reader.d1)
            .ok_or_else(|| format!("reader {} invalid D1 profile", reader.channel + 1))?;
        lines.push(open_edge_line(d0, index, 0)?);
        lines.push(open_edge_line(d1, index, 1)?);
    }
    if lines.is_empty() {
        return Err("no reader GPIO inputs configured".into());
    }
    let mut buffers: Vec<EdgeBuffer> = profile.readers.iter()
        .map(|_| EdgeBuffer::default()).collect();
    info!(target: "nexus_wiegand", inputs = lines.len(),
          "PRODUCTION WIEGAND FALLING-EDGE CAPTURE STARTED");

    loop {
        let mut fds: Vec<libc::pollfd> = lines.iter().map(|line| libc::pollfd {
            fd: line.file.as_raw_fd(),
            events: libc::POLLPRI | libc::POLLERR,
            revents: 0,
        }).collect();
        let n = unsafe {
            libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, EDGE_POLL_TIMEOUT_MS)
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("Wiegand GPIO poll failed: {e}"));
        }
        for (index, fd) in fds.iter().enumerate() {
            if fd.revents & libc::POLLNVAL != 0 {
                return Err(format!("Wiegand GPIO {} invalid poll descriptor", lines[index].gpio));
            }
            if fd.revents & (libc::POLLPRI | libc::POLLERR) != 0 {
                let line = &mut lines[index];
                let at = Instant::now();
                rearm_edge(&mut line.file)
                    .map_err(|e| format!("Wiegand GPIO {} rearm error: {e}", line.gpio))?;
                buffers[line.reader_index].push(line.bit, at);
            }
        }
        let now = Instant::now();
        for (index, buffer) in buffers.iter_mut().enumerate() {
            let channel = profile.readers[index].channel;
            if let Some(frame) = buffer.finish_if_quiet(channel, now) {
                // Never stall the timing-critical GPIO collector for SQLite or a relay command.
                if let Err(err) = frames_tx.try_send(frame) {
                    warn!(target: "nexus_wiegand", channel,
                          error = %err, "WIEGAND FRAME DROPPED: event-consumer unavailable or busy");
                }
            }
        }
    }
}

pub async fn run(profile: &BoardProfile, db_path: &str, relay_tx: mpsc::Sender<RelayCommand>) {
    // Preserve explicit diagnostic-only behavior: never authorize or actuate in this mode.
    if std::env::var("HLAXS_WIEGAND_EDGE_DIAGNOSTIC").as_deref() == Ok("1") {
        let profile = profile.clone();
        match tokio::task::spawn_blocking(move || super::wiegand_edge_diagnostic::run(&profile)).await {
            Ok(Ok(())) => warn!("Diagnostic edge worker unexpectedly returned"),
            Ok(Err(err)) => error!(error=%err, "Diagnostic edge worker stopped"),
            Err(err) => error!(error=%err, "Diagnostic edge worker panicked"),
        }
        return;
    }

    let db = match NexusDatabase::open(db_path) {
        Ok(db) => db,
        Err(err) => {
            error!(error=%err, "Unable to open Nexus database for production Wiegand engine");
            return;
        }
    };
    let mut readers: Vec<ReaderState> = profile.readers.iter().map(|r| ReaderState {
        channel: r.channel,
        bits: Vec::with_capacity(EDGE_MAX_BITS),
        last_bit_at: None,
    }).collect();

    let (frame_tx, mut frame_rx) = mpsc::channel::<EdgeFrame>(64);
    let edge_profile = profile.clone();
    let mut worker = tokio::task::spawn_blocking(move || collect_edge_frames(edge_profile, frame_tx));
    info!(target: "nexus_wiegand", readers = readers.len(),
          "Wiegand production access engine awaiting captured GPIO frames");

    loop {
        tokio::select! {
            worker_result = &mut worker => {
                match worker_result {
                    Ok(Ok(())) => error!(target: "nexus_wiegand", "Wiegand edge collector unexpectedly exited"),
                    Ok(Err(err)) => error!(target: "nexus_wiegand", error=%err,
                                          "Wiegand edge collector stopped; ACCESS READER INPUTS OFFLINE"),
                    Err(err) => error!(target: "nexus_wiegand", error=%err,
                                       "Wiegand edge collector panicked; ACCESS READER INPUTS OFFLINE"),
                }
                break;
            }
            frame = frame_rx.recv() => {
                let Some(frame) = frame else {
                    error!(target: "nexus_wiegand", "Wiegand frame channel closed");
                    break;
                };
                info!(target: "nexus_wiegand", reader=frame.channel+1, channel=frame.channel,
                      bits=frame.bits.len(), min_observed_gap_us=?frame.min_gap_us,
                      max_observed_gap_us=?frame.max_gap_us, overflow=frame.overflow,
                      "WIEGAND EDGE FRAME RECEIVED");
                if frame.overflow {
                    warn!(target: "nexus_wiegand", channel=frame.channel,
                          "Wiegand frame overflow: rejecting instead of attempting authorization");
                    queue_event(&db, "wiegand_invalid_frame", frame.channel,
                                json!({"reason":"capture_overflow", "bits":frame.bits.len()}));
                    continue;
                }
                if let Some(reader) = readers.iter_mut().find(|r| r.channel == frame.channel) {
                    reader.bits = frame.bits;
                    reader.last_bit_at = None;
                    finish_frame(reader, &db, &relay_tx).await;
                } else {
                    error!(target: "nexus_wiegand", channel=frame.channel, "Unknown reader channel");
                }
            }
        }
    }
}

#[cfg(test)]
mod sa16i_edge_tests {
    use super::*;

    #[test]
    fn full_26_bit_frame_preserved() {
        let now = Instant::now();
        let mut f = EdgeBuffer::default();
        let mut bits = vec![0];
        bits.extend([0u8; 24]);
        bits.push(1);
        for (i, bit) in bits.iter().enumerate() {
            f.push(*bit, now + Duration::from_millis(i as u64 * 2));
        }
        assert!(f.finish_if_quiet(1, now + Duration::from_millis(70)).is_none());
        let done = f.finish_if_quiet(1, now + Duration::from_millis(82)).unwrap();
        assert_eq!(done.channel, 1);
        assert_eq!(done.bits, bits);
        assert!(!done.overflow);
        assert_eq!(done.min_gap_us, Some(2000));
        assert_eq!(done.max_gap_us, Some(2000));
    }

    #[test]
    fn buffers_isolated_across_readers() {
        let start = Instant::now();
        let mut a = EdgeBuffer::default();
        let mut b = EdgeBuffer::default();
        a.push(0, start);
        b.push(1, start + Duration::from_millis(5));
        assert_eq!(a.finish_if_quiet(0, start + Duration::from_millis(31)).unwrap().bits, vec![0]);
        assert!(b.finish_if_quiet(1, start + Duration::from_millis(31)).is_none());
        assert_eq!(b.finish_if_quiet(1, start + Duration::from_millis(36)).unwrap().bits, vec![1]);
    }

    #[test]
    fn overlong_capture_marked_overflow() {
        let now = Instant::now();
        let mut frame = EdgeBuffer::default();
        for i in 0..130 {
            frame.push((i % 2) as u8, now);
        }
        let result = frame.finish_if_quiet(0, now + Duration::from_millis(31)).unwrap();
        assert_eq!(result.bits.len(), EDGE_MAX_BITS);
        assert!(result.overflow);
    }
}
