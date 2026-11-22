//! Opt-in diagnostic-only sysfs edge collection. NEVER issues relay commands.
use super::profile::{BoardProfile, GpioLine};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::sync::mpsc::{self, SyncSender};
use std::time::{Duration, Instant};
use tracing::info;

const MAX_BITS: usize = 128;
const GAP: Duration = Duration::from_millis(30);
const POLL_TIMEOUT_MS: i32 = 2;

fn gpio_number(line: &GpioLine) -> Result<u32, String> {
    let idx = line
        .chip
        .strip_prefix("gpiochip")
        .ok_or_else(|| format!("invalid GPIO chip {}", line.chip))?
        .parse::<u32>()
        .map_err(|e| e.to_string())?;
    Ok(idx * 32 + line.line)
}

#[derive(Default)]
struct Frame {
    bits: Vec<u8>,
    first: Option<Instant>,
    last: Option<Instant>,
    min_gap_us: Option<u128>,
    max_gap_us: Option<u128>,
    max_rearm_us: u128,
    overflow: bool,
}
struct CompletedFrame {
    bits: Vec<u8>,
    overflow: bool,
    duration_us: u128,
    min_gap_us: Option<u128>,
    max_gap_us: Option<u128>,
    max_rearm_us: u128,
}
impl Frame {
    fn push(&mut self, bit: u8, at: Instant, rearm_us: u128) {
        if let Some(last) = self.last {
            let delta = at.saturating_duration_since(last).as_micros();
            self.min_gap_us = Some(self.min_gap_us.map_or(delta, |v| v.min(delta)));
            self.max_gap_us = Some(self.max_gap_us.map_or(delta, |v| v.max(delta)));
        } else {
            self.first = Some(at);
        }
        self.max_rearm_us = self.max_rearm_us.max(rearm_us);
        if self.bits.len() < MAX_BITS {
            self.bits.push(bit);
        } else {
            self.overflow = true;
        }
        self.last = Some(at);
    }
    fn take_if_expired(&mut self, at: Instant) -> Option<CompletedFrame> {
        if self
            .last
            .is_some_and(|t| at.saturating_duration_since(t) >= GAP)
        {
            let duration_us = match (self.first, self.last) {
                (Some(first), Some(last)) => last.saturating_duration_since(first).as_micros(),
                _ => 0,
            };
            self.first = None;
            self.last = None;
            Some(CompletedFrame {
                bits: std::mem::take(&mut self.bits),
                overflow: std::mem::take(&mut self.overflow),
                duration_us,
                min_gap_us: self.min_gap_us.take(),
                max_gap_us: self.max_gap_us.take(),
                max_rearm_us: std::mem::take(&mut self.max_rearm_us),
            })
        } else {
            None
        }
    }
}

#[derive(Default)]
struct ReaderStats {
    total: u64,
    valid_26: u64,
    bad_parity_26: u64,
    other_length: u64,
    overflow: u64,
    prev: Option<Vec<u8>>,
    repeated: u64,
}
impl ReaderStats {
    fn record(&mut self, frame: &CompletedFrame) -> (bool, bool) {
        self.total += 1;
        let valid = matches!(parity_26(&frame.bits), Some((_, _, true)));
        if frame.bits.len() == 26 {
            if valid {
                self.valid_26 += 1;
            } else {
                self.bad_parity_26 += 1;
            }
        } else {
            self.other_length += 1;
        }
        if frame.overflow {
            self.overflow += 1;
        }
        let repeated = self.prev.as_deref() == Some(frame.bits.as_slice());
        if repeated {
            self.repeated += 1;
        }
        self.prev = Some(frame.bits.clone());
        (valid, repeated)
    }
}

struct Line {
    file: File,
    channel: usize,
    bit: u8,
    gpio: u32,
}

fn arm(file: &mut File) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut buf = [0u8; 8];
    let _ = file.read(&mut buf)?;
    Ok(())
}

fn open_line(gpio: u32, channel: usize, bit: u8) -> Result<Line, String> {
    let base = format!("/sys/class/gpio/gpio{gpio}");
    let direction = std::fs::read_to_string(format!("{base}/direction"))
        .map_err(|e| format!("GPIO {gpio}: {e}"))?;
    let edge =
        std::fs::read_to_string(format!("{base}/edge")).map_err(|e| format!("GPIO {gpio}: {e}"))?;
    if direction.trim() != "in" || edge.trim() != "falling" {
        return Err(format!(
            "GPIO {gpio}: requires existing direction=in edge=falling, found {} {}",
            direction.trim(),
            edge.trim()
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .open(format!("{base}/value"))
        .map_err(|e| format!("GPIO {gpio}: {e}"))?;
    arm(&mut file).map_err(|e| format!("GPIO {gpio} arm: {e}"))?;
    Ok(Line {
        file,
        channel,
        bit,
        gpio,
    })
}

fn parity_26(bits: &[u8]) -> Option<(u8, u16, bool)> {
    if bits.len() != 26 {
        return None;
    }
    let f = bits[1..9].iter().fold(0u8, |v, b| (v << 1) | b);
    let c = bits[9..25]
        .iter()
        .fold(0u16, |v, b| (v << 1) | u16::from(*b));
    let even = bits[..13].iter().filter(|b| **b == 1).count() % 2 == 0;
    let odd = bits[13..].iter().filter(|b| **b == 1).count() % 2 == 1;
    Some((f, c, even && odd))
}

fn report(
    reader: usize,
    frame: CompletedFrame,
    stats: &mut ReaderStats,
    sender: Option<&SyncSender<super::credential_capture::CaptureFrame>>,
    shadow_sender: Option<&SyncSender<super::credential_capture::CaptureFrame>>,
) {
    if let Some(tx) = sender {
        let _ = tx.try_send(super::credential_capture::CaptureFrame {
            reader_number: reader + 1,
            raw_bits: frame
                .bits
                .iter()
                .map(|b| if *b == 0 { '0' } else { '1' })
                .collect(),
            overflow: frame.overflow,
        });
    }
    // Indagate Access 0.4: separate bounded channel into IN-PROCESS Rust worker.
    // No network/crypto work on the GPIO timing-sensitive thread.
    if let Some(tx) = shadow_sender {
        let _ = tx.try_send(super::credential_capture::CaptureFrame {
            reader_number: reader + 1,
            raw_bits: frame.bits.iter().map(|b| if *b == 0 { '0' } else { '1' }).collect(),
            overflow: frame.overflow,
        });
    }
    let candidates = super::credential_formats::identify(&frame.bits, frame.overflow);
    // Candidate interpretation is diagnostic information, never an authorization override.
    for candidate in &candidates {
        info!(target: "indagate_format_identifier", reader=reader+1,
            format_id=candidate.format_id, frame_bits=candidate.frame_bits,
            facility_code=?candidate.facility_code, card_code=?candidate.card_code,
            parity=candidate.parity, authorization_eligible=candidate.authorization_eligible,
            "CANDIDATE ONLY: no format selection or relay command");
    }
    // Opt-in shadow mode uses the EXISTING access decision engine with READ-ONLY SQLite.
    // Never calls the relay worker or enqueues access events.
    if std::env::var("HLAXS_V22_SHADOW_AUTH").as_deref() == Ok("1") {
        let eligible = candidates
            .iter()
            .find(|c| c.authorization_eligible && c.format_id == "H10301-26");
        match eligible {
            Some(c) => {
                let db_path = std::env::var("INDAGATE_DB_PATH").or_else(|_| std::env::var("NEXUS_DB_PATH"))
                    .unwrap_or_else(|_| "/var/lib/highline-nexus/nexus.db".to_string());
                let outcome = rusqlite::Connection::open_with_flags(
                    &db_path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )
                .map_err(|e| e.to_string())
                .and_then(|conn| {
                    crate::access::engine::evaluate(
                        &conn,
                        c.facility_code.unwrap() as u8,
                        c.card_code.unwrap() as u16,
                        reader as u8,
                    )
                    .map_err(|e| e.to_string())
                });
                match outcome {
                    Ok(decision) => info!(target: "indagate_shadow_auth", reader=reader+1,
                        decision=?decision.decision, reason=%decision.reason,
                        "SHADOW ONLY: no relay actuation or access queue mutation"),
                    Err(error) => tracing::warn!(target: "indagate_shadow_auth", reader=reader+1,
                        error=%error, "SHADOW UNAVAILABLE: no relay actuation"),
                }
            }
            None => info!(target: "indagate_shadow_auth", reader=reader+1,
                "SHADOW REJECT: invalid/unsupported/overflowed frame; no relay actuation"),
        }
    }

    let (_, repeated) = stats.record(&frame);
    let raw: String = frame
        .bits
        .iter()
        .map(|b| if *b == 0 { '0' } else { '1' })
        .collect();
    // Notification timestamps are observed in userspace, NOT hardware pulse timestamps.
    // A 26-bit valid frame does not prove that sysfs event delivery is lossless.
    let min_gap_us = frame.min_gap_us.unwrap_or(0);
    let max_gap_us = frame.max_gap_us.unwrap_or(0);
    if let Some((fc, card, parity)) = parity_26(&frame.bits) {
        info!(target: "indagate_edge_diag", reader=reader+1, count=frame.bits.len(), raw_bits=%raw,
            facility_code=fc, card_code=card, parity_valid=parity,
            overflow=frame.overflow, duration_us=frame.duration_us,
            min_observed_gap_us=min_gap_us, max_observed_gap_us=max_gap_us,
            max_rearm_us=frame.max_rearm_us, repeated, valid_26=stats.valid_26,
            invalid_26=stats.bad_parity_26, other_length=stats.other_length,
            total_frames=stats.total, total_overflows=stats.overflow,
            "DIAGNOSTIC ONLY: no access decision / no relay actuation");
    } else {
        info!(target: "indagate_edge_diag", reader=reader+1, count=frame.bits.len(), raw_bits=%raw,
            overflow=frame.overflow, duration_us=frame.duration_us,
            min_observed_gap_us=min_gap_us, max_observed_gap_us=max_gap_us,
            max_rearm_us=frame.max_rearm_us, repeated, valid_26=stats.valid_26,
            invalid_26=stats.bad_parity_26, other_length=stats.other_length,
            total_frames=stats.total, total_overflows=stats.overflow,
            "DIAGNOSTIC ONLY: variable-length frame / no relay actuation");
    }
}

pub fn run(profile: &BoardProfile) -> Result<(), String> {
    let mut lines = Vec::<Line>::new();
    for (channel, reader) in profile.readers.iter().enumerate() {
        lines.push(open_line(gpio_number(&reader.d0)?, channel, 0)?);
        lines.push(open_line(gpio_number(&reader.d1)?, channel, 1)?);
    }
    let capture_sender = super::credential_capture::start();
    // The bench shadow-policy worker that used to listen here needed a hosted service that
    // no longer exists, and was removed.
    let shadow_sender: Option<SyncSender<super::credential_capture::CaptureFrame>> = None;
    let mut frames: Vec<Frame> = (0..profile.readers.len())
        .map(|_| Frame::default())
        .collect();
    let mut stats: Vec<ReaderStats> = (0..profile.readers.len())
        .map(|_| ReaderStats::default())
        .collect();
    info!(target: "indagate_edge_diag", inputs=lines.len(),
          "STARTED sysfs edge diagnostic: relay commands disabled in this path");
    loop {
        let mut fds: Vec<libc::pollfd> = lines
            .iter()
            .map(|line| libc::pollfd {
                fd: line.file.as_raw_fd(),
                events: libc::POLLPRI | libc::POLLERR,
                revents: 0,
            })
            .collect();
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, POLL_TIMEOUT_MS) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("poll failed: {err}"));
        }
        for (index, pollfd) in fds.iter().enumerate() {
            if pollfd.revents & (libc::POLLPRI | libc::POLLERR) != 0 {
                let line = &mut lines[index];
                let detected = Instant::now();
                arm(&mut line.file).map_err(|e| format!("GPIO {} rearm failed: {e}", line.gpio))?;
                let rearm_us = detected.elapsed().as_micros();
                frames[line.channel].push(line.bit, detected, rearm_us);
            } else if pollfd.revents & libc::POLLNVAL != 0 {
                return Err(format!("GPIO {} invalid poll fd", lines[index].gpio));
            }
        }
        let now = Instant::now();
        for (reader, frame) in frames.iter_mut().enumerate() {
            if let Some(completed) = frame.take_if_expired(now) {
                report(
                    reader,
                    completed,
                    &mut stats[reader],
                    capture_sender.as_ref(),
                    shadow_sender.as_ref(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn credential_26(fc: u8, card: u16) -> Vec<u8> {
        let mut b = vec![0];
        for i in (0..8).rev() {
            b.push((fc >> i) & 1);
        }
        for i in (0..16).rev() {
            b.push(((card >> i) & 1) as u8);
        }
        b[0] = (b[1..13].iter().filter(|x| **x == 1).count() % 2) as u8;
        b.push(if b[13..25].iter().filter(|x| **x == 1).count() % 2 == 0 {
            1
        } else {
            0
        });
        b
    }
    #[test]
    fn decode_known_prox() {
        assert_eq!(parity_26(&credential_26(5, 22271)), Some((5, 22271, true)));
    }
    #[test]
    fn detect_invalid_parity() {
        let mut b = credential_26(101, 2083);
        b[0] ^= 1;
        assert_eq!(parity_26(&b).unwrap().2, false);
    }
    #[test]
    fn reject_non26() {
        assert_eq!(parity_26(&[1, 0, 0, 1]), None);
    }
    #[test]
    fn simultaneous_buffers_and_timeouts() {
        let t = Instant::now();
        let mut a = Frame::default();
        let mut b = Frame::default();
        a.push(0, t, 0);
        b.push(1, t, 0);
        a.push(1, t + Duration::from_millis(2), 0);
        assert!(a.take_if_expired(t + Duration::from_millis(25)).is_none());
        assert_eq!(
            b.take_if_expired(t + Duration::from_millis(31))
                .unwrap()
                .bits,
            vec![1]
        );
        assert_eq!(
            a.take_if_expired(t + Duration::from_millis(33))
                .unwrap()
                .bits,
            vec![0, 1]
        );
    }
    #[test]
    fn gap_and_rearm_metrics() {
        let t = Instant::now();
        let mut f = Frame::default();
        f.push(0, t, 3);
        f.push(1, t + Duration::from_micros(1500), 8);
        f.push(0, t + Duration::from_micros(2700), 5);
        let done = f.take_if_expired(t + Duration::from_millis(40)).unwrap();
        assert_eq!(done.duration_us, 2700);
        assert_eq!(done.min_gap_us, Some(1200));
        assert_eq!(done.max_gap_us, Some(1500));
        assert_eq!(done.max_rearm_us, 8);
    }
    #[test]
    fn reader_stats_are_isolated() {
        let t = Instant::now();
        let mut a = Frame::default();
        let mut b = Frame::default();
        for bit in credential_26(5, 22271) {
            a.push(bit, t, 0);
        }
        b.push(0, t, 0);
        let mut sa = ReaderStats::default();
        let mut sb = ReaderStats::default();
        let x = a.take_if_expired(t + Duration::from_millis(31)).unwrap();
        let y = b.take_if_expired(t + Duration::from_millis(31)).unwrap();
        assert!(sa.record(&x).0);
        assert!(!sb.record(&y).0);
        assert_eq!(sa.valid_26, 1);
        assert_eq!(sb.other_length, 1);
    }
    #[test]
    fn overflow_flag() {
        let mut f = Frame::default();
        for _ in 0..130 {
            f.push(1, Instant::now(), 0);
        }
        assert_eq!(f.bits.len(), 128);
        assert!(f.overflow);
    }
}
