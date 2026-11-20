//! Optional, isolated cloud telemetry for Wiegand DIAGNOSTIC ONLY.
//! Capture sessions are read from, and frames sent to, the configured Indagate server under
//! `/v1/credential-capture`. The server does not offer that yet, so until it does the worker
//! only reports that session discovery failed.
//! Zero actuator imports. Does not change GPIO configuration or access rules.
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant};
use tracing::{info, warn};


#[derive(Debug)]
pub struct CaptureFrame {
    pub reader_number: usize,
    pub raw_bits: String,
    pub overflow: bool,
}
#[derive(Debug, Deserialize)]
struct Envelope<T> {
    success: bool,
    data: Option<T>,
}
#[derive(Debug, Deserialize)]
struct ActiveList {
    sessions: Vec<Session>,
}
#[derive(Debug, Clone, Deserialize)]
struct Session {
    id: String,
    reader_id: String,
    reader_number: usize,
}

fn eligible(frame: &CaptureFrame) -> bool {
    (1..=32).contains(&frame.reader_number)
        && (1..=128).contains(&frame.raw_bits.len())
        && frame.raw_bits.bytes().all(|b| b == b'0' || b == b'1')
}

// Indagate Access 0.3.6 LOCAL SHADOW EMITTER. Never calls cloud or actuator APIs.
// The existing diagnostic capture worker delivers completed frames to this
// non-blocking local publisher BEFORE the technician-session filter.
fn publish_local_shadow(frame: &CaptureFrame) {
    if std::env::var("HLAXS_WIEGAND_EDGE_DIAGNOSTIC").as_deref() != Ok("1") {
        return;
    }
    // Only the root-owned local observer can receive from this socket;
    // the receiving process separately validates SO_PASSCRED + service MainPID.
    let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() else {
        return;
    };
    let msg = serde_json::json!({
        "schema": "hlaxs-access-036-local-frame-v1",
        "reader_number": frame.reader_number,
        "raw_bits": frame.raw_bits,
        "bit_count": frame.raw_bits.len(),
        "overflow": frame.overflow,
        "reader_identity_verified": false,
        "actuator_authority": false,
    });
    if sock.set_nonblocking(true).is_err() {
        return;
    }
    if let Ok(data) = serde_json::to_vec(&msg) {
        if data.len() <= 512 {
            // No error logging: transient absent observer cannot leak frames
            // or alter the original diagnostic capture pipeline.
            let _ = sock.send_to(&data, "/run/hlaxs-shadow-036/events.sock");
        }
    }
}

pub fn start() -> Option<SyncSender<CaptureFrame>> {
    // Do not turn on by accident: the separate diagnostic switch is mandatory.
    if std::env::var("HLAXS_WIEGAND_EDGE_DIAGNOSTIC").as_deref() != Ok("1")
        || std::env::var("HLAXS_V23_CAPTURE_UPLOAD").as_deref() != Ok("1")
    {
        return None;
    }
    let identity = match crate::cloud::agent::load_identity() {
        Ok(Some(id)) => id,
        Ok(None) => {
            warn!(target: "indagate_v23_capture", "Capture upload disabled: device not enrolled");
            return None;
        }
        Err(err) => {
            warn!(target: "indagate_v23_capture", error=%err,"Capture upload disabled: cannot load identity");
            return None;
        }
    };
    let api_url = match crate::cloud::endpoint::base_url() {
        Ok(base) => format!("{base}/v1/credential-capture"),
        Err(err) => {
            warn!(target: "indagate_v23_capture", error=%err, "Capture upload disabled: no server address");
            return None;
        }
    };
    // Bounded and non-blocking sender protects the timing-sensitive GPIO poll loop.
    let (tx, rx) = mpsc::sync_channel::<CaptureFrame>(256);
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                warn!(target: "indagate_v23_capture",error=%err,"Capture runtime unavailable");
                return;
            }
        };
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                warn!(target: "indagate_v23_capture",error=%err,"Capture HTTP unavailable");
                return;
            }
        };
        let mut sessions: HashMap<usize, Session> = HashMap::new();
        let mut last_lookup = Instant::now() - Duration::from_secs(30);
        info!(target: "indagate_v23_capture", "Read-only credential upload worker enabled");
        loop {
            if last_lookup.elapsed() >= Duration::from_secs(5) {
                let result = rt.block_on(async {
                    let response = client
                        .get(format!("{api_url}/active"))
                        .header("x-indagate-device-id", &identity.device_id)
                        .header("x-nexus-device-id", &identity.device_id)
                        .header("x-indagate-device-secret", &identity.device_secret)
                        .header("x-nexus-device-secret", &identity.device_secret)
                        .send()
                        .await?;
                    if !response.status().is_success() {
                        anyhow::bail!("active session request rejected: {}", response.status());
                    }
                    let result: Envelope<ActiveList> = response.json().await?;
                    if !result.success {
                        anyhow::bail!("active sessions rejected");
                    }
                    Ok::<_, anyhow::Error>(result.data.unwrap_or(ActiveList { sessions: vec![] }))
                });
                match result {
                    Ok(active) => {
                        let mut next = HashMap::new();
                        for session in active.sessions {
                            if (1..=32).contains(&session.reader_number)
                                && !session.reader_id.is_empty()
                            {
                                next.entry(session.reader_number).or_insert(session);
                            }
                        }
                        sessions = next;
                    }
                    Err(err) => {
                        sessions.clear();
                        warn!(target: "indagate_v23_capture",error=%err,"Capture upload paused: session discovery failed");
                    }
                }
                last_lookup = Instant::now();
            }
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(frame) => {
                    if !eligible(&frame) {
                        continue;
                    }
                    // Indagate Access 0.3.6: independent of technician capture sessions;
                    // read-only local IPC only, sender is the existing GPIO owner.
                    publish_local_shadow(&frame);
                    let Some(session) = sessions.get(&frame.reader_number) else {
                        continue;
                    };
                    let body = json!({"session_id":session.id,"reader_id":session.reader_id,
                        "raw_bits":frame.raw_bits,"bit_count":frame.raw_bits.len(),"overflow":frame.overflow});
                    let result = rt.block_on(async {
                        let response = client
                            .post(format!("{api_url}/capture"))
                            .header("x-indagate-device-id", &identity.device_id)
                            .header("x-nexus-device-id", &identity.device_id)
                            .header("x-indagate-device-secret", &identity.device_secret)
                            .header("x-nexus-device-secret", &identity.device_secret)
                            .json(&body)
                            .send()
                            .await?;
                        if !response.status().is_success() {
                            anyhow::bail!("capture rejected: {}", response.status());
                        }
                        Ok::<_, anyhow::Error>(())
                    });
                    if let Err(err) = result {
                        warn!(target: "indagate_v23_capture",reader=frame.reader_number,error=%err,"Diagnostic upload failed (no actuation)");
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    });
    Some(tx)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_bits() {
        assert!(!eligible(&CaptureFrame {
            reader_number: 2,
            raw_bits: "102".into(),
            overflow: false
        }));
        assert!(!eligible(&CaptureFrame {
            reader_number: 0,
            raw_bits: "01".into(),
            overflow: false
        }));
        assert!(!eligible(&CaptureFrame {
            reader_number: 1,
            raw_bits: "".into(),
            overflow: false
        }));
    }
    #[test]
    fn accepts_raw_frame_even_when_overflow_flagged() {
        assert!(eligible(&CaptureFrame {
            reader_number: 4,
            raw_bits: "0101".into(),
            overflow: true
        }));
    }
}
