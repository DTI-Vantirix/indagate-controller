//! Where the cloud is and how this controller connects to it.
//!
//! Three things live here, all additive to the existing cloud agent:
//!
//! * **The server address.** `INDAGATE_SERVER_URL` replaces the built-in address. It must be
//!   `https://`, except for a loopback address, or when `INDAGATE_SERVER_ALLOW_PLAINTEXT=lab-only`
//!   is set for bench work. A malformed value stops the cloud agent rather than falling back
//!   to the built-in address: the device secret must never be sent to a server the operator
//!   did not intend. Local access control keeps working either way.
//! * **Extra trusted certificate authorities.** `INDAGATE_SERVER_CA_FILE` names a PEM file whose
//!   certificates are trusted *in addition to* the built-in public roots, so a self-hosted
//!   server with a private certificate can be used. Certificate checking is never disabled.
//! * **The push stream.** [`run_stream`] holds `GET /v1/stream` open and turns the server's
//!   lines into [`Nudge`]s for the agent loop, which then makes the same calls its timers
//!   make. A nudge is only a hint; if the stream is unavailable the timers still run, so
//!   nothing depends on it. `INDAGATE_SERVER_PUSH=off` disables it.
//!
//! One HTTP client is shared by all requests, so the TLS connection is reused instead of
//! being set up again for every call.

use anyhow::{Context, Result, anyhow};
use reqwest::{Certificate, Client, StatusCode, Url};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Per-request limit for ordinary API calls (unchanged from the original agent).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// The stream is given up if the server is silent this long. The server writes a keepalive
/// line every 15 seconds by default, so this allows several to be missed.
const STREAM_SILENCE_LIMIT: Duration = Duration::from_secs(90);
const MAX_CA_FILE_BYTES: u64 = 1024 * 1024;
const MAX_STREAM_LINE_BYTES: usize = 64 * 1024;

// ---------- server address ----------

fn is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else { return false };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|address| address.is_loopback())
}

/// Decide the base address from the configured value (or the built-in one when unset).
fn resolve_base_url(configured: Option<&str>, allow_plaintext: bool, built_in: &str) -> Result<String> {
    let Some(raw) = configured.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(built_in.to_string());
    };
    let url = Url::parse(raw).map_err(|_| anyhow!("INDAGATE_SERVER_URL is not a valid URL"))?;
    if url.host().is_none() || url.cannot_be_a_base() {
        return Err(anyhow!("INDAGATE_SERVER_URL must name a server"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(anyhow!("INDAGATE_SERVER_URL must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(anyhow!("INDAGATE_SERVER_URL must not contain a query or fragment"));
    }
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&url) || allow_plaintext => {}
        "http" => {
            return Err(anyhow!(
                "INDAGATE_SERVER_URL must use https (the device secret is sent on every request)"
            ));
        }
        _ => return Err(anyhow!("INDAGATE_SERVER_URL must be an https address")),
    }
    Ok(raw.trim_end_matches('/').to_string())
}

/// A server setting from the environment: `INDAGATE_SERVER_<name>`, or the name used before
/// the rename, `NEXUS_CLOUD_<name>`. The new name wins when it is set to something; an empty
/// value counts as not set, as it always has. A malformed new value is reported, never
/// replaced by the old one.
fn setting(name: &str) -> Option<String> {
    pick_setting(
        std::env::var(format!("INDAGATE_SERVER_{name}")).ok(),
        std::env::var(format!("NEXUS_CLOUD_{name}")).ok(),
    )
}

fn pick_setting(new: Option<String>, old: Option<String>) -> Option<String> {
    new.filter(|v| !v.trim().is_empty()).or(old)
}

/// The address every cloud request is built on, decided once per process.
pub fn base_url() -> Result<&'static str> {
    static BASE: OnceLock<std::result::Result<String, String>> = OnceLock::new();
    BASE.get_or_init(|| {
        let configured = setting("URL");
        let allow_plaintext = setting("ALLOW_PLAINTEXT").as_deref() == Some("lab-only");
        resolve_base_url(configured.as_deref(), allow_plaintext, super::agent::DEFAULT_BASE_URL)
            .map_err(|e| e.to_string())
    })
    .as_deref()
    .map_err(|e| anyhow!("{e}"))
}

// ---------- HTTP clients ----------

/// Certificates from `INDAGATE_SERVER_CA_FILE`, if that is set.
fn extra_roots(path: Option<&str>) -> Result<Vec<Certificate>> {
    let Some(path) = path.map(str::trim).filter(|p| !p.is_empty()) else {
        return Ok(Vec::new());
    };
    let size = std::fs::metadata(path).with_context(|| format!("read INDAGATE_SERVER_CA_FILE {path}"))?.len();
    if size > MAX_CA_FILE_BYTES {
        return Err(anyhow!("INDAGATE_SERVER_CA_FILE is too large"));
    }
    let pem = std::fs::read(path).with_context(|| format!("read INDAGATE_SERVER_CA_FILE {path}"))?;
    let certificates = Certificate::from_pem_bundle(&pem).context("parse INDAGATE_SERVER_CA_FILE")?;
    if certificates.is_empty() {
        return Err(anyhow!("INDAGATE_SERVER_CA_FILE contains no certificates"));
    }
    Ok(certificates)
}

fn builder() -> Result<reqwest::ClientBuilder> {
    let mut builder = Client::builder()
        .connect_timeout(REQUEST_TIMEOUT)
        .tcp_keepalive(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(60));
    for certificate in extra_roots(setting("CA_FILE").as_deref())? {
        builder = builder.add_root_certificate(certificate);
    }
    Ok(builder)
}

/// The client for ordinary API calls. Shared, so connections are reused.
pub fn client() -> Result<Client> {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client.clone());
    }
    let client = builder()?.timeout(REQUEST_TIMEOUT).build()?;
    Ok(CLIENT.get_or_init(|| client).clone())
}

/// The client for the push stream: no overall time limit, only a limit on silence.
fn stream_client() -> Result<Client> {
    Ok(builder()?.read_timeout(STREAM_SILENCE_LIMIT).build()?)
}

// ---------- push stream ----------

/// "The server says there is something to collect."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nudge {
    /// Fetch commands now.
    Commands,
    /// Check in now (and fetch the configuration if the check-in says so).
    Config,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signal {
    Ready,
    Nudge(Nudge),
}

/// Reads the server's `event:` lines out of the byte stream, however it is split into chunks.
#[derive(Default)]
struct StreamParser {
    buffer: Vec<u8>,
    event: Option<String>,
}

impl StreamParser {
    fn push(&mut self, chunk: &[u8]) -> Result<Vec<Signal>> {
        self.buffer.extend_from_slice(chunk);
        let mut signals = Vec::new();
        while let Some(end) = self.buffer.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=end).collect();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim_end_matches(['\n', '\r']);
            if line.is_empty() {
                // A blank line ends one event.
                match self.event.take().as_deref() {
                    Some("ready") => signals.push(Signal::Ready),
                    Some("commands") => signals.push(Signal::Nudge(Nudge::Commands)),
                    Some("config") => signals.push(Signal::Nudge(Nudge::Config)),
                    _ => {} // unknown events are ignored, so the server can add more later
                }
            } else if let Some(name) = line.strip_prefix("event:") {
                self.event = Some(name.trim().to_string());
            }
            // "data:" lines carry nothing we act on; lines starting with ':' are keepalives.
        }
        if self.buffer.len() > MAX_STREAM_LINE_BYTES {
            self.buffer.clear();
            return Err(anyhow!("push stream sent an over-long line"));
        }
        Ok(signals)
    }
}

enum StreamEnd {
    /// The server closed the stream normally.
    Closed,
    /// This server has no push stream (for example the original cloud).
    Unsupported,
    /// The server refused the request (credential problem or rate limit).
    Refused(StatusCode),
    /// The agent loop has gone away; stop.
    AgentStopped,
}

async fn stream_once(device_id: &str, device_secret: &str, nudges: &mpsc::Sender<Nudge>) -> Result<StreamEnd> {
    let mut response = stream_client()?
        .get(format!("{}/v1/stream", base_url()?))
        .header("x-indagate-device-id", device_id)
        .header("x-nexus-device-id", device_id)
        .header("x-indagate-device-secret", device_secret)
        .header("x-nexus-device-secret", device_secret)
        .send()
        .await
        .context("open push stream")?;
    let status = response.status();
    if status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED {
        return Ok(StreamEnd::Unsupported);
    }
    if !status.is_success() {
        return Ok(StreamEnd::Refused(status));
    }
    let mut parser = StreamParser::default();
    while let Some(chunk) = response.chunk().await.context("read push stream")? {
        for signal in parser.push(&chunk)? {
            match signal {
                Signal::Ready => info!(target: "indagate_cloud", "Push stream connected"),
                Signal::Nudge(nudge) => match nudges.try_send(nudge) {
                    Ok(()) => {}
                    // The loop already has nudges waiting; one more would tell it nothing new.
                    Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => return Ok(StreamEnd::AgentStopped),
                },
            }
        }
    }
    Ok(StreamEnd::Closed)
}

/// Whether the push stream should be used at all (`INDAGATE_SERVER_PUSH=off` disables it).
pub fn push_enabled() -> bool {
    !matches!(
        setting("PUSH").as_deref().map(str::trim),
        Some("off" | "0" | "false" | "disabled")
    )
}

/// Keep the push stream open for as long as the agent runs, reconnecting with a growing
/// delay. Never returns an error: every failure only means "fall back to the timers".
pub async fn run_stream(device_id: String, device_secret: String, nudges: mpsc::Sender<Nudge>) {
    let mut delay = Duration::from_secs(2);
    loop {
        let wait = match stream_once(&device_id, &device_secret, &nudges).await {
            Ok(StreamEnd::AgentStopped) => return,
            Ok(StreamEnd::Closed) => {
                delay = Duration::from_secs(2);
                delay
            }
            Ok(StreamEnd::Unsupported) => {
                info!(target: "indagate_cloud", "Cloud has no push stream; using timed polling only");
                Duration::from_secs(300)
            }
            Ok(StreamEnd::Refused(status)) => {
                warn!(target: "indagate_cloud", status = %status, "Push stream refused; using timed polling");
                Duration::from_secs(60)
            }
            Err(e) => {
                warn!(target: "indagate_cloud", error = %e, "Push stream unavailable; using timed polling");
                let wait = delay;
                delay = (delay * 2).min(Duration::from_secs(60));
                wait
            }
        };
        if nudges.is_closed() {
            return;
        }
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILT_IN: &str = "https://built-in.example/functions/v1/nexus-device";

    #[test]
    fn the_new_setting_name_wins_and_the_old_one_still_works() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(pick_setting(s("new"), s("old")), s("new"));
        assert_eq!(pick_setting(None, s("old")), s("old"));
        assert_eq!(pick_setting(None, None), None);
        // An empty new value counts as not set; a malformed one is reported, not replaced.
        assert_eq!(pick_setting(s(" "), s("https://old.example")), s("https://old.example"));
        assert!(resolve_base_url(pick_setting(s("not a url"), s("https://old.example")).as_deref(), false, BUILT_IN).is_err());
    }

    #[test]
    fn unset_address_uses_the_built_in_one() {
        assert_eq!(resolve_base_url(None, false, BUILT_IN).unwrap(), BUILT_IN);
        assert_eq!(resolve_base_url(Some("   "), false, BUILT_IN).unwrap(), BUILT_IN);
    }

    #[test]
    fn https_addresses_are_accepted_and_tidied() {
        assert_eq!(
            resolve_base_url(Some(" https://access.example.com/ "), false, BUILT_IN).unwrap(),
            "https://access.example.com"
        );
        assert_eq!(
            resolve_base_url(Some("https://access.example.com:8443/functions/v1/nexus-device"), false, BUILT_IN).unwrap(),
            "https://access.example.com:8443/functions/v1/nexus-device"
        );
    }

    #[test]
    fn plaintext_is_only_for_loopback_or_explicit_lab_use() {
        assert!(resolve_base_url(Some("http://127.0.0.1:8080"), false, BUILT_IN).is_ok());
        assert!(resolve_base_url(Some("http://localhost:8080"), false, BUILT_IN).is_ok());
        assert!(resolve_base_url(Some("http://[::1]:8080"), false, BUILT_IN).is_ok());
        assert!(resolve_base_url(Some("http://192.168.1.20:8080"), false, BUILT_IN).is_err());
        assert!(resolve_base_url(Some("http://192.168.1.20:8080"), true, BUILT_IN).is_ok());
    }

    #[test]
    fn a_bad_address_is_an_error_not_a_silent_fallback() {
        for bad in [
            "access.example.com",
            "ftp://access.example.com",
            "https://user:pw@access.example.com",
            "https://access.example.com/?x=1",
            "https://access.example.com/#frag",
            "https://",
        ] {
            assert!(resolve_base_url(Some(bad), true, BUILT_IN).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn stream_lines_become_signals() {
        let mut parser = StreamParser::default();
        let signals = parser
            .push(b"event: ready\ndata: {\"keepalive_seconds\":15}\n\n: keepalive\n\nevent: commands\ndata: {}\n\n")
            .unwrap();
        assert_eq!(signals, vec![Signal::Ready, Signal::Nudge(Nudge::Commands)]);
    }

    #[test]
    fn stream_lines_may_arrive_in_pieces_and_with_crlf() {
        let mut parser = StreamParser::default();
        assert!(parser.push(b"event: con").unwrap().is_empty());
        assert!(parser.push(b"fig\r\ndata: {}\r\n").unwrap().is_empty());
        assert_eq!(parser.push(b"\r\n").unwrap(), vec![Signal::Nudge(Nudge::Config)]);
    }

    #[test]
    fn unknown_events_and_bare_data_are_ignored() {
        let mut parser = StreamParser::default();
        assert!(parser.push(b"event: something_new\ndata: {}\n\ndata: orphan\n\n").unwrap().is_empty());
        assert_eq!(parser.push(b"event: commands\n\n").unwrap(), vec![Signal::Nudge(Nudge::Commands)]);
    }

    #[test]
    fn an_endless_line_is_refused() {
        let mut parser = StreamParser::default();
        assert!(parser.push(&vec![b'x'; MAX_STREAM_LINE_BYTES + 1]).is_err());
    }

    #[test]
    fn a_ca_file_must_exist_and_hold_certificates() {
        assert!(extra_roots(None).unwrap().is_empty());
        assert!(extra_roots(Some("")).unwrap().is_empty());
        assert!(extra_roots(Some("/nonexistent/ca.pem")).is_err());
        let path = std::env::temp_dir().join(format!("nexus-empty-ca-{}.pem", std::process::id()));
        std::fs::write(&path, b"not a certificate\n").unwrap();
        assert!(extra_roots(path.to_str()).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
