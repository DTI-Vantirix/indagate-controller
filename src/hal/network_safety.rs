//! Host-wide lock and bounded subprocess runner for isolated NetworkManager operations.
//! These primitives do not activate network interfaces by themselves.
use anyhow::{Context, Result, anyhow};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub struct HostNetworkLock {
    file: File,
}

impl HostNetworkLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("cannot open network lock {}", path.display()))?;
        let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if status != 0 {
            return Err(anyhow!(
                "network lock is already held or unavailable: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { file })
    }
}

impl Drop for HostNetworkLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub fn bounded_command(program: &str, args: &[&str], limit: Duration) -> Result<String> {
    if limit.is_zero() || limit > Duration::from_secs(60) {
        return Err(anyhow!("invalid subprocess timeout"));
    }
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start {program}"))?;
    let start = Instant::now();
    loop {
        match child
            .try_wait()
            .with_context(|| format!("failed waiting for {program}"))?
        {
            Some(_) => {
                let output = child.wait_with_output()?;
                if !output.status.success() {
                    return Err(anyhow!(
                        "{program} failed: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    ));
                }
                return Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned());
            }
            None if start.elapsed() >= limit => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(anyhow!(
                    "{program} exceeded {} second timeout",
                    limit.as_secs()
                ));
            }
            None => thread::sleep(Duration::from_millis(25)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lock_is_exclusive_and_released() {
        let path = std::env::temp_dir().join(format!(
            "hlaxs-network-lock-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let first = HostNetworkLock::acquire(&path).unwrap();
        assert!(HostNetworkLock::acquire(&path).is_err());
        drop(first);
        assert!(HostNetworkLock::acquire(&path).is_ok());
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn bounded_command_returns_output() {
        assert_eq!(
            bounded_command("/bin/echo", &["ready"], Duration::from_secs(2)).unwrap(),
            "ready"
        );
    }
    #[test]
    fn bounded_command_rejects_invalid_timeout() {
        assert!(bounded_command("/bin/echo", &[], Duration::ZERO).is_err());
    }
    #[test]
    fn bounded_command_times_out() {
        assert!(bounded_command("/bin/sleep", &["2"], Duration::from_millis(100)).is_err());
    }
}
