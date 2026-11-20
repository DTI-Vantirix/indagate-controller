//! SA-15F: native Linux AF_ALG adapter for a CAAM CCM black key.
//!
//! Development-only. This module is NOT called by the live cloud agent.
//! It wraps a random 32-byte DEK using tk(cbc(aes)), and must be used ONLY
//! through HybridSecretEnvelope, which authenticates the secret with GCM.
//! The AES-CBC operation by itself is malleable and is not an AEAD.
//!
//! The SightPas HAB closure fuse is OPEN. Hardware/device-unique protection,
//! reboot persistence, rollback prevention and production assurance are NOT
//! established. Do not use with real device credentials.

use crate::cloud::hybrid_secret_envelope::DataKeyWrapper;
use anyhow::{Context, Result, ensure};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

const BLACK_KEY_BYTES: usize = 64; // 32-byte CCM CAAM black key, observed on the target.
const MAX_KEY_NAME: usize = 100;
const TEST_PREFIX: &str = "hlaxs-sa15f-";

pub struct CaamAfAlgDevelopmentWrapper {
    // Only a CAAM *black key* is held here; no white/plaintext CAAM master key.
    // This still represents sensitive key material and must never be logged.
    black_key: [u8; BLACK_KEY_BYTES],
}

fn test_name_ok(name: &str) -> bool {
    name.len() > TEST_PREFIX.len()
        && name.len() <= MAX_KEY_NAME
        && name.starts_with(TEST_PREFIX)
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

impl CaamAfAlgDevelopmentWrapper {
    /// Loads an explicitly named, root-owned development black-key artifact.
    /// No filesystem paths from cloud requests or envelope JSON are accepted.
    pub fn from_test_key_file(path: &Path) -> Result<Self> {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        ensure!(test_name_ok(name), "invalid experimental CAAM key name");
        ensure!(path.parent() == Some(Path::new("/data/caam")), "CAAM test directory mismatch");
        let dir = fs::symlink_metadata("/data/caam").context("inspect CAAM directory")?;
        ensure!(dir.is_dir() && !dir.file_type().is_symlink(), "unsafe CAAM directory");
        ensure!(dir.uid() == 0 && dir.permissions().mode() & 0o022 == 0, "unsafe CAAM directory owner or mode");
        let meta = fs::symlink_metadata(path).context("inspect CAAM black key")?;
        ensure!(meta.is_file() && !meta.file_type().is_symlink(), "CAAM key must be regular file");
        ensure!(meta.uid() == 0 && meta.permissions().mode() & 0o077 == 0, "insecure CAAM key owner or mode");
        ensure!(meta.len() == BLACK_KEY_BYTES as u64, "unexpected CAAM key length");
        // Protect against a symlink being swapped in after metadata validation.
        let mut opts = fs::OpenOptions::new();
        opts.read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        use std::os::unix::fs::OpenOptionsExt;
        use std::io::Read;
        let mut file = opts.open(path).context("open experimental CAAM black key")?;
        let opened = file.metadata()?;
        ensure!(opened.is_file() && opened.uid() == 0 && opened.len() == BLACK_KEY_BYTES as u64
            && opened.permissions().mode() & 0o077 == 0, "CAAM key changed during open");
        let mut black_key = [0u8; BLACK_KEY_BYTES];
        file.read_exact(&mut black_key).context("read experimental CAAM black key")?;
        Ok(Self { black_key })
    }
}

impl DataKeyWrapper for CaamAfAlgDevelopmentWrapper {
    fn wrap_32(&self, dek: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
        caam_cbc_32(&self.black_key, dek, iv, false)
    }
    fn unwrap_32(&self, wrapped: &[u8; 32], iv: &[u8; 16]) -> Result<[u8; 32]> {
        caam_cbc_32(&self.black_key, wrapped, iv, true)
    }
}

// The Linux AF_ALG ABI uses native-endian u32 for ALG_SET_OP / alg_iv lengths.
const SOL_ALG: libc::c_int = 279;
const ALG_SET_KEY: libc::c_int = 1;
const ALG_SET_IV: libc::c_int = 2;
const ALG_SET_OP: libc::c_int = 3;
const ALG_OP_DECRYPT: u32 = 0;
const ALG_OP_ENCRYPT: u32 = 1;

#[repr(C)]
struct SockAddrAlg {
    family: libc::sa_family_t,
    salg_type: [u8; 14],
    feat: u32,
    mask: u32,
    name: [u8; 64],
}

fn caam_cbc_32(key: &[u8; 64], data: &[u8; 32], iv: &[u8; 16], decrypt: bool) -> Result<[u8; 32]> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::mem::{size_of, zeroed};
    let mut sa = SockAddrAlg { family: libc::AF_ALG as libc::sa_family_t,
        salg_type: [0; 14], feat: 0, mask: 0, name: [0; 64] };
    sa.salg_type[..8].copy_from_slice(b"skcipher");
    sa.name[..12].copy_from_slice(b"tk(cbc(aes))");
    let raw = unsafe { libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    ensure!(raw >= 0, "AF_ALG socket unavailable: {}", std::io::Error::last_os_error());
    let parent = unsafe { OwnedFd::from_raw_fd(raw) };
    let rc = unsafe { libc::bind(parent.as_raw_fd(), (&sa as *const SockAddrAlg).cast(), size_of::<SockAddrAlg>() as libc::socklen_t) };
    ensure!(rc == 0, "CAAM tagged-key cipher unavailable: {}", std::io::Error::last_os_error());
    let rc = unsafe { libc::setsockopt(parent.as_raw_fd(), SOL_ALG, ALG_SET_KEY,
        key.as_ptr().cast(), key.len() as libc::socklen_t) };
    ensure!(rc == 0, "CAAM protected-key rejection: {}", std::io::Error::last_os_error());
    let raw_op = unsafe { libc::accept4(parent.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
    ensure!(raw_op >= 0, "CAAM cipher operation unavailable: {}", std::io::Error::last_os_error());
    let op = unsafe { OwnedFd::from_raw_fd(raw_op) };
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() };
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    // Stack storage aligned for cmsghdr; total buffer must exceed two records.
    let mut controls = [0usize; 16];
    let op_len = unsafe { libc::CMSG_SPACE(size_of::<u32>() as u32) } as usize;
    let iv_len = unsafe { libc::CMSG_SPACE((size_of::<u32>() + 16) as u32) } as usize;
    ensure!(op_len + iv_len <= size_of::<[usize;16]>(), "AF_ALG control buffer too small");
    msg.msg_control = controls.as_mut_ptr().cast();
    msg.msg_controllen = op_len + iv_len;
    unsafe {
        let cm1 = libc::CMSG_FIRSTHDR(&msg);
        ensure!(!cm1.is_null(), "missing AF_ALG operation control");
        (*cm1).cmsg_level = SOL_ALG;
        (*cm1).cmsg_type = ALG_SET_OP;
        (*cm1).cmsg_len = libc::CMSG_LEN(size_of::<u32>() as u32) as _;
        let action = if decrypt { ALG_OP_DECRYPT } else { ALG_OP_ENCRYPT };
        std::ptr::copy_nonoverlapping(action.to_ne_bytes().as_ptr(), libc::CMSG_DATA(cm1), 4);
        let cm2 = libc::CMSG_NXTHDR(&msg, cm1);
        ensure!(!cm2.is_null(), "missing AF_ALG IV control");
        (*cm2).cmsg_level = SOL_ALG;
        (*cm2).cmsg_type = ALG_SET_IV;
        (*cm2).cmsg_len = libc::CMSG_LEN((size_of::<u32>() + 16) as u32) as _;
        let ivdst = libc::CMSG_DATA(cm2);
        std::ptr::copy_nonoverlapping(16u32.to_ne_bytes().as_ptr(), ivdst, 4);
        std::ptr::copy_nonoverlapping(iv.as_ptr(), ivdst.add(4), 16);
    }
    let sent = unsafe { libc::sendmsg(op.as_raw_fd(), &msg, 0) };
    ensure!(sent == 32, "CAAM incomplete encryption request: {}", std::io::Error::last_os_error());
    let mut output = [0u8; 32];
    let got = unsafe { libc::recv(op.as_raw_fd(), output.as_mut_ptr().cast(), 32, libc::MSG_WAITALL) };
    ensure!(got == 32, "CAAM incomplete encryption result: {}", std::io::Error::last_os_error());
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_explicit_sa15f_names() {
        assert!(test_name_ok("hlaxs-sa15f-test-123"));
        assert!(!test_name_ok("../hlaxs-sa15f-test"));
        assert!(!test_name_ok("hlaxs-sa15e-test"));
        assert!(!test_name_ok("hlaxs-sa15f-"));
    }
    #[test]
    fn missing_key_fails_closed() {
        assert!(CaamAfAlgDevelopmentWrapper::from_test_key_file(
            Path::new("/data/caam/hlaxs-sa15f-does-not-exist")).is_err());
    }
}
