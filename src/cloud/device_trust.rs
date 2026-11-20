//! SA-15A read-only platform discovery.
//! Diagnostic observations are not remote attestation or permission to use
//! a production controller identity. Never changes fuses, CAAM keys, or RPMB.

use serde::Serialize;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const IMX8MP_COMPAT: &[u8] = b"fsl,imx8mp";
const OCOTP_SEC_CONFIG_OFFSET: u64 = 28; // i.MX8MP Bank 1 Word 3
const SEC_CONFIG_CLOSED_MASK: u32 = 1 << 25;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootClosure {
    /// Bank 1 Word 3 SEC_CONFIG[1] is clear.
    Open,
    /// The closing fuse appears set. This does not validate the boot chain.
    ClosedFuseIndicated,
    /// The relevant NVMEM word could not be read.
    Unavailable,
    /// Not known to be an i.MX8M Plus.
    NotAssessed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Assurance {
    /// HAB closure fuse known clear; keys must be development-only.
    DevelopmentOnly,
    /// More verification needed; never claim hardware attestation.
    NotEstablished,
}

#[derive(Debug, Clone, Serialize)]
pub struct HardwareTrustReport {
    pub schema_version: u8,
    pub platform: &'static str,
    pub caam_keygen_device_present: bool,
    pub caam_crypto_driver_registered: bool,
    pub rpmb_interface_present: bool,
    pub optee_device_present: bool,
    pub secure_boot_closure: BootClosure,
    pub assurance: Assurance,
    /// Hard safety boundary until independent production provisioning is added.
    pub production_identity_approved: bool,
    pub remote_attestation_verified: bool,
}

fn imx8mp_compatible() -> bool {
    fs::read("/proc/device-tree/compatible")
        .map(|contents| {
            contents
                .split(|byte| *byte == 0)
                .any(|name| name == IMX8MP_COMPAT)
        })
        .unwrap_or(false)
}

fn decode_sec_config(word: u32) -> BootClosure {
    if word & SEC_CONFIG_CLOSED_MASK == 0 {
        BootClosure::Open
    } else {
        BootClosure::ClosedFuseIndicated
    }
}

fn read_boot_closure(path: &Path) -> BootClosure {
    let read_word = || -> std::io::Result<u32> {
        let mut fuse = File::open(path)?;
        fuse.seek(SeekFrom::Start(OCOTP_SEC_CONFIG_OFFSET))?;
        let mut bytes = [0u8; 4];
        fuse.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    };
    read_word()
        .map(decode_sec_config)
        .unwrap_or(BootClosure::Unavailable)
}

fn rpmb_interface_present() -> bool {
    fs::read_dir("/dev")
        .map(|entries| {
            entries.flatten().any(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("mmcblk") && name.ends_with("rpmb")
            })
        })
        .unwrap_or(false)
}

fn caam_crypto_registered() -> bool {
    fs::read_to_string("/proc/crypto")
        .map(|contents| {
            contents.lines().any(|line| {
                line.trim_start().starts_with("driver") && line.contains("-caam")
            })
        })
        .unwrap_or(false)
}

fn assurance_for(closure: BootClosure) -> Assurance {
    match closure {
        BootClosure::Open => Assurance::DevelopmentOnly,
        _ => Assurance::NotEstablished,
    }
}

/// Read-only diagnostic. Values from a running OS cannot constitute a secure
/// remote attestation, especially without verified boot and signed reports.
pub fn collect_hardware_trust() -> HardwareTrustReport {
    let is_imx8mp = imx8mp_compatible();
    let closure = if is_imx8mp {
        read_boot_closure(Path::new("/sys/bus/nvmem/devices/imx-ocotp0/nvmem"))
    } else {
        BootClosure::NotAssessed
    };

    HardwareTrustReport {
        schema_version: 1,
        platform: if is_imx8mp { "imx8mp" } else { "unknown_or_other" },
        caam_keygen_device_present: Path::new("/dev/caam-keygen").exists(),
        caam_crypto_driver_registered: caam_crypto_registered(),
        rpmb_interface_present: rpmb_interface_present(),
        optee_device_present: Path::new("/dev/tee0").exists(),
        secure_boot_closure: closure,
        assurance: assurance_for(closure),
        production_identity_approved: false,
        remote_attestation_verified: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imx8mp_open_fuse_is_development_only() {
        let boot = decode_sec_config(0);
        assert_eq!(boot, BootClosure::Open);
        assert_eq!(assurance_for(boot), Assurance::DevelopmentOnly);
    }

    #[test]
    fn closed_bit_does_not_mean_production_trust() {
        let boot = decode_sec_config(0x0200_0000);
        assert_eq!(boot, BootClosure::ClosedFuseIndicated);
        assert_eq!(assurance_for(boot), Assurance::NotEstablished);
    }

    #[test]
    fn missing_fuse_never_promotes_assurance() {
        let boot = read_boot_closure(Path::new("/this/path/does/not/exist"));
        assert_eq!(boot, BootClosure::Unavailable);
        assert_eq!(assurance_for(boot), Assurance::NotEstablished);
    }
}
