//! Where the controller keeps its data on the board.
//!
//! Everything the controller stores lives in one folder: its identity (`device.json`),
//! its database, the journals beside the database, and the door overrides. This is the
//! only place that folder is named.
//!
//! The folder is `/var/lib/indagate`. Boards set up before the rename keep theirs at
//! `/var/lib/highline-nexus`, and a controller must never start without its identity, so
//! the folder is chosen by where the identity is:
//!
//! 1. `INDAGATE_DATA_DIR`, when set, is used as given.
//! 2. Otherwise the new folder, if it holds the identity.
//! 3. Otherwise the old folder, if that holds the identity.
//! 4. Otherwise the new folder (a board that is not enrolled yet).
//!
//! So a board keeps running from the old folder until its data has been moved, and an
//! empty new folder created by mistake does not hide the identity.
//!
//! The database file is `indagate.db`, or `nexus.db` where only that exists. The journals
//! take their name from the database file, so the two always stay together.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const DATA_DIR: &str = "/var/lib/indagate";
pub const LEGACY_DATA_DIR: &str = "/var/lib/highline-nexus";

const IDENTITY_FILE: &str = "device.json";
const DB_FILE: &str = "indagate.db";
const LEGACY_DB_FILE: &str = "nexus.db";

/// The lock held while the board's network settings are being changed. It holds no data.
pub const NETWORK_LOCK: &str = "/run/lock/indagate-network.lock";

fn choose_data_dir(setting: Option<&str>, exists: impl Fn(&Path) -> bool) -> PathBuf {
    if let Some(dir) = setting.map(str::trim).filter(|dir| !dir.is_empty()) {
        return PathBuf::from(dir);
    }
    let has_identity = |dir: &str| exists(&Path::new(dir).join(IDENTITY_FILE));
    if !has_identity(DATA_DIR) && has_identity(LEGACY_DATA_DIR) {
        return PathBuf::from(LEGACY_DATA_DIR);
    }
    PathBuf::from(DATA_DIR)
}

fn choose_db_file(dir: &Path, exists: impl Fn(&Path) -> bool) -> PathBuf {
    let current = dir.join(DB_FILE);
    let legacy = dir.join(LEGACY_DB_FILE);
    if !exists(&current) && exists(&legacy) { legacy } else { current }
}

/// The controller's data folder. Decided once, when first asked, and the same from then on.
pub fn data_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = choose_data_dir(std::env::var("INDAGATE_DATA_DIR").ok().as_deref(), |path| path.exists());
        if dir == Path::new(LEGACY_DATA_DIR) {
            tracing::warn!(
                target: "indagate_paths",
                dir = LEGACY_DATA_DIR,
                "using the data folder from before the rename; move it to /var/lib/indagate when convenient"
            );
        }
        dir
    })
}

/// The database used when none is named in the environment.
pub fn default_db_path() -> String {
    choose_db_file(data_dir(), |path| path.exists()).to_string_lossy().into_owned()
}

/// Whether `path` is a live database of a controller: one no test or offline tool may touch.
pub fn is_live_db(path: &str) -> bool {
    let path = Path::new(path);
    [DATA_DIR, LEGACY_DATA_DIR].iter().any(|dir| path.starts_with(dir)) || path == Path::new(&default_db_path())
}

/// The controller's identity file. It holds the device secret.
pub fn identity_path() -> &'static str {
    static PATH: OnceLock<String> = OnceLock::new();
    PATH.get_or_init(|| data_dir().join(IDENTITY_FILE).to_string_lossy().into_owned())
}

/// The door overrides that outlive a restart.
pub fn overrides_path() -> PathBuf {
    data_dir().join("door-overrides.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(setting: Option<&str>, present: &[&str]) -> String {
        let present: Vec<PathBuf> = present.iter().map(PathBuf::from).collect();
        choose_data_dir(setting, |path| present.iter().any(|p| p == path)).to_string_lossy().into_owned()
    }

    #[test]
    fn the_data_folder_is_wherever_the_identity_is() {
        let new_identity = "/var/lib/indagate/device.json";
        let old_identity = "/var/lib/highline-nexus/device.json";
        // A board set up before the rename keeps running from its old folder.
        assert_eq!(dir(None, &[old_identity]), LEGACY_DATA_DIR);
        // Once the data has been moved, the new folder is used, even with the old copy kept.
        assert_eq!(dir(None, &[new_identity, old_identity]), DATA_DIR);
        assert_eq!(dir(None, &[new_identity]), DATA_DIR);
        // A board that is not enrolled yet starts in the new folder.
        assert_eq!(dir(None, &[]), DATA_DIR);
        // An empty new folder made by mistake does not hide the identity: only the
        // identity file counts, not the folder.
        assert_eq!(dir(None, &["/var/lib/indagate", old_identity]), LEGACY_DATA_DIR);
    }

    #[test]
    fn a_named_data_folder_is_used_as_given() {
        assert_eq!(dir(Some("/srv/controller"), &["/var/lib/highline-nexus/device.json"]), "/srv/controller");
        // Blank counts as not set.
        assert_eq!(dir(Some("  "), &["/var/lib/highline-nexus/device.json"]), LEGACY_DATA_DIR);
    }

    #[test]
    fn the_database_keeps_its_old_name_until_it_is_renamed() {
        let folder = Path::new("/var/lib/indagate");
        let file = |present: &[&str]| {
            let present: Vec<PathBuf> = present.iter().map(PathBuf::from).collect();
            choose_db_file(folder, |path| present.iter().any(|p| p == path)).to_string_lossy().into_owned()
        };
        assert_eq!(file(&["/var/lib/indagate/nexus.db"]), "/var/lib/indagate/nexus.db");
        assert_eq!(file(&["/var/lib/indagate/indagate.db", "/var/lib/indagate/nexus.db"]), "/var/lib/indagate/indagate.db");
        assert_eq!(file(&[]), "/var/lib/indagate/indagate.db");
    }

    #[test]
    fn live_databases_are_recognised_in_both_folders() {
        assert!(is_live_db("/var/lib/indagate/indagate.db"));
        assert!(is_live_db("/var/lib/highline-nexus/nexus.db"));
        assert!(!is_live_db("/tmp/test-controller.db"));
    }
}
