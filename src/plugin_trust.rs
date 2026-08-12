//! Filesystem-backed trust-on-first-use store for plugin signing keys.
//!
//! Maps a plugin ID to the public key it was first seen signed with. A
//! later load with a *different* key for the same ID is a `Mismatch`, not
//! silently re-pinned -- recovering from a legitimate key rotation is a
//! deliberate, manual operator action (see the design spec's Non-goals).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::VerifyingKey;
use std::{collections::BTreeMap, path::PathBuf, sync::Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    Trusted,
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStoreError {
    /// The on-disk file exists but doesn't parse. Never silently reset --
    /// every signed plugin fails to load until an operator fixes or
    /// removes the file (see the design spec's Error Handling table).
    Corrupt,
    /// The atomic write (temp file + rename) failed while pinning a new
    /// key -- disk full, permissions, etc.
    WriteFailed,
}

pub struct TrustStore {
    path: PathBuf,
    pins: Mutex<BTreeMap<String, String>>,
}

impl std::fmt::Debug for TrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustStore")
            .field("path", &self.path)
            .finish()
    }
}

impl PartialEq for TrustStore {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl TrustStore {
    /// Loads the trust store from `path`. A missing file is treated as an
    /// empty store (nothing has been pinned yet); a present-but-unparseable
    /// file is `Err(TrustStoreError::Corrupt)`.
    pub fn load(path: PathBuf) -> Result<Self, TrustStoreError> {
        let pins = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<BTreeMap<String, String>>(&bytes)
                .map_err(|_| TrustStoreError::Corrupt)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(_) => return Err(TrustStoreError::Corrupt),
        };
        Ok(Self {
            path,
            pins: Mutex::new(pins),
        })
    }

    /// Checks `key` against the pin (if any) already recorded for
    /// `plugin_id`. No prior pin: pins `key` (persisted atomically) and
    /// returns `Trusted`. Prior pin matches `key`: returns `Trusted`
    /// without writing. Prior pin differs: returns `Mismatch` -- the store
    /// is never overwritten on a mismatch.
    pub fn check_or_pin(
        &self,
        plugin_id: &str,
        key: &VerifyingKey,
    ) -> Result<TrustDecision, TrustStoreError> {
        let encoded = BASE64.encode(key.to_bytes());
        let mut pins = self.pins.lock().map_err(|_| TrustStoreError::WriteFailed)?;
        match pins.get(plugin_id) {
            Some(existing) if existing == &encoded => Ok(TrustDecision::Trusted),
            Some(_) => Ok(TrustDecision::Mismatch),
            None => {
                pins.insert(plugin_id.to_string(), encoded);
                self.persist(&pins)?;
                Ok(TrustDecision::Trusted)
            }
        }
    }

    fn persist(&self, pins: &BTreeMap<String, String>) -> Result<(), TrustStoreError> {
        let json = serde_json::to_vec_pretty(pins).map_err(|_| TrustStoreError::WriteFailed)?;
        let tmp_path = self.path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &json).map_err(|_| TrustStoreError::WriteFailed)?;
        std::fs::rename(&tmp_path, &self.path).map_err(|_| TrustStoreError::WriteFailed)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    fn key() -> ed25519_dalek::VerifyingKey {
        SigningKey::generate(&mut OsRng).verifying_key()
    }

    #[test]
    fn first_use_pins_the_key() {
        let dir = tempdir().unwrap();
        let store = TrustStore::load(dir.path().join("trusted-keys.json")).unwrap();
        let k = key();
        assert_eq!(
            store.check_or_pin("demo", &k).unwrap(),
            TrustDecision::Trusted
        );
    }

    #[test]
    fn the_same_key_stays_trusted_on_a_later_check() {
        let dir = tempdir().unwrap();
        let store = TrustStore::load(dir.path().join("trusted-keys.json")).unwrap();
        let k = key();
        store.check_or_pin("demo", &k).unwrap();
        assert_eq!(
            store.check_or_pin("demo", &k).unwrap(),
            TrustDecision::Trusted
        );
    }

    #[test]
    fn a_different_key_for_the_same_id_is_a_mismatch() {
        let dir = tempdir().unwrap();
        let store = TrustStore::load(dir.path().join("trusted-keys.json")).unwrap();
        store.check_or_pin("demo", &key()).unwrap();
        assert_eq!(
            store.check_or_pin("demo", &key()).unwrap(),
            TrustDecision::Mismatch
        );
    }

    #[test]
    fn a_mismatch_does_not_overwrite_the_existing_pin() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trusted-keys.json");
        let store = TrustStore::load(path.clone()).unwrap();
        let original = key();
        store.check_or_pin("demo", &original).unwrap();
        store.check_or_pin("demo", &key()).unwrap();

        let reloaded = TrustStore::load(path).unwrap();
        assert_eq!(
            reloaded.check_or_pin("demo", &original).unwrap(),
            TrustDecision::Trusted
        );
    }

    #[test]
    fn a_pin_survives_reloading_the_store_from_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trusted-keys.json");
        let k = key();
        {
            let store = TrustStore::load(path.clone()).unwrap();
            store.check_or_pin("demo", &k).unwrap();
        }
        let reloaded = TrustStore::load(path).unwrap();
        assert_eq!(
            reloaded.check_or_pin("demo", &k).unwrap(),
            TrustDecision::Trusted
        );
    }

    #[test]
    fn a_missing_file_loads_as_an_empty_store() {
        let dir = tempdir().unwrap();
        let store = TrustStore::load(dir.path().join("does-not-exist.json")).unwrap();
        assert_eq!(
            store.check_or_pin("demo", &key()).unwrap(),
            TrustDecision::Trusted
        );
    }

    #[test]
    fn a_corrupt_file_fails_to_load_rather_than_silently_resetting() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trusted-keys.json");
        std::fs::write(&path, b"{ not valid json").unwrap();
        assert_eq!(TrustStore::load(path), Err(TrustStoreError::Corrupt));
    }
}
