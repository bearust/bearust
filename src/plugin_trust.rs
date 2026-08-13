//! Filesystem-backed trust-on-first-use store for plugin signing keys.
//!
//! Maps a plugin ID to the public key it was first seen signed with. A
//! later load with a *different* key for the same ID is a `Mismatch`, not
//! silently re-pinned -- recovering from a legitimate key rotation is a
//! deliberate, manual operator action (see the design spec's Non-goals).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::VerifyingKey;
use std::io::Write as _;
use std::{collections::BTreeMap, path::PathBuf, sync::Mutex};

/// A generous upper bound for `trusted-keys.json`: a JSON map of
/// plugin-id-to-base64-key entries stays well under 1 MiB even with
/// hundreds of pinned plugins. Anyone who can drop a plugin bundle into
/// the plugins directory can also plant an oversized file at this path, so
/// this bounds how much a reload is forced to read into memory.
const MAX_TRUST_STORE_BYTES: u64 = 1_048_576;

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

#[cfg(test)]
impl std::fmt::Debug for TrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustStore")
            .field("path", &self.path)
            .finish()
    }
}

#[cfg(test)]
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
        let pins = match std::fs::metadata(&path) {
            Ok(metadata) => {
                // Reject anything that isn't a plain file (e.g. a FIFO)
                // before reading it, so a load can't block forever.
                if !metadata.is_file() {
                    return Err(TrustStoreError::Corrupt);
                }
                if metadata.len() > MAX_TRUST_STORE_BYTES {
                    return Err(TrustStoreError::Corrupt);
                }
                let bytes = std::fs::read(&path).map_err(|_| TrustStoreError::Corrupt)?;
                // A crash between writing the temp file and the atomic
                // rename in `persist` can realistically leave a
                // zero-length (or whitespace-only) file behind. Treat that
                // the same as a missing file -- nothing pinned yet -- not
                // as corruption that bricks all plugin loading.
                if bytes.iter().all(|b| b.is_ascii_whitespace()) {
                    BTreeMap::new()
                } else {
                    serde_json::from_slice::<BTreeMap<String, String>>(&bytes)
                        .map_err(|_| TrustStoreError::Corrupt)?
                }
            }
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
                // Build a candidate map and persist it *before* mutating the
                // shared in-memory state. If `persist` fails, `pins` must be
                // left completely unchanged so a later retry actually
                // retries the write instead of finding a stale in-memory
                // pin and returning `Trusted` without ever writing to disk.
                let mut candidate = pins.clone();
                candidate.insert(plugin_id.to_string(), encoded);
                self.persist(&candidate)?;
                *pins = candidate;
                Ok(TrustDecision::Trusted)
            }
        }
    }

    fn persist(&self, pins: &BTreeMap<String, String>) -> Result<(), TrustStoreError> {
        let json = serde_json::to_vec_pretty(pins).map_err(|_| TrustStoreError::WriteFailed)?;
        let tmp_path = self.path.with_extension("json.tmp");
        let mut file =
            std::fs::File::create(&tmp_path).map_err(|_| TrustStoreError::WriteFailed)?;
        file.write_all(&json)
            .map_err(|_| TrustStoreError::WriteFailed)?;
        // Make sure the temp file's contents are durable before it's
        // atomically swapped into place -- otherwise a crash between the
        // write and the rename (or shortly after) can leave a truncated or
        // zero-length file behind.
        file.sync_all().map_err(|_| TrustStoreError::WriteFailed)?;
        drop(file);
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
    fn a_failed_persist_does_not_pin_in_memory_and_a_retry_tries_again() {
        let dir = tempdir().unwrap();
        // The parent directory of this path doesn't exist, so `persist`'s
        // temp-file write will fail with `NotFound` every time, while
        // `load` still treats the missing file as an empty store.
        let path = dir
            .path()
            .join("does-not-exist-subdir")
            .join("trusted-keys.json");
        let store = TrustStore::load(path).unwrap();
        let k = key();

        assert_eq!(
            store.check_or_pin("demo", &k),
            Err(TrustStoreError::WriteFailed)
        );
        // If the failed persist had already mutated the in-memory map, this
        // retry would hit the `Some(existing) if existing == &encoded`
        // fast path and return `Ok(Trusted)` without attempting to write
        // again. It must instead fail the same way, proving the write is
        // actually retried.
        assert_eq!(
            store.check_or_pin("demo", &k),
            Err(TrustStoreError::WriteFailed)
        );
    }

    #[test]
    fn a_corrupt_file_fails_to_load_rather_than_silently_resetting() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trusted-keys.json");
        std::fs::write(&path, b"{ not valid json").unwrap();
        assert_eq!(TrustStore::load(path), Err(TrustStoreError::Corrupt));
    }

    #[test]
    fn an_empty_file_loads_as_an_empty_store_not_as_corrupt() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trusted-keys.json");
        std::fs::write(&path, b"").unwrap();
        let store = TrustStore::load(path).unwrap();
        let k = key();
        assert_eq!(
            store.check_or_pin("demo", &k).unwrap(),
            TrustDecision::Trusted
        );
    }

    #[test]
    fn an_oversized_file_fails_to_load_as_corrupt() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trusted-keys.json");
        // One byte over the cap, padded with whitespace so it would parse
        // as an empty store if the size check were skipped.
        let oversized = vec![b' '; MAX_TRUST_STORE_BYTES as usize + 1];
        std::fs::write(&path, &oversized).unwrap();
        assert_eq!(TrustStore::load(path), Err(TrustStoreError::Corrupt));
    }
}
