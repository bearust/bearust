//! Small file-backed secret store used for credentials which must survive restarts.
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("invalid secret name")]
    InvalidName,
    #[error("secret store I/O error")]
    Io(#[source] io::Error),
}

#[derive(Clone, Debug)]
pub struct SecretStore {
    root: PathBuf,
}

impl SecretStore {
    pub fn open(root: &Path) -> Result<Self, SecretError> {
        if let Ok(meta) = fs::symlink_metadata(root) {
            if meta.file_type().is_symlink() {
                return Err(SecretError::InvalidName);
            }
        }
        fs::create_dir_all(root).map_err(SecretError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))
                .map_err(SecretError::Io)?;
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub fn put(&self, name: &str, value: &[u8]) -> Result<(), SecretError> {
        self.validate(name)?;
        let path = self.root.join(name);
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                return Err(SecretError::InvalidName);
            }
        }
        // Never follow or overwrite a pre-existing temporary path.  A unique
        // create_new file also makes concurrent writers independent.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let tmp = self.root.join(format!(
            ".{name}.tmp-{}-{nonce:x}-{sequence:x}",
            std::process::id()
        ));
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .map_err(SecretError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(SecretError::Io)?;
        }
        use io::Write;
        file.write_all(value).map_err(SecretError::Io)?;
        file.sync_all().map_err(SecretError::Io)?;
        drop(file);
        // Re-check immediately before replacement so a target symlink is
        // rejected rather than atomically replaced through an attacker path.
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                let _ = fs::remove_file(&tmp);
                return Err(SecretError::InvalidName);
            }
        }
        fs::rename(&tmp, &path).map_err(SecretError::Io)?;
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<Option<Vec<u8>>, SecretError> {
        self.validate(name)?;
        let path = self.root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => Err(SecretError::InvalidName),
            Ok(_) => fs::read(path).map(Some).map_err(SecretError::Io),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(SecretError::Io(error)),
        }
    }

    fn validate(&self, name: &str) -> Result<(), SecretError> {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(SecretError::InvalidName);
        }
        Ok(())
    }
}
