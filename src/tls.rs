//! Native Pingora TLS listener configuration.
//!
//! Certificate files are loaded by Pingora's TLS backend at startup.  Errors
//! deliberately retain only paths and the backend error, never PEM contents.

use crate::{certificates::CertificateStore, config::TlsConfig};
use pingora_core::listeners::tls::TlsSettings;
use std::{io, path::Path};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("TLS certificate file is not readable")]
    Certificate(#[source] io::Error),
    #[error("TLS private key file is not readable")]
    PrivateKey(#[source] io::Error),
    #[error("TLS certificate or private key is invalid")]
    InvalidMaterial,
}

/// Build native Pingora TLS settings from certificate-store paths.
pub fn settings(config: &TlsConfig) -> Result<TlsSettings, TlsError> {
    // Check readability through the certificate-store boundary before handing
    // paths to Pingora.  We do not include path values or file contents in
    // errors, preventing accidental private-key disclosure in logs.
    ensure_readable(&config.cert_path, false)?;
    ensure_readable(&config.key_path, true)?;
    CertificateStore::validate_material_paths(&config.cert_path, &config.key_path)
        .map_err(|_| TlsError::InvalidMaterial)?;
    TlsSettings::intermediate(
        config.cert_path.to_string_lossy().as_ref(),
        config.key_path.to_string_lossy().as_ref(),
    )
    .map_err(|_| TlsError::InvalidMaterial)
}

fn ensure_readable(path: &Path, key: bool) -> Result<(), TlsError> {
    match std::fs::File::open(path) {
        Ok(_) => Ok(()),
        Err(error) if key => Err(TlsError::PrivateKey(error)),
        Err(error) => Err(TlsError::Certificate(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn missing_material_has_no_secret_in_error() {
        let config = TlsConfig {
            cert_path: PathBuf::from("/missing/cert.pem"),
            key_path: PathBuf::from("/missing/secret-key.pem"),
        };
        let error = match settings(&config) {
            Ok(_) => panic!("expected missing certificate error"),
            Err(error) => error.to_string(),
        };
        assert!(!error.contains("secret-key"));
        assert!(error.contains("certificate file"));
    }
}
