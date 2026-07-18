//! Secure storage and validation of certificate material.

pub mod renewal;
pub use renewal::{RenewalError, RenewalIssuer, RenewalOutcome, RenewalScheduler, RenewedCertificate};

use openssl::{asn1::Asn1Time, pkey::PKey, x509::X509};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    fs, io,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("certificate name is invalid")]
    InvalidName,
    #[error("certificate material is malformed")]
    Malformed,
    #[error("certificate and private key do not match")]
    KeyMismatch,
    #[error("certificate is expired")]
    Expired,
    #[error("certificate storage path is invalid")]
    InvalidPath,
    #[error("certificate '{name}' was not found")]
    NotFound { name: String },
    #[error("certificate storage operation failed")]
    Io(#[source] io::Error),
    #[error("certificate metadata is invalid")]
    Metadata(#[source] serde_json::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CertificateSource {
    Custom,
    LetsEncrypt,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateRecord {
    pub name: String,
    pub source: CertificateSource,
    pub covered_hostnames: Vec<String>,
    /// ASN.1 time rendered as a stable string; no secret material is included.
    pub expiry: String,
    pub certificate_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveCertificate {
    pub record: CertificateRecord,
}

#[derive(Clone, Debug)]
pub struct CertificateStore {
    root: PathBuf,
    active_path: PathBuf,
}

impl CertificateStore {
    /// Validate PEM material before it is handed to a TLS backend.
    pub fn validate_material_paths(
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<(), CertificateError> {
        let cert_pem = fs::read(cert_path).map_err(CertificateError::Io)?;
        let key_pem = fs::read(key_path).map_err(CertificateError::Io)?;
        let cert = X509::from_pem(&cert_pem).map_err(|_| CertificateError::Malformed)?;
        let key = PKey::private_key_from_pem(&key_pem).map_err(|_| CertificateError::Malformed)?;
        let cert_pub = cert
            .public_key()
            .map_err(|_| CertificateError::Malformed)?
            .public_key_to_der()
            .map_err(|_| CertificateError::Malformed)?;
        let key_pub = key
            .public_key_to_der()
            .map_err(|_| CertificateError::Malformed)?;
        if cert_pub != key_pub {
            return Err(CertificateError::KeyMismatch);
        }
        Ok(())
    }

    pub fn new(root: impl AsRef<Path>) -> Result<Self, CertificateError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(CertificateError::Io)?;
        if fs::symlink_metadata(&root)
            .map_err(CertificateError::Io)?
            .file_type()
            .is_symlink()
        {
            return Err(CertificateError::InvalidPath);
        }
        Ok(Self {
            active_path: root.join("active.json"),
            root,
        })
    }

    pub fn import_custom(
        &self,
        name: impl Into<String>,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<CertificateRecord, CertificateError> {
        let name = name.into();
        validate_name(&name)?;
        let cert = X509::from_pem(cert_pem).map_err(|_| CertificateError::Malformed)?;
        let key = PKey::private_key_from_pem(key_pem).map_err(|_| CertificateError::Malformed)?;
        let cert_pub = cert
            .public_key()
            .map_err(|_| CertificateError::Malformed)?
            .public_key_to_der()
            .map_err(|_| CertificateError::Malformed)?;
        let key_pub = key
            .public_key_to_der()
            .map_err(|_| CertificateError::Malformed)?;
        if cert_pub != key_pub {
            return Err(CertificateError::KeyMismatch);
        }
        let now = Asn1Time::days_from_now(0).map_err(|_| CertificateError::Malformed)?;
        if cert
            .not_after()
            .compare(now.as_ref())
            .map_err(|_| CertificateError::Malformed)?
            == Ordering::Less
        {
            return Err(CertificateError::Expired);
        }
        let hostnames = hostnames(&cert);
        let expiry = cert.not_after().to_string();
        let dir = self.root.join(&name);
        if fs::symlink_metadata(&dir)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(CertificateError::InvalidPath);
        }
        let staging = self
            .root
            .join(format!(".staging-{}-{}", name, uuid::Uuid::new_v4()));
        if staging.exists() {
            let _ = fs::remove_dir_all(&staging);
        }
        fs::create_dir(&staging).map_err(CertificateError::Io)?;
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        let staged_cert = staging.join("cert.pem");
        let staged_key = staging.join("key.pem");
        atomic_write(&staged_cert, cert_pem, false)?;
        atomic_write(&staged_key, key_pem, true)?;
        let record = CertificateRecord {
            name: name.clone(),
            source: CertificateSource::Custom,
            covered_hostnames: hostnames,
            expiry,
            certificate_path: cert_path,
            key_path,
        };
        let metadata = serde_json::to_vec(&record).map_err(CertificateError::Metadata)?;
        atomic_write(&staging.join("metadata.json"), &metadata, false)?;
        if dir.exists() {
            let backup = self
                .root
                .join(format!(".backup-{}-{}", name, std::process::id()));
            fs::rename(&dir, &backup).map_err(CertificateError::Io)?;
            if let Err(e) = fs::rename(&staging, &dir) {
                let _ = fs::rename(&backup, &dir);
                return Err(CertificateError::Io(e));
            }
            let _ = fs::remove_dir_all(backup);
        } else {
            fs::rename(&staging, &dir).map_err(CertificateError::Io)?;
        }
        Ok(record)
    }

    pub fn import_letsencrypt(
        &self,
        name: impl Into<String>,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<CertificateRecord, CertificateError> {
        let mut record = self.import_custom(name, cert_pem, key_pem)?;
        record.source = CertificateSource::LetsEncrypt;
        let metadata = serde_json::to_vec(&record).map_err(CertificateError::Metadata)?;
        atomic_write(
            &record
                .certificate_path
                .parent()
                .unwrap()
                .join("metadata.json"),
            &metadata,
            false,
        )?;
        Ok(record)
    }

    pub fn activate(&self, name: impl AsRef<str>) -> Result<ActiveCertificate, CertificateError> {
        let name = name.as_ref();
        validate_name(name)?;
        let path = self.root.join(name).join("metadata.json");
        let bytes = fs::read(path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                CertificateError::NotFound {
                    name: name.to_string(),
                }
            } else {
                CertificateError::Io(e)
            }
        })?;
        let record: CertificateRecord =
            serde_json::from_slice(&bytes).map_err(CertificateError::Metadata)?;
        let active = ActiveCertificate { record };
        let active_bytes =
            serde_json::to_vec(&active.record).map_err(CertificateError::Metadata)?;
        atomic_write(&self.active_path, &active_bytes, false)?;
        Ok(active)
    }

    pub fn active(&self) -> Option<ActiveCertificate> {
        let bytes = fs::read(&self.active_path).ok()?;
        serde_json::from_slice(&bytes)
            .ok()
            .map(|record| ActiveCertificate { record })
    }
}

fn validate_name(name: &str) -> Result<(), CertificateError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_ascii_control())
    {
        return Err(CertificateError::InvalidName);
    }
    Ok(())
}

fn hostnames(cert: &X509) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(names) = cert.subject_alt_names() {
        for n in names {
            if let Some(dns) = n.dnsname() {
                out.push(dns.to_ascii_lowercase());
            }
        }
    }
    if out.is_empty() {
        for e in cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        {
            if let Ok(s) = e.data().as_utf8() {
                out.push(s.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn atomic_write(path: &Path, bytes: &[u8], secret: bool) -> Result<(), CertificateError> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&tmp, bytes).map_err(CertificateError::Io)?;
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .map_err(CertificateError::Io)?;
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .open(&tmp)
        .map_err(CertificateError::Io)?;
    file.sync_all().map_err(CertificateError::Io)?;
    fs::rename(&tmp, path).map_err(CertificateError::Io)?;
    if let Some(parent) = path.parent() {
        let dir = fs::File::open(parent).map_err(CertificateError::Io)?;
        dir.sync_all().map_err(CertificateError::Io)?;
    }
    Ok(())
}
