//! Certificates and HTTP-01 challenges pushed by a managing control plane
//! through `PUT /api/desired-state`.
//!
//! Managed certificates are stored like uploaded ones under the name
//! `managed-<name>` and served by SNI; each push replaces the whole managed
//! set. Dashboard certificates are never touched.

use super::models::{ManagedAcmeChallenge, ManagedCertificate};
use super::{repository, AppState};
use crate::certificates::CertificateStore;

pub(crate) const MANAGED_PREFIX: &str = "managed-";
/// Order key under which pushed challenges live in the shared HTTP-01 store.
const CHALLENGE_ORDER: &str = "desired-state";
const MAX_CERTIFICATES: usize = 2000;
const MAX_CHALLENGES: usize = 2000;
const MAX_PEM_BYTES: usize = 64 * 1024;

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && !name.starts_with('.')
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// Checks the pushed certificates and challenges without changing anything.
pub(crate) fn validate(
    certificates: &[ManagedCertificate],
    challenges: &[ManagedAcmeChallenge],
) -> Result<(), String> {
    if certificates.len() > MAX_CERTIFICATES {
        return Err(format!("at most {MAX_CERTIFICATES} certificates"));
    }
    if challenges.len() > MAX_CHALLENGES {
        return Err(format!("at most {MAX_CHALLENGES} ACME challenges"));
    }
    let mut seen = std::collections::HashSet::new();
    for cert in certificates {
        if !valid_name(&cert.name) {
            return Err(format!("certificate name {:?} is invalid", cert.name));
        }
        if !seen.insert(cert.name.as_str()) {
            return Err(format!("certificate name {:?} is duplicated", cert.name));
        }
        if cert.cert_pem.len() > MAX_PEM_BYTES || cert.key_pem.len() > MAX_PEM_BYTES {
            return Err(format!("certificate {:?} is too large", cert.name));
        }
        CertificateStore::check_pair(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
            .map_err(|e| format!("certificate {:?}: {e}", cert.name))?;
    }
    for challenge in challenges {
        if !valid_host(&challenge.host) {
            return Err(format!(
                "ACME challenge host {:?} is invalid",
                challenge.host
            ));
        }
    }
    // Token and key-authorization format are checked by the store itself.
    crate::acme::Http01Store::new(std::time::Duration::from_secs(1))
        .replace_order("check", &entries(challenges))
        .map_err(|e| e.to_string())
}

fn entries(challenges: &[ManagedAcmeChallenge]) -> Vec<(String, String, String)> {
    challenges
        .iter()
        .map(|c| (c.host.clone(), c.token.clone(), c.key_authorization.clone()))
        .collect()
}

/// Replaces the served challenge set. Call after [`validate`].
pub(crate) fn apply_challenges(
    s: &AppState,
    challenges: &[ManagedAcmeChallenge],
) -> Result<(), String> {
    s.http01
        .replace_order(CHALLENGE_ORDER, &entries(challenges))
        .map_err(|e| e.to_string())
}

/// Makes the stored managed certificates equal to `certificates`: writes new
/// or changed ones, deletes the rest, and tells the SNI resolver when
/// anything changed. Returns whether anything changed. Call after
/// [`validate`].
pub(crate) async fn apply_certificates(
    s: &AppState,
    certificates: &[ManagedCertificate],
) -> Result<bool, String> {
    let existing = repository::list_certificates(&s.db)
        .await
        .map_err(|e| e.to_string())?;
    let mut changed = false;
    for cert in certificates {
        let stored_name = format!("{MANAGED_PREFIX}{}", cert.name);
        let current = existing.iter().find(|m| m.name == stored_name);
        if let Some(meta) = current {
            let same = repository::certificate_paths(&s.db, meta.id)
                .await
                .ok()
                .flatten()
                .and_then(|(_, cert_path, _)| std::fs::read(cert_path).ok())
                .is_some_and(|bytes| bytes == cert.cert_pem.as_bytes());
            if same {
                continue;
            }
        }
        let record = s
            .certificates
            .import_custom(
                &stored_name,
                cert.cert_pem.as_bytes(),
                cert.key_pem.as_bytes(),
            )
            .map_err(|e| format!("certificate {:?}: {e}", cert.name))?;
        let hosts = serde_json::to_string(&record.covered_hostnames).map_err(|e| e.to_string())?;
        repository::upsert_certificate(
            &s.db,
            &stored_name,
            "managed",
            &hosts,
            &record.expiry,
            &record.certificate_path.to_string_lossy(),
            &record.key_path.to_string_lossy(),
        )
        .await
        .map_err(|e| e.to_string())?;
        changed = true;
    }
    for meta in existing
        .iter()
        .filter(|m| m.name.starts_with(MANAGED_PREFIX))
        .filter(|m| {
            !certificates
                .iter()
                .any(|c| m.name[MANAGED_PREFIX.len()..] == c.name)
        })
    {
        if repository::delete_certificate_by_name(&s.db, &meta.name)
            .await
            .map_err(|e| e.to_string())?
            > 0
        {
            let _ = s.certificates.remove(&meta.name);
            changed = true;
        }
    }
    if changed {
        s.realtime.publish("certificates.changed");
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_hosts_are_restricted() {
        assert!(valid_name("org-1.wildcard"));
        assert!(!valid_name("../etc"));
        assert!(!valid_name("Upper"));
        assert!(!valid_name(""));
        assert!(valid_host("shop.example.com"));
        assert!(!valid_host("a/b"));
    }

    #[test]
    fn rejects_bad_challenges_and_pems() {
        let challenge = ManagedAcmeChallenge {
            host: "shop.example.com".into(),
            token: "tok".into(),
            key_authorization: "other.digest".into(),
        };
        assert!(validate(&[], &[challenge]).is_err());
        let cert = ManagedCertificate {
            name: "x".into(),
            cert_pem: "nope".into(),
            key_pem: "nope".into(),
        };
        assert!(validate(&[cert], &[]).is_err());
    }
}
