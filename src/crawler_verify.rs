//! Search-engine crawler verification by forward-confirmed reverse DNS
//! (FCrDNS), the method Google, Bing, and others document for their bots.
//!
//! An IP is verified for a crawler domain when its PTR name is that domain
//! or a subdomain of it, and that name resolves back to the same IP. The
//! request path never waits on DNS: an unseen IP starts a background lookup
//! and is treated as unverified (fail closed) until the result is cached.

use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VERIFIED_TTL: Duration = Duration::from_secs(3600);
const UNVERIFIED_TTL: Duration = Duration::from_secs(600);
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_ENTRIES: usize = 10_000;
const MAX_PENDING: usize = 256;

#[async_trait]
pub trait CrawlerResolver: Send + Sync {
    /// PTR names for `ip`, without trailing dots.
    async fn reverse(&self, ip: IpAddr) -> Vec<String>;
    /// A/AAAA addresses for `host`.
    async fn forward(&self, host: &str) -> Vec<IpAddr>;
}

/// System-configured DNS resolver.
pub struct SystemResolver(hickory_resolver::TokioAsyncResolver);

impl SystemResolver {
    pub fn from_system() -> Option<Self> {
        hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()
            .ok()
            .map(Self)
    }
}

#[async_trait]
impl CrawlerResolver for SystemResolver {
    async fn reverse(&self, ip: IpAddr) -> Vec<String> {
        self.0
            .reverse_lookup(ip)
            .await
            .map(|names| {
                names
                    .iter()
                    .map(|name| name.to_string().trim_end_matches('.').to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn forward(&self, host: &str) -> Vec<IpAddr> {
        self.0
            .lookup_ip(format!("{host}."))
            .await
            .map(|ips| ips.iter().collect())
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
struct Entry {
    /// Verified PTR hostname, or `None` when verification failed.
    host: Option<String>,
    at: Instant,
}

pub struct CrawlerVerifier {
    resolver: Arc<dyn CrawlerResolver>,
    cache: Mutex<HashMap<IpAddr, Entry>>,
    pending: Mutex<HashSet<IpAddr>>,
}

/// Whether `host` is `domain` or a subdomain of it.
pub fn host_in_domain(host: &str, domain: &str) -> bool {
    let domain = domain
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    !domain.is_empty() && (host == domain || host.ends_with(&format!(".{domain}")))
}

impl CrawlerVerifier {
    pub fn new(resolver: Arc<dyn CrawlerResolver>) -> Arc<Self> {
        Arc::new(Self {
            resolver,
            cache: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashSet::new()),
        })
    }

    /// The verified PTR hostname for `ip`, if FCrDNS already succeeded.
    /// Otherwise schedules a lookup (at most one per IP) and returns `None`.
    pub fn verified_host(self: &Arc<Self>, ip: IpAddr) -> Option<String> {
        if let Ok(cache) = self.cache.lock() {
            if let Some(entry) = cache.get(&ip) {
                let ttl = if entry.host.is_some() {
                    VERIFIED_TTL
                } else {
                    UNVERIFIED_TTL
                };
                if entry.at.elapsed() < ttl {
                    return entry.host.clone();
                }
            }
        }
        self.schedule(ip);
        None
    }

    fn schedule(self: &Arc<Self>, ip: IpAddr) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        {
            let Ok(mut pending) = self.pending.lock() else {
                return;
            };
            if pending.len() >= MAX_PENDING || !pending.insert(ip) {
                return;
            }
        }
        let verifier = self.clone();
        handle.spawn(async move {
            let host = tokio::time::timeout(LOOKUP_TIMEOUT, verifier.verify(ip))
                .await
                .ok()
                .flatten();
            verifier.store(ip, host);
            if let Ok(mut pending) = verifier.pending.lock() {
                pending.remove(&ip);
            }
        });
    }

    /// Full FCrDNS check; public for tests and diagnostics.
    pub async fn verify(&self, ip: IpAddr) -> Option<String> {
        for host in self.resolver.reverse(ip).await {
            if self.resolver.forward(&host).await.contains(&ip) {
                return Some(host);
            }
        }
        None
    }

    fn store(&self, ip: IpAddr, host: Option<String>) {
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        if cache.len() >= MAX_ENTRIES && !cache.contains_key(&ip) {
            if let Some(oldest) = cache.iter().min_by_key(|(_, e)| e.at).map(|(ip, _)| *ip) {
                cache.remove(&oldest);
            }
        }
        cache.insert(
            ip,
            Entry {
                host,
                at: Instant::now(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeDns;

    #[async_trait]
    impl CrawlerResolver for FakeDns {
        async fn reverse(&self, ip: IpAddr) -> Vec<String> {
            match ip.to_string().as_str() {
                "66.249.66.1" => vec!["crawl-66-249-66-1.googlebot.com".into()],
                // Attacker controls their own PTR record...
                "203.0.113.7" => vec!["crawl-1.googlebot.com".into()],
                _ => Vec::new(),
            }
        }
        async fn forward(&self, host: &str) -> Vec<IpAddr> {
            match host {
                "crawl-66-249-66-1.googlebot.com" => vec!["66.249.66.1".parse().unwrap()],
                // ...but not Google's forward zone.
                "crawl-1.googlebot.com" => vec!["66.249.66.2".parse().unwrap()],
                _ => Vec::new(),
            }
        }
    }

    #[tokio::test]
    async fn forward_confirmation_defeats_spoofed_ptr_records() {
        let verifier = CrawlerVerifier::new(Arc::new(FakeDns));
        let google: IpAddr = "66.249.66.1".parse().unwrap();
        let spoofed: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(
            verifier.verify(google).await.as_deref(),
            Some("crawl-66-249-66-1.googlebot.com")
        );
        assert_eq!(verifier.verify(spoofed).await, None);

        // First sight is unverified and schedules the lookup in the background.
        assert_eq!(verifier.verified_host(google), None);
        for _ in 0..50 {
            if verifier.verified_host(google).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(verifier.verified_host(google).is_some());
        assert!(host_in_domain(
            "crawl-66-249-66-1.googlebot.com",
            "googlebot.com"
        ));
        assert!(!host_in_domain("evilgooglebot.com", "googlebot.com"));
    }
}
