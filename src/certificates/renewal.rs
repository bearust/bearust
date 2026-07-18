//! Asynchronous certificate renewal scheduling.
//!
//! Renewal deliberately lives outside Pingora's request path.  The scheduler
//! only activates a newly issued record after the issuer has returned valid
//! material; failures leave the store's last-known-good active record intact.

use super::{CertificateRecord, CertificateStore};
use async_trait::async_trait;
use std::{sync::Arc, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use thiserror::Error;

const DEFAULT_WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const DEFAULT_RETRY: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Error, Clone)]
#[error("certificate renewal failed")]
pub struct RenewalError;

#[async_trait]
pub trait RenewalIssuer: Send + Sync {
    async fn renew(&self, record: &CertificateRecord) -> Result<CertificateRecord, RenewalError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalOutcome {
    NotDue,
    Renewed(CertificateRecord),
    Retrying { attempt: u32 },
    Failed { attempts: u32 },
}

pub struct RenewalScheduler {
    store: CertificateStore,
    issuer: Arc<dyn RenewalIssuer>,
    renewal_window: Duration,
    retry_limit: u32,
    retry_delay: Duration,
    attempts: u32,
    next_retry: Option<Instant>,
}

impl RenewalScheduler {
    pub fn new(store: CertificateStore, issuer: Arc<dyn RenewalIssuer>) -> Self {
        Self { store, issuer, renewal_window: DEFAULT_WINDOW, retry_limit: 3, retry_delay: DEFAULT_RETRY, attempts: 0, next_retry: None }
    }

    pub fn with_policy(mut self, renewal_window: Duration, retry_limit: u32, retry_delay: Duration) -> Self {
        self.renewal_window = renewal_window;
        self.retry_limit = retry_limit;
        self.retry_delay = retry_delay;
        self
    }

    /// Return the monotonic time at which a record enters its renewal window.
    /// Expiry strings are the stable OpenSSL ASN.1 representation emitted by
    /// `CertificateStore`; malformed values are treated as immediately due.
    pub fn next_due(record: &CertificateRecord, now: SystemTime) -> Instant {
        let now_instant = Instant::now();
        let Some(expiry) = parse_openssl_time(&record.expiry) else { return now_instant };
        let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        let due_secs = expiry.saturating_sub(DEFAULT_WINDOW.as_secs() as i64);
        if due_secs <= now_secs { now_instant } else { now_instant + Duration::from_secs((due_secs - now_secs) as u64) }
    }

    pub fn attempts(&self) -> u32 { self.attempts }

    pub async fn run_once(&mut self, now: SystemTime) -> RenewalOutcome {
        let Some(active) = self.store.active() else { return RenewalOutcome::NotDue };
        let due = self.next_due_with_window(&active.record, now);
        let now_mono = Instant::now();
        if now_mono < due || self.next_retry.is_some_and(|retry| now_mono < retry) {
            return RenewalOutcome::NotDue;
        }
        match self.issuer.renew(&active.record).await {
            Ok(record) => {
                if self.store.activate(&record.name).is_err() {
                    self.attempts = self.attempts.saturating_add(1);
                    return self.retry_or_fail();
                }
                self.attempts = 0;
                self.next_retry = None;
                RenewalOutcome::Renewed(record)
            }
            Err(_) => {
                self.attempts = self.attempts.saturating_add(1);
                self.retry_or_fail()
            }
        }
    }

    fn next_due_with_window(&self, record: &CertificateRecord, now: SystemTime) -> Instant {
        let now_instant = Instant::now();
        let Some(expiry) = parse_openssl_time(&record.expiry) else { return now_instant };
        let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        let due_secs = expiry.saturating_sub(self.renewal_window.as_secs() as i64);
        if due_secs <= now_secs { now_instant } else { now_instant + Duration::from_secs((due_secs - now_secs) as u64) }
    }

    fn retry_or_fail(&mut self) -> RenewalOutcome {
        if self.attempts >= self.retry_limit {
            self.next_retry = None;
            RenewalOutcome::Failed { attempts: self.attempts }
        } else {
            let factor = 1u32 << self.attempts.saturating_sub(1).min(6);
            self.next_retry = Some(Instant::now() + self.retry_delay.saturating_mul(factor));
            RenewalOutcome::Retrying { attempt: self.attempts }
        }
    }

    /// Run the scheduler until cancellation. This task is intentionally
    /// independent of proxy request handling.
    pub async fn run_forever(mut self, interval: Duration, mut stop: tokio::sync::watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(interval);
        loop {
            tokio::select! {
                _ = ticker.tick() => { let _ = self.run_once(SystemTime::now()).await; }
                changed = stop.changed() => if changed.is_err() || *stop.borrow() { break; },
            }
        }
    }
}

fn parse_openssl_time(value: &str) -> Option<i64> {
    let mut p = value.split_whitespace();
    let month = match p.next()? { "Jan"=>1,"Feb"=>2,"Mar"=>3,"Apr"=>4,"May"=>5,"Jun"=>6,"Jul"=>7,"Aug"=>8,"Sep"=>9,"Oct"=>10,"Nov"=>11,"Dec"=>12,_=>return None };
    let day: i64 = p.next()?.parse().ok()?;
    let hms: Vec<i64> = p.next()?.split(':').map(|x| x.parse().ok()).collect::<Option<_>>()?;
    let year: i64 = p.next()?.parse().ok()?;
    if p.next()? != "GMT" || hms.len() != 3 { return None; }
    Some(days_from_civil(year, month, day) * 86_400 + hms[0] * 3600 + hms[1] * 60 + hms[2])
}

// Howard Hinnant's proleptic Gregorian conversion, valid for modern dates.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = y - (m <= 2) as i64;
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}
