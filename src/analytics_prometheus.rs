use crate::analytics::AnalyticsSnapshot;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrometheusConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_internal_only")]
    pub internal_only: bool,
    #[serde(default = "default_require_auth")]
    pub require_auth: bool,
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    #[serde(default = "default_max_output")]
    pub max_output_bytes: usize,
}
fn default_internal_only() -> bool {
    true
}
fn default_require_auth() -> bool {
    true
}
fn default_bind() -> SocketAddr {
    "127.0.0.1:9090".parse().unwrap()
}
fn default_max_output() -> usize {
    DEFAULT_MAX_OUTPUT_BYTES
}
impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            internal_only: true,
            require_auth: true,
            bind: default_bind(),
            max_output_bytes: default_max_output(),
        }
    }
}
impl PrometheusConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_output_bytes == 0 || self.max_output_bytes > 4 * 1024 * 1024 {
            return Err("max_output_bytes out of bounds");
        }
        if self.enabled && self.internal_only && !is_loopback(self.bind.ip()) {
            return Err("internal prometheus endpoint must bind loopback");
        }
        if self.enabled && !self.internal_only && !self.require_auth {
            return Err("externally exposed prometheus endpoint requires authentication");
        }
        Ok(())
    }
}
fn is_loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
}

#[allow(clippy::result_unit_err)]
pub fn render(snapshot: &AnalyticsSnapshot, config: &PrometheusConfig) -> Result<String, ()> {
    config.validate().map_err(|_| ())?;
    let mut out = String::new();
    out.push_str("# TYPE bearust_requests_total counter\n# TYPE bearust_request_duration_ms gauge\n# TYPE bearust_security_events_total counter\n# TYPE bearust_rate_limit_events_total counter\n");
    let mut counters: BTreeMap<(String, String, String), u64> = BTreeMap::new();
    let mut gauges: BTreeMap<(String, String), u64> = BTreeMap::new();
    for b in &snapshot.timeseries {
        let host = b.proxy_host_id.to_string();
        let class = [
            ("2xx", b.status_2xx),
            ("3xx", b.status_3xx),
            ("4xx", b.status_4xx),
            ("5xx", b.status_5xx),
        ];
        for (status, count) in class {
            *counters
                .entry(("bearust_requests_total".into(), host.clone(), status.into()))
                .or_default() += count;
        }
        let key = ("bearust_request_duration_ms".to_string(), host.clone());
        gauges
            .entry(key)
            .and_modify(|v| *v = (*v).max(b.p95_ms.unwrap_or(0)))
            .or_insert(b.p95_ms.unwrap_or(0));
        let security = b.waf_blocks + b.bot_blocks + b.bot_challenges;
        *counters
            .entry((
                "bearust_security_events_total".into(),
                host.clone(),
                "".into(),
            ))
            .or_default() += security;
        *counters
            .entry(("bearust_rate_limit_events_total".into(), host, "".into()))
            .or_default() += b.rate_limited;
    }
    for ((name, host, status), value) in counters {
        if status.is_empty() {
            line(&mut out, &name, &[("proxy_host_id", host.as_str())], value);
        } else {
            line(
                &mut out,
                &name,
                &[
                    ("proxy_host_id", host.as_str()),
                    ("status_class", status.as_str()),
                ],
                value,
            );
        }
    }
    for ((name, host), value) in gauges {
        line(&mut out, &name, &[("proxy_host_id", host.as_str())], value);
    }
    if out.len() > config.max_output_bytes {
        // Keep only complete exposition lines; never return a partial sample.
        let end = out
            .get(..config.max_output_bytes)
            .unwrap_or("")
            .rfind('\n')
            .map(|idx| idx + 1)
            .unwrap_or(0);
        out.truncate(end);
    }
    Ok(out)
}
fn line(out: &mut String, name: &str, labels: &[(&str, &str)], value: u64) {
    out.push_str(name);
    if !labels.is_empty() {
        out.push('{');
        for (i, (key, val)) in labels.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(key);
            out.push_str("=\"");
            escape(out, val);
            out.push('"');
        }
        out.push('}');
    }
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}
fn escape(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
}
