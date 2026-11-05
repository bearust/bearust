use crate::config::RouteConfig;
use crate::rate_limit::{Decision, TokenBucket};
use http::uri::Authority;
use std::{
    collections::HashMap,
    str::FromStr,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRoute {
    pub name: String,
    pub host: String,
    pub path_prefix: String,
    pub upstream_pool: String,
    pub max_body_bytes: Option<u64>,
    pub paused: bool,
}

pub struct Router {
    routes: HashMap<String, Vec<ResolvedRoute>>,
    /// One shared bucket per rate-limited route, keyed by route name. Buckets
    /// start full whenever a new configuration is applied.
    limiters: HashMap<String, Mutex<TokenBucket>>,
}

impl Router {
    pub fn new(routes: &[RouteConfig]) -> Self {
        let mut indexed: HashMap<String, Vec<ResolvedRoute>> = HashMap::new();
        let mut limiters = HashMap::new();
        for route in routes {
            if let Some(limit) = route.rate_limit {
                if let Ok(bucket) =
                    TokenBucket::new(limit.burst, f64::from(limit.requests_per_second))
                {
                    limiters.insert(route.name.clone(), Mutex::new(bucket));
                }
            }
            let Some(host) = normalize_host(&route.host) else {
                continue;
            };
            indexed
                .entry(host.clone())
                .or_default()
                .push(ResolvedRoute {
                    name: route.name.clone(),
                    host,
                    path_prefix: route.path_prefix.clone(),
                    upstream_pool: route.upstream_pool.clone(),
                    max_body_bytes: route.max_body_bytes,
                    paused: route.paused,
                });
        }
        for routes in indexed.values_mut() {
            routes.sort_by_key(|route| std::cmp::Reverse(route.path_prefix.len()));
        }
        Self {
            routes: indexed,
            limiters,
        }
    }

    /// Take one token from the route's bucket. `Err(retry_after)` means the
    /// route is over its rate; routes without a limit always pass.
    pub fn admit(&self, route_name: &str, now: Instant) -> Result<(), Duration> {
        let Some(bucket) = self.limiters.get(route_name) else {
            return Ok(());
        };
        let Ok(mut bucket) = bucket.lock() else {
            return Ok(());
        };
        match bucket.try_consume(now, 1) {
            Decision::Allowed { .. } => Ok(()),
            Decision::Limited { retry_after, .. } => Err(retry_after),
        }
    }

    pub fn route(&self, authority: &str, path: &str) -> Option<&ResolvedRoute> {
        let host = normalize_host(authority)?;
        self.routes.get(&host).and_then(|routes| {
            routes
                .iter()
                .find(|route| path_matches(&route.path_prefix, path))
        })
    }
}

pub fn normalize_host(authority: &str) -> Option<String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    let parsed = Authority::from_str(authority).ok()?;
    let host = parsed.host();
    if host.is_empty() {
        return None;
    }
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty()
        || host
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
    {
        return None;
    }
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn path_matches(prefix: &str, path: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|remaining| remaining.starts_with('/'))
}

#[cfg(test)]
mod limit_tests {
    use super::*;
    use crate::config::RouteRateLimit;

    fn route(name: &str, limit: Option<RouteRateLimit>) -> RouteConfig {
        RouteConfig {
            name: name.into(),
            host: format!("{name}.example"),
            path_prefix: "/".into(),
            upstream_pool: "pool".into(),
            rate_limit: limit,
            max_body_bytes: Some(1024),
            paused: false,
        }
    }

    #[test]
    fn rate_limited_route_refills_and_unlimited_route_always_passes() {
        let router = Router::new(&[
            route(
                "limited",
                Some(RouteRateLimit {
                    requests_per_second: 2,
                    burst: 2,
                }),
            ),
            route("open", None),
        ]);
        let now = Instant::now();
        assert!(router.admit("limited", now).is_ok());
        assert!(router.admit("limited", now).is_ok());
        let retry = router.admit("limited", now).unwrap_err();
        assert!(retry <= Duration::from_secs(1));
        assert!(router
            .admit("limited", now + Duration::from_millis(500))
            .is_ok());
        for _ in 0..100 {
            assert!(router.admit("open", now).is_ok());
        }
        assert_eq!(
            router.route("open.example", "/").unwrap().max_body_bytes,
            Some(1024)
        );
        assert!(!router.route("open.example", "/").unwrap().paused);
        let mut paused = route("paused", None);
        paused.paused = true;
        assert!(
            Router::new(&[paused])
                .route("paused.example", "/")
                .unwrap()
                .paused
        );
    }
}
