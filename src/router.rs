use crate::config::RouteConfig;
use http::uri::Authority;
use std::{collections::HashMap, str::FromStr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRoute {
    pub name: String,
    pub host: String,
    pub path_prefix: String,
    pub upstream_pool: String,
}

pub struct Router {
    routes: HashMap<String, Vec<ResolvedRoute>>,
}

impl Router {
    pub fn new(routes: &[RouteConfig]) -> Self {
        let mut indexed: HashMap<String, Vec<ResolvedRoute>> = HashMap::new();
        for route in routes {
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
                });
        }
        for routes in indexed.values_mut() {
            routes.sort_by_key(|route| std::cmp::Reverse(route.path_prefix.len()));
        }
        Self { routes: indexed }
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
