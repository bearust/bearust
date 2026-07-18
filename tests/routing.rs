use bearust::{
    config::{Config, RouteConfig},
    router::{normalize_host, Router},
};

fn router(routes: Vec<RouteConfig>) -> Router {
    Router::new(&routes)
}

#[test]
fn normalizes_dns_host_case_trailing_dot_and_port() {
    assert_eq!(
        normalize_host("API.Example.COM.:8080").as_deref(),
        Some("api.example.com")
    );
}

#[test]
fn chooses_longest_segment_aware_prefix() {
    let config = Config::parse(include_str!("fixtures/routes.toml")).unwrap();
    let router = router(config.routes);
    assert_eq!(
        router.route("api.example.com", "/api/users").unwrap().name,
        "users"
    );
    assert_eq!(router.route("api.example.com", "/api").unwrap().name, "api");
    // `/api` is segment-aware and must not match `/apiv2`; `/` remains the
    // mandated catch-all route for paths that do not match a more specific
    // prefix.
    assert_eq!(
        router.route("api.example.com", "/apiv2").unwrap().name,
        "root"
    );
}

#[test]
fn rejects_unknown_host() {
    let config = Config::parse(include_str!("fixtures/routes.toml")).unwrap();
    assert!(router(config.routes)
        .route("other.example.com", "/api")
        .is_none());
}
