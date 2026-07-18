use bearust::config::{normalize_config_host, Algorithm, Config, HealthCheckKind};

const VALID: &str = include_str!("fixtures/valid.toml");

#[test]
fn parses_valid_configuration_and_defaults() {
    let config = Config::parse(VALID).expect("valid fixture");
    assert_eq!(config.server.bind.to_string(), "127.0.0.1:18080");
    assert_eq!(config.server.graceful_shutdown_seconds, 30);
    assert_eq!(config.health.healthy_threshold, 2);
    assert_eq!(config.server.graceful_shutdown_seconds, 30);
    assert_eq!(config.server.pid_file.to_string_lossy(), "./bearust.pid");
    assert_eq!(config.health.interval_seconds, 10);
    assert_eq!(config.health.timeout_seconds, 2);
    assert_eq!(config.health.unhealthy_threshold, 3);
    assert_eq!(config.upstream_pools[0].connect_timeout_seconds, 3);
    assert_eq!(config.upstream_pools[0].request_timeout_seconds, 30);
    assert_eq!(
        config.upstream_pools[0].algorithm,
        Algorithm::LeastConnections
    );
    assert_eq!(
        config.upstream_pools[0].backends[0].health_check,
        HealthCheckKind::Http
    );
}

fn invalid(replacement: &str) -> String {
    VALID.replace("path_prefix = \"/\"", replacement)
}

#[test]
fn rejects_route_that_references_missing_pool() {
    let invalid = VALID.replace("upstream_pool = \"api\"", "upstream_pool = \"missing\"");
    let error = Config::parse(&invalid).unwrap_err().to_string();
    assert!(error.contains("routes[0].upstream_pool"));
    assert!(error.contains("missing"));
}

#[test]
fn rejects_weight_field_in_phase_one() {
    let invalid = VALID.replace(
        "address = \"127.0.0.1:19001\"",
        "address = \"127.0.0.1:19001\"\nweight = 2",
    );
    assert!(Config::parse(&invalid)
        .unwrap_err()
        .to_string()
        .contains("weight"));
}

#[test]
fn rejects_duplicate_names_and_empty_pool() {
    let dup = format!("{VALID}\n[[upstream_pools]]\nname=\"api\"\nalgorithm=\"round_robin\"\n[[upstream_pools.backends]]\naddress=\"127.0.0.1:2\"\nhealth_check=\"tcp\"");
    assert!(Config::parse(&dup)
        .unwrap_err()
        .to_string()
        .contains("upstream_pools[1].name"));
    let empty = VALID.replace(
        "[[upstream_pools.backends]]",
        "# [[upstream_pools.backends]]",
    );
    assert!(Config::parse(&empty).is_err());

    let duplicate_route = format!("{VALID}\n[[routes]]\nname=\"api\"\nhost=\"other.example.com\"\npath_prefix=\"/v2\"\nupstream_pool=\"api\"");
    assert!(Config::parse(&duplicate_route)
        .unwrap_err()
        .to_string()
        .contains("routes[1].name"));
}

#[test]
fn rejects_unsupported_algorithm() {
    let invalid = VALID.replace(
        "algorithm = \"least_connections\"",
        "algorithm = \"random\"",
    );
    let error = Config::parse(&invalid).unwrap_err().to_string();
    assert!(error.contains("algorithm"));
}

#[test]
fn rejects_invalid_health_and_addresses() {
    for (needle, replacement) in [
        ("interval_seconds", "interval_seconds = 0"),
        ("timeout_seconds", "timeout_seconds = 0"),
        ("unhealthy_threshold", "unhealthy_threshold = 0"),
        ("healthy_threshold", "healthy_threshold = 0"),
    ] {
        let input = VALID.replace("[health]\n", &format!("[health]\n{replacement}\n"));
        assert!(Config::parse(&input)
            .unwrap_err()
            .to_string()
            .contains(needle));
    }
    let bad = VALID.replace("127.0.0.1:19001", "not-an-address");
    assert!(Config::parse(&bad).is_err());

    for field in ["connect_timeout_seconds", "request_timeout_seconds"] {
        let invalid = VALID.replace(
            "[[upstream_pools.backends]]",
            &format!("{field} = 0\n[[upstream_pools.backends]]"),
        );
        assert!(Config::parse(&invalid)
            .unwrap_err()
            .to_string()
            .contains(field));
    }
}

#[test]
fn normalizes_ports_trailing_dots_and_bracketed_ipv6() {
    assert_eq!(
        normalize_config_host("API.EXAMPLE.COM.:8080"),
        "api.example.com"
    );
    assert_eq!(normalize_config_host("[2001:DB8::1]:8443"), "2001:db8::1");
    assert_eq!(normalize_config_host("[2001:DB8::1]"), "2001:db8::1");
    assert_eq!(normalize_config_host("2001:db8::1"), "2001:db8::1");
}

#[test]
fn accepts_dns_route_host_with_single_trailing_dot() {
    let input = VALID.replace("host = \"api.example.com\"", "host = \"api.example.com.\"");
    Config::parse(&input).expect("single DNS root dot is valid");
}

#[test]
fn rejects_http_path_and_route_path_errors() {
    let no_path = VALID.replace("health_path = \"/health\"\n", "");
    assert!(Config::parse(&no_path)
        .unwrap_err()
        .to_string()
        .contains("health_path"));
    let bad = invalid("path_prefix = \"api\"");
    assert!(Config::parse(&bad)
        .unwrap_err()
        .to_string()
        .contains("path_prefix"));

    for payload in ["/health\\r\\nX-Injected: yes", "/health\\nX-Injected: yes"] {
        let invalid = VALID.replace(
            "health_path = \"/health\"",
            &format!("health_path = \"{payload}\""),
        );
        let error = Config::parse(&invalid).unwrap_err().to_string();
        assert!(error.contains("health_path"), "{payload:?}: {error}");
    }
}

#[test]
fn rejects_duplicate_normalized_routes() {
    let dup = format!("{VALID}\n[[routes]]\nname=\"other\"\nhost=\"API.EXAMPLE.COM:80.\"\npath_prefix=\"/\"\nupstream_pool=\"api\"");
    assert!(Config::parse(&dup)
        .unwrap_err()
        .to_string()
        .contains("routes"));
}

#[test]
fn rejects_empty_or_malformed_route_hosts() {
    for host in [
        "",
        "   ",
        "api.example.com\\r\\nX: y",
        "http://api.example.com",
        "[2001:db8::1",
    ] {
        let invalid = VALID.replace("host = \"api.example.com\"", &format!("host = \"{host}\""));
        let error = Config::parse(&invalid).unwrap_err().to_string();
        assert!(error.contains("routes[0].host"), "{host:?}: {error}");
    }
}
