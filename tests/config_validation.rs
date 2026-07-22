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
    assert!(!config.rate_limit.enabled);
    assert_eq!(config.rate_limit.capacity, 100);
    assert_eq!(config.rate_limit.refill_per_second, 10.0);
    assert_eq!(config.upstream_pools[0].connect_timeout_seconds, 3);
    assert_eq!(config.upstream_pools[0].request_timeout_seconds, 30);
    assert!(!config.prometheus.enabled);
    assert_eq!(
        config.upstream_pools[0].algorithm,
        Algorithm::LeastConnections
    );
    assert_eq!(
        config.upstream_pools[0].backends[0].health_check,
        HealthCheckKind::Http
    );
}

#[test]
fn parses_and_validates_prometheus_configuration() {
    let input = format!(
        "{VALID}\n[prometheus]\nenabled = true\nbind = \"127.0.0.1:9191\"\nmax_output_bytes = 4096\n"
    );
    let config = Config::parse(&input).expect("valid prometheus configuration");
    assert!(config.prometheus.enabled);
    assert_eq!(config.prometheus.bind.to_string(), "127.0.0.1:9191");
    assert_eq!(config.prometheus.max_output_bytes, 4096);

    let external_internal =
        format!("{VALID}\n[prometheus]\nenabled = true\nbind = \"0.0.0.0:9191\"\n");
    assert!(Config::parse(&external_internal).is_err());
}

#[test]
fn prometheus_internal_bind_is_valid_when_control_bind_is_external() {
    let input = VALID.replace(
        "[server]\nbind = \"127.0.0.1:18080\"",
        "[server]\nbind = \"127.0.0.1:18080\"\ncontrol_bind = \"0.0.0.0:8080\"",
    ) + "\n[prometheus]\nenabled = true\nbind = \"127.0.0.1:9191\"\n";
    let config = Config::parse(&input).expect("loopback prometheus bind should be valid");
    assert_eq!(config.server.control_bind.to_string(), "0.0.0.0:8080");
    assert!(config.prometheus.bind.ip().is_loopback());
}

#[test]
fn rate_limit_policy_is_strict_and_bounded() {
    let configured = format!("{VALID}\n[rate_limit]\nenabled = true\naction = \"block\"\ncapacity = 500\nrefill_per_second = 25.5\nkey_scope = \"proxy_host_ip\"\n");
    let config = Config::parse(&configured).expect("valid rate limit policy");
    assert!(config.rate_limit.enabled);
    assert_eq!(config.rate_limit.capacity, 500);

    for replacement in [
        "capacity = 0",
        "capacity = 1000001",
        "refill_per_second = 0",
        "refill_per_second = 100001",
    ] {
        let input = format!("{VALID}\n[rate_limit]\n{replacement}\n");
        assert!(
            Config::parse(&input).is_err(),
            "accepted invalid policy: {replacement}"
        );
    }
    let unknown = format!("{VALID}\n[rate_limit]\nunknown = true\n");
    assert!(Config::parse(&unknown).is_err());
}

#[test]
fn parses_optional_tls_configuration() {
    let input = format!("{VALID}\n[server.tls]\ncert_path = \"/etc/bearust/tls/fullchain.pem\"\nkey_path = \"/etc/bearust/tls/privkey.pem\"\n");
    let config = Config::parse(&input).expect("valid TLS configuration");
    let tls = config.server.tls.expect("TLS block");
    assert_eq!(
        tls.cert_path.to_string_lossy(),
        "/etc/bearust/tls/fullchain.pem"
    );
    assert_eq!(
        tls.key_path.to_string_lossy(),
        "/etc/bearust/tls/privkey.pem"
    );
}

#[test]
fn rejects_one_sided_tls_blocks() {
    for block in [
        "[server.tls]\ncert_path = \"/etc/cert.pem\"",
        "[server.tls]\nkey_path = \"/etc/key.pem\"",
    ] {
        let input = format!("{VALID}\n{block}\n");
        assert!(Config::parse(&input).is_err(), "accepted: {block}");
    }
}

#[test]
fn rejects_empty_tls_paths() {
    for field in ["cert_path", "key_path"] {
        let input = format!(
            "{VALID}\n[server.tls]\ncert_path = \"/etc/cert.pem\"\nkey_path = \"/etc/key.pem\"\n"
        )
        .replace(
            &format!(
                "{field} = \"/etc/{}pem\"",
                if field == "cert_path" {
                    "cert."
                } else {
                    "key."
                }
            ),
            &format!("{field} = \"\""),
        );
        let error = Config::parse(&input).unwrap_err().to_string();
        assert!(error.contains(field), "{field}: {error}");
    }
}

#[test]
fn rejects_unknown_tls_keys() {
    let input = format!(
        "{VALID}\n[server.tls]\ncert_path = \"/etc/cert.pem\"\nkey_path = \"/etc/key.pem\"\nextra = true\n"
    );
    let error = Config::parse(&input).unwrap_err().to_string();
    assert!(error.contains("extra"), "{error}");
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

#[test]
fn omitted_cluster_config_uses_safe_single_node_defaults() {
    let config = Config::parse(VALID).expect("valid fixture");
    assert_eq!(config.cluster.node_id, "node1");
    assert!(config.cluster.peers.is_empty());
    assert_eq!(config.cluster.timeout_seconds, 2);
}

#[test]
fn parses_valid_multi_node_cluster_config() {
    let toml = format!(
        "{VALID}\n[cluster]\nnode_id = \"node1\"\nbind = \"127.0.0.1:9092\"\ntimeout_seconds = 5\n\n[[cluster.peers]]\nnode_id = \"node2\"\naddress = \"127.0.0.1:9093\"\n\n[[cluster.peers]]\nnode_id = \"node3\"\naddress = \"127.0.0.1:9094\""
    );
    let config = Config::parse(&toml).expect("valid multi-node cluster config");
    assert_eq!(config.cluster.node_id, "node1");
    assert_eq!(config.cluster.peers.len(), 2);
    assert_eq!(config.cluster.peers[0].node_id, "node2");
    assert_eq!(
        config.cluster.peers[0].address,
        "127.0.0.1:9093".parse().unwrap()
    );
    assert_eq!(config.cluster.peers[1].node_id, "node3");
    assert_eq!(
        config.cluster.peers[1].address,
        "127.0.0.1:9094".parse().unwrap()
    );
}

#[test]
fn parses_cluster_peers_env_var_format() {
    let peers =
        bearust::config::ClusterPeer::parse_peers("node2=127.0.0.1:9092,node3=127.0.0.1:9093")
            .expect("valid peers str");
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0].node_id, "node2");
    assert_eq!(peers[0].address, "127.0.0.1:9092".parse().unwrap());
    assert_eq!(peers[1].node_id, "node3");
    assert_eq!(peers[1].address, "127.0.0.1:9093".parse().unwrap());

    let empty = bearust::config::ClusterPeer::parse_peers("   ").expect("empty peers");
    assert!(empty.is_empty());
}

#[test]
fn rejects_invalid_cluster_peer_format() {
    assert!(bearust::config::ClusterPeer::parse_peers("node2").is_err());
    assert!(bearust::config::ClusterPeer::parse_peers("node2=invalid_host").is_err());
    assert!(bearust::config::ClusterPeer::parse_peers("=127.0.0.1:9092").is_err());
}

#[test]
fn rejects_self_referential_cluster_peer() {
    let toml = format!(
        "{VALID}\n[cluster]\nnode_id = \"node1\"\n[[cluster.peers]]\nnode_id = \"node1\"\naddress = \"127.0.0.1:9093\""
    );
    let err = Config::parse(&toml).unwrap_err().to_string();
    assert!(err.contains("matches local node_id"), "{err}");
}

#[test]
fn rejects_duplicate_cluster_peer_ids_or_addresses() {
    let dup_id = format!(
        "{VALID}\n[cluster]\nnode_id = \"node1\"\n[[cluster.peers]]\nnode_id = \"node2\"\naddress = \"127.0.0.1:9093\"\n[[cluster.peers]]\nnode_id = \"node2\"\naddress = \"127.0.0.1:9094\""
    );
    let err_id = Config::parse(&dup_id).unwrap_err().to_string();
    assert!(err_id.contains("duplicate peer node_id"), "{err_id}");

    let dup_addr = format!(
        "{VALID}\n[cluster]\nnode_id = \"node1\"\n[[cluster.peers]]\nnode_id = \"node2\"\naddress = \"127.0.0.1:9093\"\n[[cluster.peers]]\nnode_id = \"node3\"\naddress = \"127.0.0.1:9093\""
    );
    let err_addr = Config::parse(&dup_addr).unwrap_err().to_string();
    assert!(err_addr.contains("duplicate peer address"), "{err_addr}");
}

#[test]
fn rejects_empty_peer_entries_in_env_var() {
    // Doubled commas (empty entries) must be rejected, not silently skipped.
    let err =
        bearust::config::ClusterPeer::parse_peers("node2=127.0.0.1:9000,,node3=127.0.0.1:9001")
            .unwrap_err()
            .to_string();
    assert!(err.contains("empty peer entry"), "{err}");

    // Trailing comma is also an empty entry.
    let err2 = bearust::config::ClusterPeer::parse_peers("node2=127.0.0.1:9000,")
        .unwrap_err()
        .to_string();
    assert!(err2.contains("empty peer entry"), "{err2}");
}

#[test]
fn rejects_peer_list_exceeding_64_peers() {
    // Build TOML with 65 [[cluster.peers]] entries.
    let mut toml = format!("{VALID}\n[cluster]\nnode_id = \"node1\"\n");
    for i in 2..=66 {
        toml.push_str(&format!(
            "[[cluster.peers]]\nnode_id = \"node{i}\"\naddress = \"127.0.0.{}.{}:{}\"\n",
            (i / 256) + 1,
            i % 256,
            9000 + i
        ));
    }
    let err = Config::parse(&toml).unwrap_err().to_string();
    assert!(
        err.contains("peer count exceeds maximum"),
        "expected peer count error, got: {err}"
    );
}
