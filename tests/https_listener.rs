//! End-to-end check of the NPM-style listener pair: plain HTTP on `bind`
//! with automatic redirects, and HTTPS on `https_bind` with per-host SNI
//! certificates loaded from the control-plane database.
#![cfg(unix)]

use bearust::control_plane::{models::ProxyHost, repository};
use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::{extension::SubjectAlternativeName, X509NameBuilder, X509},
};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use tempfile::tempdir;

fn certificate(root: &Path, hostname: &str) -> (PathBuf, PathBuf, Vec<u8>) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", hostname).unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns(hostname)
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(san).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = builder.build();
    let cert_path = root.join(format!("{hostname}.crt"));
    let key_path = root.join(format!("{hostname}.key"));
    fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();
    fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    (cert_path, key_path, cert.to_der().unwrap())
}

fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn http_get(addr: SocketAddr, host: &str, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

/// Returns the served leaf certificate (DER) and the HTTP response.
fn https_get(addr: SocketAddr, sni: &str) -> Option<(Vec<u8>, String)> {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut tls = connector.connect(sni, stream).ok()?;
    let peer = tls.ssl().peer_certificate()?.to_der().ok()?;
    write!(
        tls,
        "GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    let _ = tls.read_to_string(&mut response);
    Some((peer, response))
}

#[test]
fn http_redirects_and_https_serves_per_host_certificates() {
    let dir = tempdir().unwrap();
    let (cert_path, key_path, secure_der) = certificate(dir.path(), "secure.test");

    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let upstream_thread = thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            match upstream.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let mut request = [0u8; 2048];
                    let _ = stream.read(&mut request);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nupstream",
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let database = dir.path().join("bearust.sqlite");
    let database_url = format!("sqlite://{}?mode=rwc", database.display());
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let db = repository::connect(&database_url).await.unwrap();
        repository::migrate(&db).await.unwrap();
        let certificate_id = repository::insert_certificate(
            &db,
            "secure",
            "custom",
            r#"["secure.test"]"#,
            "",
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        )
        .await
        .unwrap();
        for (name, tls_mode, certificate_id) in [
            ("secure.test", "internal", Some(certificate_id)),
            ("plain.test", "disabled", None),
        ] {
            repository::insert_host(
                &db,
                &ProxyHost {
                    id: 0,
                    name: name.into(),
                    domain: name.into(),
                    upstream_host: upstream_addr.ip().to_string(),
                    upstream_port: upstream_addr.port(),
                    tls_mode: tls_mode.into(),
                    certificate_id,
                    enabled: true,
                },
            )
            .await
            .unwrap();
        }
    });

    let http_addr = free_addr();
    let https_addr = free_addr();
    let config_path = dir.path().join("bearust.toml");
    fs::write(
        &config_path,
        format!(
            r#"[server]
bind = "{http_addr}"
https_bind = "{https_addr}"
https_public_port = 443
control_bind = "127.0.0.1:0"
pid_file = "{pid}"
certificate_store = "{store}"
graceful_shutdown_seconds = 1
[health]
interval_seconds = 1
timeout_seconds = 1
healthy_threshold = 1
unhealthy_threshold = 1
[[upstream_pools]]
name = "app"
algorithm = "round_robin"
[[upstream_pools.backends]]
address = "{upstream_addr}"
health_check = "tcp"
[[routes]]
name = "toml-only"
host = "toml.test"
path_prefix = "/"
upstream_pool = "app"
"#,
            pid = dir.path().join("bearust.pid").display(),
            store = dir.path().join("certificates").display(),
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_bearust"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .env("DATABASE_URL", &database_url)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    let mut secure = None;
    for _ in 0..80 {
        if let Some(result) = https_get(https_addr, "secure.test") {
            if result.1.contains("200 OK") {
                secure = Some(result);
                break;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    let redirect = http_get(http_addr, "secure.test", "/path?q=1");
    let acme = http_get(
        http_addr,
        "secure.test",
        "/.well-known/acme-challenge/missing",
    );
    let plain = http_get(http_addr, "plain.test", "/");
    let unknown = https_get(https_addr, "unknown.test");

    let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
    let _ = child.wait();
    stop.store(true, Ordering::Relaxed);
    let _ = upstream_thread.join();

    let (peer, body) = secure.expect("HTTPS listener did not serve secure.test");
    assert_eq!(peer, secure_der, "secure.test must get its own certificate");
    assert!(body.ends_with("upstream"), "{body}");

    let redirect = redirect.expect("HTTP listener did not answer");
    assert!(redirect.starts_with("HTTP/1.1 301"), "{redirect}");
    assert!(
        redirect
            .to_ascii_lowercase()
            .contains("location: https://secure.test/path?q=1\r\n"),
        "{redirect}"
    );

    let acme = acme.expect("HTTP listener did not answer ACME path");
    assert!(
        !acme.starts_with("HTTP/1.1 301"),
        "ACME must not redirect: {acme}"
    );

    let plain = plain.expect("HTTP listener did not answer plain host");
    assert!(plain.starts_with("HTTP/1.1 200"), "{plain}");
    assert!(plain.ends_with("upstream"), "{plain}");

    let (unknown_peer, _) = unknown.expect("HTTPS listener refused unknown SNI");
    let unknown_cn = X509::from_der(&unknown_peer)
        .unwrap()
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .unwrap()
        .data()
        .to_string()
        .unwrap();
    assert_eq!(unknown_cn, "bearust-default");
}
