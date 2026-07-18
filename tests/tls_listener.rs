use bearust::{config::TlsConfig, tls};
use openssl::{
    asn1::Asn1Time, hash::MessageDigest, pkey::PKey, rsa::Rsa, x509::X509NameBuilder, x509::X509,
};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use tempfile::tempdir;

#[test]
fn generated_certificate_builds_native_tls_settings() {
    let dir = tempdir().unwrap();
    let rsa = Rsa::generate(2048).unwrap();
    let key = PKey::from_rsa(rsa).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
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
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = dir.path().join("cert.pem");
    let private = dir.path().join("key.pem");
    fs::write(&cert, builder.build().to_pem().unwrap()).unwrap();
    fs::write(&private, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let config = TlsConfig {
        cert_path: cert,
        key_path: private,
    };
    assert!(tls::settings(&config).is_ok());
}

#[cfg(unix)]
#[test]
fn spawned_tls_listener_proxies_to_local_upstream() {
    use nix::{
        sys::signal::{kill, Signal},
        unistd::Pid,
    };
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

    let dir = tempdir().unwrap();
    let (cert, private) = generated_material(dir.path());
    let (replacement_cert, replacement_private) =
        generated_material_with_suffix(dir.path(), "replacement");

    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let stop_upstream = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop_upstream);
    let upstream_thread = thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            match upstream.accept() {
                Ok((mut stream, _)) => {
                    let mut request = [0u8; 2048];
                    let _ = stream.read(&mut request);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello tls!",
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    drop(proxy);
    let pid_path = dir.path().join("bearust.pid");
    let config_path = dir.path().join("bearust.toml");
    fs::write(
        &config_path,
        format!(
            r#"[server]
bind = "{proxy_addr}"
pid_file = "{}"
graceful_shutdown_seconds = 1
[server.tls]
cert_path = "{}"
key_path = "{}"
[health]
interval_seconds = 1
timeout_seconds = 1
healthy_threshold = 1
unhealthy_threshold = 1
[[upstream_pools]]
name = "api"
algorithm = "round_robin"
[[upstream_pools.backends]]
address = "{upstream_addr}"
health_check = "tcp"
health_path = ""
[[routes]]
name = "api"
host = "localhost"
path_prefix = "/"
upstream_pool = "api"
"#,
            pid_path.display(),
            cert.display(),
            private.display()
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_bearust"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let connector = {
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        builder.build()
    };
    let mut response = None;
    for _ in 0..40 {
        if let Ok(stream) = TcpStream::connect(proxy_addr) {
            if let Ok(mut tls_stream) = connector.connect("localhost", stream) {
                if tls_stream
                    .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .is_ok()
                {
                    let mut body = String::new();
                    let _ = tls_stream.read_to_string(&mut body);
                    if body.contains("200 OK") && body.ends_with("hello tls!") {
                        response = Some(body);
                        break;
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    let updated = fs::read_to_string(&config_path)
        .unwrap()
        .replace(
            cert.to_string_lossy().as_ref(),
            replacement_cert.to_string_lossy().as_ref(),
        )
        .replace(
            private.to_string_lossy().as_ref(),
            replacement_private.to_string_lossy().as_ref(),
        );
    fs::write(&config_path, updated).unwrap();
    kill(Pid::from_raw(child.id() as i32), Signal::SIGHUP).unwrap();
    let replacement_der = X509::from_pem(&fs::read(&replacement_cert).unwrap())
        .unwrap()
        .to_der()
        .unwrap();
    let mut saw_replacement = false;
    for _ in 0..50 {
        if let Ok(stream) = TcpStream::connect(proxy_addr) {
            if let Ok(tls_stream) = connector.connect("localhost", stream) {
                if let Some(peer) = tls_stream.ssl().peer_certificate() {
                    if peer.to_der().unwrap() == replacement_der {
                        saw_replacement = true;
                        break;
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
    let status = child.wait().unwrap();
    stop_upstream.store(true, Ordering::Relaxed);
    let _ = upstream_thread.join();
    assert!(status.success(), "proxy exited unsuccessfully: {status}");
    assert!(
        response.is_some(),
        "TLS proxy did not return upstream response"
    );
    assert!(
        saw_replacement,
        "TLS listener did not adopt replacement certificate"
    );
}

fn generated_material(root: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    generated_material_with_suffix(root, "initial")
}

fn generated_material_with_suffix(
    root: &std::path::Path,
    suffix: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let rsa = Rsa::generate(2048).unwrap();
    let key = PKey::from_rsa(rsa).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
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
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = root.join(format!("cert-{suffix}.pem"));
    let private = root.join(format!("key-{suffix}.pem"));
    fs::write(&cert, builder.build().to_pem().unwrap()).unwrap();
    fs::write(&private, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    (cert, private)
}
