//! Layer-4 TCP and UDP proxying for non-HTTP protocols (databases, game
//! servers, DNS, MQTT, ...).
//!
//! Backends are tried round-robin; a TCP backend that refuses or times out
//! is skipped for that connection. UDP keeps one upstream socket per client
//! address (a "session") so replies route back to the right client, and
//! drops sessions idle past `idle_timeout_seconds`. The IP security policy
//! used by the HTTP proxy also applies here. Connection and session counts
//! are capped per listener; excess TCP connections are closed and excess
//! UDP datagrams from new clients are dropped.

use crate::config::{StreamConfig, StreamProtocol};
use crate::security_policy::IpSecurityStore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex, Semaphore};

const UDP_DATAGRAM_BYTES: usize = 65_535;

struct Shared {
    config: StreamConfig,
    next: AtomicUsize,
    ip_security: Option<Arc<IpSecurityStore>>,
}

impl Shared {
    /// Backends starting from the next round-robin position.
    fn rotation(&self) -> Vec<SocketAddr> {
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let backends = &self.config.backends;
        (0..backends.len())
            .map(|offset| backends[(start + offset) % backends.len()])
            .collect()
    }

    fn blocked(&self, client: SocketAddr) -> bool {
        self.ip_security
            .as_ref()
            .is_some_and(|policy| policy.evaluate(client.ip()).blocked)
    }
}

/// Run one stream listener until `shutdown` flips to true.
pub async fn serve(
    config: StreamConfig,
    ip_security: Option<Arc<IpSecurityStore>>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let shared = Arc::new(Shared {
        config,
        next: AtomicUsize::new(0),
        ip_security,
    });
    match shared.config.protocol {
        StreamProtocol::Tcp => {
            let listener = TcpListener::bind(shared.config.listen).await?;
            serve_tcp(listener, shared, shutdown).await
        }
        StreamProtocol::Udp => {
            let socket = UdpSocket::bind(shared.config.listen).await?;
            serve_udp(Arc::new(socket), shared, shutdown).await
        }
    }
}

/// Bind and run a TCP listener on an already bound socket (tests use this
/// to learn the port first).
pub async fn serve_tcp_listener(
    listener: TcpListener,
    config: StreamConfig,
    ip_security: Option<Arc<IpSecurityStore>>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let shared = Arc::new(Shared {
        config,
        next: AtomicUsize::new(0),
        ip_security,
    });
    serve_tcp(listener, shared, shutdown).await
}

pub async fn serve_udp_socket(
    socket: UdpSocket,
    config: StreamConfig,
    ip_security: Option<Arc<IpSecurityStore>>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let shared = Arc::new(Shared {
        config,
        next: AtomicUsize::new(0),
        ip_security,
    });
    serve_udp(Arc::new(socket), shared, shutdown).await
}

async fn serve_tcp(
    listener: TcpListener,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let slots = Arc::new(Semaphore::new(shared.config.max_connections));
    tracing::info!(event = "stream_listener_start", name = %shared.config.name, protocol = "tcp", listen = %shared.config.listen);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (client, peer) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::warn!(event = "stream_accept_failed", error = %error);
                        continue;
                    }
                };
                if shared.blocked(peer) {
                    tracing::info!(event = "stream_ip_blocked", name = %shared.config.name, client_ip = %peer.ip());
                    continue;
                }
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    tracing::warn!(event = "stream_connection_limit", name = %shared.config.name);
                    continue;
                };
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    let _permit = permit;
                    proxy_tcp(client, &shared).await;
                });
            }
        }
    }
}

async fn proxy_tcp(mut client: TcpStream, shared: &Shared) {
    let connect_timeout = Duration::from_millis(shared.config.connect_timeout_ms);
    let mut upstream = None;
    for backend in shared.rotation() {
        match tokio::time::timeout(connect_timeout, TcpStream::connect(backend)).await {
            Ok(Ok(stream)) => {
                upstream = Some(stream);
                break;
            }
            _ => {
                tracing::warn!(event = "stream_backend_unavailable", name = %shared.config.name, backend = %backend)
            }
        }
    }
    let Some(mut upstream) = upstream else {
        return;
    };
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);
    let idle = Duration::from_secs(shared.config.idle_timeout_seconds);
    // Bounded overall by the idle timeout per direction of activity: the
    // copy restarts its timer on every successful transfer.
    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let up = copy_with_idle(&mut client_read, &mut upstream_write, idle);
    let down = copy_with_idle(&mut upstream_read, &mut client_write, idle);
    let _ = tokio::join!(up, down);
}

/// Copy until EOF, error, or `idle` without data; then shut the writer down.
async fn copy_with_idle<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle: Duration,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buffer = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let read = match tokio::time::timeout(idle, reader.read(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(read)) => read,
            Ok(Err(error)) => {
                let _ = writer.shutdown().await;
                return Err(error);
            }
        };
        writer.write_all(&buffer[..read]).await?;
        total += read as u64;
    }
    let _ = writer.shutdown().await;
    Ok(total)
}

struct UdpSession {
    upstream: Arc<UdpSocket>,
    last_seen: Arc<std::sync::Mutex<Instant>>,
}

async fn serve_udp(
    socket: Arc<UdpSocket>,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    tracing::info!(event = "stream_listener_start", name = %shared.config.name, protocol = "udp", listen = %shared.config.listen);
    let sessions: Arc<Mutex<HashMap<SocketAddr, UdpSession>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let idle = Duration::from_secs(shared.config.idle_timeout_seconds);
    let mut buffer = vec![0u8; UDP_DATAGRAM_BYTES];
    let mut sweep = tokio::time::interval(idle.min(Duration::from_secs(30)));
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            _ = sweep.tick() => {
                let mut sessions = sessions.lock().await;
                sessions.retain(|_, session| {
                    session.last_seen.lock().map(|at| at.elapsed() < idle).unwrap_or(false)
                });
            }
            received = socket.recv_from(&mut buffer) => {
                let (len, client) = match received {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                if shared.blocked(client) {
                    continue;
                }
                let datagram = buffer[..len].to_vec();
                let mut table = sessions.lock().await;
                if let Some(session) = table.get(&client) {
                    if let Ok(mut at) = session.last_seen.lock() {
                        *at = Instant::now();
                    }
                    let _ = session.upstream.send(&datagram).await;
                    continue;
                }
                if table.len() >= shared.config.max_connections {
                    tracing::warn!(event = "stream_session_limit", name = %shared.config.name);
                    continue;
                }
                let Some(upstream) = connect_udp(&shared).await else {
                    continue;
                };
                let upstream = Arc::new(upstream);
                let last_seen = Arc::new(std::sync::Mutex::new(Instant::now()));
                let _ = upstream.send(&datagram).await;
                // Relay replies from this session's upstream back to the client.
                let relay_socket = Arc::clone(&socket);
                let relay_upstream = Arc::clone(&upstream);
                let relay_seen = Arc::clone(&last_seen);
                let relay_sessions = Arc::clone(&sessions);
                tokio::spawn(async move {
                    let mut reply = vec![0u8; UDP_DATAGRAM_BYTES];
                    loop {
                        match tokio::time::timeout(idle, relay_upstream.recv(&mut reply)).await {
                            Ok(Ok(len)) => {
                                if let Ok(mut at) = relay_seen.lock() {
                                    *at = Instant::now();
                                }
                                let _ = relay_socket.send_to(&reply[..len], client).await;
                            }
                            Ok(Err(_)) => break,
                            Err(_) => {
                                let idle_for = relay_seen.lock().map(|at| at.elapsed()).unwrap_or(idle);
                                if idle_for >= idle {
                                    break;
                                }
                            }
                        }
                    }
                    relay_sessions.lock().await.remove(&client);
                });
                table.insert(client, UdpSession { upstream, last_seen });
            }
        }
    }
}

/// A connected UDP socket to the first backend that accepts a connect.
async fn connect_udp(shared: &Shared) -> Option<UdpSocket> {
    for backend in shared.rotation() {
        let bind: SocketAddr = if backend.is_ipv4() {
            "0.0.0.0:0".parse().ok()?
        } else {
            "[::]:0".parse().ok()?
        };
        if let Ok(socket) = UdpSocket::bind(bind).await {
            if socket.connect(backend).await.is_ok() {
                return Some(socket);
            }
        }
    }
    None
}
