#![allow(dead_code)]

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::any, Router};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
};
use tokio::{net::TcpListener, sync::oneshot};

/// Return the opt-in external database URL used by integration tests.
///
/// Keeping this lookup in the shared test support module makes the opt-in
/// contract consistent across external-backend tests and avoids accidentally
/// providing a default that could mutate a developer's database.
pub fn external_database_url() -> Option<String> {
    std::env::var("DATABASE_URL_EXTERNAL")
        .ok()
        .filter(|url| !url.trim().is_empty())
}

/// Render a database URL without credentials or path/query components.
/// This is suitable for diagnostics when an external test cannot connect.
pub fn redacted_database_target(url: &str) -> String {
    let (scheme, remainder) = url
        .split_once("://")
        .map_or(("unknown", url), |parts| parts);
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let host = if host.starts_with('[') {
        host.find(']').map_or(host, |end| &host[..=end])
    } else {
        host.split(':').next().unwrap_or(host)
    };
    format!("{scheme}://{host}")
}

pub struct TestServer {
    pub address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
}
impl TestServer {
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

pub async fn spawn_http_backend(status: Arc<AtomicU16>, body: &'static str) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/health", any(health_handler))
        .fallback(any(body_handler))
        .with_state((status, body));
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    TestServer {
        address,
        shutdown: Some(tx),
    }
}

async fn health_handler(
    State((status, _)): State<(Arc<AtomicU16>, &'static str)>,
) -> impl IntoResponse {
    StatusCode::from_u16(status.load(Ordering::Relaxed))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

async fn body_handler(
    State((status, body)): State<(Arc<AtomicU16>, &'static str)>,
) -> impl IntoResponse {
    let _ = status;
    (StatusCode::OK, body)
}
