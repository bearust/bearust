use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::any, Router};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
};
use tokio::{net::TcpListener, sync::oneshot};

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
        .fallback(any(handler))
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

async fn handler(
    State((status, body)): State<(Arc<AtomicU16>, &'static str)>,
) -> impl IntoResponse {
    let code = StatusCode::from_u16(status.load(Ordering::Relaxed))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (code, body)
}
