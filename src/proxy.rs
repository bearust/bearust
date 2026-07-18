use crate::{
    balancer::BackendLease,
    observability::{append_forwarded_for, validated_request_id},
    router::ResolvedRoute,
    runtime::{RuntimeSnapshot, RuntimeStore},
};
use async_trait::async_trait;
use pingora_core::{upstreams::peer::HttpPeer, Result};
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session};
use std::{sync::Arc, time::Instant};

pub struct RequestContext {
    pub snapshot: Option<Arc<RuntimeSnapshot>>,
    pub route: Option<ResolvedRoute>,
    pub lease: Option<BackendLease>,
    pub request_id: String,
    pub start: Instant,
    pub upstream_started: bool,
}

impl Default for RequestContext {
    fn default() -> Self {
        Self { snapshot: None, route: None, lease: None, request_id: validated_request_id(None), start: Instant::now(), upstream_started: false }
    }
}

pub struct BeaRustProxy { pub runtime: Arc<RuntimeStore> }

impl BeaRustProxy { pub fn new(runtime: Arc<RuntimeStore>) -> Self { Self { runtime } } }

#[async_trait]
impl ProxyHttp for BeaRustProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX { RequestContext::default() }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let snapshot = self.runtime.load();
        let host = session.req_header().headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
        let path = session.req_header().uri.path();
        let Some((route, _)) = snapshot.route(host, path) else {
            session.respond_error(404).await?;
            return Ok(true);
        };
        ctx.request_id = validated_request_id(session.req_header().headers.get("x-request-id").map(|v| v.as_bytes()));
        ctx.route = Some(route.clone());
        ctx.snapshot = Some(snapshot);
        Ok(false)
    }

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let snapshot = ctx.snapshot.as_ref().expect("request_filter must run");
        let route = ctx.route.as_ref().expect("route must be set");
        let pool = snapshot.route(&route.host, &route.path_prefix).map(|(_, p)| p).expect("pool must exist");
        let Some(lease) = pool.select(None) else {
            session.respond_error(503).await?;
            return Ok(Box::new(HttpPeer::new(("127.0.0.1", 9), false, String::new())));
        };
        let address = lease.address();
        ctx.lease = Some(lease);
        Ok(Box::new(HttpPeer::new(address, false, String::new())))
    }

    async fn upstream_request_filter(&self, session: &mut Session, request: &mut RequestHeader, ctx: &mut Self::CTX) -> Result<()> {
        if let Some(host) = session.req_header().headers.get("host").and_then(|v| v.to_str().ok()) { let _ = request.insert_header("Host", host); }
        append_forwarded_for(request, session.client_addr().map(ToString::to_string).as_deref());
        let _ = request.insert_header("X-Request-Id", ctx.request_id.clone());
        ctx.upstream_started = true;
        Ok(())
    }

    async fn logging(&self, _session: &mut Session, _error: Option<&pingora_core::Error>, ctx: &mut Self::CTX) { ctx.lease.take(); }
}
