use pingora_http::RequestHeader;

pub type InitError = Box<dyn std::error::Error + Send + Sync>;

pub fn init(json: bool, filter: &str) -> Result<(), InitError> {
    let filter = tracing_subscriber::EnvFilter::try_new(filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if json {
        tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_env_filter(filter)
            .try_init()
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).try_init()
    }
}

pub fn classify_error(error: &pingora_core::Error) -> &'static str {
    let kind = format!("{:?}", error.etype()).to_ascii_lowercase();
    if kind.contains("httpstatus") {
        if error
            .to_string()
            .to_ascii_lowercase()
            .contains("healthy upstream")
        {
            return "no_healthy_upstream";
        }
        return "upstream";
    }
    if kind.contains("connect") {
        return "connect";
    }
    if kind.contains("timeout") {
        return "timeout";
    }
    if kind.contains("client") {
        return "client";
    }
    if kind.contains("read") || kind.contains("write") || kind.contains("upstream") {
        return "upstream";
    }
    if kind.contains("route") {
        return "routing";
    }
    "internal"
}

pub fn validated_request_id(value: Option<&[u8]>) -> String {
    let valid = value
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .and_then(|v| std::str::from_utf8(v).ok())
        .filter(|s| {
            s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-:_.".contains(&b))
        });
    valid.map_or_else(|| uuid::Uuid::new_v4().to_string(), str::to_owned)
}

pub fn append_forwarded_for(request: &mut RequestHeader, client: Option<&str>) {
    if let Some(client) = client {
        let client = client
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| client.trim_matches(['[', ']']).to_owned());
        let value = request
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|v| format!("{v}, {client}"))
            .unwrap_or(client);
        let _ = request.insert_header("X-Forwarded-For", value);
    }
    let _ = request.insert_header("X-Forwarded-Proto", "http");
}

pub fn log_request(
    request_id: &str,
    method: &str,
    path: &str,
    route: &str,
    upstream: &str,
    status: u16,
    duration_ms: u64,
    error_category: &str,
) {
    tracing::info!(
        event = "request_complete",
        request_id,
        method,
        path,
        route,
        upstream,
        status,
        latency_ms = duration_ms,
        error_category,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_core::{Error, ErrorType};
    #[test]
    fn accepts_only_bounded_safe_request_ids() {
        assert_eq!(validated_request_id(Some(b"abc-123:_.")), "abc-123:_.");
        assert_ne!(validated_request_id(Some(b"has space")), "has space");
        assert_ne!(validated_request_id(Some(&[b'a'; 129])), "a".repeat(129));
    }

    #[test]
    fn appends_ip_without_port_and_preserves_chain() {
        let mut request = RequestHeader::build("GET", b"/", Some(2)).unwrap();
        request
            .insert_header("X-Forwarded-For", "10.0.0.1")
            .unwrap();
        append_forwarded_for(&mut request, Some("[2001:db8::1]:8443"));
        assert_eq!(
            request.headers.get("x-forwarded-for").unwrap(),
            "10.0.0.1, 2001:db8::1"
        );
        assert_eq!(request.headers.get("x-forwarded-proto").unwrap(), "http");
    }

    #[test]
    fn classifies_pingora_errors_into_stable_categories() {
        let error = Error::explain(ErrorType::ConnectError, "dial failed");
        assert_eq!(classify_error(&error), "connect");
        let error = Error::explain(ErrorType::HTTPStatus(503), "no healthy upstream");
        assert_eq!(classify_error(&error), "no_healthy_upstream");
    }
}
