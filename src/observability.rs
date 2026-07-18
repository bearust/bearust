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
    use pingora_core::{ErrorSource, ErrorType};

    // Preserve the explicit routing failure emitted when a pool has no
    // eligible backends.  This is more actionable than a generic upstream
    // category and must not depend on the error context string.
    if matches!(error.etype(), ErrorType::HTTPStatus(503)) {
        return "no_healthy_upstream";
    }

    // Pingora has distinct timeout variants for each phase.  Treat all of
    // them uniformly, regardless of the source attached by the callback.
    if matches!(
        error.etype(),
        ErrorType::ConnectTimedout
            | ErrorType::TLSHandshakeTimedout
            | ErrorType::ReadTimedout
            | ErrorType::WriteTimedout
    ) {
        return "timeout";
    }

    // ErrorSource is the authoritative attribution for errors created by
    // Pingora's proxy pipeline.  It avoids leaking or parsing free-form
    // error context and keeps the log contract stable across releases.
    match &error.esource {
        ErrorSource::Downstream => return "client",
        ErrorSource::Upstream => return "upstream",
        ErrorSource::Internal => return "internal",
        ErrorSource::Unset => {}
    }

    // For errors without an explicit source, use only the typed variant as a
    // conservative fallback.  Connection failures retain their dedicated
    // category; HTTP/read/write failures are upstream-facing; everything
    // else is internal.
    match error.etype() {
        ErrorType::ConnectRefused
        | ErrorType::ConnectNoRoute
        | ErrorType::ConnectError
        | ErrorType::ConnectProxyFailure => "connect",
        ErrorType::HTTPStatus(_)
        | ErrorType::ReadError
        | ErrorType::WriteError
        | ErrorType::ConnectionClosed => "upstream",
        _ => "internal",
    }
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

#[allow(clippy::too_many_arguments)]
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
