use bearust::observability::{classify_error, validated_request_id};
use pingora_core::{Error, ErrorSource, ErrorType};

#[test]
fn request_ids_are_safe_or_generated() {
    assert_eq!(validated_request_id(Some(b"req-123:_")), "req-123:_");
    assert_ne!(validated_request_id(Some(b"super secret")), "super secret");
    assert_ne!(validated_request_id(Some(&[b'x'; 129])), "x".repeat(129));
}

#[test]
fn errors_use_stable_categories_without_body_content() {
    let error = Error::explain(ErrorType::ConnectError, "super-secret-body");
    assert_eq!(classify_error(&error), "connect");
    assert!(!classify_error(&error).contains("super-secret-body"));
}

#[test]
fn timeout_variants_are_classified_without_context_matching() {
    for kind in [
        ErrorType::ConnectTimedout,
        ErrorType::TLSHandshakeTimedout,
        ErrorType::ReadTimedout,
        ErrorType::WriteTimedout,
    ] {
        let error = Error::create(kind, ErrorSource::Upstream, None, None);
        assert_eq!(classify_error(&error), "timeout");
    }
}

#[test]
fn source_classifies_client_and_upstream_errors() {
    let client = Error::create(
        ErrorType::InvalidHTTPHeader,
        ErrorSource::Downstream,
        None,
        None,
    );
    assert_eq!(classify_error(&client), "client");

    let upstream = Error::create(ErrorType::ReadError, ErrorSource::Upstream, None, None);
    assert_eq!(classify_error(&upstream), "upstream");

    let internal = Error::create(ErrorType::InternalError, ErrorSource::Internal, None, None);
    assert_eq!(classify_error(&internal), "internal");
}

#[test]
fn no_healthy_upstream_status_is_explicit_category() {
    let error = Error::create(
        ErrorType::HTTPStatus(503),
        ErrorSource::Internal,
        Some("secret context".into()),
        None,
    );
    assert_eq!(classify_error(&error), "no_healthy_upstream");
}
