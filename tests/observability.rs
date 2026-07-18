use bearust::observability::{classify_error, validated_request_id};
use pingora_core::{Error, ErrorType};

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
