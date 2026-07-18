use bearust::observability::{append_forwarded_for, validated_request_id};
use pingora_http::RequestHeader;

#[test]
fn forwarding_headers_append_ip_and_request_id_is_safe() {
    let mut request = RequestHeader::build("GET", b"/", Some(2)).unwrap();
    request.insert_header("Host", "api.example.test").unwrap();
    request
        .insert_header("X-Forwarded-For", "10.0.0.1")
        .unwrap();
    append_forwarded_for(&mut request, Some("[2001:db8::1]:8080"));
    assert_eq!(request.headers.get("host").unwrap(), "api.example.test");
    assert_eq!(
        request.headers.get("x-forwarded-for").unwrap(),
        "10.0.0.1, 2001:db8::1"
    );
    assert_eq!(request.headers.get("x-forwarded-proto").unwrap(), "http");
    assert_eq!(validated_request_id(Some(b"req-1")), "req-1");
}
