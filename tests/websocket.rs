//! Pingora's normal HTTP streaming path preserves upgrade frames; this smoke test
//! locks the header semantics used by WebSocket handshakes.
use bearust::observability::append_forwarded_for;
use pingora_http::RequestHeader;

#[test]
fn websocket_upgrade_headers_are_forwardable() {
    let mut request = RequestHeader::build("GET", b"/socket", Some(4)).unwrap();
    request.insert_header("Host", "ws.example.test").unwrap();
    request.insert_header("Connection", "Upgrade").unwrap();
    request.insert_header("Upgrade", "websocket").unwrap();
    append_forwarded_for(&mut request, Some("192.0.2.10:443"));
    assert_eq!(request.headers.get("upgrade").unwrap(), "websocket");
    assert_eq!(request.headers.get("connection").unwrap(), "Upgrade");
    assert_eq!(
        request.headers.get("x-forwarded-for").unwrap(),
        "192.0.2.10"
    );
}
