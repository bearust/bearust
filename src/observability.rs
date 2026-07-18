use pingora_http::RequestHeader;

pub fn validated_request_id(value: Option<&[u8]>) -> String {
    let valid = value
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .and_then(|v| std::str::from_utf8(v).ok())
        .filter(|s| s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-:_.".contains(&b)));
    valid.map_or_else(|| uuid::Uuid::new_v4().to_string(), str::to_owned)
}

pub fn append_forwarded_for(request: &mut RequestHeader, client: Option<&str>) {
    if let Some(client) = client {
        let value = request
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|v| format!("{v}, {client}"))
            .unwrap_or_else(|| client.to_owned());
        let _ = request.insert_header("X-Forwarded-For", value);
    }
    let _ = request.insert_header("X-Forwarded-Proto", "http");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_bounded_safe_request_ids() {
        assert_eq!(validated_request_id(Some(b"abc-123:_.")), "abc-123:_.");
        assert_ne!(validated_request_id(Some(b"has space")), "has space");
        assert_ne!(validated_request_id(Some(&vec![b'a'; 129])), "a".repeat(129));
    }
}
