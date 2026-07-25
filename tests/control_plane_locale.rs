use bearust::control_plane::locale::validate_locale;

#[test]
fn locale_allowlist_accepts_supported_values_and_rejects_invalid_values() {
    for value in ["en", "id", "ja"] {
        assert!(validate_locale(value).is_ok(), "{value} should be accepted");
    }

    for value in ["fr", "", &"x".repeat(256)] {
        assert!(
            validate_locale(value).is_err(),
            "{value:?} should be rejected"
        );
    }
}
