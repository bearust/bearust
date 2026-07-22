# Task 4 report: signed bot challenges

Commit: `845673c feat: add signed bot challenges`

Implemented bounded HMAC-SHA256 challenge tokens (version, nonce, fingerprint prefix, issue/expiry), one-time nonce replay protection, expiry/tamper/fingerprint checks, five-attempt cap, bounded proof-of-work, persistent signing secret via `SecretStore::get_or_create`, and challenge/verify endpoints with `Secure; HttpOnly; SameSite=Strict; Path=/` cookie attributes and `Cache-Control: no-store`.

Verification:

- `cargo +stable test --test bot_challenge -q` — 3 passed, 0 failed.
- `cargo +stable clippy --test bot_challenge --lib -- -D warnings` — passed.
- `git diff --check` — passed.

Concerns/deferred integration: proxy enforcement and clearance-cookie consumption are Task 5 scope. The challenge endpoint intentionally returns only bounded token metadata and generic verification errors; signing material and raw request fields are not exposed.
