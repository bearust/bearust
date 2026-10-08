# Phase 7B: Deterministic Bot Protection Design

## Goal

Add bounded, deterministic bot protection to Bearust without external network
calls in the proxy request path. Monitor-only remains the default, while admins
can select challenge or block behavior.

## Scope

Phase 7B includes:

- a bounded request fingerprint derived from non-sensitive request attributes;
- deterministic bot-risk signals and a conservative score threshold;
- monitor, challenge, and block policy modes;
- a stateless, HMAC-signed challenge token with expiry and replay-safe nonce;
- admin configuration for policy and trusted-crawler rules (runtime bypass deferred pending signed ingress metadata);
- redacted audit and realtime telemetry;
- proxy, control-plane, and unit/integration regression tests.

The following are out of scope: third-party CAPTCHA providers, DNS lookups or
reverse lookups in the request path, machine learning, distributed counters,
adaptive rate-limit tuning, browser fingerprinting scripts, and retaining raw
IP addresses, User-Agent values, cookies, bodies, or credentials in telemetry.

## Architecture

`BotSnapshot` is immutable and is published through the same atomic store/reload
pattern used by the WAF. It contains the policy mode, bounded score threshold,
challenge TTL, signing-key reference, and normalized trusted-crawler rules.
The default mode is `monitor` and the default policy never blocks solely because
the bot evaluator cannot safely normalize an input.

The proxy constructs a bounded `BotInspectionContext` from the request method,
path, selected headers, and the configured trusted proxy address. A fingerprint
is generated from canonicalized values and represented internally as a keyed
hash; only a short redacted prefix may cross audit/realtime boundaries. No body,
authorization value, cookie, or raw address is persisted.

The evaluator emits stable signals such as missing/automated User-Agent,
inconsistent fetch headers, malformed protocol combinations, and repeated
challenge failures. Each signal has a bounded weight, category, and source
label. The final score and action are deterministic for a snapshot and request.

Trusted-crawler rules are explicit administrator configuration containing a
normalized hostname pattern and User-Agent pattern. They are stored and exposed
through the admin API/UI, but do not bypass bot scoring in Phase 7B. Runtime
bypass is deferred until a cryptographically signed ingress marker is available;
unsigned Host, User-Agent, and client headers are never trusted.
Every mutation is authorized through the existing RBAC policy and produces a
redacted audit record plus `bot.changed` realtime invalidation.

## Challenge protocol

In `challenge` mode, a suspicious request receives a non-cacheable challenge
response containing a short-lived nonce and bounded proof-of-work parameters.
The client submits the nonce and solution to the challenge endpoint. The server
verifies the signed challenge context, expiry, difficulty, and one-time nonce
use, then issues an HMAC-signed HttpOnly cookie/token containing only the
fingerprint hash prefix, issue time, expiry, and token version. Invalid,
expired, replayed, or tampered tokens fail closed with a fresh challenge and do
not reveal signing material.

The challenge verifier has strict size and work limits. It must not perform
blocking I/O or unbounded allocation. Signing keys are loaded from the existing
secret/configuration mechanism and are never returned through the API.

## Request flow

1. The proxy obtains the current immutable bot snapshot.
2. It builds the bounded inspection context and computes the fingerprint.
3. The bot evaluator returns score, signals, and a redacted action.
4. Existing WAF evaluation runs; an explicit WAF block remains dominant.
5. Monitor forwards and emits telemetry; challenge returns the challenge
   response unless a valid token is present; block returns `403`.
6. Successful challenge verification issues the signed token and emits only a
   redacted success event.

## API and configuration

Admin endpoints expose the current bot policy and CRUD for trusted-crawler
rules. Requests validate mode, threshold, TTL, patterns, and maximum list
sizes before atomically publishing a new snapshot. TOML import/export follows
the existing WAF conventions and remains backward compatible when the bot
section is absent.

## Error handling and security

Malformed or oversized inputs are treated as non-matching bounded signals, not
as proxy errors. Challenge failures use a generic response and bounded audit
category. Fingerprint hashing uses a server-held key to prevent correlation
across installations; telemetry is redacted before persistence and realtime
publication. Monitor mode is the safe default for upgrades and fresh installs.

## Testing and success criteria

Tests cover deterministic fingerprinting, canonicalization and input limits,
score/action precedence, trusted-crawler matching, challenge issuance and
verification, expiry/tamper/replay rejection, all policy modes, RBAC and audit
redaction, immutable reload behavior, and proxy regressions. Phase 7B is
complete when scoped tests, all-target tests, Clippy, and relevant formatting
checks pass, and the PRD documents the delivered and deferred capabilities.
