use serde::{de::DeserializeOwned, Serialize};

/// Packs a guest pointer and length into the `i64` ABI result used by
/// `bearust_health_check_v2` and future data-carrying exports:
/// `(ptr as i64) << 32 | (len as i64)`, both halves zero-extended so the
/// pack/unpack round trip is exact for any `i32` bit pattern.
pub fn pack(ptr: i32, len: i32) -> i64 {
    ((ptr as u32 as i64) << 32) | (len as u32 as i64)
}

/// Unpacks an ABI result produced by [`pack`] back into `(ptr, len)`.
pub fn unpack(value: i64) -> (i32, i32) {
    let ptr = ((value >> 32) & 0xFFFF_FFFF) as u32 as i32;
    let len = (value & 0xFFFF_FFFF) as u32 as i32;
    (ptr, len)
}

/// Encodes `value` as JSON. Returns an empty buffer if serialization fails
/// (it should not for the SDK's own plain-data types); the host treats an
/// empty or malformed payload as a decode failure, never a crash.
pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

/// Decodes a JSON payload into `T`.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_round_trips_ordinary_values() {
        assert_eq!(unpack(pack(1024, 34)), (1024, 34));
        assert_eq!(unpack(pack(0, 0)), (0, 0));
    }

    #[test]
    fn pack_unpack_round_trips_max_i32_values() {
        assert_eq!(unpack(pack(i32::MAX, i32::MAX)), (i32::MAX, i32::MAX));
    }

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Sample {
        healthy: bool,
        detail: Option<String>,
    }

    #[test]
    fn encode_decode_round_trips_a_struct() {
        let value = Sample {
            healthy: true,
            detail: Some("ok".to_owned()),
        };
        let bytes = encode(&value);
        let decoded: Sample = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn decode_rejects_malformed_json() {
        let result: Result<Sample, _> = decode(b"not json");
        assert!(result.is_err());
    }

    #[test]
    fn waf_block_event_round_trips() {
        let value = WafBlockEvent {
            request_id: "req-1".into(),
            occurred_at_ms: 1_700_000_000_000,
            category: "sqli".into(),
            score: 42,
            severity: "high".into(),
            reason_ids: "sqli".into(),
        };
        let bytes = encode(&value);
        let decoded: WafBlockEvent = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn waf_detect_request_round_trips() {
        let value = WafDetectRequest {
            method: "POST".into(),
            path: "/login".into(),
            query: "next=/".into(),
            headers: vec![("host".into(), "example.com".into())],
            body: b"user=admin".to_vec(),
        };
        let bytes = encode(&value);
        let decoded: WafDetectRequest = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn waf_detect_verdict_round_trips() {
        let value = WafDetectVerdict {
            decision: WafPluginDecision::Block,
            category: "custom_detector".into(),
            score: 10,
        };
        let bytes = encode(&value);
        let decoded: WafDetectVerdict = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn transform_request_round_trips() {
        let value = TransformRequest {
            method: "GET".into(),
            path: "/api/orders".into(),
            query: "page=2".into(),
            headers: vec![("host".into(), "example.com".into())],
        };
        let bytes = encode(&value);
        let decoded: TransformRequest = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn transform_response_round_trips() {
        let value = TransformResponse {
            headers: vec![
                ("x-region".into(), "us-east-1".into()),
                ("host".into(), "internal.example.com".into()),
            ],
        };
        let bytes = encode(&value);
        let decoded: TransformResponse = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn transform_response_request_round_trips() {
        let value = TransformResponseRequest {
            status: 200,
            body: "aGVsbG8=".into(),
        };
        let bytes = encode(&value);
        let decoded: TransformResponseRequest = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn transform_response_result_round_trips() {
        let value = TransformResponseResult {
            body: "d29ybGQ=".into(),
        };
        let bytes = encode(&value);
        let decoded: TransformResponseResult = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn waf_plugin_decision_serializes_as_lowercase() {
        assert_eq!(
            serde_json::to_string(&WafPluginDecision::Allow).unwrap(),
            "\"allow\""
        );
        assert_eq!(
            serde_json::to_string(&WafPluginDecision::Log).unwrap(),
            "\"log\""
        );
        assert_eq!(
            serde_json::to_string(&WafPluginDecision::Block).unwrap(),
            "\"block\""
        );
    }

    #[test]
    fn load_balance_request_round_trips() {
        let value = LoadBalanceRequest {
            pool: "api".into(),
            method: "GET".into(),
            path: "/orders".into(),
            query: String::new(),
            headers: vec![("host".into(), "example.com".into())],
            backends: vec![
                BackendCandidate {
                    id: 0,
                    address: "127.0.0.1:19001".into(),
                    healthy: true,
                    inflight: 2,
                },
                BackendCandidate {
                    id: 1,
                    address: "127.0.0.1:19002".into(),
                    healthy: false,
                    inflight: 0,
                },
            ],
            excluded_backend_id: Some(1),
        };
        let bytes = encode(&value);
        let decoded: LoadBalanceRequest = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn load_balance_result_round_trips() {
        let value = LoadBalanceResult { backend_id: 0 };
        let bytes = encode(&value);
        let decoded: LoadBalanceResult = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }
}

/// Guest-exported allocator entry point: reserves `len` bytes of this
/// module's own linear memory and returns a pointer the host can write
/// into before calling a plugin function that takes `(ptr, len)`.
///
/// Guest-only: compiled solely for `wasm32` targets, where pointers really
/// are 32-bit so the `i32` return is exact. Not exercised by this
/// repository's test suite (see Task 4's hand-written WAT fixture for the
/// host-side contract this implements).
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn bearust_alloc(len: i32) -> i32 {
    let len = len.max(0) as usize;
    let buf = vec![0u8; len].into_boxed_slice();
    Box::into_raw(buf) as *mut u8 as i32
}

/// Guest-exported deallocator: releases a buffer previously returned by
/// [`bearust_alloc`] or by a [`write_output`] result, once the host has
/// finished reading it.
///
/// # Safety (informal — this is an `extern "C"` ABI boundary, not `unsafe fn`)
/// `ptr`/`len` must be a pair previously returned by `bearust_alloc` (or by
/// `write_output`, whose buffer has the same provenance) and not already
/// deallocated. The host is the only caller and always passes back exactly
/// the pair it received.
///
/// Guest-only: compiled solely for `wasm32` targets.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn bearust_dealloc(ptr: i32, len: i32) {
    if ptr == 0 {
        return;
    }
    let len = len.max(0) as usize;
    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            ptr as *mut u8,
            len,
        )));
    }
}

/// Decodes a JSON payload the host wrote into this guest's own memory at
/// `ptr` with length `len`. Guest-only: compiled solely for `wasm32` targets.
///
/// # Safety
/// `ptr` and `len` must together describe a live, valid, initialised region
/// of *this guest module's own* linear memory — in practice, exactly the
/// `(ptr, len)` pair the host passed to the plugin export after allocating
/// via [`bearust_alloc`] and writing the input JSON there. The region must
/// remain allocated and not be mutated for the duration of the call, and
/// `len` must be non-negative. Passing arbitrary integers is undefined
/// behaviour: this function performs no validation beyond clamping a
/// negative `len` to zero.
#[cfg(target_arch = "wasm32")]
pub unsafe fn read_input<T: DeserializeOwned>(ptr: i32, len: i32) -> T {
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len.max(0) as usize) };
    decode(bytes).expect("bearust-plugin-sdk: host sent malformed input")
}

/// Encodes `value` as JSON into a freshly allocated guest buffer and
/// returns the packed `(ptr, len)` result the host expects. Guest-only:
/// compiled solely for `wasm32` targets, where the `i32` pointer cast is
/// exact.
#[cfg(target_arch = "wasm32")]
pub fn write_output<T: Serialize>(value: &T) -> i64 {
    let bytes = encode(value);
    let len = bytes.len() as i32;
    let boxed = bytes.into_boxed_slice();
    let ptr = Box::into_raw(boxed) as *mut u8 as i32;
    pack(ptr, len)
}

/// Expands to the `bearust_abi_version() -> i32` export every plugin must
/// have. Call once at crate root: `bearust_plugin_sdk::abi_version!(2);`.
#[macro_export]
macro_rules! abi_version {
    ($version:expr) => {
        #[no_mangle]
        pub extern "C" fn bearust_abi_version() -> i32 {
            $version
        }
    };
}

/// Input to `bearust_health_check_v2`, shared between host and guest so
/// both sides always agree on the wire shape.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct HealthCheckInput {
    pub requested_at_ms: u64,
}

/// Output of `bearust_health_check_v2`. `detail` is free-form and bounded
/// by the plugin's configured `max_output_bytes` on the host side.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct HealthCheckOutput {
    pub healthy: bool,
    pub detail: Option<String>,
}

/// Event delivered to a `notify.waf_block` capability plugin when the WAF
/// blocks a request. Mirrors `src/waf.rs::RedactedTelemetry` on the host
/// side, plus a request identifier and timestamp. Never carries raw
/// headers, body, query string, or client IP — only what
/// `redacted_telemetry` already produces for tracing/audit today.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct WafBlockEvent {
    pub request_id: String,
    pub occurred_at_ms: u64,
    pub category: String,
    pub score: u16,
    pub severity: String,
    pub reason_ids: String,
}

/// A plugin's decision on `waf.detect`, mirroring `src/waf.rs::WafDecision`
/// on the host side. Serialized in `snake_case` (`"allow" | "log" |
/// "block"`).
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WafPluginDecision {
    Allow,
    Log,
    Block,
}

/// Input to `bearust_waf_detect`. The host (`src/proxy.rs::waf_detect_request`)
/// bounds `method`/`path`/`query`/`headers` to the same
/// `MAX_NORMALIZED_METADATA_BYTES`/`MAX_NORMALIZED_HEADERS`/
/// `MAX_NORMALIZED_FIELD_BYTES` budgets the built-in rule engine enforces on
/// the same raw fields, and separately caps `body` smaller than the rule
/// engine's own body limit to keep worst-case JSON size well under a
/// plugin's declared `max_output_bytes`.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct WafDetectRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Output of `bearust_waf_detect`. Merged into the host's `Evaluation` via
/// an escalate-only rule: `decision` can raise severity but never lower a
/// decision the rule engine already reached.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct WafDetectVerdict {
    pub decision: WafPluginDecision,
    pub category: String,
    pub score: u16,
}

/// Input to `bearust_transform_request`. The host
/// (`src/proxy.rs::transform_request`) bounds `method`/`path`/`query`/
/// `headers` to the same combined `MAX_NORMALIZED_METADATA_BYTES` /
/// `MAX_NORMALIZED_HEADERS` / `MAX_NORMALIZED_FIELD_BYTES` budgets
/// `waf_detect_request` uses for the same raw fields. There is no `body`
/// field: this hook only ever sees and returns headers.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransformRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
}

/// Output of `bearust_transform_request`. The host wholesale-replaces the
/// outbound request's header list with `headers` (subject to the same
/// bounds checked on the input side), then unconditionally reasserts
/// `Host`, `X-Forwarded-For`, and `X-Request-Id` afterward — this hook can
/// never remove, blank, or spoof those three.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransformResponse {
    pub headers: Vec<(String, String)>,
}

/// Input to `bearust_transform_response`. `status` is context only (not
/// mutable). `body` is the full response body the host buffered, base64
/// encoded to avoid the ~4x JSON-array expansion `WafDetectRequest::body`
/// (a `Vec<u8>`) incurs -- matching the ~4/3 base64 overhead
/// `MIN_TRANSFORM_RESPONSE_INPUT_BYTES` is sized around. There is no
/// `headers` field: unlike `TransformRequest`, this hook cannot mutate
/// headers -- pingora already sends response headers to the downstream
/// client by the time this hook's body decision is known (see
/// `docs/superpowers/specs/2026-08-09-phase-13f-response-transform-design.md`).
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransformResponseRequest {
    pub status: u16,
    pub body: String,
}

/// Output of `bearust_transform_response`. The host replaces the buffered
/// response body wholesale with the base64-decoded `body` on success.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransformResponseResult {
    pub body: String,
}

/// One upstream backend as a `balance.select` plugin sees it: a live
/// snapshot from the host, never plugin-supplied. `id` is the backend's
/// stable index within its pool (`balancer::BackendId`, widened to `u64`
/// for the wire format); `address` is `host:port`; `healthy` mirrors the
/// host's current live health-check state; `inflight` is the backend's
/// current in-flight request count (as `LeastConnections` already uses
/// internally).
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BackendCandidate {
    pub id: u64,
    pub address: String,
    pub healthy: bool,
    pub inflight: u32,
}

/// Input to `bearust_balance_select`. `pool` names the upstream pool this
/// selection is for (a single active plugin may serve several
/// `algorithm: plugin` pools; this field lets it branch per pool).
/// `method`/`path`/`query`/`headers` share the same
/// `MAX_NORMALIZED_METADATA_BYTES`/`MAX_NORMALIZED_HEADERS`/
/// `MAX_NORMALIZED_FIELD_BYTES` budget `waf_detect_request` and
/// `transform_request` already use. `backends` is capped at
/// `MAX_BALANCE_CANDIDATES` (128) entries by the host before this struct
/// is built. `excluded_backend_id` is set when this call is a failover
/// retry -- the backend that just failed on this same request. The host
/// enforces this exclusion itself (`PoolState::select_specific`) rather
/// than trusting the plugin to honor it.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct LoadBalanceRequest {
    pub pool: String,
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub backends: Vec<BackendCandidate>,
    pub excluded_backend_id: Option<u64>,
}

/// Output of `bearust_balance_select`. The host leases `backend_id`
/// directly if it names a backend that is currently healthy and isn't
/// `excluded_backend_id` -- otherwise the whole call is treated as a
/// failure and the host falls back to its own deterministic selection.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct LoadBalanceResult {
    pub backend_id: u64,
}
