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
}

/// Guest-exported allocator entry point: reserves `len` bytes of this
/// module's own linear memory and returns a pointer the host can write
/// into before calling a plugin function that takes `(ptr, len)`.
///
/// Only meaningful when compiled for `wasm32-wasip1`; not exercised by this
/// repository's test suite (see Task 4's hand-written WAT fixture for the
/// host-side contract this implements).
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
/// `ptr` with length `len`. Guest-only; see the module-level caveat above.
pub fn read_input<T: DeserializeOwned>(ptr: i32, len: i32) -> T {
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len.max(0) as usize) };
    decode(bytes).expect("bearust-plugin-sdk: host sent malformed input")
}

/// Encodes `value` as JSON into a freshly allocated guest buffer and
/// returns the packed `(ptr, len)` result the host expects. Guest-only; see
/// the module-level caveat above.
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
