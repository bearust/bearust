;; Deterministic Phase 13C fixture. Build with:
;;   wat2wasm notify_sink_v2.wat -o notify_sink_v2.wasm
;;
;; The test suite parses this WAT with the pinned `wat` dev dependency, so the
;; generated binary and any compiler cache are intentionally not checked in.
;;
;; Ignores the JSON the host writes as input and always returns status 0
;; (success) from bearust_notify_waf_block, proving the host's
;; alloc/write/call/dealloc round trip end to end. Every abi_version: 2
;; module must also export bearust_health_check_v2 regardless of its
;; declared capabilities (an existing Phase 13B requirement); this fixture
;; is never health-checked in tests, so that export is a trivial stub.
(module
  (memory (export "memory") 1)
  (global $heap_ptr (mut i32) (i32.const 1024))

  (func (export "bearust_abi_version") (result i32)
    i32.const 2)

  (func (export "bearust_alloc") (param $len i32) (result i32)
    (local $ptr i32)
    global.get $heap_ptr
    local.set $ptr
    global.get $heap_ptr
    local.get $len
    i32.add
    global.set $heap_ptr
    local.get $ptr)

  (func (export "bearust_dealloc") (param $ptr i32) (param $len i32)
    nop)

  (func (export "bearust_health_check_v2") (param $ptr i32) (param $len i32) (result i64)
    i64.const 0)

  (func (export "bearust_notify_waf_block") (param $ptr i32) (param $len i32) (result i32)
    i32.const 0))
