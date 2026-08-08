;; Deterministic Phase 13D fixture. Build with:
;;   wat2wasm waf_detect_v2.wat -o waf_detect_v2.wasm
;;
;; The test suite parses this WAT with the pinned `wat` dev dependency, so the
;; generated binary and any compiler cache are intentionally not checked in.
;;
;; Ignores the JSON the host writes as input and always returns the fixed
;; JSON literal `{"decision":"block","category":"custom_detector","score":10}`
;; (60 bytes) stored at memory offset 0, proving the host's
;; alloc/write/call/read/dealloc round trip end to end. Every abi_version: 2
;; module must also export bearust_health_check_v2 regardless of its
;; declared capabilities (an existing Phase 13B requirement); this fixture
;; is never health-checked in tests, so that export is a trivial stub.
(module
  (memory (export "memory") 1)
  (global $heap_ptr (mut i32) (i32.const 1024))
  (data (i32.const 0) "{\22decision\22:\22block\22,\22category\22:\22custom_detector\22,\22score\22:10}")

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

  (func (export "bearust_waf_detect") (param $ptr i32) (param $len i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
      (i64.extend_i32_u (i32.const 60)))))
