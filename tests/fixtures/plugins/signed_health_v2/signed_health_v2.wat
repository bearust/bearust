;; Deterministic fixture for Phase 14 signing tests. Build with:
;;   wat2wasm signed_health_v2.wat -o signed_health_v2.wasm
;;
;; Minimal abi_version: 2 module: always reports healthy (status 1), no
;; detail. Content is irrelevant to these tests -- what's under test is
;; whether the *signature* over this exact manifest+wasm pair is accepted,
;; not the plugin's runtime behavior.
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
    i64.const 1))
