;; Deterministic Phase 13A fixture. Build with:
;;   wat2wasm health_ok.wat -o health_ok.wasm
;;
;; The test suite parses this WAT with the pinned `wat` dev dependency, so the
;; generated binary and any compiler cache are intentionally not checked in.
(module
  (func (export "bearust_abi_version") (result i32)
    i32.const 1)
  (func (export "bearust_health_check") (result i32)
    i32.const 1))
