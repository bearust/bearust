# Phase 13B final review

Date: 2026-08-05

## Scope and evidence

Phase 13B adds the public `bearust-plugin-sdk` crate (`crates/bearust-plugin-sdk`)
and a JSON-over-linear-memory host/guest convention. `abi_version: 1` plugins
are unchanged; `abi_version: 2` plugins export `bearust_alloc`, `bearust_dealloc`,
and `bearust_health_check_v2`, exchanging JSON through bounds-checked guest
memory. No new plugin capability, host import, or traffic hook was added.

## Security review

| Check | Result | Evidence |
| --- | --- | --- |
| Guest pointer/length bounds | Pass | `bounded_guest_range` rejects negative values, arithmetic overflow, and any range extending past `memory.data_size`, before any read or write; covered by `v2_out_of_bounds_output_pointer_is_trap_not_a_host_crash`. |
| Output size cap | Pass | `bounded_guest_range` rejects any claimed length over the plugin's configured `max_output_bytes` with `MemoryLimit`, independent of the bounds check; covered by `v2_oversized_output_is_memory_limit_not_trap`. |
| Malformed guest output | Pass | JSON decode failures map to `PluginError::Trap`, never a panic; covered by `v2_malformed_json_output_is_trap`. |
| `detail` truncation safety | Pass | Truncation walks back to the nearest UTF-8 char boundary before cutting, so no panic and no invalid `String`; covered by `v2_long_detail_is_truncated_at_a_char_boundary`. |
| v1 regression | Pass | Every pre-existing Phase 13A test in `tests/plugin_runtime.rs` and `tests/control_plane_plugins.rs` passes unmodified in behavior. |
| No new capability/import | Pass | `Instance::new(&mut store, &self.module, &[])` still installs zero imports; the memory convention only reads/writes the guest's own already-sandboxed linear memory. |

## Acceptance gate

```text
cargo fmt --all -- --check                              PASS
cargo clippy --all-targets -- -D warnings                PASS
DATABASE_URL=sqlite::memory: cargo test --all-targets    PASS
npm test --prefix frontend -- --run                       PASS
npm run build --prefix frontend                            PASS
npm run validate-locales --prefix frontend                 PASS
git diff --check                                            PASS
```

One `cargo fmt` drift (in `tests/plugin_runtime.rs`) and one `cargo clippy`
lint (`clippy::cast_slice_from_raw_parts` in
`crates/bearust-plugin-sdk/src/lib.rs`'s `bearust_dealloc`, from casting the
result of `std::slice::from_raw_parts_mut` instead of using
`std::ptr::slice_from_raw_parts_mut`) were found and fixed at the reported
location during this gate run, then the gate was re-run clean.

## Deferred scope

The `bearust-plugin-sdk` crate's guest-only unsafe pointer wrappers
(`bearust_alloc`, `bearust_dealloc`, `read_input`, `write_output`) are not
exercised by an actual `wasm32-wasip1` build in this repository's test suite;
the host-side contract they implement is instead proven against a
hand-written WAT fixture. A future increment may add an optional
`wasm32-wasip1`-target CI job to compile a real SDK-based example plugin, but
that remains out of scope here, matching the approved Phase 13B design's
non-goals.

The project-wide CSRF token contract for mutating control-plane endpoints
(noted in the Phase 13A review) remains open and unrelated to this phase's
scope.

Phase 13C (traffic hooks) and Phase 14 (registry/signatures) remain future
work, as documented in `docs/PRD.md`.
