# PR #84 foundations disposition

| Field | Value |
|---|---|
| Reviewed source | PR #84, `f072940b08ad8eb8b3dc0a483232a6cbffffe0d8` |
| Source checks | 4 passed, 40 failed, 55 pending and 3 skipped in the captured inventory; no blanket green or red-fix claim |
| Integration result | No source file checkout. Current implementations are retained and the source head is recorded by a genuine merge. |

## Current implementations retained

- `no_legacy_storage` and its shrinking baseline are registered. The current
  integration audit exercises that ratchet and the separate inventory scripts;
  the current count is not replaced by the source's older 89-line baseline.
- `no_float_in_consensus_paths` is now a `syn` AST gate with test-item skipping,
  architecture-independent integer semantics and a single explicit AI pin. The
  source's token-scan baseline is obsolete.
- The EE-unwind, B.U.D.3 universal-object, custody, paid-view, workspace and
  README gates are present in stronger executed forms. In particular the source
  EE gate's empty worker list and the README-claims no-op are not restored.
- `crates/budlum-types` now carries the shared node/mobile `Address` definition
  and canonical parser/serializer behavior rather than the empty cradle.
- Persistence and state recovery contain their real trie, database, pruning,
  retention, health, stage, mempool and tick implementations. The source's
  `recovery_*` forwarding stubs would bypass these current modules.
- `ContentRef` is now the permanent validated content/object/NFT reference with
  atomic replacement. The transitional `Bud3NotReady` interface and its refusal
  pins belong to the retired pre-B.U.D.3 phase and are not reintroduced.

## Deliberately absent source artifacts

The source's removed token-scan baselines, `object.rs`/`refcount.rs` and other
small module placeholders, `recovery_health.rs`/`recovery_ledger.rs`/
`recovery_mempool.rs`/`recovery_tick.rs` forwarding files, transitional
`bud3_refusal_pins.rs`, and trivial `readme_claims_are_wired.rs` are absent for
the reasons above. Their absence is not treated as a request to recreate no-op
gates or parallel storage/state-recovery implementations.

`Cargo.toml`, parent module declarations, `docs/work/PACKAGES.md` and
`xtask/gates/src/main.rs` already carry the later workspace/package/gate state.
The older package ledger and gate registry are not allowed to overwrite them.

## Verification boundary

All 50 PR-scoped paths were inventoried against the current tree and classified
as retained/superseded above. The current Python integration audit passes 14/14
checks and all 14 injected canaries. No new production suppression or baseline is
added. There is no new Rust build/test result and the source's 40 failed checks
remain historical evidence requiring per-job triage, not a claim that this
provenance merge repaired them. Existing package and testnet findings remain
open under their current records.
