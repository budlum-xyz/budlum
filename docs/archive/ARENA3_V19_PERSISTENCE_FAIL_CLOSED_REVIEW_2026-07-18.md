# ARENA3 — V19 Persistence Fail-Closed Review

**Status:** Decision/RFC review — no implementation is authorized by this document
**Date:** 2026-07-18
**Scope:** bridge state, verified QC blob, finality certificate/canonical height,
startup restore and durable commit boundaries.
**Trigger:** V19 persistence-risk finding; independent source review.

---

## 1. Conclusion

V19 is **confirmed as a medium-to-high operational and consensus-integrity
risk**, but the earlier claim that every ignored storage result is equally
critical is overstated. The critical class is not every `let _ =`; it is a
state transition whose in-memory result is accepted while the durable source of
truth fails or is silently replaced at restart.

Logging an error improves observability but does not make the operation
fail-closed. Several current paths mutate live state before a storage write and
then either return an error without rollback or log and return success.

## 2. Evidence matrix

| ID | Path | Current behaviour | Risk | Required design outcome |
|---|---|---|---|---|
| V19-A | `process_relayed_message` → `save_bridge_state` (`blockchain.rs:1924`) | Bridge unlock and balance effects occur; save failure is only `tracing::error!`; method returns `Ok`. | High: live bridge state and disk diverge; restart can reintroduce an old bridge state/replay view. | No success response after durable bridge-state failure; enter a fail-stop/degraded mode or atomically commit before publishing the transition. |
| V19-B | Direct bridge register/lock/burn/unlock paths (`~1221–1451`) | Mutate `BridgeState`, then call `save_bridge_state` and return `Err` on failure. No rollback occurs. | High: caller sees failure but in-memory state remains changed; retry semantics and subsequent processing are ambiguous. | Stage/copy mutation, persist staged state, then commit in-memory state; or use a transaction/rollback mechanism with a tested invariant. |
| V19-C | Verified QC insert → `save_qc_blob` (`~2260`) | Inserts into `verified_qc_blobs`, logs save error, then continues pending-finality processing. | High: a node can make finality decisions on an unpersisted QC blob. | Persist verified QC record atomically before it is visible to finality processing, or fail-stop after a durability uncertainty. |
| V19-D | Finality update → certificate/height writes (`~3443`) | Sets finalized height/hash, logs failed cert/height writes, returns `Ok`. Writes are separate operations. | Critical: restart may see a certificate and height from different points, or neither, after a live finality advance. | One atomic durable finality record/batch containing certificate + canonical height + required checkpoint metadata; update memory only after success. |
| V19-E | Startup bridge restore (`blockchain.rs:420`) | `if let Ok(Some(...))`; load/decode errors are silently ignored and default bridge state remains. | High: corrupted/unavailable persisted bridge state is indistinguishable from “no saved bridge state”. | Distinguish `None` from `Err`; for a non-empty initialized database, fail startup or enter an explicit recovery/quarantine path. |
| V19-F | Genesis durable batch (`~201`) | Failed genesis `commit_durable_batch` is logged, then genesis is pushed into memory and startup continues. | High at initialization: a process may operate without durable genesis/state. | Mainnet/production must fail startup on initial durable-commit failure. Dev/test policy may be explicit but cannot be implicit. |
| V19-G | Mempool deletes/saves and PoS checkpoint/seen-block writes | Some errors are intentionally ignored. | Low to medium, depending on replay/consensus use. | Classify explicitly as reconstructible/best-effort or promote to durable critical state; do not apply one policy blindly. |

## 3. Existing useful primitive and its gap

`Storage::commit_durable_batch` already writes a sled batch with an
`IN_PROGRESS_HEIGHT` marker, applies the batch atomically and flushes it. It is
used for block-oriented state but does not currently model a standalone bridge
transition, QC blob + finality relationship, or the complete finality checkpoint
as one durable unit.

A simple `save_*` call plus `flush()` is not an atomic relationship between
multiple keys. In particular, `save_finality_cert` and `save_canonical_height`
are independently flushed.

## 4. Required design before code

### 4.1 Durability classes

Define a small, named classification rather than scattering error handling:

- **Consensus-critical:** finalized height/hash, finality certificate, verified
  QC material needed to finalize.
- **Bridge-critical:** transfer/replay/asset-location state and the associated
  balance transition.
- **Reconstructible/best-effort:** mempool cache, telemetry, and any state that
  can be deterministically rebuilt without changing consensus/asset safety.

Every storage call must be assigned one class, owner and restart invariant.

### 4.2 Commit protocol

For consensus/bridge-critical transitions:

1. validate and construct a staged next state without publishing it;
2. construct one durable batch/journal record containing every inseparable key;
3. apply and flush it;
4. only then publish the staged state to live memory and return success.

A flush/apply error can leave durability uncertain. The selected recovery policy
must be explicit: fail-stop/read-only plus operator recovery is safer than
continuing to relay, finalize or accept dependent transactions.

### 4.3 Startup policy

`None` is allowed only for a provably fresh/empty database or a documented
migration boundary. Decode/I/O errors, missing required records in a non-empty
chain, and inconsistent finality tuples require typed startup failure or an
operator-visible quarantine/recovery workflow; defaulting to an empty
`BridgeState` is forbidden for production state.

## 5. Mandatory tests

Implementation is not accepted without failure injection or an equivalent
storage test double that proves:

1. bridge write failure leaves neither live bridge state nor balances advanced;
2. relay/unlock cannot return `Ok` after a critical durable write failure;
3. QC persistence failure cannot be used by finality processing;
4. certificate + canonical-height batch is all-or-nothing across restart;
5. corrupted/missing bridge state in a non-empty database fails loud rather
   than silently defaulting;
6. fresh database initialization remains valid;
7. best-effort paths are explicitly documented and cannot affect consensus or
   asset ownership;
8. failure/restart tests are deterministic and run in CI.

## 6. Decisions required

1. **Production failure response:** fail-stop process exit, read-only/degraded
   node mode, or a separately designed operator recovery loop.
2. **Scope boundary:** include bridge + QC + finality in one durability project,
   or task bridge first while blocking finality changes until its batch design
   is ready.
3. **Dev/test policy:** whether in-memory/no-storage operation remains allowed
   only under explicit non-production configuration.

**Decision owner:** Ayaz.
**Implementation owner:** chain/storage owner with ARENA3 review; this RFC does
not authorize a cross-domain or consensus behaviour change by itself.

*Co-authored-by: ARENA3 <arena3@budlum.xyz>*
