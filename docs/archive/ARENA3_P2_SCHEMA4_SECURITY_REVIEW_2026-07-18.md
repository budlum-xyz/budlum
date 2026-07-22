# ARENA3 — P2 Schema-4 Security Review

**Date:** 2026-07-18
**Reviewer:** ARENA3
**Scope:** independent review of `docs/P2_SCHEMA4_UYGULAMA_PLANI_2026-07-18.md`
before C1–C6 implementation.
**Code basis:** `StateSnapshotV2` in `src/chain/snapshot.rs`, `BridgeState` in
`src/cross_domain/bridge.rs`, and the user-approved uncapped `u128` luminance
migration RFC.
**Outcome:** **conditional approval** — P2 must resolve the blocking design
items below before C2/C3/C4 implementation is accepted.

---

## 1. Review findings

| ID | Severity | Finding | Required resolution |
|---|---|---|---|
| P2-R1 | High | The plan says “14” or “15” GAP-2 fields, while its serialization table actually describes **16**: tokenomics, tokenomics_burn, registry, liveness, invalid_votes, bns_registry, nft_registry, marketplace, hub, storage_registry, ai_registry, bridge_state, message_registry, external_roots, finality_certificates, created_at. `ai_registry` is absent from the prose list but present in the table. | Freeze a numbered canonical field manifest in code and test it by name. No prose-only count is an acceptance criterion. |
| P2-R2 | High | The plan proposes generic `bincode` for several consensus-digest fields. `StateSnapshotV2::calculate_hash` currently sorts its top-level `HashMap` keys manually. A generic serializer must not be assumed canonical for nested maps/sets, enum variants, length boundaries, or future type changes. | Define field-specific canonical encodings, tags, length prefixes and sorted iteration; prove determinism with insertion-order permutation tests. `bincode` may be used only after a per-type canonicality proof, not as the default digest primitive. |
| P2-R3 | Critical | `trust_policy` must not be trusted when it is supplied by the snapshot being authenticated. An attacker could choose `AllowUnsigned` in a forged manifest if loader policy reads snapshot-owned policy state. The plan also names a “trust-list” but does not define its authoritative source or root/config binding. | Loader receives an external, trusted policy/config. Snapshot wire metadata may describe a signer but cannot downgrade verification. Define signed-key/trust-list provenance, rotation binding and mainnet fail-closed default. |
| P2-R4 | High | Manifest signature fields must be excluded from their own signed digest. The plan references `calculate_digest()` but does not state a testable self-reference exclusion rule. | Specify `digest_v4` exact field order and state that signer/signature bytes are excluded. Add mutation tests for every included field and a test that changes only signature bytes without changing digest. |
| P2-R5 | High | Schema-3 legacy snapshots cannot verify with a schema-4 prefix/digest. Current `calculate_hash()` has no version-dispatched digest path. Deserialization compatibility alone is not integrity compatibility. | Keep a frozen schema-3 digest implementation; dispatch by parsed schema version before migration; migrate only after successful old-digest verification. Pin schema-2/3/4 vectors. |
| P2-R6 | Critical | V24 is not fully closed by adding `bridge_state` to the snapshot digest. `BridgeState::root()` currently commits only `asset_locations`; block/header `bridge_root` callers continue to omit transfer amount, owner, recipient, source/target domain, status, source-event hash, expiry queue/replay semantics. | P2 must separately version and expand `BridgeState::root()` with canonical transfer/replay coverage, then pin both header-root and snapshot-digest mutation tests. |
| P2-R7 | High | The user-approved SocialFi migration changes luminance from `u64` to `u128`; P2’s current field matrix has no explicit representation/version/migration rule for this root-committed state. | Add `u128` little-endian canonical encoding, schema-3 widening behavior, JSON/RPC/protobuf audit, and preflight atomicity tests from `RFC_SOCIALFI_LUMINANCE_POLICY_CAP.md`. |
| P2-R8 | Medium | P4 is described as a workflow/branch-protection gate, but an implementation sequence and permission-safe fallback are not specified. The project has previously encountered workflow permission restrictions. | Implement and self-test `scripts/check-snapshot-schema.sh` first; add a workflow/required-check only through an authorized path, otherwise record the explicit operational gap. |

## 2. Confirmed strengths

- A single schema-4 PR for GAP-1, GAP-2 and B2 correctly avoids incompatible
  one-sided root changes.
- `AssetId` alias-to-struct migration belongs with bridge serde/hash changes.
- `created_at` is correctly identified as a missing integrity input, subject to
  a canonical `u128` encoding.
- Existing snapshot code explicitly sorts top-level balances/nonces/validators;
  that is the appropriate pattern to preserve rather than replacing it with
  opaque serialization.
- Snapshot `bridge_root` is already included in the outer digest. V24 is an
  **inner-root scope** issue, not a reason to remove the outer binding.

## 3. Required pre-implementation artifacts

Before C2/C3/C4 is considered ready, the P2 owner must add or approve:

1. a machine-readable ordered field manifest (`Schema4DigestField` or equivalent);
2. a byte-level digest specification: domain tag, field tag, length encoding,
   option encoding and canonical ordering;
3. external `SnapshotTrustPolicy` ownership and signer/trust-list/rotation
   source of truth;
4. schema-2/3/4 verification and migration vector plan;
5. bridge header-root expansion design; and
6. the `u128` SocialFi migration insertion point and atomic preflight invariant.

## 4. ARENA3 P4 review-gate plan

After C6 and before merge, ARENA3 will review/implement the following gate
contract (subject to authorized workflow changes):

- a named schema-4 field-manifest assertion;
- a vacuous-gate canary (missing one required field must fail);
- deterministic insertion-order tests for every map/set in the digest path;
- mutation tests for all committed fields, including BridgeTransfer details and
  `u128` luminance bytes;
- legacy schema verification before migration; and
- malformed snapshot bytes → typed failure/no panic fuzz coverage.

## 5. Decision and ownership boundary

This is a review, not a code change. ARENA1 owns C1–C6 implementation and
ARENA2 owns the chain/restore/signing integration described in the task plan.
ARENA3 does not modify those domains until a written file-level handoff or the
P4/C6 integration point is announced.

*Co-authored-by: ARENA3 <arena3@budlum.xyz>*
