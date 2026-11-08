# Independent Security Audit: Execution, Mobile, and Clients (WP-48)

Date: 2026-11-06
Scope: WP-11, WP-26..WP-41, WP-61, and cross-module verification across
`src/execution/`, `crates/uel-abi/`, `budzero/`, `mobile/{android,ios,tools}/`,
`crates/wallet-core/`, `crates/budlum-explorer/`, `src/bin/budlum-light.rs`, and
`src/core/{money,tx_bundle}.rs`.

Note on path allocation: `docs/audit/REVIEW_2.md` and `docs/audit/FINDINGS.md`
are held in flight by open PRs (`#100`, `#77`, `#60`, `#36`), and finding IDs
up to `BLG-368` are allocated across the open PR stack. To uphold Section 15.3
lock discipline without conflict, new findings discovered and remediated in this
audit are numbered `BLG-370` through `BLG-373` and recorded in this report and
in PR #43.

---

## 1. Invariant Verification Matrix (`Y-1`..`Y-7`, `K-1`..`K-4`, `G-2`, `G-3`, `G-4`)

| Invariant | Verification Path | Status |
|---|---|---|
| `Y-1` Unmodified bytecode | `crates/uel-abi/src/types.rs` (`EeCallKind::Deploy`), `execution/*` workers take raw ecosystem bytecode without transpilation | Verified |
| `Y-2` Single state root & deterministic order | `src/execution/coordinator/scheduler/mod.rs` (`plan`, `parallel_schedule_equals_sequential_root`) | Verified |
| `Y-3` Atomic Universal Calls | `crates/uel-abi/src/{types,wire}.rs` (`UniversalCall`, `UniversalResult`, `HostError::DepthExceeded`) | Verified |
| `Y-4` Single BUD ledger | `src/core/money.rs` (`Bud` newtype), `crates/uel-abi/src/types.rs` (`BudAmount` in attoBUD) | Verified |
| `Y-5` No minted representations | Asset pointers carry zero independent balance; home environment holds canonical balance | Verified (cross-PR tag dedup noted in `#100`) |
| `Y-6` Worker fault isolation | `crates/uel-abi/src/types.rs` (`EeFault` deterministic receipt with `panic_digest`), `src/execution/proof_verifier.rs` | Hardened (`BLG-370`) |
| `Y-7` Visible classical quantum class | `src/account_abstraction/quantum_account.rs` & foreign envelope tagging (`classical_crypto_is_paired`) | Verified |
| `K-1` No unbacked claims | `xtask/gates` (`pq-claims-are-backed`, `binding-claims`), `budzero/bud-pul/src/pul_air.rs` fail-closed `UnboundProof` | Verified |
| `K-2` Consent is the sole gate | Sealed key/plaintext access requires explicit consent proof; testnet privacy transfers gated closed (`WP-45`) | Verified |
| `K-3` Classical crypto is paired | V7/V8 composite witnesses (`src/core/transaction.rs`, `src/core/tx_bundle.rs`) require both ML-DSA-87 and Ed25519 | Hardened (`BLG-373`) |
| `K-4` Single primitive definition | `crates/note-packing` shared Poseidon packing, `crates/bpqs` canonical XMSS/WOTS, `wallet-core` V5/V7 hash vectors | Verified |
| `G-2` Determinism (no consensus float) | Integer/basis-point arithmetic in `budlum-mobile-log-analyzer`, `scheduler`, `Bud`, `ProofVerifier` | Verified |
| `G-3` Fixed 100M BUD supply | `Bud::try_from(u128)` overflow refusal, `minting-paths-are-counted` gate, checked receiver addition in `Executor` | Verified |
| `G-4` Refusals never mutate state | Pre-mutation checks in `Executor::apply_transaction`, `ProofVerifier::verify`, `MobileValidatorEngine`, `IosOpportunisticValidator` | Verified |

---

## 2. Section 13 Risk & Adversarial Attack Matrix

| Risk | Adversarial Vector Tested | Mitigation & Evidence |
|---|---|---|
| `R-01` | Malformed / panicking EE payload | Worker boundary converts engine panics into `EeFault { ee, panic_digest }` without crashing node |
| `R-05` | OEM killer stops Android FGS | `ValidatorService` (`specialUse`) + 15m unmetered `WorkManager` (`android_workmanager_answers_audit_when_service_stopped`) + `OemBatteryGuide` |
| `R-07` | Phone behind Carrier CGNAT / IPv6-only | Relay v2 + DCUtR + AutoNAT tracked in `budlum-mobile-log-analyzer` (`mobile_nat_matrix`) |
| `R-08` | Unauthenticated bundle / RPC abuse | `BLG-371` JSON-RPC escaping & error parser; `BLG-373` Pass-1 zero-chain & witness-bloat refusal before PQ verify |
| `R-11` | Cross-arch (`x86_64` vs `aarch64`) drift | Ordered `BTreeMap`/`BTreeSet` in `scheduler::plan` (`parallel_scheduler_is_deterministic_across_arch`) and integer bps in `log-analyzer` |
| `R-12` | Unbounded state/envelope growth | `MAX_PROOF_BYTES` (1 MiB), `MAX_CHAIN_FILE_BYTES` (256 MiB), mobile `[1 GiB, 64 GiB]` & iOS `[1 GiB, 8 GiB]` quotas |
| `R-15` | Faucet sybil / bot draining | PoW nonce + rate/address caps on testnet faucet drip |
| `R-16` | Stolen phone operator key | Hardware-wrapped `ML-DSA-65` duty key cannot sign stake/unbond; `ML-DSA-87` owner key requires biometric/PIN + `RotateOperatorKey` (`android_keys_are_keystore_wrapped`) |
| `R-18` | Underpriced execution / STARK gas | **Found & Fixed (`BLG-370`)**: `ProofVerifier::verify` now rejects `2^degree_bits < trace_len` before STARK verification |
| `R-19` | Cross-EE reentrancy & balance theft | `HostError::DepthExceeded` + single `AccountState` ledger + atomic wave ordering |
| `R-20` | Ecosystem tool incompatibility | Standard V5/V7 JSON-RPC client bodies in `wallet-core::rpc` hardened against pretty-printed JSON (`BLG-371`) |
| `R-36` | Classical signature / chain-id confusion | V4/V5/V6/V7/V8 domain-separated signing tags; `budlum-light` full header-slice `chain_id` enforcement (`BLG-372`) |

---

## 3. New Findings Discovered & Remediated (`BLG-370`..`BLG-373`)

### `BLG-370` (High) - `ProofVerifier::verify` allowed STARK gas underpricing via caller-controlled `degree_bits`
- **Location:** `src/execution/proof_verifier.rs` (`ProofVerifier::verify`).
- **Vulnerability:** Verification gas was computed as `envelope.degree_bits * GAS_PER_DEGREE_BIT` and checked against `gas_limit` without verifying that `2^envelope.degree_bits >= expected_inputs.trace_len`, `expected_inputs.trace_len > 0`, or `expected_inputs.gas_used <= expected_inputs.gas_limit`. A caller could set `degree_bits = 0` on a large trace (`trace_len = 2^20`) to pay `0` verification gas while forcing full deserialization and STARK verifier work (`R-18`).
- **Fix:** Added pre-STARK consistency checks requiring `trace_len > 0`, `gas_used <= gas_limit`, and `1u64.checked_shl(envelope.degree_bits) >= Some(expected_inputs.trace_len)`.
- **Regression tests:** `blg_370_underpriced_degree_bits_below_trace_len_rejected`, `blg_370_zero_trace_or_gas_overrun_in_public_inputs_rejected`.
- **Status:** Closed in PR #43.

### `BLG-371` (High) - `wallet-core::rpc` JSON parameter injection and `"error":null` substring error-masking
- **Location:** `crates/wallet-core/src/rpc.rs` (`request`, `get_nonce`, `get_balance`, `string_result`).
- **Vulnerability:** (1) `get_nonce` and `get_balance` interpolated `address_hex` directly into a JSON string literal without escaping quotes, backslashes, or control characters, permitting JSON-RPC parameter/method injection from untrusted URI inputs. (2) `string_result` checked `answer.contains("\"error\":") && !answer.contains("\"error\":null")`, which missed `"error" : {...}` with whitespace before `:`, falsely rejected pretty-printed `"error": null`, and swallowed real node errors whenever `"data"` or `"result"` contained the substring `"error":null`.
- **Fix:** Added `json_escape_str` on `method` and hex address parameters, and replaced substring matching with quote-aware `top_level_value` scanning at object depth 1.
- **Regression tests:** `blg_371_error_is_not_masked_by_error_null_inside_string_or_spaces`, `blg_371_address_param_escapes_json_injection_payloads`.
- **Status:** Closed in PR #43.

### `BLG-372` (High) - `budlum-light` checked `chain_id` only on `headers[0]` and ignored duplicate global header openings
- **Location:** `src/bin/budlum-light.rs` (`main`, `verify_global_opening`).
- **Vulnerability:** (1) Only `export.headers[0].chain_id` was compared against `cli.network.chain_id()` up front before feeding the export slice into verification. (2) `verify_global_opening` used `.find(...)`, silently ignoring trailing conflicting `GlobalHeaderOpening` entries for the same `checkpoint_height`.
- **Fix:** Added `validate_headers_chain_id` across every header in `export.headers` and rejected duplicate `GlobalHeaderOpening` entries per checkpoint height.
- **Regression tests:** `blg_372_mixed_chain_header_after_index_zero_is_refused`, `blg_372_duplicate_global_header_opening_for_same_height_is_refused`.
- **Status:** Closed in PR #43.

### `BLG-373` (Medium) - `TxBundle::verify_in` permitted unauthenticated `witness.authorization_signatures` bloat and deferred `chain_id == 0` past PQ verification
- **Location:** `src/core/tx_bundle.rs` (`TxBundle::verify_in`).
- **Vulnerability:** `TxBundle::sign` always emits `witness.authorization_signatures = []`, but `verify_in` never rejected non-empty `witness.authorization_signatures`, allowing relays to append unauthenticated witness bytes without invalidating the bundle signature. In addition, a bundle where all members carried `chain_id == 0` passed Pass 1 and paid Pass 2's full composite ML-DSA-87 + Ed25519 verification before failing Pass 3.
- **Fix:** Rejected `first.chain_id == 0` in Pass 1 and rejected non-empty `witness.authorization_signatures` prior to composite signature decoding.
- **Regression test:** `blg_373_unauthenticated_witness_authorization_bloat_and_zero_chain_refused`.
- **Status:** Closed in PR #43.
