# Consensus Module Findings

Files reviewed: mod.rs, pos.rs, poa.rs, pow.rs, filiz.rs, handoff.rs, qc.rs, registration.rs, block_signature.rs, budget.rs, merkle_tree.rs, split_resolver.rs

## F-0001: Error message whitespace corruption in PoS preview

- **Location**: `src/consensus/pos.rs:575-576`
- **What is wrong**: The error message string literal spans multiple source lines and the Rust compiler preserves the indentation whitespace. The resulting message contains roughly 18 consecutive spaces between "one" and "consensus-ready".
- **Why it is wrong**: String literals in Rust include all characters between the quotes, including indentation whitespace when a line is continued. The message is: `"No active validators - PoS block production requires at least one                  consensus-ready validator..."`.
- **What it causes**: Log output and error reports contain garbled spacing. Operators reading the error see a broken message. Automated log parsing that matches on the error text will fail to match the message with the extra spaces.
- **How to fix it**: Either join the string on one line or use a `format!` macro. Alternatively break the literal at a word boundary without the indentation spaces.
- **Status**: open

## F-0002: Broken doc comment reference in PoS epoch randomness

- **Location**: `src/consensus/pos.rs:322`
- **What is wrong**: The doc comment reads "Epoch `E` consumes epoch ` `" with an empty backtick pair. It should read "Epoch `E` consumes epoch `E - 2`".
- **Why it is wrong**: A character was lost during editing. The lookback is 2 epochs, as the code on line 353 shows (`LOOKBACK_EPOCHS: u64 = 2`).
- **What it causes**: The generated documentation gives an incomplete description of the randomness derivation. A developer reading the doc without reading the code would not know the lookback distance.
- **How to fix it**: Replace `` ` ` `` with `` `E - 2` `` on line 322.
- **Status**: open

## F-0003: ZK QC fault proof verifier is stubbed (fail-closed)

- **Location**: `src/consensus/qc.rs:908-930`
- **What is wrong**: The ZK fault proof verification path returns a hard error: "ZK QC fault proof verifier not implemented". All ZK domain attestations that pass the BLS quorum check are accepted but cannot be challenged.
- **Why it is wrong**: The stub is explicitly fail-closed, which is the safe default. The code documents this as deliberate: no pairing-based SNARK sits on a Budlum verification path, and a BudZero STARK verifier is needed.
- **What it causes**: For testnet: ZK domain QC blobs are accepted (BLS quorum is verified) but cannot be disputed through fault proofs. A malicious ZK domain attestation that clears the BLS threshold would be accepted with no recourse. The code itself documents this risk on lines 918-921.
- **How to fix it**: Implement the BudZero STARK verifier in a `consensus::zk_verifier` module and wire it into the `ZkInvalidAttestationV1` match arm. Until then, consider disabling ZK domain QC import on testnet (as the code comment suggests on line 929).
- **Status**: open

## F-0004: PoW accumulated work uses saturating U256 in split resolver

- **Location**: `src/consensus/pow.rs:583-588`
- **What is wrong**: When `is_better_chain` delegates to `resolve_split_tie` for equal accumulated work, it passes `saturating_to_u128()` as the score. If both candidates have accumulated work above 2^128 (which saturates to `u128::MAX`), the resolver sees identical scores and falls through to the hash comparison. The U256 comparison on line 572 correctly handles this case, so the resolver only fires when the U256 values are truly equal. However, the `SplitCandidate.weight` field is u128 and carries a truncated value, which means any audit of the resolver's weight-based decision sees a saturated number.
- **Why it is wrong**: The weight field in the resolver is informational for this call path since the U256 check on line 572 already decided the work is equal. The truncated u128 is a cosmetic issue for logging and debugging, not a correctness bug.
- **What it causes**: No incorrect behavior. The U256 comparison ensures correctness. The resolver's weight field shows `u128::MAX` for both candidates when their true work exceeds 2^128, but the resolver only runs when work is truly equal (decided by U256), so the weight field is not used for ordering in this case.
- **How to fix it**: No fix required. The code is correct. A comment on line 585 noting that the u128 score is not used for ordering here would improve clarity.
- **Status**: open (informational)

## Module Quality Assessment

The consensus module is production-grade. Specific strengths:

1. **Round pricing** (mod.rs): The leader-round retry mechanism is carefully designed. Wall-clock pricing from the shared parent stamp prevents local-input consensus splits (RT-001 incident reference). Producer-side pacing is stricter than validation-side, so a node never proposes what it would reject.

2. **Slashing evidence** (pos.rs): Double-sign detection distinguishes same-round equivocation from legitimate re-proposals at different rounds or on different parents (lines 770-783). Evidence is verified before acceptance. The frame-up resistance in qc.rs (lines 889-901) correctly refuses to issue verdicts on signatures that fail to verify.

3. **Checkpoint safety** (pos.rs): Epoch-boundary checkpoints are parked pending finalization rather than committed at local time. This prevents the split where two nodes commit different blocks at a boundary and then refuse each other's chains permanently.

4. **PoA admission control** (poa.rs): The fail-closed design correctly distinguishes "gated and nobody let in" from "not gated at all". KYC expiry works without any action. Cross-domain isolation is enforced.

5. **Filiz chain** (filiz.rs): Identity-binding of reveals prevents commitment stealing. The zeroize-on-drop protects unrevealed chain state. The activation delay prevents front-running registrations.

6. **Merkle tree** (merkle_tree.rs): The promotion-not-duplication rule for odd tails eliminates the ambiguity where `[a,b,c]` and `[a,b,c,c]` shared a root. Domain separation between leaf, node, and promotion hashes is correct.

7. **Handoff certificates** (handoff.rs): The committee is seated by the verifier's independent knowledge of epoch randomness, not the certificate's own field. The 2/3+1 quorum is strictly enforced.

8. **Split resolver** (split_resolver.rs): Deterministic, arrival-order-independent tie-break for equal-weight forks. Pure function of block fields, no local state.

9. **Budget system** (budget.rs): Body and witness sections are tracked separately with rollback on failure. The per-transaction bound prevents any single item from consuming the budget.

10. **Test coverage**: Every module has extensive tests covering happy paths, edge cases, security invariants, and regression scenarios. The Kani model-checking integration adds formal verification for the Merkle tree shape.
