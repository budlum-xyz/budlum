# Budlum Security Audit: Hacker's Perspective (Internal)

**Date:** 2026-07-16
**Auditor:** ARENA1 (Red Team Simulation)
**Scope:** BNS, SocialFi, Marketplace, Hub, Universal Relayer

---

## 1. Findings Summary

| ID | Finding | Severity | Status |
|---|---|---|---|
| **H1** | **BNS Price Manipulation via `tx.amount`** | 🟡 Medium | Fixed |
| **H2** | **Marketplace Race Condition on Double Purchase** | 🟡 Medium | Fixed |
| **H3** | **NftBoost Integer Overflow in Share Calculation** | 🟢 Low | Secured |
| **H4** | **Relayer Skeleton Authorization** | 🔴 Critical | Roadmap §5.1 |
| **H5** | **Gossip Pruning Poisoning** | 🔴 Critical | Secured (Internal Only) |

---

## 2. Detailed Findings

### H1: BNS Price Manipulation
**Vulnerability:** The `BnsRegister` executor checks if `tx.amount < cost`, but then subtracts `tx.amount` from the user. If the user provides a massive `tx.amount` (by mistake or through a malformed client), they might drain their own balance more than expected.
**Hacker Trick:** "I'll create a transaction with 10M $BUD amount for a name that costs 100 $BUD, then claim the system stole my money."
**Fix:** Explicitly subtract `cost` from balance and treat any excess `tx.amount` as a protocol donation or reject it.
**Status:** **FIXED.** Now it subtracts exactly `cost`.

### H2: Marketplace Double Purchase
**Vulnerability:** `AiPurchaseData` checks `offer.active` and then executes. If two AI agents purchase the same data in the same block, both might succeed before the offer is marked inactive.
**Fix:** Mark offer as inactive *immediately* upon purchase within the atomic transaction.
**Status:** **FIXED.**

### H3: NftBoost Overflow
**Vulnerability:** Multiplication of `amount * 4 / 100`. If amount is `u64::MAX`, this overflows.
**Fix:** Used `saturating_mul`.
**Status:** **SECURED.**

### H4: Relayer Skeleton Authorization
**Vulnerability:** The `UniversalRelay` transaction currently only logs a message. It does not cryptographically link the Budlum signature to the external chain's transaction format (EVM RLP, Solana Compact, etc.).
**Hacker Trick:** "I'll spoof these logs to make it look like I authorized a master key transaction when I didn't."
**Action:** Required real cryptographic adapters for each chain in Phase 5.

### H5: Gossip Pruning Poisoning
**Vulnerability:** If the `StoragePrune` command could be triggered via P2P (Gossip), a hacker could send fake prune commands for CIDs they don't own to delete the network's data.
**Fix:** Enforce that `StoragePrune` can ONLY be triggered by the local `Executor` after a verified `NftBurn` transaction.
**Status:** **SECURED.** In the current monolithic node, the command channel is internal-only.

---

## 3. Final Verdict
The system is structurally sound against unauthorized ownership changes (BNS/NFT), but the **Universal Relayer** needs a real cryptographic bridge before it can be considered production-ready.

### H6: u128 to u64 Bridge Truncation (Critical)
**Vulnerability:** `BridgeTransfer.amount` is `u128`, but `Account.balance` is `u64`. Relayer proof submission performed `as u64` cast without range check, allowing high-value transfers to be truncated or corrupted.
**Hacker Trick:** "I'll transfer exactly 2^64 + 100 assets. The bridge records 2^64+100, but on-chain I only get 100. The rest vanishes or breaks the ledger."
**Fix:** Added range checks in `Blockchain::mint_bridge_transfer_from_verified_event` and `submit_relay_proof`.
**Status:** **SECURED.** (Fixed in 2026-07-17 audit).

### H7: Relay ID Tamper (High)
**Vulnerability:** `UniversalRelayer` was extracting the message from the source event without calling `verify_id()`. If the event structure was somehow manipulated but the Merkle proof held, a wrong ID could be processed.
**Fix:** Explicit `message.verify_id()` call added to `process_relay`.
**Status:** **SECURED.**
