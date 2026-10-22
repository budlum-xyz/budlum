# Pollen: the B.U.D. data marketplace (module README)

**This is Pollen's own README, as the module-separation rule requires.**
The root `README.md` is only a dashboard; maturity and risk warnings live here.

## Status

- **Maturity:** core types + the Data Rights gate + the content gate.
  The `DataAsset` and `AccessGrant` primitives are in the code; if an AI
  `input_ref` points at Pollen/B.U.D. data, the request is refused without a
  grant (strict, no override).
- **Code location:** `src/pollen/`, `mod.rs` (core types: `AssetId`,
  `Signature64`, `GrantId`), `data_rights.rs` (`DataAsset`, `AccessGrant`,
  `SaleAuthorization`, `AiDataInputRef`), `offers.rs` (`MarketplaceRegistry`
  and `DataOffer`), `content_gate.rs` (the bridge between a Pollen asset and
  the B.U.D. bytes behind it).
- **Test count:** 46 `#[test]` functions under `src/pollen/`
  (`content_gate.rs` 15, `offers.rs` 13, `data_rights.rs` 10, `mod.rs` 8),
  plus the `pollen_ai_data_rights` regressions registered in `src/tests/`.
- **Naming:** renamed `bud_marketplace` -> `pollen` on 2026-07-18 at the
  user's instruction.

## AccessGrant v2 decisions

Address-bound grant, immutable scope, separate payment, on-chain ReadOnce,
single buyer, `SaleAuthorization`. HPKE hard enforcement sits on top of the
soft enforcement.

## Maturity warnings

- **Tier -1 = protocol admission enforcement.** An AI inference request that
  carries a Pollen `AiDataInputRef` is not admitted without a valid
  `AccessGrant`. That is a strong on-chain read prohibition, but it does not
  guarantee cryptographic privacy while a storage node can see the plaintext.
  Hard enforcement (HPKE key wrapping) is tier -2 (the HSM/encryption domain).
- **P0/P1 core types are present** (`AssetId` is JSON-safe, `Signature64` has a
  sentinel default, plus `DataAsset`, `AccessGrant`, `AiDataInputRef`). The
  next expansion: HPKE key wrapping, DAO encryption parameters, and the
  transaction-backed grant/authorization registration RPC surface.

## Data sovereignty

The assumption is an honest storage node. When the storage node is malicious,
only economic penalties apply (tier -1). With HPKE (tier -2) a storage node
never sees the plaintext.

## Next (P1)

`src/pollen/marketplace.rs` (P1): the RFC section 3.2 primitives plus the
signature helpers (RFC section 5). This file does not exist yet; the offer
economy currently lives in `offers.rs`.
