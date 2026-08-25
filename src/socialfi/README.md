# SocialFi / the NFT registry - a module README

**This is SocialFi's own README, as the module-separation rule requires.**
The root `README.md` is only a dashboard; the maturity and risk warnings live
here.

## Status

- **Maturity:** live (the NFT registry plus the boost economy).
- **Code location:** `src/socialfi/`, with `mod.rs` (`NftRegistry`) and
  `types.rs` (`Nft`).
- **Test count:** 4 unit tests in `src/socialfi/mod.rs`, plus 2 async tests in
  `src/tests/socialfi.rs`. They run inside the core suite; there is no separate
  module gate.
- **Snapshot:** `StateSnapshotV2.nft_registry: Option<NftRegistry>` (inside the
  GAP-2 digest).

## Maturity warnings

- **The boost economy.** NftBoost sends a 4% B.U.D. share to the operator pool
  (`distribute_bud_boost_share_in_state` in `src/chain/blockchain.rs`, the F4
  fix). `NftBurn` triggers the storage pruning hook
  (`NodeCommand::StoragePrune`).
- **Out of scope for mainnet v1** (debt M10: SocialFi, budlumxyz and the
  marketplace are all post-launch). `nft_registry` stays empty on mainnet until
  governance activates it.
- **The NftBoost integer overflow** (security review H3) is closed. The guard
  is in `src/execution/executor.rs`: the cost, the creator share and the pool
  share each go through `checked_add`/`checked_mul` and refuse with a
  validation error rather than wrapping.

  Note: an earlier version of this file said the fix used `saturating_mul`.
  That was measured and is wrong - saturating would have silently capped the
  value, which is the opposite of refusing.

## Next

Extending SocialFi, after mainnet. The boost economy model is documented.
