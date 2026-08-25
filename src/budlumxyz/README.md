# The budlumxyz registry - a module README

**This is budlumxyz's own README, as the module-separation rule requires.**
The root `README.md` is only a dashboard; the maturity and risk warnings live
here.

## Status

- **Maturity:** a skeleton. The registration and resolve types exist; the
  economy and governance come after mainnet.
- **Code location:** `src/budlumxyz/`, with `mod.rs` (`BudlumxyzRegistry`) and
  `types.rs` (`AppRecord`).
- **Test count:** 10, all in `src/budlumxyz/mod.rs`.

  Note: an earlier version of this file said "0 tests; behaviour is covered
  indirectly in the parent tests through the `MarketplaceRegistry` pattern".
  That was measured and is wrong: the module carries its own tests.
- **Snapshot:** `StateSnapshotV2.budlumxyz: Option<BudlumxyzRegistry>` (inside
  the GAP-2 digest).

## Maturity warnings

- **Out of scope for mainnet v1.** budlumxyz - the application registry listing
  DeEd, SocialFi and dApps - is post-launch. It stays empty on mainnet until
  governance activates it.
- **No economic model.** Listing fees, curation and slashing are a post-mainnet
  design.

## Next

Extending budlumxyz, after mainnet, on the user's instruction.
