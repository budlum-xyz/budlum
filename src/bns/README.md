# BNS: the Budlum Name Service (`.bud`) - a module README

**This is BNS's own README, as the module-separation rule requires.**

## Status

- **Maturity:** implemented in `src/bns/` (`registry.rs`: `BnsRegistry`,
  `BNS_PRIMARY_SELLERS`; `types.rs`: `NameRecord`, `BnsError`, `BnsResolved`;
  `bud3.rs`: `Bud3BnsResolver`, `Bud3NameBinding`) and `MarketplaceRegistry`
  (`NameOffer`, `OfferKind`, `CreateNameOffer`).
- **Completed items:**
  - **B1 (`.bud` suffix and label bounds):** every registrable name must consist
    of exactly one lowercase ASCII label (`a-z`, `0-9`, interior `-`) of 3 to 32
    characters followed by `.bud` (e.g. `ayaz.bud`). Suffixless names (`bids`),
    short labels (`ab.bud`), multi-label strings (`sub.ayaz.bud`) and foreign
    suffixes (`ayaz.eth`) return `BnsError::InvalidName`. `calculate_cost`
    computes its 100x / 10x / 1x tiers strictly from the label length (excluding
    `.bud`), and `NameRecord::try_new` plus all `bud_bnsPrepare*` RPC endpoints
    enforce the same rule.
  - **B2 (`.bud` domain marketplace):** direct standalone registration
    (`BnsRegister`) is removed and `BnsRegistry::register` is invoked only from
    consensus settlement. All `.bud` sales flow through `MarketplaceRegistry`
    (`NameOffer` with `OfferKind::Primary` and `OfferKind::Resale`, committed to
    the state root and snapshots). `Primary` offers are restricted to
    `BNS_PRIMARY_SELLERS` (seeded from genesis and updated exclusively via
    `GovernanceAction::BnsSetPrimarySellers`); `Resale` offers transfer live
    seller-owned names and clear pointers. Consensus transactions
    `BnsCreateOffer`, `BnsCancelOffer`, and `BnsBuyName` settle atomically with
    `spendable_balance` paid directly to the seller without burning (while
    `BnsRenew` continues to burn). RPC exposes `bud_bnsGetOffer`,
    `bud_bnsListOffers`, `bud_bnsPrepareCreateOffer`, `bud_bnsPrepareBuyName`,
    and `bud_bnsPrepareCancelOffer`; CLI `bud bns sell` batch-publishes
    `Primary` offers from a file.

## Current behaviour (locked by tests)

Marketplace primary and resale settlement for `<label>.bud` names (3..=32 label
length), label-based renewal cost tiering (3-char labels pay 100x, 4..=6 pay
10x, 7..=32 pay 1x), governance-controlled primary sellers, expiration and
grace-period protection, renewal and transfer transaction doors, owner-only
subdomains, full resolve through storage, B.U.D. 3.0 content binding, and RPC
`bud_bns*` read and prepare validation.

## Test suite

- Covered in `src/bns/registry.rs`, `src/bns/types.rs`, `src/bns/bud3.rs`,
  `src/rpc/tests.rs`, `src/bin/bud.rs`, `src/tests/bns.rs` (2), and
  `src/tests/bns_expanded.rs` (13).
- Runs inside the core lib suite (`cargo test --lib`). The CI gates are
  **`bns-gate`** and **`bns-names`** in `xtask/gates`, both protected against a
  vacuous pass with positive and negative canaries.
