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
  - **B3 (anti-squatting limits and reserved labels):** protocol constants in
    `src/registry/params.rs` (`RESERVED_LABELS`, `MIN_DURATION = 10`,
    `MAX_DURATION = 365_000`, `MAX_NAMES_PER_OWNER = 64`) guard all BNS write
    paths. `RESERVED_LABELS` covers core service labels (`bud`, `www`, `app`,
    `api`, `rpc`, `docs`, `mail`, `explorer`, `faucet`, `status`, `testnet`,
    `mainnet`, `devnet`, `seed`, `seed-1`, `root`, `admin`, `bns`, `budlum`,
    `validator`, `node`, `gateway`), is seeded from
    `GenesisConfig::bns_reserved_labels` and committed into `BnsRegistry::root()`,
    and may only be registered when an authorized `BNS_PRIMARY_SELLERS` address
    settles a `Primary` marketplace offer. Registration and renewal durations
    outside `MIN_DURATION..=MAX_DURATION` (including post-renewal remaining
    duration above `MAX_DURATION`) return `BnsError::InvalidDuration`, and
    holding `MAX_NAMES_PER_OWNER` live/grace names blocks further purchases or
    incoming transfers with `BnsError::OwnerNameLimitExceeded`.
  - **B4 (forward target address and bidirectional reverse resolution):**
    separates `resolve_owner` (authorization) from `resolve` (`record.address`
    forwarding target), adds `BnsSetAddress` (wire tag `74`) and
    `BnsSetPrimaryName` (wire tag `75`), stores `primary_names` committed into
    `BnsRegistry::root()`, enforces two-way live ownership/target verification on
    `reverse_resolve`, clears stale reverse mappings on `transfer` / target
    rotation, and exposes `bud_bnsReverseResolve`, `bud_bnsPrepareSetAddress`,
    `bud_bnsPrepareSetPrimaryName`, and `bud bns {set-address,set-primary,reverse}`.
  - **B5 (bounded text/profile/multi-chain records and `BDLM_BNS_REGISTRY_V3`):**
    adds `NameRecord::records` (`MAX_RECORDS_PER_NAME = 32`,
    `MAX_RECORD_KEY_LEN = 64`, `MAX_RECORD_VALUE_BYTES = 512`, rejecting
    `javascript:`/`vbscript:`/`data:`/`file:` URIs and control bytes), bumps
    `BnsRegistry::root()` and `budlum-explorer` to `BDLM_BNS_REGISTRY_V3`
    (registered in `src/crypto/domain_tags.rs`), adds `BnsSetRecords` (wire tag
    `76`), clears `records` on `transfer`, and exposes `bud_bnsGetRecords`,
    `bud_bnsPrepareSetRecords`, and `bud bns {set-record,get-records}`.
  - **B6 (two-level `.bud` subdomains and consensus door hardening):** resolves
    `<sub_label>.<label>.bud` directly through `BnsRegistry::resolve` (failing
    closed on parent expiry or 3+ label hierarchies), adds `remove_subdomain` /
    `list_subdomains` and `BnsRemoveSubdomain` (wire tag `77`), hardens
    `BnsSetContent`, `BnsRegisterSubdomain`, and `BnsSetStorage` to require zero
    header amount/recipient and unlocked spendable fee balance, and exposes
    `bud_bnsListSubdomains`, `bud_bnsPrepareRemoveSubdomain`, and
    `bud bns {set-subdomain,remove-subdomain,list-subdomains}`.
  - **B7 (native B.U.D. 3.0 `ContentRef` binding in consensus):** adds
    `NameRecord::bud3_content` (`Option<ContentRef>`) committed into
    `BnsRegistry::root()`, validates object existence, `ContentId` parity, and
    sealed NFT requirements against `AccountState::bud3_registry` via
    `BnsSetBud3Content` (wire tag `78`), clears `bud3_content` on `transfer`,
    resolves on-chain bindings directly in `Bud3BnsResolver::resolve_via_bud3_view`,
    and exposes `bud_bnsGetBud3Content`, `bud_bnsPrepareSetBud3Content`, and
    `bud bns {set-bud3,get-bud3}`.
  - **B8 (grace-period owner rescue, lifecycle status, and owner enumeration):**
    exports `GRACE_PERIOD = 3_000` in `src/registry/params.rs` and `NameStatus`
    (`Active`, `Grace`, `Expired`), allows the current owner to rescue a name in
    `Grace` via `BnsRenew` (`new_expires_at = max(expires_at, current_epoch) + duration`)
    while keeping resolution, mutations, and third-party registration fail-closed,
    automatically invalidates stale `Resale` marketplace offers on `transfer` /
    `buy`, and exposes `bud_bnsListNamesByOwner` and `bud bns list --owner`.
  - **B9 ($O(\log N)$ per-name Merkle state proofs and browser verification):**
    upgrades `BnsRegistry::root()` (`BDLM_BNS_REGISTRY_V3`) to commit
    `meta_digest` (`BDLM_BNS_META_V1`) + binary `names_merkle_root`
    (`BDLM_BNS_LEAF_V1`, `BDLM_BNS_EXTRAS_V1`, `BDLM_BNS_NODE_V1`), adds
    `prove_name` / `verify_state_proof` (supporting both inclusion and adjacent
    boundary non-existence proofs), upgrades `budlum-explorer`
    `BnsInclusionProof::PerName` to produce `Strength::Verified` against
    `bns_v1` while refusing expired or forged proofs, and exposes
    `bud_bnsGetProof` and `bud bns proof --name`.
  - **B10 (`wallet-core` `.bud` recipient validation and proof-verified transfers):**
    adds `crates/wallet-core/src/bns.rs` (`parse_recipient_input`,
    `WalletBnsProof`, `verify_bns_recipient_proof` authenticating custom
    `record.address` via `BDLM_BNS_EXTRAS_V1` + `BDLM_BNS_LEAF_V1` +
    `BDLM_BNS_REGISTRY_V3`), `UnsignedTransfer::to_verified_bud_recipient`, and
    transport-free `bud_bns{Resolve,ResolveFull,GetProof,ReverseResolve}` JSON-RPC
    builders/readers in `crates/wallet-core/src/rpc.rs`.
  - **B11 (identity profile and SocialFi `.bud` integration):**
    enforces canonical `.bud` validation on identity profiles, binds V3 text and
    social records (`IdentitySocialSummary`), B.U.D. 3.0 `ContentRef`,
    bidirectional primary `.bud` names, and per-name `BnsStateProof` Merkle
    verification into `build_identity_profile_verified`, and attaches
    reverse-resolved `author_bud_name` handles to SocialFi RPC posts and feeds.
  - **B12 (complete `bud bns` CLI and static site publishing):**
    completes `bud bns` with `resolve [--verify-proof]`, `info`, `offers`,
    `get-offer`, and `publish-site` (packaging single files or static site
    directories into B.U.D. 3.0 via `StorageTxV3::RegisterObject` +
    `BnsSetBud3Content` + `BnsSetRecords`), and upgrades `bud tx send --to` to
    verify `.bud` recipient Merkle proofs client-side.

  - **B12b (governance price door):** `ProposalType::BnsSetBaseCost` and
    `GovernanceAction::BnsSetBaseCost` replace `BnsRegistry::base_cost` and
    nothing else. `BnsRegistry::check_base_cost_bounds` enforces
    `MIN_BNS_BASE_COST..=MAX_BNS_BASE_COST` at proposal submission;
    `BnsRegistry::set_base_cost` enforces the same bounds plus
    `BNS_BASE_COST_MAX_STEP_FACTOR` (10x in one step, symmetric, never clamps)
    at execution. A registered name keeps its owner and term, and the next
    renewal is charged at the new base. All three constants live in
    `src/registry/params.rs`.
  - **B13 (capacity parameter and the expiry index):** `DEFAULT_MAX_NAMES`
    (`1_000_000`) is the genesis value of `BnsRegistry::max_names`, a stored
    field rather than a constant, so a snapshot restores the ceiling it was
    written with. `BnsRegistry::expired_by_grace_end` is a `BTreeSet` keyed by
    `(expires_at + GRACE_PERIOD, name)`; `register` reclaims the head of the
    set instead of scanning every record, `renew` re-indexes the new expiry,
    `prune_expired` deletes the expired prefix at the epoch boundary, and
    `rebuild_expiry_index` restores the view after a snapshot load. The index
    is skipped by serde and is not part of `BnsRegistry::root()`.
  - **B15 (metrics):** `budlum_bns_names_in_grace`, `budlum_bns_open_offers`,
    `budlum_bns_sales_total` and `budlum_bns_sales_amount_total` join the
    existing name counters, and every BNS write type has its own
    `budlum_bns_<type>_total` counter incremented at the applied-transaction
    site, so a refused transaction moves none of them.
  - **B16 (tests and gates):** `bns-gate` names the seven B12/B13/B15/B16
    tests, so a green relay requires them to exist and pass. The root property
    test (`bns_root_is_independent_of_insertion_order`) runs under `proptest`,
    and the gates keep their positive and negative canaries.

  - **Content existence at the consensus door:** `BnsSetContent` is refused
    with `bns_content_unknown` unless the id is a public B.U.D. 3.0 object
    whose shares are all confirmed. Sealed content binds only through
    `BnsSetBud3Content`, which checks the NFT grant.
  - **`bud_bnsPrepareSetStorage`:** builds the `BnsSetStorage` template and
    refuses a root that is not 32 bytes.
  - **Gateway answers:** an expired record whose proof folds to the verified
    root is a 404, a proof that does not fold is a 502, two nodes that answer
    with different heights disagree, and a site policy of `'none'` narrows the
    baseline.

- **Open items (not implemented):**
  - `BnsSetStorage` does not look the root up anywhere, because the chain
    holds no per-domain storage root table. There is no `bns_storage_unknown`
    refusal.
  - A subdomain is an owner pointer (`BTreeMap<String, Address>`). There is
    no `SubdomainRecord`, no `BnsSetSubdomainContent` and no subdomain content
    RPC, so a subdomain serves the content of its parent name.
  - `NameRecord` still carries the unused `resolver` field and two content
    fields (`content_id` and `bud3_content`). They are not merged into one
    `ContentRef`.
  - The name tree is a binary Merkle tree over the sorted names with
    adjacent-leaf absence proofs. It is not a sparse Merkle tree and is
    recomputed from the rows, not updated incrementally.
  - `wallet-core` verifies a recipient proof against a header it trusts
    (`verify_bns_recipient_proof_from_header`). No entry point takes a root
    as an argument. It has no `resolve_bns` and no generated mobile or
    browser bindings for it.
  - The gateway binary reads pinned header roots and epochs from its
    configuration and judges expiry against the pinned epoch, never against
    the epoch a node answer carries. A height with a root and no pinned epoch
    is unknown. It does not follow headers with the light client. Its content
    source is a local directory and its content cache is in memory. `serve`
    and `tls` live in the binary, not in `src/web_gateway/`.

### Proof hardening (review findings)

The `bns-gate` list also names the two tests below. Both close a hole where a
proof was well formed, opened to the header root, and still said something the
root does not say.

- **Absence proofs carry positions.** `BnsMerkleBranch::leaf_index` and
  `tree_size` are the leaf's position in the ordered name list and the size of
  that list. `check_boundary_pair` requires both boundary branches to agree on
  the size and to be adjacent positions, so "no name sorts between these two"
  is checked instead of assumed. Order alone was not a proof: every branch in
  the tree sorts next to some target, so an honest inclusion branch of a live
  name could be relabelled and served as proof that the target is free. A
  branch without a position still verifies for inclusion and is refused for
  non-inclusion.
- **Extras ship their pre-image.** `BnsMerkleBranch::extras` is the
  `BnsBranchExtras` the `extras_digest` commits to: resolver, address, both
  domain ids, storage root height, the B.U.D. 3.0 reference, subdomains and
  records. `verify_state_proof` recomputes the digest from it and refuses the
  branch on any mismatch, and refuses a top-level `address` that contradicts
  it. `evaluate_bns_evidence` marks a profile Verified only when a verified
  proof discloses an extras pre-image that matches every field the profile
  prints. Before this, the digest was opaque and the disclosed values were
  whatever the answering node chose.

Known open finding, not fixed here: the digest is over the registry's name
ordering, so a non-inclusion proof still relies on the prover having read the
header. Separating "the header root at this epoch" from "the root the prover
names" is the wallet-side change tracked in PR #126.

### B14: the network gateway (`budlum.xyz`)

A `.bud` name is reachable as `ad.budlum.xyz` through `src/web_gateway`, and the
gateway's answer is derived, never asserted. `budlum.xyz` belongs to Budlum, so
the wildcard certificate and the wildcard DNS record are both within one
operator's control.

- **`host`** parses a `Host` header into a registry name and an optional
  subdomain label. `ayaz.budlum.xyz` is `ayaz.bud`; `shop.ayaz.budlum.xyz` is
  `ayaz.bud` with subdomain `shop`; more than one subdomain, a look-alike
  suffix, a bare apex, a bad label or any of `RESERVED_LABELS` returns `None`.
  Case is folded before the check, so `AYAZ.budlum.xyz` is the same name; the
  suffix is configuration (`DEFAULT_GATEWAY_SUFFIX` is `budlum.xyz`) and the
  label table is `BnsRegistry::is_valid_label`, now public for exactly this
  reason. A reserved label goes to a Budlum service, never to BNS, and an
  explicit DNS record backs each one.
- **`manifest`** maps a request path to a `ContentRef` and a mime type. The
  traversal rule lives here and nowhere else: a `..` or `.` segment, a doubled
  slash, a backslash or a NUL is refused before any lookup, and a path the
  manifest does not carry is a 404 rather than a fallback, because a fallback
  is where one site's bytes answer another site's URL. The mime allow list is
  enforced when a route is resolved.
- **`policy`** holds the response headers, the per-key fixed-window rate
  limiter and the block list. A response never carries `set-cookie`: a cookie
  set here belongs to the suffix, not to the name, and would follow the reader
  to every other name. A site may narrow the `Content-Security-Policy` and may
  never widen it; the comparison is conservative, so a policy the gateway cannot
  parse is refused rather than trusted. Content addressed by `ContentId` is immutable
  for a year; a name resolution is cached for ten seconds, because a record can
  move. A block list affects this gateway only and never touches a chain
  record, which is the only statement a host can honestly make.
- **`resolve`** is the trust boundary. `resolve_verified` asks every configured
  prover, requires them to agree (a disagreement is a refusal, not a vote),
  takes the state root of the proof's height from a light client that already
  verified the header, requires the proof to fold to that root, and reads every
  served field from the folded branch. A record supplied next to the proof is
  never read: that would be a second source for the same fact, and the second
  source is the one an attacker writes. A failed proof is a 502 and no content;
  `ContentCache` re-checks every byte against the `ContentId` digest on insert
  and again on read, so a bad write cannot become a bad page.

The module is `web_gateway`, not `gateway`: `src/gateway` already holds the
wallet gateway (atlas, passport, service), which is a different thing. The gate
`gateway-gate` names six of these tests, including the cookie
prohibition, the CSP floor, the traversal rule and the 502-on-tampered-proof
rule, so none of them can be deleted without failing the relay.

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
  `src/tests/bns_expanded.rs` (21).
- Runs inside the core lib suite (`cargo test --lib`). The CI gates are
  **`bns-gate`** and **`bns-names`** in `xtask/gates`, both protected against a
  vacuous pass with positive and negative canaries.
