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
    forwarding target, or the owner when that record is empty; `resolve_full`
    answers the same value), adds `BnsSetAddress` (wire tag `74`) and
    `BnsSetPrimary` (wire tag `75`), stores `primary_names` committed into
    `BnsRegistry::root()`, enforces two-way live ownership/target verification on
    `reverse_resolve`, clears stale reverse mappings on `transfer` / target
    rotation, and exposes `bud_bnsReverseResolve` (alias `bud_bnsReverse`),
    `bud_bnsPrepareSetAddress`, `bud_bnsPrepareSetPrimaryName` (alias
    `bud_bnsPrepareSetPrimary`), and `bud bns {set-address,set-primary,reverse}`.
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
  - **B7 (native B.U.D. 3.0 `ContentRef` binding in consensus):** the name
    record carries one content field, `NameRecord::content`
    (`Option<ContentRef>`). `BnsSetContent` (wire tag `6`) carries
    `(name, Option<ContentRef>)`, validates object existence, `ContentId`
    parity and the NFT bond of sealed content against
    `AccountState::bud3_registry`, and `transfer` clears the field.
    `Bud3BnsResolver` holds no table of its own: it reads the record out of
    chain state, and the `Bud3NameBinding` digest
    (`BDLM_BUD3_BNS_BINDING_V2`, over name, owner and reference) is what the
    name leaf commits to. `bud_bnsResolveContent` answers
    `{name, content, bytes, view_error}` through
    `Bud3BnsResolver::resolve_via_bud3_view`; `bud_bnsPrepareSetContent`
    builds the template; the CLI is `bud bns {set-content,get-content}`. Wire
    tag `78` (`BnsSetBud3Content`) is retired and its decoder refuses it.
  - **B8 (grace-period owner rescue, lifecycle status, and owner enumeration):**
    exports `GRACE_PERIOD = 3_000` in `src/registry/params.rs` and `NameStatus`
    (`Active`, `Grace`, `Expired`), allows the current owner to rescue a name in
    `Grace` via `BnsRenew` (`new_expires_at = max(expires_at, current_epoch) + duration`)
    while keeping resolution, mutations, and third-party registration fail-closed,
    automatically invalidates stale `Resale` marketplace offers on `transfer` /
    `buy`, and exposes `bud_bnsListNamesByOwner` and `bud bns list --owner`.
  - **B9 (sparse Merkle tree, per-name proofs, light-client verification):**
    `BnsRegistry::root()` (`BDLM_BNS_REGISTRY_V3`) commits `meta_digest`
    (`BDLM_BNS_META_V1`) and the root of a sparse Merkle tree over the names
    (`src/bns/smt.rs`). Key: `SHA-256("BDLM_BNS_KEY_V1" || name)`. Value: the
    record digest (`BDLM_BNS_LEAF_V1`, which commits to `BDLM_BNS_EXTRAS_V3`).
    Leaf node `BDLM_BNS_SMT_LEAF_V1`, inner node `BDLM_BNS_SMT_NODE_V1`, an
    empty subtree is 32 zero bytes, and a subtree with one name is that
    name's leaf. The tree is updated incrementally: a write marks its name
    and the next read re-hashes only the marked paths. `prove_name` returns
    the path to the name's leaf, or an absence path that ends in an empty
    slot or in another name's leaf. `verify_state_proof` checks both.
    `bud_bnsProof` (alias `bud_bnsGetProof`) returns the record, the path,
    `state_root` and `height`, and `absence {siblings, occupant}` for a name
    the registry does not hold. `budlum-wallet-core` has `verify_bns_proof`,
    which reads that answer, checks it against a header the host trusts
    (`BnsHeaderBook`) and returns the record or the absence. It is exported
    with wasm-bindgen (`BrowserHeaderBook`, `verify_bns_proof`) and through
    the `uniffi_bindings` module. `resolve_bns` takes the answers of every
    configured node, refuses the ones that do not verify and returns the
    freshest one that does; it has the same two exports. `budlum-explorer`
    `BnsInclusionProof::PerName` folds the same path. The three
    implementations pin the same vectors
    (`bns_proof_vectors_are_the_ones_light_clients_pin`).
  - **B10 (`wallet-core` `.bud` recipient validation and proof-verified transfers):**
    adds `crates/wallet-core/src/bns.rs` (`parse_recipient_input`,
    `WalletBnsProof`, `verify_bns_recipient_proof` authenticating custom
    `record.address` via `BDLM_BNS_EXTRAS_V3` + `BDLM_BNS_LEAF_V1` +
    `BDLM_BNS_REGISTRY_V3`), `UnsignedTransfer::to_verified_bud_recipient`, and
    transport-free `bud_bns{Resolve,ResolveFull,GetProof,ReverseResolve}` JSON-RPC
    builders/readers in `crates/wallet-core/src/rpc.rs`.
  - **B11 (identity profile and SocialFi `.bud` integration):**
    enforces canonical `.bud` validation on identity profiles, binds V3 text and
    social records (`IdentitySocialSummary`), B.U.D. 3.0 `ContentRef`, and
    per-name `BnsStateProof` Merkle verification into
    `build_identity_profile_verified`, discloses node-asserted reverse-resolved
    `primary_name` with an explicit `EvidenceStatus::Unverified` card because
    the per-name proof commits to `primary_names` only as a whole, and attaches
    reverse-resolved `author_bud_name` handles to SocialFi RPC posts and feeds.
  - **B12 (complete `bud bns` CLI and static site publishing):**
    completes `bud bns` with `resolve [--verify-proof]`, `info`, `offers`,
    `get-offer`, and `publish-site` (packaging single files or static site
    directories into B.U.D. 3.0 via `StorageTxV3::RegisterObject` +
    `BnsSetContent` + `BnsSetRecords`), and upgrades `bud tx send --to` to
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
    with `bns_content_unknown` unless the reference names an object the
    B.U.D. 3.0 registry holds under the same content id. Sealed content
    needs an NFT, and an NFT the reference names has to be bound to that
    object. Share confirmation is not required: `bud bns publish-site`
    registers and names a site in one block.
  - **Storage root existence at the consensus door:** `BnsSetStorage` is
    refused with `bns_storage_unknown` unless the root equals the finalized
    root the chain holds for the named domain (`AccountState::external_roots`,
    written only by a finalized domain commitment). The chain keeps one root
    per domain, the latest. A name bound to an older root keeps it, and
    `storage_root_height` says when it was bound.
  - **`bud_bnsPrepareSetStorage`:** builds the `BnsSetStorage` template and
    refuses a root that is not 32 bytes.
  - **Subdomain records:** a subdomain is a `SubdomainRecord { owner,
    address, content }`. `register_subdomain` refuses a label that exists
    with `NameTaken`; the parent owner removes it first. `BnsSetSubdomainContent`
    (wire tag `79`) is signed by the subdomain owner, not the parent owner,
    sets or clears the content (an `Option<ContentRef>`, checked like
    `BnsSetContent`), is refused with `bns_content_unknown` for content the
    registry does not hold, and is refused
    once the parent name expired. `bud_bnsResolveSubdomainContent` and
    `bud_bnsPrepareSetSubdomainContent` expose it. RPC answers and proofs
    carry each subdomain as `{owner, address, content}`, and the extras
    commitment that binds all three is `BDLM_BNS_EXTRAS_V3`. A transfer of
    the parent still clears every subdomain.
  - **Gateway answers:** an expired record whose proof folds to the verified
    root is a 404, a proof that does not fold is a 502, two nodes that answer
    with different heights disagree, and a site policy of `'none'` narrows the
    baseline. A subdomain is served from the public content its own
    `SubdomainRecord` names and never from the parent: with none it is a 404.
    The CLI command is `bud bns set-subdomain-content`.

- **Open items (not implemented):**
  - `bud_bnsResolveContent` returns `bytes: null` with a `view_error` on a
    node that holds no symbols of the object: the RPC node has no symbol
    transport of its own. The reference in `content` is always answered.
  - `bns_v1` enters the block `state_root` through one flat hash with the
    other registries, so the registry root cannot be opened from a header
    alone. A light client needs the registry root of a height from a source
    it trusts for that header. `bud_bnsProof` returns `state_root` and
    `height` so the answer names its header; it does not make the root
    derivable.
  - The `uniffi_bindings` module is plain Rust: the crate has no UniFFI
    dependency and no `.udl`, so Kotlin and Swift code is not generated yet.
    `bindings_are_wired` stays false for that reason. The wasm-bindgen
    export is real.
  - The gateway binary reads verified header roots and epochs from the
    `[[checkpoints]]` of its configuration and from an optional
    `checkpoints_file` it re-reads when the file changes. It judges expiry
    against that epoch, never against the epoch a node answer carries. A
    height with no checkpoint is unknown and answers 502. The binary does
    not follow headers itself: another process has to keep the file
    current. Its content source is a local directory and its content cache
    is in memory. Cache misses have their own per-client limit
    (`fill_per_minute`), and the process logs its counters once a minute. `serve`
    and `tls` live in the binary, not in `src/web_gateway/`.

### Proof hardening (review findings)

The `bns-gate` list also names the two tests below. Both close a hole where a
proof was well formed, opened to the header root, and still said something the
root does not say.

- **Absence proofs are paths.** The slot of a name is fixed by its key, so
  the only path that folds to the root for a held name ends in that name's
  own leaf. `verify_state_proof` refuses an absence path whose occupied slot
  is the queried key itself or does not share the queried prefix, and an
  inclusion proof that also carries an absence path. The path of one name
  cannot be replayed for another, because each level's side is a bit of the
  key. `bns_absence_proof_cannot_hide_a_live_name` covers each forgery.
- **Extras ship their pre-image.** `BnsMerkleBranch::extras` is the
  `BnsBranchExtras` the `extras_digest` commits to: address, both
  domain ids, storage root height, the B.U.D. 3.0 reference, subdomains and
  records. `verify_state_proof` recomputes the digest from it and refuses the
  branch on any mismatch, and refuses a top-level `address` that contradicts
  it. `evaluate_bns_evidence` marks a profile Verified only when a verified
  proof discloses an extras pre-image that matches every field the profile
  prints. Before this, the digest was opaque and the disclosed values were
  whatever the answering node chose.

The root a proof is checked against always comes from a header the verifier
trusts, never from the answer: `verify_bns_proof` and
`verify_bns_recipient_proof_from_header` in the wallet take a header source,
and no entry point takes a root as an argument.

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
`gateway-gate` names ten of these tests: the cookie prohibition, the CSP floor,
the traversal rule, the 502-on-tampered-proof rule, the 404 for an expired
record and for a proven absence, the subdomain that never falls back to its
parent, and the rule that one prover alone is not agreement. None of them can be
deleted without failing the relay. The `bns-gate` CI job runs the gate against
the `web_gateway` test log and runs the tests of the `budlum-gateway` binary.

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
