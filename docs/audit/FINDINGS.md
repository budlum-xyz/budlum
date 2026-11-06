# Finding ledger (WP-04)

Package WP-04, lane D. This is the flat, directive-numbered ledger that card item 3 asks for:
one row per record with its identity, importance, area, English title, live state, test name and
closing package. Section 14 of `THE_BUDLUM_DIREKTIF.md` is the source; this file is its English form
for the records that belong to lane D.

Snapshot: `main` = `cccf1da1f4bcfe97503a3a00cfba24b172b49b31`, read 2026-11-06 05:50 UTC.
Lane ledger: `docs/audit/live/lane-d.md`. Status index: `docs/audit/LIVE_STATUS.md`.

## How a state is decided

| State | Meaning |
|---|---|
| Fixed in the tree | The code no longer shows the defect and a test or a build declaration pins it. **Not closed**: section 15.5 rule 8 closes a record in this file only with a commit SHA and a CI run number, and this repository has no completed CI run yet (400 sampled runs: 152 `cancelled`, 348 without a conclusion, 0 `success`, 0 `failure`). |
| Not reproducible | The tree no longer carries what the record describes, and the record text is not available to decide whether that is the fix. |
| Partly fixed | Some clauses of the record are closed in the tree and others were not re-tested. |
| Measured | The record is a count, and the count was recomputed; the number is in `docs/audit/live/lane-d.md`. |
| Open | The defect is still present, or nothing has been checked against the record yet. |

The last case is the honest default. Section 15.8 (WP-01 item 2) places the old finding ledger, which
holds each record's description and evidence, outside this repository, and it is not in this
checkout. This file therefore never writes "fixed" for a record it did not read.

## Records

| Id | Importance | Area | Title | State | Test | Closing package |
|---|---|---|---|---|---|---|
| BLG-004 | Medium | crypto | Rewriting the key file does not narrow the permissions it already has | Open | not run | WP-61 |
| BLG-009 | Medium | crypto | The PQ API does not require the registered FIPS context and an explicit scheme id | Open | not run | WP-61 |
| BLG-010 | Medium | crypto | The PKCS#11 key label is applied after the constructor binds an unlabelled single key | Open | not run | WP-61 |
| BLG-011 | Medium | ops | The shipped systemd unit does not provide the RPC credential the runtime reads and raises LimitCORE to infinity | Open | not run | WP-41 |
| BLG-012 | High | ci | The global coverage ratchet reads the first file's percentage instead of the total, and passes a NaN floor | Open | not run | WP-42 |
| BLG-013 | Medium | ci | The documented prepush helper always runs the deliberately invalid all-features combination | Open | not run | WP-42 |
| BLG-014 | Medium | ci | The backup drill ignores the --check-db exit code and accepts a substring match as success | Open | not run | WP-42 |
| BLG-015 | Medium | ci | Unit tests of three standalone Rust packages never run under the root cargo test --workspace | Open | not run | WP-42 |
| BLG-016 | High | ci | A fresh RustSec scan finds patchable advisories in six of the eleven tracked lockfiles | Open | not run | WP-42 |
| BLG-022 | Medium | light-client | The light client checkpoint iterator loops forever at u64::MAX and costs O(interval) on large intervals | Open | not run | WP-11 |
| BLG-026 | Medium | ci | Sub-workspaces lack fmt, clippy and --locked coverage, one gate test is an empty assert, and the wallet seed path is twelve words and not NFKD | Open | not run | WP-39 |
| BLG-029 | High | rpc | Client IP extraction trusts the first X-Forwarded-For entry and the rate limiter evicts FIFO, so the per-IP quota and the allow list can be bypassed | Open | not run | WP-61 |
| BLG-030 | Critical | rpc | Public RPC endpoints change consensus state outside block execution and the developer faucet stays open on the testnet chain id | Open | not run | WP-61, WP-41 |
| BLG-032 | Medium | rpc | The gateway content key is separated from the Pollen guard, the production cache resets on every request, and fourteen Prepare templates emit invalid nonce or fee | Open | not run | WP-61 |
| BLG-068 | High | explorer | The explorer marks an unverified storage root backup as verified, resolves a content id search to a wallet account, and carries address bar, CID and scoring defects | Open | not run | WP-40 |
| BLG-081 | High | ci | Gate blind spots in workspace and first-party crate coverage: a wallet-core directory that does not exist, geiger classifying first-party crates as third-party, and bud/ outside the scan | Open | not run | WP-42 |
| BLG-082 | High | ci | Static analysis blind spots: a while/for decoy escape in the AST gate, a UTF-8 slicing panic in the panic gate, and gaps in the reachability and chain-id checks | Open | not run | WP-42 |
| BLG-083 | Medium | ci | Verification gaps in the supply count, ratio consensus, metric, indexing, badge and actionlint gates | Open | not run | WP-42 |
| BLG-084 | High | ci | The relay gate returns Ok on a signature or digest mismatch, the regeneration gate silently restores a deleted source file, and --all skips the tree pin | Open | not run | WP-42 |
| BLG-085 | High | ci | Seven further gates scan a nonexistent wallet-core root, standalone workspaces lack release hardening, and the signature, timing and paid-content checks are partial | Open | not run | WP-42 |
| BLG-086 | Medium | ci | A UTF-8 panic in the brand gate, predictable /tmp directories, a substring match standing in for a test name, an escape bug in the literal stripper, and Turkish strings left in gates | Open | not run | WP-42 |
| BLG-087 | High | ci | Unbounded bincode deserialization in fuzz targets, an empty consensus_validate target, a zk_verifier target that never reaches the verifier, and a u8 wrap in the throughput bench | Open | not run | WP-42 |
| BLG-092 | High | docs | A public framing rule is broken in five documents, the Turkish README leaks a private key through argv, and stale architecture and path references remain | Open | not run | WP-43 |
| BLG-095 | Medium | ops | Supply-chain scripts and Dependabot skip most of the eleven lockfiles, the audit config keeps a stale exception, CODEOWNERS is empty, and fifteen workflows name a deleted branch | Open | not run | WP-41 |
| BLG-097 | High | ci | The kani and bud/fuzz workspaces have no Cargo.lock, kani/src/lib.rs fails on unexpected_cfgs, bud/kani/kani_bud_format.rs is an orphan that cannot compile, and crates/budscan has no CI job | Open | not run | WP-42 |
| BLG-098 | Critical | security | The arg-skipped NodeConfig defaults open the RPC, a single environment variable without an API key stops startup, and the validator role closes the local operator listener | Partly fixed: the auth and allow-list defaults are closed | not run | WP-39 |
| BLG-099 | High | security | The constant-time string compare compares the buffer with itself on a length mismatch, so the optimiser removes the loads and the API-key length leaks | Fixed in the tree, not closed (no CI run) | constant_time_eq_str_correctness | WP-61 |
| BLG-117 | Critical | wallet | A four-round Poseidon permutation and an i32 recipient tag lock every private note, spending secrets carry 64-bit entropy, and a recovery proposal replays across chains and A to B to A | Open | not run | WP-39 |
| BLG-121 | High | explorer | ENS arweave name service verification always refuses, an expired BNS record is marked verified, a Merkle balance is unbound, and the patchset walk escapes its directory | Open | not run | WP-40 |
| BLG-143 | High | explorer | Real content manifest ids are always refused, the HTTPS target scheme is not validated, an evidence badge carries no reason, and a domain profile fails to deserialize | Open | not run | WP-40 |
| BLG-150 | Critical | crypto | Prevote, precommit and block signatures share one preimage and the address is derived from a raw key, plus a nullifier of zero is accepted as a proof | Open | not run | WP-61 |
| BLG-169 | Medium | sdk | The developer config silently swallows removed sections, the punycode normaliser mishandles case and scheme, name records have unvalidated constructors, and tier labels are undocumented | Open | not run | WP-40 |
| BLG-170 | High | ci | Concurrent verification escapes and comment or character-literal blindness across the AST and source-scanning security gates | Open | not run | WP-42 |
| BLG-171 | High | ci | Error swallowing, a comment-line canary and multi-line download escapes in the workflow security gates | Open | not run | WP-42 |
| BLG-172 | Medium | ops | The developer tools emit an invalid PoA validators file, the RPC ports collide, a fuzz corpus writes to a dead path, the backup drill reports false positives, and the prepush check is partial | Open | not run | WP-42 |
| BLG-174 | High | ci | Zero-multiplier first-row pinning, one-sided rs2 canonicality blindness and decoy forgery tests across five ZK and AIR soundness gates | Open | not run | WP-42 |
| BLG-175 | High | ci | Pinned git dependencies can slip past the supply-chain gate, and the Docker toolchain, image manifest and domain tag gates are blind in specific cases | Open | not run | WP-42 |
| BLG-176 | Medium | bench | The pipeline throughput bench rejects every transaction, the canonical program set is missing its fourth member, micro-benchmarks cap at u32::MAX, and test modules ship in production | Open | not run | WP-42 |
| BLG-177 | Medium | registry | An extra digest input in the address gate, one-byte dust laundering in server admission, a role id collision, and a magic value outside the registry | Open | not run | WP-42 |
| BLG-178 | High | ci | A zero-constraint AIR proof passes the zero-tests gate, gas calibration is shadowed by a comment and leaks across arms, the forgery test scan is blind to one file, and the required-tests gate is vacuous | Open | not run | WP-42 |
| BLG-179 | High | ci | Snapshot map-key serialization is blind to enum and tuple keys, the genesis schema misses validators, allocations and ratios, and two gates can be bypassed | Open | not run | WP-42 |
| BLG-180 | Medium | ci | Tuple-key, comment-mask and cfg(all(test)) blindness in the content encryption, coding audit, AI prompt and idle-code gates | Open | not run | WP-42 |
| BLG-181 | Medium | ci | A fixed 128-byte split in the MPT fuzz target, a dead prefix and path normalisation in module coverage, an empty root scripts gate, and a test module exported in production | Open | not run | WP-42 |
| BLG-187 | High | ci | Deep reorganization is unreachable in five fuzz targets and the custody oracles are missing | Open | not run | WP-42 |
| BLG-188 | High | ci | A runtime inversion in the uncheckable-proof gate plus bypasses in four further gates | Open | not run | WP-42 |
| BLG-189 | Medium | ci | Blind spots in five pricing and placement gates, a missing 16-byte wire size in the differential table, and an integer gauge overflow | Open | not run | WP-42 |
| BLG-192 | High | rpc | bud_estimateGas ignores the proportional transfer fee and the folded governance proposal fee, so it under-reports the fee | Open | not run | WP-61 |
| BLG-193 | Medium | ci | Comment and syntax bypasses, fake test output accepted as a pass, and English-tree gate blind spots across thirty-four gate modules | Open | not run | WP-42 |
| BLG-200 | High | crypto | BLS key constructors accept a zero secret and the identity point, the finality aggregator is open to identity-signature poisoning, one keypair test passes wrongly, and RLP encoding and decoding have no depth bound | Open | not run | WP-61 |
| BLG-231 | Medium | docs | A BudZero document claims recursive aggregation that the code does not implement | Not reproducible: the sentence is absent from both files the record names | not run | WP-43 |
| BLG-241 | Low | docs | BudZero documents describe a Poseidon width of eight while the code uses twelve | Open | not run | WP-43 |
| BLG-254 | High | ci | Three gates force the model that B.U.D. 3.0 is a recipe only, which the correct model cannot merge with | Open | not run | WP-07, WP-42 |
| BLG-255 | Low | naming | Retired concept names remain spread across the tree | Measured: see lane-d.md section 6.3 | not run | WP-05, WP-43 |
| BLG-257 | High | mobile | No mobile client application exists; the mobile profile is only a node command-line flag, so a phone user cannot become a validator | Open | not run | WP-11, WP-36 |
| BLG-259 | Medium | light-client | A checkpoint certificate carrying one ML-DSA-65 signature per seat is about 420 KB at 128 seats, which is large for a mobile light client, and the trust model is not documented | Open | not run | WP-12, WP-11 |
| BLG-265 | Medium | mobile | The mobile power and challenge model ignores Android foreground service limits | Open | not run | WP-36 |
| BULGU-011 | S3 | rpc | A CORS wildcard reflects the caller's origin header | Fixed in the tree, not closed (no CI run) | cors_wildcard_does_not_reflect_headers | WP-61 |
| BULGU-012 | S3 | rpc | A serialization failure is answered with a silent null | Fixed in the tree, not closed (no CI run) | rpc_serialization_error_is_explicit | WP-61 |
| TEST-GAP-02 | Medium | ci | Kani covers a quarter of the SECURITY.md targets | Open | not run | WP-42 |
| TEST-GAP-04 | Low | ci | src/bin/budlum-domain-producer.rs has no tests | Open | not run | WP-42 |
| TEST-GAP-07 | Low | rpc | Direct test coverage of the RPC endpoints is low | Open | not run | WP-61 |
| DOC-GAP-01 | S1 | ops | The first testnet run is blocked because the SoftHSM configuration is missing | Open | not run | WP-41 |
| DOC-GAP-02 | S3 | docs | Port documentation disagrees across the four modes | Open | not run | WP-43 |
| DOC-GAP-03 | S3 | docs | The README, CONTRIBUTING and ops/scripts reference scripts that do not exist | Open | not run | WP-43 |
| DOC-GAP-04 | S3 | ops | The systemd unit names the wrong repository and omits the HSM context | Open | not run | WP-41 |
| DOC-GAP-05 | S3 | docs | Three operator guides contain half sentences | Open | not run | WP-43 |
| DOC-GAP-06 | S3 | docs | The source measurement tables are empty | Open | not run | WP-46 |
| DOC-GAP-07 | S3 | ci | The budlum-indexer binary has no explicit registration | Fixed in the tree: Cargo.toml:255 declares the bin | not run | WP-42 |
| DOC-GAP-08 | S3 | cli | The CLI fee default disagrees with the network base fee | Open | not run | WP-39 |
| DOC-GAP-09 | S3 | docs | The ledger table needs detail that WP-04 verifies | Open | not run | WP-43 |

## Named-test rule

Section 16.4 rule 1 requires a regression test named `blg_NNN_<short>` for every record. No such
test exists in the tree: a search for a `fn` name starting `blg_` over `src/`, `crates/`, `budzero/`
and `xtask/` returns zero definitions. The three records marked "Fixed in the tree" carry tests
under the names the directive also writes for them, which is not the same thing.

## What this file does not claim

- No record is closed. No commit SHA and no CI run number is cited, because none exists.
- No build, test, clippy or gate result is claimed: the agent sandbox has no Rust toolchain.
- The English titles are this file's renderings of the source records' own titles. They are
  descriptions of the defect, not a new severity or ordering decision.
