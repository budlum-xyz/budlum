# Wiring matrix (testnet directive, section 5.4)

One row per module capability. Measured at commit `f588d62`.

A row is `wired` only when all eight parts of the directive's definition
(WP-6) hold: (a) a signed transaction door, (b) an executor arm, (c) entry
into the state root and, where needed, the global header, (d) RPC reads,
(e) persistence with a restart test, (f) a metric, (g) an end-to-end
rehearsal scenario, (h) a current English module README. A row is `gated`
when the capability is closed on purpose, a test proves it is closed and the
module README says why. Every other row is `missing`.

No rehearsal tool exists yet (WP-12: `xtask/tools ... testnet-rehearsal`), so
column (g) is `none` for every row and no row can be `wired` today. That is
the measured state, not a placeholder.

Column values: a code reference where the part exists; `none` where it was
looked for and not found; `not verified` where it has not been read yet. A
`not verified` cell is never counted as present.

The global header column refers to `GlobalBlockHeader` as built by
`Blockchain::build_global_header` (`src/chain/blockchain.rs:2214-2272`).
That header is node-local today (B-01), so a root listed there is not yet a
consensus commitment.

## State root coverage (measured)

`AccountState::calculate_state_root` (`src/core/account.rs:2827`) folds:
accounts, validators, unbonding queue, base fee, tokenomics (block reward,
timed burn, burned total, burn reserve, team vesting), `bridge_root`,
`message_root`, `settlement_root`, AI registry, note registry, storage
registry, proof market, BNS, NFT registry, identity, vault, Pollen
marketplace, budlumxyz hub, permissionless registry, liveness, invalid
votes, PoA admission, PoA compliance, `external_roots`,
`external_bond_escrow`, governance, `global_header_summary` (always zero,
B-01), domain unfreeze, governance flags.

It does **not** fold the registries that live on `Blockchain` rather than on
`AccountState`: the consensus domain registry, the domain commitment
registry, the universal relayer ledger, the external intake
(`external_intake`), and the sovereign template registry. Those are covered
only by the node-local global header. See N-10 in `FINDINGS.md`.

## Matrix

| Module | Capability | Tx door | Executor arm | State root | Global header root | RPC read | Persistence | Metrics | Rehearsal scenario | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| Core | Transfer, nonce, fee | `Transfer` | yes (`src/execution/executor.rs`) | accounts | none | `bud_getBalance`, `bud_getNonce`, `bud_getTransactionByHash`, `bud_getTransactionReceipt` | sled (`src/storage/`) not verified | not verified | none | missing |
| Core | Protocol fee rates | none (parameters default 0, B-18) | none | registry params | none | none | not verified | none | none | missing |
| Core | Mempool admission | `bud_sendRawTransaction`, `bud_txPrecheck` | n/a | n/a | n/a | `bud_txPrecheck` | in memory | not verified | none | missing |
| Core | Snapshot and state sync | n/a | n/a | snapshot hash | n/a | not verified | snapshot V2 | not verified | none | missing |
| Consensus | PoS block production and BLS finality | `Stake`, `Unstake`, `RegisterConsensusKeys` | yes | validators, unbonding | none | `bud_getValidatorSet`, `bud_getSlashingHistory` | not verified | not verified | none (smoke runs PoW, B-04) | missing |
| Consensus | PoS validator rewards | none (pool unwired, B-12) | none | tokenomics | none | none | none | none | none | missing |
| Consensus | Delegation | none (B-12) | none | none | none | none | none | none | none | missing |
| Consensus domains | PoW, BFT, ZK domain finality | none (operator RPC `bud_registerConsensusDomain`, `bud_submitVerifiedDomainCommitment`, B-02) | none | `external_roots` only | `domain_registry_root`, `domain_commitment_root` | `bud_getConsensusDomains`, `bud_getDomainCommitments`, `bud_getDomainInfo` | sled | not verified | none | missing |
| Consensus domains | PoA domain | `PoaOnboarding` | yes | PoA admission, PoA compliance | none | not verified | not verified | not verified | none (bootstrap domain frozen, B-19) | missing |
| Cross domain | Messages | none (`bud_submitCrossDomainMessage` writes out of block) | none | `message_root` | `message_root` | not verified | `save_cross_domain_message` | not verified | none | missing |
| Cross domain | Bridge lock, mint, burn, unlock | none (operator RPCs, B-02) | none | `bridge_root` | `bridge_state_root`, `replay_nonce_root` | `bud_getSettlementInfo` | `save_bridge_state` | `bridge_transfers_total` | none | missing |
| Cross domain | Relay proof settlement | `RelayerResult` (exists); proof path is operator RPC `bud_submitRelayProof` (B-02) | `RelayerResult` arm not verified | partial | none | none | `save_universal_relayer` | not verified | none | missing |
| Cross domain | EVM adapter (Sepolia) | none | none | none | none | `bud_inspectEthereumUpdate`, `bud_planEvmVerification` | n/a | none | none | missing |
| External domains | Registration, evidence, prover bond and slash, quorum, fork windows, readmit | none (operator RPCs refuse or write out of block, B-02, B-03) | in-block entries exist with no caller (`apply_*_in_block`) | `external_bond_escrow` only | none | `bud_getExternalDomains`, `bud_getExternalDomainProfile`, `bud_getExternalIntakeDigest`, `bud_getExternalQuorumRound(s)`, `bud_getExternalDomainStatus` | `save_external_intake` | not verified | none | missing |
| Relayer intents | `UserIntent`, `SolverBid`, `IntentSettlement` | none (B-10) | none | none | none | none | none | none | none | missing |
| Registry and roles | Permissionless role bonds | `RoleBond`, `Stake` | yes | registry | none | `bud_registryQuery`, `bud_registryActiveMembers` | not verified | not verified | none | missing |
| Registry and roles | Role bond RPC writers | `bud_registryRegister`, `bud_registryBondRelayer`, `bud_registryBondProver`, `bud_registryBeginRoleBondUnbonding`, `bud_registryWithdrawRoleBond` (classification pending, WP-1) | not verified | registry | none | as above | not verified | not verified | none | missing |
| B.U.D. | Manifests, deals, challenges, repair | `Storage` | yes | storage registry | `storage_root` (from `pending_storage_root`) | `bud_storage*` reads | registry: not verified; content bytes: memory only (B-15) | not verified | none | missing |
| B.U.D. | Persistent content store | n/a | n/a | n/a | n/a | n/a | none (`MemoryContentStore`, B-15) | none | none | missing |
| BNS | Register, content, subdomain, storage | `BnsRegister`, `BnsSetContent`, `BnsRegisterSubdomain`, `BnsSetStorage` | yes | BNS | none | `bud_bnsResolve*`, `bud_bnsPrepare*` | not verified | not verified | none | missing |
| BNS | Transfer, renew | none (B-17) | none | none | none | none | none | none | none | missing |
| SocialFi, NFT, Vault | Mint, transfer, burn, boost, tag, light, folders | `NftMint`, `NftTransfer`, `NftBurn`, `NftBoost`, `NftTag`, `NftUpdateLight`, `Vault` | yes | NFT registry, vault | none | `bud_social*` | not verified | not verified | none | missing |
| Pollen | Assets, grants, sales, purchases | `PollenRegisterDataAsset`, `PollenAuthorizeSale`, `PollenGrantAccess`, `PollenRevokeGrant`, `PollenRevokeDataAsset`, `AiOfferData`, `AiPurchaseData` | yes | Pollen marketplace | none | `bud_pollen*`, `bud_market*` | not verified | not verified | none | missing |
| budlumxyz hub | App register and attest | `BudlumxyzRegisterApp`, `BudlumxyzAttestApp` | yes | hub | none | `bud_hubGetApps`, `bud_hubPrepareRegister` | not verified | not verified | none | missing |
| DeEd | Manifest roles | not verified | not verified | not verified | none | not verified | not verified | not verified | none | missing |
| Identity | DID, credentials, revocation, guardian recovery | `Identity` | yes | identity | `identity_root` | `bud_identityResolve`, `bud_identityCredential`, `bud_identityVerifyPresentation` | not verified | not verified | none | missing |
| Privacy | Notes and private transfer | `PrivacyNoteInsert`, `PrivateTransferSubmit` | yes, refused on mainnet | note registry | none | not verified | not verified | not verified | none | missing |
| Privacy | `private_transfer_auth`, `tee_attestation` (account abstraction) | none | none | none | none | none | none | none | none | gated (WIRING: unwired markers; README reason not verified) |
| AI layer (`src/ai/`) | Model registry, requests, k-of-n verifier agreement, fee escrow, reclaim, dispute | `AiModelRegister`, `AiInferenceRequest`, `AiFeeReclaim`, `AiModelDeactivate`, `AiModelReactivate`, `AiRequestCancel`, `AiDisputeSlash`, `AiAgentPayment*` | yes | AI registry | `ai_root` | `bud_ai*` reads | not verified | not verified | none | missing |
| AI layer (`src/ai/`) | Inference proof verification | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | gated (MainnetActivation `verify_inference_enabled: false`, `.github/unwired-guards-baseline.txt`) |
| AI layer, Lubot origin | AI_OPERATOR bond and operator results | `AiOperatorBond`, `AiOperatorUnbond`, `AiOperatorWithdraw`, `AiInferenceResult` | yes | registry | none | not verified | not verified | not verified | none | out of scope (L-01) |
| Governance and DAO | Proposals and votes | `Vote` | yes | governance | none | not verified | not verified | not verified | none | missing (feature flag gates nothing, B-16) |
| Constitution | Hard guardrails | n/a | via governance | not verified | none | none | not verified | none | none | missing |
| Tokenomics | Burns, vesting | protocol rules | yes | tokenomics | none | not verified | not verified | not verified | none | missing |
| BudZero, BudZKVM | `ContractCall`, program allow list, proof requests | `ContractCall` | yes | not verified | none | `bud_submitZkProof` (classification pending) | not verified | not verified | none | missing |
| BudZero, BudZKVM | `VerifyMerkle` at production depth | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | gated (K10) |
| Settlement | Commitment tree and proof verifier | n/a | not verified | `settlement_root` | `settlement_finality_root` | `bud_getSettlementInfo` | not verified | not verified | none | missing |
| Settlement | Proof market tasks and receipts | none (B-19) | none | proof market | none | none | not verified | none | none | missing |
| Settlement | PQ anchor | n/a | n/a | n/a | anchor input is the sealed header | none | anchor log | not verified | none | gated (K11; production mode fails closed) |
| Gateway | Atlas and Passport read-only | n/a | n/a | n/a | n/a | `bud_atlasGetWalletContext`, `bud_passportGetProfile`, `bud_passportGetProofBundle`, `bud_gatewayFetchContent`, `bud_gatewayRenderContent` | n/a | not verified | none | missing |
| Sovereign domain kit | Template registration | none (operator RPC `bud_registerSovereignTemplate`) | none | none | none | `bud_validateSovereignAuditExport` | not verified | not verified | none | missing |
| Sharding | Shard placement | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | gated (directive: stays closed; reason in README not verified) |
| Network | Gossip, sync, peer score, bans, mobile profile | n/a | n/a | n/a | n/a | `bud_netPeerCount`, `bud_adminListBannedPeers` | banned peer file | `budlum_p2p_peers_connected` | none | missing |
| Network | Egress privacy policy (`src/network/privacy.rs`) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | gated (WIRING: unwired marker; README reason not verified) |
| Developer OS and SDK | Project schema | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | missing (`src/sdk/mod.rs` is `WIRING: unwired`; no `bud dev` command verified) |
| Budscan crate | `.bud` resolution over RPC and indexer | n/a | n/a | n/a | n/a | uses `bud_bnsResolve*` (not verified) | n/a | n/a | none | missing (no indexer, B-08) |
| `bud` crate | B.U.D. core | n/a | n/a | n/a | n/a | n/a | n/a | n/a | none | missing (build and tests are CI's) |
| Light client (`budlum-light`) | Trust anchor to event proof | n/a | n/a | n/a | n/a | n/a | n/a | n/a | none | missing (WP-2 chain not built) |
| Explorer and indexer | Blocks, transactions, addresses, validators, domains | n/a | n/a | n/a | n/a | none (B-08) | none | none | none | missing |
| Faucet | Testnet BUD | none (B-07: dev credit is out of consensus) | n/a | n/a | n/a | none | none | none | none | missing |
| Graft | Apps from other networks, paid in BUD | none (WP-8) | none | none | none | none | none | none | none | missing |
| Shared security | Restaked validators | none (WP-10) | none | none | none | none | none | none | none | missing |

## Gated rows: what is still owed

A `gated` row needs a test that proves the capability is closed and a module
README that states why. The rows above marked "README reason not verified"
were marked from the in-file `WIRING: unwired` marker alone; the README and
the pinning test are checked when each module is read in full (see
`COVERAGE.md`).
