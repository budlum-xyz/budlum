# Strix kayit defteri

Bu dosya `audit-notes/strix-ledger.md`. Her kayit bir Strix bulgusudur.
Kaynak: PR satir ici inceleme yorumlari, canli GitHub API, 13-11-2026.
Defter yorumlar silinmeden once yazildi. Silme bu defteri yok etmez.
Kimlik bicimi `S-<PR>-<yorum>`. Durum degerleri: cozuldu, acik, gecersiz, ertelendi.

## Sayim

| PR | Yuksek | Orta | Dusuk | Toplam |
|----|--------|------|-------|--------|
| #110 | 3 | 3 | 11 | 17 |
| #126 | 15 | 13 | 11 | 39 |
| **Toplam** | **18** | **16** | **22** | **56** |

## Kayitlar

### S-110-4542839504

- **PR:** #110
- **Konum:** `src/consensus/handoff.rs`:95
- **Onem:** high
- **Ozet:** Handoff set digest omits the BLS consensus keys, so a light client following handoffs adopts attacker-chosen BLS keys and accepts forged checkpoints
- **Durum:** cozuldu
- **Commit:** 30c5ab48
- **CI run:** yok
- **Not:** set_digest BLS anahtarini ve PoP u kapsiyor. Bulgu b58674d40 uzerine yazilmis; kod o tarihten sonra duzeltilmis. Kapanis: kod okumasi ve follow_handoffs PoP zinciri.

### S-110-4555294348

- **PR:** #110
- **Konum:** `src/network/protocol.rs`:191
- **Onem:** high
- **Ozet:** Unbounded `slashing_evidence` list in protobuf block/header conversions lets one peer frame expand into gigabytes
- **Durum:** cozuldu
- **Commit:** 30c5ab48
- **CI run:** yok
- **Not:** scan_proto_block_header tag 9 ve 18 sayiyor, MAX_SLASHING_ITEMS_PER_CONTAINER ile sinirliyor. BlockHeader::try_from bu tarayicidan sonra calisiyor.

### S-110-4558176035

- **PR:** #110
- **Konum:** `src/network/protocol.rs`:680
- **Onem:** high
- **Ozet:** Pre-decode wire scanner leaves `ProtoBlock.transactions` unbounded, so one peer frame expands into gigabytes
- **Durum:** cozuldu
- **Commit:** 30c5ab48
- **CI run:** yok
- **Not:** scan_proto_block tag 5 sayiyor, MAX_TRANSACTIONS_PER_BLOCK ile sinirliyor ve her islemi scan_proto_transaction ile tariyor.

### S-126-4506126991

- **PR:** #126
- **Konum:** `src/chain/finality.rs`:989
- **Onem:** high
- **Ozet:** Seat-quorum finality lets a minimum-stake validator coalition finalize alone
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4506127017

- **PR:** #126
- **Konum:** `src/validators/committee.rs`:141
- **Onem:** high
- **Ozet:** Checkpoint proposer can move committee seats by forging the unverified `seat_participation` record
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4510483736

- **PR:** #126
- **Konum:** `mobile/android/app/src/main/java/network/budlum/validator/core/KeystoreKeyVault.kt`
- **Onem:** high
- **Ozet:** Owner spend/stake/rotation authorization gate is satisfied by a hardcoded public string instead of a biometric or PIN prompt
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4510483855

- **PR:** #126
- **Konum:** `src/execution/coordinator/evm_ee.rs`
- **Onem:** high
- **Ozet:** Unmetered EVM memory expansion lets a single cheap transaction abort the node process
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4542828156

- **PR:** #126
- **Konum:** `src/execution/coordinator/svm_ee.rs`:889
- **Onem:** high
- **Ozet:** SVM adapter mints any mint and overwrites any account without ownership or authority checks
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4542828236

- **PR:** #126
- **Konum:** `contracts/object-layer/move/sources/settlement_endpoint.move`
- **Onem:** high
- **Ozet:** Unbound asset class in Move and SVM settlement endpoints lets any depositor mint a unique asset into an arbitrary registered class
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4542839428

- **PR:** #126
- **Konum:** `src/execution/coordinator/svm_ee.rs`:889
- **Onem:** high
- **Ozet:** SVM adapter mints any mint and overwrites any account without ownership or authority checks
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4542839507

- **PR:** #126
- **Konum:** `contracts/object-layer/move/sources/settlement_endpoint.move`
- **Onem:** high
- **Ozet:** Unbound asset class in Move and SVM settlement endpoints lets any depositor mint a unique asset into an arbitrary registered class
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4544946230

- **PR:** #126
- **Konum:** `src/storage/bud3/registry.rs`:827
- **Onem:** high
- **Ozet:** `BurnReference` deletes and permanently tombstones another account's B.U.D. 3.0 object for any holder of a self-declared NFT id
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4544946255

- **PR:** #126
- **Konum:** `src/object_layer/tx.rs`:331
- **Onem:** high
- **Ozet:** Unauthenticated home-identity binding lets any account adopt (steal) `Holder::Home` balances
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4544946277

- **PR:** #126
- **Konum:** `src/storage/bud3/replace.rs`:110
- **Onem:** high
- **Ozet:** ReplaceObject quorum is unsigned and record-blind: one Full share-holder can replace an object and destroy its live representation
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4555265932

- **PR:** #126
- **Konum:** `crates/bud-codec/src/lib.rs`:106
- **Onem:** high
- **Ozet:** zstd decode is bounded only by the untrusted header `content_len`, allowing a decompression bomb
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4555266000

- **PR:** #126
- **Konum:** `src/execution/coordinator/evm_ee.rs`
- **Onem:** high
- **Ozet:** Unbounded native recursion in EVM intra-call path (zero-value CALL) crashes the node
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4568516329

- **PR:** #126
- **Konum:** `execution/cairo/src/lib.rs`:589
- **Onem:** high
- **Ozet:** Cairo EE executes any caller-named contract entrypoint with caller calldata, letting any account rewrite another contract's storage and act as it
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4568516410

- **PR:** #126
- **Konum:** `execution/utxo/src/lib.rs`:276
- **Onem:** high
- **Ozet:** UTXO Script multisig opcode "verifies" a publicly computable hash, so any account can spend any multisig-locked UTXO
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-110-4555294239

- **PR:** #110
- **Konum:** `contracts/external-domain/BudlumFinalityVerifier.sol`
- **Onem:** medium
- **Ozet:** Fraud verdict in BudlumFinalityVerifier is digest-scoped, so a disproved (height, stateRoot) can be re-presented and settled
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-110-4568472236

- **PR:** #110
- **Konum:** `src/registry/permissionless.rs`:160
- **Onem:** medium
- **Ozet:** `RelayerIntentTx::Expire` reverts for a slashed-but-still-bonded awarded relayer, locking the intent owner's escrow forever
- **Durum:** cozuldu
- **Commit:** c3c6ed92
- **CI run:** bekliyor
- **Not:** Expire kolu AlreadySlashed ve NotRegistered hatasini yutuyor; iade slashtan ayrildi. Ayni sinif graft.rs ve slash_failed_prover icinde de duzeltildi. Test: relayer_intent_expiry_refunds_an_owner_whose_bidder_is_already_slashed.

### S-110-4568539249

- **PR:** #110
- **Konum:** `src/domain/storage_deal.rs`:1872
- **Onem:** medium
- **Ozet:** Expired custody deals keep contesting `owner_of` forever, so one cheap deal permanently strips another account's ownership authority
- **Durum:** cozuldu
- **Commit:** c3c6ed92
- **CI run:** bekliyor
- **Not:** has_custody_deal yalnizca DealStatus::Active sayiyor. Test: a_lapsed_custody_deal_stops_contesting_the_owner.

### S-126-4555266054

- **PR:** #126
- **Konum:** `src/rpc/compat/aptos.rs`:510
- **Onem:** medium
- **Ozet:** Aptos compat proxy lets caller paths escape the configured /v1 upstream prefix
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4555266093

- **PR:** #126
- **Konum:** `src/execution/coordinator/evm_ee.rs`
- **Onem:** medium
- **Ozet:** EVM nested CALL does not roll back callee storage writes when the callee reverts
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4555266146

- **PR:** #126
- **Konum:** `src/execution/coordinator/evm_ee.rs`
- **Onem:** medium
- **Ozet:** EVM CALL forwards a gas budget that is never enforced, so a callee can spend the caller's entire transaction allowance
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4555266178

- **PR:** #126
- **Konum:** `src/storage/bud3/pipeline.rs`
- **Onem:** medium
- **Ozet:** Missing content ceiling at the B.U.D. 3.0 registration door lets a signed transaction commit an object_len that readers pre-allocate
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4559129527

- **PR:** #126
- **Konum:** `src/execution/coordinator/mod.rs`:384
- **Onem:** medium
- **Ozet:** BudZero storage write in StatefulBudZeroEe persists caller-supplied calldata into any deployed contract's namespace without an authorisation check
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4568516161

- **PR:** #126
- **Konum:** `execution/svm/src/lib.rs`:247
- **Onem:** medium
- **Ozet:** SVM System `CreateAccount` overwrites any existing account record, letting any caller blank another user's token, mint or program account
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4568516253

- **PR:** #126
- **Konum:** `src/domain/storage_deal.rs`:4157
- **Onem:** medium
- **Ozet:** Storage challenge verifier accepts a self-contained bundle, so an operator holding no shard bytes answers every challenge and collects the boost payout
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4568516309

- **PR:** #126
- **Konum:** `execution/move-sui/src/lib.rs`:586
- **Onem:** medium
- **Ozet:** Sui EE MoveCall appends caller-supplied bytes to any Shared object, letting any account permanently corrupt another user's shared object
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4568516376

- **PR:** #126
- **Konum:** `execution/near/src/lib.rs`:465
- **Onem:** medium
- **Ozet:** NEAR, TVM, Plutus and PolkaVM workers expose no caller identity, so no contract in those environments can enforce access control on its own state
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4568600764

- **PR:** #126
- **Konum:** `crates/wallet-core/src/bns.rs`:290
- **Onem:** medium
- **Ozet:** Wallet `.bud` verification trusts a root and epoch taken from the node's own proof answer, so a lying node chooses the transfer recipient
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4568600860

- **PR:** #126
- **Konum:** `src/wallet/identity_profile.rs`:683
- **Onem:** medium
- **Ozet:** Per-name BNS proof leaves `address` (and records, subdomains, B.U.D. 3.0 content) outside the leaf digest, so the identity profile labels merchant-controlled data Verified
- **Durum:** cozuldu
- **Commit:** c3c6ed92
- **CI run:** bekliyor
- **Not:** BnsMerkleBranch::extras on-imaj tasiyor. verify_state_proof ozeti yeniden hesapliyor. evaluate_bns_evidence basililan her alani esliyor. Test: a_swapped_address_under_a_valid_proof_is_not_verified.

### S-126-4568600961

- **PR:** #126
- **Konum:** `src/bns/registry.rs`:1427
- **Onem:** medium
- **Ozet:** BNS non-inclusion proof verifier accepts one non-adjacent boundary branch, so a prover can certify any registered `.bud` name as absent
- **Durum:** cozuldu
- **Commit:** c3c6ed92
- **CI run:** bekliyor
- **Not:** BnsMerkleBranch::leaf_index ve tree_size eklendi. check_boundary_pair komsuluk ve liste boyu sarti koyuyor. Test: bns_absence_proof_boundaries_must_be_adjacent_positions.

### S-126-4568708115

- **PR:** #126
- **Konum:** `src/execution/coordinator/migration/mod.rs`:91
- **Onem:** medium
- **Ozet:** EVM migration EIP-712 authorization does not commit to the payload it admits, so one deployer signature authorizes any imported code and state
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-110-4385754569

- **PR:** #110
- **Konum:** `src/consensus/handoff.rs`
- **Onem:** low
- **Ozet:** Handoff Certificate committee is derived from the certificate's own unverified `randomness` field
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-110-4385754716

- **PR:** #110
- **Konum:** `src/registry/identity.rs`:1326
- **Onem:** low
- **Ozet:** Subject issue-consent digest does not bind the credential schema or field names, letting one consent authorize a differently-labelled credential
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-110-4385754779

- **PR:** #110
- **Konum:** `src/relayer/policy.rs`:396
- **Onem:** low
- **Ozet:** A permissionlessly registered consensus domain can write the consensus external-root anchor of an external chain it does not own
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-110-4388156525

- **PR:** #110
- **Konum:** `src/network/peer_auth.rs`
- **Onem:** low
- **Ozet:** ML-DSA peer identity proof and validator proof deadline are documented as enforced but never called on the p2p path
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-110-4429011251

- **PR:** #110
- **Konum:** `src/domain/storage_tx.rs`:831
- **Onem:** low
- **Ozet:** Storage escrow helpers on Blockchain bind a caller-named operator and debit its bond without the operator's consent
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-110-4431413673

- **PR:** #110
- **Konum:** `src/bin/budlum-indexer.rs`:47
- **Onem:** low
- **Ozet:** Public explorer API: two clients at the documented ceiling exhaust the shared node budget and deny all current-state reads
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-110-4431413685

- **PR:** #110
- **Konum:** `src/bin/budlum-indexer.rs`
- **Onem:** low
- **Ozet:** Internal node endpoint and upstream diagnostics disclosed to unauthenticated explorer API callers
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-110-4431413689

- **PR:** #110
- **Konum:** `budzero/bud-pul/src/pul_air.rs`
- **Onem:** low
- **Ozet:** PUL batch verifier accepts arbitrary statements: chip proof carries no statement binding
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-110-4510421498

- **PR:** #110
- **Konum:** `src/settlement/shared_security.rs`:443
- **Onem:** low
- **Ozet:** Restaked-weight retire-on-move is skipped for zero-unit reports, letting an operator keep unbacked validator voting weight
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-110-4510774725

- **PR:** #110
- **Konum:** `src/cross_domain/bridge_tx.rs`:550
- **Onem:** low
- **Ozet:** `deliver_message` accepts events out of staged (not-yet-applied) domain commitments, the only one of the four domain-consumption doors without the applied-chain gate
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-110-4544944690

- **PR:** #110
- **Konum:** `src/cross_domain/external/external_tx.rs`:274
- **Onem:** low
- **Ozet:** Round-cap eviction in `QuorumRounds::submit` can delete another prover's in-progress round and the votes it already collected
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4510483703

- **PR:** #126
- **Konum:** `src/data_market/mod.rs`:131
- **Onem:** low
- **Ozet:** Data Market purchase authorization does not bind `buyer` address to the signing key, so any party can debit another account
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4510483762

- **PR:** #126
- **Konum:** `src/registry/presence.rs`:396
- **Onem:** low
- **Ozet:** Presence aggregates accepted for any window: stale proof replay keeps an offline validator earning and unsuspended
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4510483785

- **PR:** #126
- **Konum:** `src/chain/snapshot.rs`:759
- **Onem:** low
- **Ozet:** Schema-13 snapshot persists the B.U.D. 3.0 registry outside the snapshot digest and manifest signature
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4510483808

- **PR:** #126
- **Konum:** `src/validators/mod.rs`:202
- **Onem:** low
- **Ozet:** BLS proof of possession is stored but never verified, enabling rogue-key aggregation over the validator directory
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4510483822

- **PR:** #126
- **Konum:** `src/settlement/domains.rs`:1703
- **Onem:** low
- **Ozet:** Object-layer home events are credited without verifying inclusion in the committed home block
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4510483907

- **PR:** #126
- **Konum:** `crates/bud-codec/src/shared_context.rs`
- **Onem:** low
- **Ozet:** Convergent dedup envelope keys its cipher from the public envelope id via a home-made unkeyed mix
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4542827826

- **PR:** #126
- **Konum:** `src/ai/answer_proof_bundle.rs`:403
- **Onem:** low
- **Ozet:** Answer Proof Bundle trusts a declared verification level: attacker-supplied `apb` block parses as VL-3
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4542839146

- **PR:** #126
- **Konum:** `src/ai/answer_proof_bundle.rs`:403
- **Onem:** low
- **Ozet:** Answer Proof Bundle trusts a declared verification level: attacker-supplied `apb` block parses as VL-3
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4544946153

- **PR:** #126
- **Konum:** `src/app_registry/mod.rs`
- **Onem:** low
- **Ozet:** `AppRegistry::register_app` records an app against an unverified caller-supplied developer and never enforces `APP_REGISTRY_MIN_FEE`
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4544946187

- **PR:** #126
- **Konum:** `src/object_layer/registry.rs`:1514
- **Onem:** low
- **Ozet:** Permissionless object-layer class challenge permanently freezes any registered asset class
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

### S-126-4544946364

- **PR:** #126
- **Konum:** `src/execution/coordinator/mod.rs`:1053
- **Onem:** low
- **Ozet:** EE host writes are not bound to the calling environment's namespace
- **Durum:** acik
- **Commit:** yok
- **CI run:** yok
- **Not:** Henuz cozulmedi.

