# Concept names

This is the English register of `config/naming/concept_map.toml`. The map is
the binding file; this page is how a reader finds it. Two concept names stay
in the architecture - `BudZero` and `B.U.D.` - and every other metaphorical
name is replaced by a term that says what the thing does.

Old names that are not ASCII are written here in ASCII. The map carries the
exact spelling, and the `concept-names` gate searches for that spelling, not
for the one on this page.

## The counter

`.github/concept-names-baseline.txt` records, per record below, how many
files still carry an old name and how many times. The `concept-names` gate
fails when a number goes up, and also when it goes down without the recorded
number coming down with it. Each package renames what its own card assigns
it; the last documentation package sets the map's `mode` to `absolute`,
after which a single occurrence is a finding.

Counts below are the recorded baseline, measured on the tree at the commit
that added this page.

## Records

| Area | Owner | Old name | New code name | English term | Searched under | Exempt | Still present |
|---|---|---|---|---|---|---|---|
| ai | WP-45 | `Fotosentez`, `DS-0..DS-3`, `BCP`, `YKP`, `Lubot` | `ai_verification, VerificationLevel, DeterministicInferenceProfile, AnswerProofBundle, on_device_assistant` | AI Verification Layer, verification level VL-0..VL-3, Deterministic Inference Profile (DIP), Answer Proof Bundle (APB), on-device assistant | all scan roots | `xtask/gates/src/gates/no_upstream_brands.rs`, `.quality/typos.toml` | 7 file(s), 19 match(es) |
| application | WP-23 | `budlumxyz` | `app_registry` | app registry | all scan roots | - | 25 file(s), 203 match(es) |
| application | WP-23 | `Pollen` | `data_market` | Data Market | all scan roots | - | 70 file(s), 755 match(es) |
| application | WP-23 | `DeEd` | `education_domain` | education domain | all scan roots | - | 12 file(s), 34 match(es) |
| application | WP-23 | `Atlas` | `explorer_evidence` | explorer evidence model | `src/`, `crates/`, `docs/ARCHITECTURE.md` | - | 7 file(s), 55 match(es) |
| application | WP-23 | `D-Web Passport` | `identity_profile` | identity profile | `src/`, `crates/`, `docs/` | - | 10 file(s), 88 match(es) |
| application | WP-23 | `Vault (SocialFi)` | `nft_folders` | NFT folders | `src/socialfi/`, `src/core/`, `src/chain/`, `src/rpc/`, `docs/` | - | 7 file(s), 152 match(es) |
| application | WP-40 | `Budscan`, `BudScan` | `budlum-explorer` | Budlum Explorer | all scan roots | - | 31 file(s), 257 match(es) |
| budzero | WP-33 | `PUL`, `PUL-Full`, `Pul-Lite` | `sigagg (crate bud-sigagg)` | signature aggregation proof | all scan roots | - | 12 file(s), 98 match(es) |
| budzero | WP-56 | `Govde`, `Govde-RV32`, `govde-konuk`, `Cep kanitcisi` | `budzero core, budzero-rv32, budzero-guest, MobileProverProfile` | BudZero core, BudZero RV32, BudZero guest SDK, mobile prover profile | all scan roots | - | 1 file(s), 1 match(es) |
| budzero | WP-60 | `Anac`, `Anac kaniti`, `Tek kanit`, `Kok gorunum` | `DomainFinalityProof, BlockAggregateProof, RemoteStateView` | domain finality proof, block aggregate proof, remote state view | all scan roots | - | none |
| budzero privacy | WP-56 | `GT-1` | `private_transfer_v1` | Private Transfer Protocol 1 (PTP-1) | all scan roots | - | none |
| budzero privacy | WP-56 | `Gonca`, `Kabuk`, `Kabuk-A`, `Kabuk-Z`, `Oz koku`, `Mezar kumesi`, `Emanet acma`, `Gonca kaniti` | `sealed_object, ciphertext_chunks, CipherProfile::{Aead, FieldNative}, plaintext_root, deletion_set, EscrowedDisclosure, PredicateProof` | sealed object and its parts | all scan roots | - | none |
| consensus | WP-12 | `Filiz (leader election)` | `hash_chain_election` | hash chain leader election (HCLE) | `src/consensus/`, `src/chain/`, `src/tests/`, `src/crypto/`, `docs/` | - | 11 file(s), 225 match(es) |
| node | WP-06 | `Regeneration`, `Turritopsis model` | `state_recovery` | node state recovery | all scan roots | - | 43 file(s), 316 match(es) |
| object layer | WP-49 | `Sera`, `Greenhouse`, `Floem`, `Phloem`, `Ksilem`, `Xylem`, `Genotip`, `Genotype`, `Fenotip`, `Phenotype`, `Tomurcuk`, `Cicek`, `Meyve`, `Kok Sozlesmesi`, `Yuva`, `Nakil` | `object_layer and Section 2.2 object layer terms` | Universal Object Layer (UOL) terms | all scan roots | - | none |
| operations | WP-41 | `Filiz (faucet)` | `faucet` | testnet faucet | `src/bin/`, `ops/`, `config/`, `mobile/` | - | 1 file(s), 14 match(es) |
| security | WP-12 | `Kiragi`, `Don`, `Zemheri` | `QuantumAlertLevel::{Advisory, Restricted, Isolated}` | quantum alert level 1, 2, 3 (Advisory, Restricted, Isolated) | `src/`, `docs/`, `crates/` | - | 6 file(s), 16 match(es) |
| settlement | WP-44 | `Graft`, `Asi` | `app_binding` | remote app binding | all scan roots | - | 41 file(s), 895 match(es) |
| settlement | WP-44 | `Mikoriza`, `Mycorrhiza` | `shared_security` | shared security | all scan roots | - | 23 file(s), 78 match(es) |
| storage | WP-07 | `Mobile Self`, `Server Admission` | `(removed)` | removed; replaced by the Mobile validator class | all scan roots | - | 13 file(s), 117 match(es) |
| storage | WP-19 | `Tarif`, `Recipe`, `TARIF-3`, `VideoRecipe` | `bud3::Object, ObjectCommitment, bof1` | B.U.D. 3.0 object, object commitment, BUD3 Object Format 1 (BOF-1) | all scan roots | `mobile/android/fdroid/` | 50 file(s), 1433 match(es) |
| storage | WP-20 | `Liquid storage` | `wide_stripe` | class-aware wide-stripe placement | all scan roots | - | none |
| storage | WP-21 | `three_* modules` | `src/storage/bud3/*` | bud3 modules | all scan roots | - | 30 file(s), 196 match(es) |
| storage | WP-23 | `Universal Gateway`, `BudGateway` | `content_gateway` | content gateway | all scan roots | - | 5 file(s), 8 match(es) |
| storage | WP-24 | `Living Threshold`, `temperature transition` | `access_tiering, TierTransition` | access tiering policy | all scan roots | - | 5 file(s), 15 match(es) |
| tooling | WP-39 | `Developer OS` | `project_manifest` | project manifest | all scan roots | - | 6 file(s), 50 match(es) |

## Why each name goes

- `ai_verification, VerificationLevel, DeterministicInferenceProfile, AnswerProofBundle, on_device_assistant` (WP-45): The names state the function.
- `app_registry` (WP-23): The name states the function.
- `data_market` (WP-23): The name states the function.
- `education_domain` (WP-23): The name states the function.
- `explorer_evidence` (WP-23): The name states the function.
- `identity_profile` (WP-23): The name states the function.
- `nft_folders` (WP-23): The name states the function.
- `budlum-explorer` (WP-40): Standard industry term.
- `sigagg (crate bud-sigagg)` (WP-33): The name states the function.
- `budzero core, budzero-rv32, budzero-guest, MobileProverProfile` (WP-56): BudZero is the concept term.
- `DomainFinalityProof, BlockAggregateProof, RemoteStateView` (WP-60): The names state the function.
- `private_transfer_v1` (WP-56): The name states the function.
- `sealed_object, ciphertext_chunks, CipherProfile::{Aead, FieldNative}, plaintext_root, deletion_set, EscrowedDisclosure, PredicateProof` (WP-56): Standard cryptographic terms.
- `hash_chain_election` (WP-12): The name states the mechanism.
- `state_recovery` (WP-06): Standard industry term.
- `object_layer and Section 2.2 object layer terms` (WP-49): Professional terms replace metaphors.
- `faucet` (WP-41): One concept, one term.
- `QuantumAlertLevel::{Advisory, Restricted, Isolated}` (WP-12): Levels are named by their effect.
- `app_binding` (WP-44): The name states the function.
- `shared_security` (WP-44): Standard industry term.
- `(removed)` (WP-07): B.U.D. 1.0 model is removed.
- `bud3::Object, ObjectCommitment, bof1` (WP-19): One storage object, one term.
- `wide_stripe` (WP-20): Standard industry term.
- `src/storage/bud3/*` (WP-21): One implementation of B.U.D. 3.0.
- `content_gateway` (WP-23): The name states the function.
- `access_tiering, TierTransition` (WP-24): Standard industry term.
- `project_manifest` (WP-39): The name states the function.

## Renaming a name

1. Rename it in your own locked paths. The record's `owner` above says which
   package that is.
2. Lower the record's line in `.github/concept-names-baseline.txt` in the same
   commit. The gate prints the replacement lines when it asks for this.
3. If the rename crosses paths another package has locked, it goes in a
   mechanical rename pull request of its own, which is announced as a short
   global lock.
4. Wire names are not frozen: the testnet opens with a new genesis, so serde
   names, RPC names and domain tags may change. A changed domain tag goes
   into `src/crypto/domain_tags.rs`; a changed RPC name replaces the old one
   with no alias left behind.
5. A newly found old name is appended to the map as a record with an owner.
   Appending keeps every existing record's position, which is what makes the
   baseline keys stable.

