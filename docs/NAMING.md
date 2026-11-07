# Naming (concept names)

This page is the English record of the concept-name map in `config/naming/concept_map.toml`.
The map is binding. The count gate (`scripts/concept_names_count.py --check`, baseline in `.github/concept-names-baseline.txt`) fails when a count grows.
Counts are measured on the tree at the time of the last `--write`. Only decreases are allowed.

| Old name(s) | New code name | English term | Area | Owner | Files | Lines | Reason |
|---|---|---|---|---|---|---|---|
| Filiz (leader election) | `hash_chain_election` | hash chain leader election (HCLE) | consensus | WP-12 | 11 | 207 | The name states the mechanism. |
| Filiz (faucet) | `faucet` | testnet faucet | operations | WP-41 | 1 | 13 | One concept, one term. |
| Kiragi, Don, Zemheri | `QuantumAlertLevel::{Advisory, Restricted, Isolated}` | quantum alert level 1, 2, 3 (Advisory, Restricted, Isolated) | security | WP-12 | 6 | 12 | Levels are named by their effect. |
| Mikoriza, Mycorrhiza | `shared_security` | shared security | settlement | WP-44 | 23 | 76 | Standard industry term. |
| Graft, Aşı | `app_binding` | remote app binding | settlement | WP-44 | 41 | 753 | The name states the function. |
| Pollen | `data_market` | Data Market | application | WP-23 | 69 | 693 | The name states the function. |
| Budscan, BudScan | `budlum-explorer` | Budlum Explorer | application | WP-40 | 25 | 132 | Standard industry term. |
| Atlas | `explorer_evidence` | explorer evidence model | application | WP-23 | 7 | 52 | The name states the function. |
| D-Web Passport | `identity_profile` | identity profile | application | WP-23 | 10 | 61 | The name states the function. |
| Vault (SocialFi) | `nft_folders` | NFT folders | application | WP-23 | 7 | 137 | The name states the function. |
| DeEd | `education_domain` | education domain | application | WP-23 | 12 | 32 | The name states the function. |
| budlumxyz | `app_registry` | app registry | application | WP-23 | 25 | 174 | The name states the function. |
| Developer OS | `project_manifest` | project manifest | tooling | WP-39 | 6 | 49 | The name states the function. |
| Universal Gateway, BudGateway | `content_gateway` | content gateway | storage | WP-23 | 5 | 8 | The name states the function. |
| Regeneration, Turritopsis model | `state_recovery` | node state recovery | node | WP-06 | 43 | 303 | Standard industry term. |
| PUL, PUL-Full, Pul-Lite | `sigagg (crate bud-sigagg)` | signature aggregation proof | budzero | WP-33 | 11 | 83 | The name states the function. |
| Tarif, Recipe, TARIF-3, VideoRecipe | `bud3::Object, ObjectCommitment, bof1` | B.U.D. 3.0 object, object commitment, BUD3 Object Format 1 (BOF-1) | storage | WP-19 | 50 | 1198 | One storage object, one term. |
| three_* modules | `src/storage/bud3/*` | bud3 modules | storage | WP-21 | 30 | 186 | One implementation of B.U.D. 3.0. |
| Liquid storage | `wide_stripe` | class-aware wide-stripe placement | storage | WP-20 | 0 | 0 | Standard industry term. |
| Living Threshold, temperature transition | `access_tiering, TierTransition` | access tiering policy | storage | WP-24 | 5 | 15 | Standard industry term. |
| Mobile Self, Server Admission | `(removed)` | removed; replaced by the Mobile validator class | storage | WP-07 | 13 | 103 | B.U.D. 1.0 model is removed. |
| Gonca, Kabuk, Kabuk-A, Kabuk-Z, Öz kökü, Mezar kümesi, Emanet açma, Gonca kanıtı | `sealed_object, ciphertext_chunks, CipherProfile::{Aead, FieldNative}, plaintext_root, deletion_set, EscrowedDisclosure, PredicateProof` | sealed object and its parts | budzero privacy | WP-56 | 0 | 0 | Standard cryptographic terms. |
| GT-1 | `private_transfer_v1` | Private Transfer Protocol 1 (PTP-1) | budzero privacy | WP-56 | 0 | 0 | The name states the function. |
| Anaç, Anaç kanıtı, Tek kanıt, Kök görünüm | `DomainFinalityProof, BlockAggregateProof, RemoteStateView` | domain finality proof, block aggregate proof, remote state view | budzero | WP-60 | 0 | 0 | The names state the function. |
| Fotosentez, DS-0..DS-3, BÇP, YKP, Lubot | `ai_verification, VerificationLevel, DeterministicInferenceProfile, AnswerProofBundle, on_device_assistant` | AI Verification Layer, verification level VL-0..VL-3, Deterministic Inference Profile (DIP), Answer Proof Bundle (APB), on-device assistant | ai | WP-45 | 8 | 17 | The names state the function. |
| Gövde, Gövde-RV32, govde-konuk, Cep kanıtçısı | `budzero core, budzero-rv32, budzero-guest, MobileProverProfile` | BudZero core, BudZero RV32, BudZero guest SDK, mobile prover profile | budzero | WP-56 | 1 | 1 | BudZero is the concept term. |
| Sera, Greenhouse, Floem, Phloem, Ksilem, Xylem, Genotip, Genotype, Fenotip, Phenotype, Tomurcuk, Çiçek, Meyve, Kök Sözleşmesi, Yuva, Nakil | `object_layer and Section 2.2 object layer terms` | Universal Object Layer (UOL) terms | object layer | WP-49 | 0 | 0 | Professional terms replace metaphors. |

Owner is the package that removes the old name (see `docs/work/PACKAGES.md`).

Rule: a name that is found in the tree and is not in this table is a new finding and is added here.
Global allow paths (not scanned): `config/naming/`, `docs/NAMING.md`, `docs/audit/`, `.github/concept-names-baseline.txt`
