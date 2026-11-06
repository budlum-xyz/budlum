# Concept names

Budlum's architecture names say what a thing does. Metaphor names are retired. This file explains the rename machinery; the binding list is `config/naming/concept_map.toml`.

## How the gate works

- `config/naming/concept_map.toml` lists every legacy name (`old`), the regular expressions that find it (`patterns`), the replacement (`new_code`, `term_en`).
- The `concept-names` gate (`xtask/gates/src/gates/concept_names.rs`, run by `budlum-gates --all` in the CI job `Gates`) searches `src`, `crates`, `budzero`, `execution`, `mobile`, `xtask`, `docs`, `config`, `proto` and `contracts`. Files under `global_allow_paths` (the map itself, this file, `docs/audit/`, the baseline) are skipped, and so are an entry's `allow_paths`.
- `mode = "count"` (now): per entry, the number of files and of matches must equal `.github/concept-names-baseline.txt`. A rise fails CI. A fall also fails until the baseline is lowered, so the numbers only decrease. Lower it with `BUDLUM_CONCEPT_NAMES_WRITE=1 cargo run --release --manifest-path xtask/gates/Cargo.toml -- concept-names`; the writer refuses to raise any number.
- `mode = "absolute"` (set once every count is zero): any match fails.
- Every rename lowers the baseline in the same pull request.
- A newly found legacy name gets an entry in the map.

## Entries

| Old name | New name | Term | Area |
|---|---|---|---|
| Filiz (leader election) | `hash_chain_election` | hash chain leader election (HCLE) | consensus |
| Filiz (faucet) | `faucet` | testnet faucet | operations |
| Kiragi, Don, Zemheri | alert level enum with the variants `Advisory`, `Restricted`, `Isolated` (exact code name in the map) | alert level 1, 2, 3 | security |
| Mikoriza, Mycorrhiza | `shared_security` | shared security | settlement |
| Graft and a [Turkish alias](../config/naming/concept_map.toml) | `app_binding` | remote app binding | settlement |
| Pollen | `data_market` | Data Market | application |
| Budscan, BudScan | `budlum-explorer` | Budlum Explorer | application |
| Atlas | `explorer_evidence` | explorer evidence model | application |
| D-Web Passport | `identity_profile` | identity profile | application |
| Vault (SocialFi) | `nft_folders` | NFT folders | application |
| DeEd | `education_domain` | education domain | application |
| budlumxyz | `app_registry` | app registry | application |
| Developer OS | `project_manifest` | project manifest | tooling |
| Universal Gateway, BudGateway | `content_gateway` | content gateway | storage |
| Regeneration, Turritopsis model | `state_recovery` | node state recovery | node |
| PUL, PUL-Full, Pul-Lite | `sigagg (crate bud-sigagg)` | signature aggregation proof | budzero |
| Tarif, Recipe, TARIF-3, VideoRecipe | `bud3::Object, ObjectCommitment, bof1` | B.U.D. 3.0 object, object commitment, BUD3 Object Format 1 (BOF-1) | storage |
| three_* modules | `src/storage/bud3/*` | bud3 modules | storage |
| Liquid storage | `wide_stripe` | class-aware wide-stripe placement | storage |
| Living Threshold, temperature transition | `access_tiering, TierTransition` | access tiering policy | storage |
| Mobile Self, Server Admission | (removed) | removed; replaced by the Mobile validator class | storage |
| Gonca, Kabuk, Kabuk-A, Kabuk-Z and [Turkish aliases](../config/naming/concept_map.toml) | `sealed_object, ciphertext_chunks, CipherProfile::{Aead, FieldNative}, plaintext_root, deletion_set, EscrowedDisclosure, PredicateProof` | sealed object and its parts | budzero privacy |
| GT-1 | `private_transfer_v1` | Private Transfer Protocol 1 (PTP-1) | budzero privacy |
| [Turkish aliases](../config/naming/concept_map.toml) | `DomainFinalityProof, BlockAggregateProof, RemoteStateView` | domain finality proof, block aggregate proof, remote state view | budzero |
| Fotosentez, DS-0..DS-3, YKP, Lubot and a [Turkish alias](../config/naming/concept_map.toml) | `ai_verification, VerificationLevel, DeterministicInferenceProfile, AnswerProofBundle, on_device_assistant` | AI Verification Layer, verification level VL-0..VL-3, Deterministic Inference Profile (DIP), Answer Proof Bundle (APB), on-device assistant | ai |
| govde-konuk and [Turkish aliases](../config/naming/concept_map.toml) | `budzero core, budzero-rv32, budzero-guest, MobileProverProfile` | BudZero core, BudZero RV32, BudZero guest SDK, mobile prover profile | budzero |
| Sera, Greenhouse, Floem, Phloem, Ksilem, Xylem, Genotip, Genotype, Fenotip, Phenotype, Tomurcuk, Meyve, Yuva, Nakil and [Turkish aliases](../config/naming/concept_map.toml) | `object_layer and Section 2.2 object layer terms` | Universal Object Layer (UOL) terms | object layer |

Brands and standards that stay: Budlum, BUD (token symbol), BudL, the `bud-*` crate prefix, BUD3, EVM, SVM, Move, CosmWasm, WASM, BNS, SocialFi, PoW, PoS, PoA, BFT, ZK.
