# Concept names

Budlum's architecture names say what a thing does. Metaphor names are retired. This file explains the rename machinery; the binding list is `config/naming/concept_map.toml`.

## How the gate works

- `config/naming/concept_map.toml` lists every legacy name (`old`), the regular expressions that find it (`patterns`), the replacement (`new_code`, `term_en`), and the owning area (`owner`).
- The `concept-names` gate (`xtask/gates/src/gates/concept_names.rs`, run by `budlum-gates --all` in the CI job `Gates`) searches `src`, `crates`, `budzero`, `execution`, `mobile`, `xtask`, `docs`, `config`, `proto` and `contracts`. Files under `global_allow_paths` (the map itself, this file, the baseline) are skipped, and so are an entry's `allow_paths`. Every path filter must be a non-empty repository-relative path without `.`/`..`, repeated separators, or backslashes. A trailing `/` selects descendants of that directory; without one, the filter matches only that exact file, never a similarly named sibling.
- `mode = "count"` (now): per entry, the number of files and of matches must equal `.github/concept-names-baseline.txt`. A rise fails CI. A fall also fails until the baseline is lowered, so the numbers only decrease. Lower it with `BUDLUM_CONCEPT_NAMES_WRITE=1 cargo run --release --manifest-path xtask/gates/Cargo.toml -- concept-names`; the writer refuses to raise any number.
- `mode = "absolute"` (set by `the implementation track` once every count is zero): any match fails.
- Every rename lowers the baseline in the same pull request.
- A newly found legacy name gets an entry in the map.

## Entries

| Old name | New name | Term | Area | Owner |
|---|---|---|---|---|
| Filiz (leader election) | `hash_chain_election` | hash chain leader election (HCLE) | consensus | `the implementation track` |
| Filiz (faucet) | `faucet` | testnet faucet | operations | `the implementation track` |
| Kiragi, Don, Zemheri | alert level enum with the variants `Advisory`, `Restricted`, `Isolated` (exact code name in the map) | alert level 1, 2, 3 | security | `the implementation track` |
| Mikoriza, Mycorrhiza | `shared_security` | shared security | settlement | `the implementation track` |
| Graft and a [Turkish alias](../config/naming/concept_map.toml) | `app_binding` | remote app binding | settlement | `the implementation track` |
| Pollen | `data_market` | Data Market | application | `the implementation track` |
| Budscan, BudScan | `budlum-explorer` | Budlum Explorer | application | `the implementation track` |
| Atlas | `explorer_evidence` | explorer evidence model | application | `the implementation track` |
| D-Web Passport | `identity_profile` | identity profile | application | `the implementation track` |
| Vault (SocialFi) | `nft_folders` | NFT folders | application | `the implementation track` |
| DeEd | `education_domain` | education domain | application | `the implementation track` |
| budlumxyz | `app_registry` | app registry | application | `the implementation track` |
| Developer OS | `project_manifest` | project manifest | tooling | `the implementation track` |
| Universal Gateway, BudGateway | `content_gateway` | content gateway | storage | `the implementation track` |
| Regeneration, Turritopsis model | `state_recovery` | node state recovery | node | `the implementation track` |
| PUL, PUL-Full, Pul-Lite | `sigagg (crate bud-sigagg)` | signature aggregation proof | budzero | `the implementation track` |
| Tarif, Recipe, TARIF-3, VideoRecipe | `bud3::Object, ObjectCommitment, bof1` | B.U.D. 3.0 object, object commitment, BUD3 Object Format 1 (BOF-1) | storage | `the implementation track` |
| three_* modules | `src/storage/bud3/*` | bud3 modules | storage | `the implementation track` |
| Liquid storage | `wide_stripe` | class-aware wide-stripe placement | storage | `the implementation track` |
| Living Threshold, temperature transition | `access_tiering, TierTransition` | access tiering policy | storage | `the implementation track` |
| Mobile Self, Server Admission | (removed) | removed; replaced by the Mobile validator class | storage | `the implementation track` |
| Gonca, Kabuk, Kabuk-A, Kabuk-Z and [Turkish aliases](../config/naming/concept_map.toml) | `sealed_object, ciphertext_chunks, CipherProfile::{Aead, FieldNative}, plaintext_root, deletion_set, EscrowedDisclosure, PredicateProof` | sealed object and its parts | budzero privacy | `the implementation track` |
| GT-1 | `private_transfer_v1` | Private Transfer Protocol 1 (PTP-1) | budzero privacy | `the implementation track` |
| [Turkish aliases](../config/naming/concept_map.toml) | `DomainFinalityProof, BlockAggregateProof, RemoteStateView` | domain finality proof, block aggregate proof, remote state view | budzero | `the implementation track` |
| Fotosentez, DS-0..DS-3, YKP, Lubot and a [Turkish alias](../config/naming/concept_map.toml) | `ai_verification, VerificationLevel, DeterministicInferenceProfile, AnswerProofBundle, on_device_assistant` | AI Verification Layer, verification level VL-0..VL-3, Deterministic Inference Profile (DIP), Answer Proof Bundle (APB), on-device assistant | ai | `the implementation track` |
| govde-konuk and [Turkish aliases](../config/naming/concept_map.toml) | `budzero core, budzero-rv32, budzero-guest, MobileProverProfile` | BudZero core, BudZero RV32, BudZero guest SDK, mobile prover profile | budzero | `the implementation track` |
| Sera, Greenhouse, Floem, Phloem, Ksilem, Xylem, Genotip, Genotype, Fenotip, Phenotype, Tomurcuk, Meyve, Yuva, Nakil and [Turkish aliases](../config/naming/concept_map.toml) | `object_layer and Section 2.2 object layer terms` | Universal Object Layer (UOL) terms | object layer | `the implementation track` |

Brands and standards that stay: Budlum, BUD (token symbol), BudL, the `bud-*` crate prefix, BUD3, EVM, SVM, Move, CosmWasm, WASM, BNS, SocialFi, PoW, PoS, PoA, BFT, ZK.
