# Concept names

Budlum names a concept once. Architecture kept two names of its own, `BudZero`
and `B.U.D.`, and one term per concept. Every other metaphor the project used
while it was being designed is retired: the name it was replaced by says what
the thing does, in English, and the code uses that name.

The machine-readable list is `config/naming/concept_map.toml`. It is the source
that the `concept-names` gate reads; this page is its English rendering. A name
that is not in the map is not a legacy name, and a name that is in the map is
forbidden everywhere the map scans except where the map itself allows it.

## What the map holds

`schema` and `mode` describe the file. `global_allow_paths` lists the files that
are never scanned, because the map has to be able to write a legacy name down in
order to ban it. Each `[[concept]]` record carries:

* `old`: the legacy names, for a reader.
* `patterns`: the expressions the gate searches for, in Rust `regex` syntax.
* `paths` (optional): the directories to search. Absent means every root.
* `allow_paths` (optional): files where the pattern is legitimate.
* `new_code`: the code name that replaced the legacy name.
* `term_en`, `term_tr`: the English and Turkish terms. The Turkish term is
  data, not prose, and it lives here rather than in this page.
* `area`: the layer the name belongs to.
* `owner`: the work package responsible for the rename, as `WP-NN`.
* `reason`: one sentence on why the new name is the better one.

## The map

| Legacy names | Code name | English term | Area | Owner |
|---|---|---|---|---|
| Filiz (leader election) | `hash_chain_election` | hash chain leader election (HCLE) | consensus | `WP-12` |
| Filiz (faucet) | `faucet` | testnet faucet | operations | `WP-41` |
| Kiragi; Don; Zemheri | `QuantumAlertLevel::{Advisory, Restricted, Isolated}` | quantum alert level 1, 2, 3 (Advisory, Restricted, Isolated) | security | `WP-12` |
| Mikoriza; Mycorrhiza | `shared_security` | shared security | settlement | `WP-44` |
| Graft; Aşı | `app_binding` | remote app binding | settlement | `WP-44` |
| Pollen | `data_market` | Data Market | application | `WP-23` |
| Budscan; BudScan | `budlum-explorer` | Budlum Explorer | application | `WP-40` |
| Atlas | `explorer_evidence` | explorer evidence model | application | `WP-23` |
| D-Web Passport | `identity_profile` | identity profile | application | `WP-23` |
| Vault (SocialFi) | `nft_folders` | NFT folders | application | `WP-23` |
| DeEd | `education_domain` | education domain | application | `WP-23` |
| budlumxyz | `app_registry` | app registry | application | `WP-23` |
| Developer OS | `project_manifest` | project manifest | tooling | `WP-39` |
| Universal Gateway; BudGateway | `content_gateway` | content gateway | storage | `WP-23` |
| Regeneration; Turritopsis model | `state_recovery` | node state recovery | node | `WP-06` |
| PUL; PUL-Full; Pul-Lite | `sigagg (crate bud-sigagg)` | signature aggregation proof | budzero | `WP-33` |
| Tarif; Recipe; TARIF-3; VideoRecipe | `bud3::Object, ObjectCommitment, bof1` | B.U.D. 3.0 object, object commitment, BUD3 Object Format 1 (BOF-1) | storage | `WP-19` |
| three_* modules | `src/storage/bud3/*` | bud3 modules | storage | `WP-21` |
| Liquid storage | `wide_stripe` | class-aware wide-stripe placement | storage | `WP-20` |
| Living Threshold; temperature transition | `access_tiering, TierTransition` | access tiering policy | storage | `WP-24` |
| Mobile Self; Server Admission | `(removed)` | removed; replaced by the Mobile validator class | storage | `WP-07` |
| Gonca; Kabuk; Kabuk-A; Kabuk-Z; Öz kökü; Mezar kümesi; Emanet açma; Gonca kanıtı | `sealed_object, ciphertext_chunks, CipherProfile::{Aead, FieldNative}, plaintext_root, deletion_set, EscrowedDisclosure, PredicateProof` | sealed object and its parts | budzero privacy | `WP-56` |
| GT-1 | `private_transfer_v1` | Private Transfer Protocol 1 (PTP-1) | budzero privacy | `WP-56` |
| Anaç; Anaç kanıtı; Tek kanıt; Kök görünüm | `DomainFinalityProof, BlockAggregateProof, RemoteStateView` | domain finality proof, block aggregate proof, remote state view | budzero | `WP-60` |
| Fotosentez; DS-0..DS-3; BÇP; YKP; Lubot | `ai_verification, VerificationLevel, DeterministicInferenceProfile, AnswerProofBundle, on_device_assistant` | AI Verification Layer, verification level VL-0..VL-3, Deterministic Inference Profile (DIP), Answer Proof Bundle (APB), on-device assistant | ai | `WP-45` |
| Gövde; Gövde-RV32; govde-konuk; Cep kanıtçısı | `budzero core, budzero-rv32, budzero-guest, MobileProverProfile` | BudZero core, BudZero RV32, BudZero guest SDK, mobile prover profile | budzero | `WP-56` |
| Sera; Greenhouse; Floem; Phloem; Ksilem; Xylem; Genotip; Genotype; Fenotip; Phenotype; Tomurcuk; Çiçek; Meyve; Kök Sözleşmesi; Yuva; Nakil | `object_layer and Section 2.2 object layer terms` | Universal Object Layer (UOL) terms | object layer | `WP-49` |

## How the gate holds the line

`xtask/gates/src/gates/concept_names.rs` searches every `patterns` expression
over the roots `src/`, `crates/`, `budzero/`, `execution/`, `mobile/`, `xtask/`,
`docs/`, `config/`, `proto/` and `contracts/`. A pattern with a `paths` list is
searched only under those prefixes.

The gate runs in two modes and starts in the first:

* `count`: the number of files and the number of matches per concept are held
  against `.github/concept-names-baseline.txt`. A count above the baseline is a
  failure: a legacy name was added. A count below it is also a failure until the
  baseline is lowered in the same change, so the recorded number can only fall
  and progress cannot go unrecorded.
* `absolute`: once every count is zero the mode becomes `absolute` and a single
  match is a failure. `WP-43` switches it at the end of the launch work.

To lower the baseline, run the gate with `BUDLUM_CONCEPT_NAMES_WRITE=1`. The
writer refuses to raise a number, so the variable cannot be used to record a
regression. Nothing else edits that file by hand.

Renaming is owned package by package. The `owner` column above names the work
package that renames the concept inside its own locked paths, and a package
that discovers a legacy name outside its paths adds a record here rather than
renaming out of its lane. `README.tr.md` is out of scope: it is the Turkish
translation and it is allowed to discuss the Turkish terms.

## Adding a record

A newly discovered legacy name gets a record with all of the fields, an owner
package, and a reason that states the function the new name describes. The
Turkish term belongs in `term_tr` and stays out of this page: this tree is
written in English, and the map is the one file in this area that carries
Turkish because the term is the datum.
