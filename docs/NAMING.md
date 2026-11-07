# Naming

One concept, one term, one spelling. This file is the English rendering of the
binding concept-name register in `config/naming/concept_map.toml`, which WP-05
writes byte for byte from the directive's Appendix C. The register is the source;
this file is the part a reader can use without opening a TOML file.

## What the register is for

Every retired name below has a pattern. The `concept-names` gate searches that
pattern under the paths the record names, and counts what it finds. The count may
not go up, and at the end of the T-Launch layer (WP-43) it must reach zero: the
mode moves from `count` to `absolute`, and the register stops accepting leftovers.

The register therefore has two jobs, and they are the same job in two directions:
it tells a writer what to call a concept today, and it tells the gate what the
concept used to be called.

| Field in the register | Meaning |
|---|---|
| `old` | The retired name, as the tree and the documents spelled it |
| `patterns` | Rust `regex` syntax. The gate searches every pattern on every line. A pattern that contains an alternation is written with its pipe escaped in this table only |
| `paths` | If present, the pattern is only searched under these paths; if absent, every root in WP-05 item 2 is searched |
| `new_code` | The identifier the code uses now |
| `term_en` | The English term the documents use now |
| `term_tr` | The Turkish term. It stays in the register and is not repeated here, because the tree is English (directive 0.1 item 6) and the register is the one place a Turkish name is data rather than prose |
| `area` | The area the concept belongs to |
| `owner` | The package responsible for the rename (`WP-NN`) |
| `reason` | One line on why the new name is the name |

`global_allow_paths` in the register lists the files the gate does not scan: the
register itself, this file, `docs/audit/`, and the baseline file. Everything else is
searched.

## The 27 records

| Area | Retired name | Replacement in code | English term | Pattern | Search roots | Owner |
|---|---|---|---|---|---|---|
| consensus | Filiz (leader election) | hash_chain_election | hash chain leader election (HCLE) | `(?i)filiz`, `BDLM_FILIZ_` | `src/consensus/`, `src/chain/`, `src/tests/`, `src/crypto/`, `docs/` | WP-12 |
| operations | Filiz (faucet) | faucet | testnet faucet | `(?i)filiz` | `src/bin/`, `ops/`, `config/`, `mobile/` | WP-41 |
| security | Kiragi, Don, Zemheri | QuantumAlertLevel::{Advisory, Restricted, Isolated} | quantum alert level 1, 2, 3 (Advisory, Restricted, Isolated) | `(?i)kiragi`, `(?i)k[ıi]ra[ğg][ıi]`, `(?i)zemheri`, `\(Don\)`, `\bDon:` | `src/`, `docs/`, `crates/` | WP-12 |
| settlement | Mikoriza, Mycorrhiza | shared_security | shared security | `(?i)mikoriza`, `(?i)mycorrhiza` | every root in WP-05 item 2 | WP-44 |
| settlement | Graft, Aşı | app_binding | remote app binding | `(?i)graft`, `\bAşı\b` | every root in WP-05 item 2 | WP-44 |
| application | Pollen | data_market | Data Market | `(?i)pollen` | every root in WP-05 item 2 | WP-23 |
| application | Budscan, BudScan | budlum-explorer | Budlum Explorer | `(?i)budscan` | every root in WP-05 item 2 | WP-40 |
| application | Atlas | explorer_evidence | explorer evidence model | `Atlas[A-Z]`, `\batlas_`, `gateway/atlas`, `\bAtlas\b` | `src/`, `crates/`, `docs/ARCHITECTURE.md` | WP-23 |
| application | D-Web Passport | identity_profile | identity profile | `(?i)d-?web ?passport`, `(?i)dweb`, `Passport[A-Z]`, `\bpassport\b` | `src/`, `crates/`, `docs/` | WP-23 |
| application | Vault (SocialFi) | nft_folders | NFT folders | `\bVault(Error\|Registry\|Tx\|Id\|Entry\|Folder)?\b`, `\bvault_` | `src/socialfi/`, `src/core/`, `src/chain/`, `src/rpc/`, `docs/` | WP-23 |
| application | DeEd | education_domain | education domain | `\bDeEd`, `src/deed`, `\bdeed::`, `\bmod deed\b` | every root in WP-05 item 2 | WP-23 |
| application | budlumxyz | app_registry | app registry | `(?i)budlumxyz` | every root in WP-05 item 2 | WP-23 |
| tooling | Developer OS | project_manifest | project manifest | `(?i)developer[ _]?os\b`, `DeveloperOs` | every root in WP-05 item 2 | WP-39 |
| storage | Universal Gateway, BudGateway | content_gateway | content gateway | `(?i)universal gateway`, `(?i)budgateway` | every root in WP-05 item 2 | WP-23 |
| node | Regeneration, Turritopsis model | state_recovery | node state recovery | `(?i)regeneration`, `(?i)\bregen_`, `Regen[A-Z]`, `(?i)turritopsis` | every root in WP-05 item 2 | WP-06 |
| budzero | PUL, PUL-Full, Pul-Lite | sigagg (crate bud-sigagg) | signature aggregation proof | `Pul[A-Z]`, `(?i)bud[-_]pul`, `\bPUL\b`, `\bpul_` | every root in WP-05 item 2 | WP-33 |
| storage | Tarif, Recipe, TARIF-3, VideoRecipe | bud3::Object, ObjectCommitment, bof1 | B.U.D. 3.0 object, object commitment, BUD3 Object Format 1 (BOF-1) | `(?i)recipe`, `(?i)\btarif`, `TARIF-3` | every root in WP-05 item 2 | WP-19 |
| storage | three_* modules | src/storage/bud3/* | bud3 modules | `\bthree_(recipe\|regime\|pipe\|hooks\|gate\|nft\|rpc\|reveal\|meter\|visibility)`, `\bTHREE_(PAYLOAD\|FRAME)_`, `BudStorageEdition` | every root in WP-05 item 2 | WP-21 |
| storage | Liquid storage | wide_stripe | class-aware wide-stripe placement | `(?i)liquid[ _-]?(storage\|placement\|stripe)` | every root in WP-05 item 2 | WP-20 |
| storage | Living Threshold, temperature transition | access_tiering, TierTransition | access tiering policy | `(?i)living[ _]?threshold`, `LivingThreshold` | every root in WP-05 item 2 | WP-24 |
| storage | Mobile Self, Server Admission | (removed) | removed; replaced by the Mobile validator class | `MobileSelf`, `(?i)mobile_self`, `ServerAdmission`, `(?i)server_admission` | every root in WP-05 item 2 | WP-07 |
| budzero privacy | Gonca, Kabuk, Kabuk-A, Kabuk-Z, Öz kökü, Mezar kümesi, Emanet açma, Gonca kanıtı | sealed_object, ciphertext_chunks, CipherProfile::{Aead, FieldNative}, plaintext_root, deletion_set, EscrowedDisclosure, PredicateProof | sealed object and its parts | `(?i)gonca`, `(?i)\bkabuk`, `(?i)\boz_koku\b`, `(?i)öz kökü`, `(?i)mezar`, `(?i)emanet açma` | every root in WP-05 item 2 | WP-56 |
| budzero privacy | GT-1 | private_transfer_v1 | Private Transfer Protocol 1 (PTP-1) | `\bGT-1\b`, `(?i)\bgt1_` | every root in WP-05 item 2 | WP-56 |
| budzero | Anaç, Anaç kanıtı, Tek kanıt, Kök görünüm | DomainFinalityProof, BlockAggregateProof, RemoteStateView | domain finality proof, block aggregate proof, remote state view | `\bAnaç`, `(?i)\banac_`, `(?i)tek kan[ıi]t`, `(?i)kök görünüm` | every root in WP-05 item 2 | WP-60 |
| ai | Fotosentez, DS-0..DS-3, BÇP, YKP, Lubot | ai_verification, VerificationLevel, DeterministicInferenceProfile, AnswerProofBundle, on_device_assistant | AI Verification Layer, verification level VL-0..VL-3, Deterministic Inference Profile (DIP), Answer Proof Bundle (APB), on-device assistant | `(?i)fotosentez`, `\bDS-[0-3]\b`, `\bBÇP\b`, `\bYKP\b`, `(?i)lubot` | every root in WP-05 item 2 | WP-45 |
| budzero | Gövde, Gövde-RV32, govde-konuk, Cep kanıtçısı | budzero core, budzero-rv32, budzero-guest, MobileProverProfile | BudZero core, BudZero RV32, BudZero guest SDK, mobile prover profile | `(?i)g[oö]vde`, `(?i)cep kan[ıi]t` | every root in WP-05 item 2 | WP-56 |
| object layer | Sera, Greenhouse, Floem, Phloem, Ksilem, Xylem, Genotip, Genotype, Fenotip, Phenotype, Tomurcuk, Çiçek, Meyve, Kök Sözleşmesi, Yuva, Nakil | object_layer and Section 2.2 object layer terms | Universal Object Layer (UOL) terms | `(?i)(^\|[^a-z])sera($\|[^a-z])`, `(?i)greenhouse`, `(?i)floem`, `(?i)phloem`, `(?i)ksilem`, `(?i)xylem`, `(?i)genotip`, `(?i)genotype`, `(?i)fenotip`, `(?i)phenotype`, `(?i)tomurcuk`, `\bÇiçek\b`, `\bMeyve\b`, `(?i)kök sözleşmesi`, `\bYuva\b`, `\bNakil\b` | every root in WP-05 item 2 | WP-49 |

## Counter

The register's mode is `count` today, with a baseline file
`.github/concept-names-baseline.txt`. That file and the gate that generates it do not
exist yet, so the counter has no value that can be quoted, and no number here would
be a measurement. When the gate lands, the baseline is generated from it, and every
number in it may only go down.

Two things follow, and neither is optional:

1. A new retired name found in the tree is added to the register as a new record,
   with its owner package. The counter is still zero at the end of WP-43.
2. A record whose count reaches zero has its baseline line deleted, not set to
   zero. A baseline that lists a file with nothing left in it is a claim the gate
   then has to check against a tree that disagrees.

## Where the names in the register came from

The register is not a style guide somebody wrote. Each record retires a name that
was in the tree, in the documents, or in both, and each owner package is the package
that has to do the rename in code. The list is therefore also the answer to "what is
still called the old thing, and who fixes it".
