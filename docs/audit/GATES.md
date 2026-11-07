# Gate Inventory

The live gate suite, read against the binding directive's gate inventory (16.3) and
its gate-change table (5.4). This file answers one question per gate: does the gate
the directive names exist here, and if it does, under which command-line name?

The directive is not part of this tree (directive 0.1 item 5). The gate names,
their packages and their rules below come from it; the presence column is measured
on `xtask/gates/src/main.rs`.

## How a gate exists here

One binary, one gate per module. A module exists as a gate only when `main.rs`
declares it **and** an entry in the `GATES` table points at it, because `--all`
walks that table and nothing else. A module that no table entry names is a helper:
`named_tests`, `exact_named_tests`, `pq_scan` and `rust_literals` are the four in
this tree, and they are called from the gates that need them.

The command-line name is not the module name. `refusals_no_mutate` runs as
`refusals-do-not-mutate-first`, `budscan_parity` as `budscan-name-rule-parity`. A
gate name in 16.3 or 5.4 is therefore matched to the table through the entry's
`run` field and reported with the name the table gives it.

## Live inventory

Measured on `main` at `20140e87`. `log` marks a gate that takes a cargo test log
path, `args` a gate that takes further positional arguments; both refuse to run
without them rather than pass over an empty input.

| Module | Command-line name | Input |
|---|---|---|
| `zkvm_immune_regeneration` | `zkvm-immune-regeneration` | tree |
| `quantum_account` | `quantum-account` | tree |
| `parallel_execution` | `parallel-execution` | tree |
| `multi_ratio_consensus` | `multi-ratio-consensus` | tree |
| `mempool_mev_free` | `mempool-mev-free` | tree |
| `ai_inference_zk` | `ai-inference-zk` | tree |
| `bridge_dual_tree` | `bridge-dual-tree` | tree |
| `minting_paths_are_counted` | `minting-paths-are-counted` | tree |
| `no_constant_security_verdicts` | `no-constant-security-verdicts` | tree |
| `pq_claims_are_backed` | `pq-claims-are-backed` | tree |
| `no_pairing_snark_in_verification_path` | `no-pairing-snark-in-verification-path` | tree |
| `proof_deps_are_exactly_pinned` | `proof-deps-are-exactly-pinned` | tree |
| `transcript_mirrors` | `transcript-mirrors` | tree |
| `capability_modules_are_wired` | `capability-wiring` | tree |
| `coding_audit_samples_the_relationship` | `coding-audit-samples-the-relationship` | tree |
| `content_encryption_is_declared_and_bound` | `content-encryption-bound` | tree |
| `mermaid` | `mermaid` | tree |
| `budscan_parity` | `budscan-name-rule-parity` | tree |
| `budscan_patchset` | `budscan-patchset` | tree |
| `bns_names_are_safe_in_an_address_bar` | `bns-names` | tree |
| `security_scans_can_fail` | `security-scans-can-fail` | tree |
| `security_parameters` | `security-parameters-are-derived` | tree |
| `self_derived_ids_cover_every_field` | `self-derived-ids-cover-every-field` | tree |
| `shard_placement` | `shard-placement-is-sticky-and-staked` | tree |
| `suppressions_are_justified` | `suppressions-are-justified` | tree |
| `threshold_rates` | `threshold-rates-share-one-scale` | tree |
| `workflows_produce_jobs` | `workflows-produce-jobs` | tree |
| `hash_inputs_are_length_prefixed` | `hash-inputs-length-prefixed` | tree |
| `wire_fields_are_signed` | `wire-fields-are-signed` | tree |
| `the_image_builds_what_the_manifest_declares` | `image-builds-the-manifest` | tree |
| `every_fuzz_target_is_run` | `every-fuzz-target-is-run` | tree |
| `no_new_shell_gates` | `no-new-shell-gates` | tree |
| `chain_id_is_not_hardcoded` | `chain-id-is-not-hardcoded` | tree |
| `indexing_is_not_new` | `indexing-is-not-new` | tree |
| `no_orphan_source_files` | `no-orphan-source-files` | tree |
| `wallet_node_address_agree` | `wallet-node-address-agree` | tree |
| `no_idle_code` | `no-idle-code` | tree |
| `metrics_are_written` | `metrics-are-written` | tree |
| `gates_do_not_panic` | `gates-do-not-panic` | tree |
| `ai_inference_prompt_is_true` | `ai-inference-prompt-is-true` | tree |
| `serialize_map_keys_are_strings` | `serialize-map-keys-are-strings` | tree |
| `tree_is_english` | `tree-is-english` | tree |
| `no_unicode_dashes` | `no-unicode-dashes` | tree |
| `no_upstream_brands` | `no-upstream-brands` | tree |
| `no_conflict_markers` | `no-conflict-markers` | tree |
| `fork_choice_gate` | `fork-choice` | log |
| `node_classification_gate` | `node-classification` | log |
| `governance_invariants` | `governance-invariants` | log |
| `poa_compliance_gate` | `poa-compliance` | log |
| `storage_provider_gate` | `storage-provider` | log |
| `network_hardening_gate` | `network-hardening` | log |
| `economy_invariants` | `economy-invariants` | log |
| `evidence_provenance` | `evidence-provenance-is-checked` | tree |
| `timing_safe` | `timing-safe` | tree |
| `domain_tags` | `domain-tags` | tree |
| `regeneration` | `regeneration` | tree |
| `regen_health_door` | `regen-health-door` | tree |
| `relay` | `relay` | tree |
| `ci_workflow_guards` | `ci-workflow-guards` | tree |
| `genesis_schema` | `genesis-schema` | tree |
| `module_coverage` | `module-coverage` | log |
| `license_consistency` | `license-consistency` | tree |
| `fsf_import_boundaries` | `fsf-import-boundaries` | tree |
| `tree_pin` | `tree-pin` | + args |
| `rejection_tests` | `rejection-tests-assert-rejection` | tree |
| `geiger` | `geiger` | log |
| `clippy_extra` | `clippy-extra` | log |
| `cargo_vet` | `cargo-vet` | tree |
| `ownerless_dependencies` | `ownerless-dependencies` | log |
| `udeps` | `udeps` | log |
| `untrusted_manifests` | `untrusted-manifests-are-fully-validated` | tree |
| `coverage` | `coverage` | log |
| `actionlint` | `actionlint` | tree |
| `typos` | `typos` | tree |
| `zizmor` | `zizmor` | tree |
| `docker_toolchain` | `docker-toolchain-matches-pin` | tree |
| `bns_gate` | `bns-gate` | log |
| `bud_e2e` | `bud-e2e` | log |
| `wallet_core_gate` | `wallet-core-gate` | log |
| `derived_content` | `derived-content-stays-byte-exact` | tree |
| `zero_storage_frozen` | `zero-storage-bytes-are-frozen` | tree |
| `repair_fires` | `repair-fires-on-loss` | tree |
| `storage_proof_boundary` | `storage-proof-production-boundary` | tree |
| `badges_current` | `badges-are-current` | log |
| `containment_defaults` | `containment-defaults` | tree |
| `generated_content` | `generated-content-is-verifiable` | tree |
| `qr_is_derivative_only` | `qr-is-derivative-only` | tree |
| `three_is_recipe_only` | `three-is-recipe-only` | tree |
| `storage_priced` | `storage-is-priced-by-size` | tree |
| `uncheckable_proof` | `uncheckable-proof-paths-do-not-slash` | tree |
| `value_transfers` | `value-transfers-are-priced-by-value` | tree |
| `slash_expression` | `slash-expression-has-one-home` | tree |
| `refusals_no_mutate` | `refusals-do-not-mutate-first` | tree |
| `storage_penalties` | `storage-penalties-are-enforced` | tree |
| `master_derivation` | `a-derivation-cannot-outlive-its-master` | tree |
| `ai_inference_reads` | `ai-inference-reads-but-does-not-generate` | tree |
| `pinned_downloads` | `pinned-downloads-are-really-pinned` | tree |
| `paid_content` | `paid-content-cannot-be-read-for-free` | tree |
| `reduction_claims` | `reduction-claims-state-both-units` | tree |
| `consensus_maps_ordered` | `consensus-maps-are-ordered` | tree |
| `required_tests` | `required-tests-are-tests` | tree |
| `zero_tests_witness` | `zero-tests-use-an-inverse-witness` | tree |
| `gating_flags` | `gating-flags-are-pinned` | tree |
| `git_deps_audited` | `git-deps-are-audited-by-commit` | tree |
| `fuzz_targets_wired` | `fuzz-targets-are-wired` | tree |
| `gas_calibration` | `gas-calibration` | tree |
| `gates_are_wired` | `gates-are-wired` | tree |
| `readme_no_deny` | `readme-does-not-deny-shipped-code` | tree |
| `guards_reachable` | `guards-are-reachable` | tree |
| `dead_pub_api` | `dead-public-api-is-ratcheted` | tree |
| `cross_table_checks` | `cross-table-checks-use-last-row` | tree |
| `logup_multipliers` | `logup-multipliers-are-boolean` | tree |
| `accumulators_pinned` | `accumulators-pin-their-first-row` | tree |
| `binding_claims` | `binding-claims-match-reality` | tree |
| `bit_decompositions` | `bit-decompositions-are-canonical` | tree |
| `air_selectors` | `air-selectors-are-opcode-bound` | tree |
| `forgery_tests` | `forgery-tests-are-named` | tree |
| `every_opcode_forgery` | `every-opcode-has-a-forgery-test` | tree |
| `lock_failures` | `lock-failures-do-not-open-a-bound` | tree |
| `source_reading` | `source-reading-tests-are-narrowed` | tree |
| `kani` | `kani` | + args |
| `semver` | `semver` | + args |
| `ast_security_gates` | `ast-security-gates` | tree |
| `zero_address_sender_is_verified` | `zero-address-sender-verified` | tree |
| `tee_trust_boundary_is_structural` | `tee-trust-boundary-structural` | tree |
| `test_modules_can_see_what_they_test` | `test-module-imports` | tree |
| `gov_slash_evidence_is_validator_only` | `gov-slash-evidence-validator-only` | tree |
| `fixture_integrity` | `fixture-integrity` | tree |
| `consensus_state_only_changes_in_blocks` | `consensus-state-only-changes-in-blocks` | tree |
| `no_out_of_block_consensus_writes` | `no-out-of-block-consensus-writes` | tree |
| `release_profile_pins` | `release-profile-pins` | tree |
| `one_house_guards` | `one-house-guards` | tree |
| `classical_crypto_is_paired` | `classical-crypto-is-paired` | tree |
| `scheme_is_never_inferred` | `scheme-is-never-inferred` | tree |
| `pq_ctx_is_bound` | `pq-ctx-is-bound` | tree |
| `pq_core_gate` | `pq-core-gate` | log |

136 gates, 140 modules, 4 helpers. The `--all` step in
`ci.yml` walks every one of them, and `--all --self-test` walks their canaries.

## 16.3: the gates the directive keeps

All 22 are present. The directive names them by module; the tree gives each a
command-line name.

| Directive gate | Command-line name in this tree |
|---|---|
| `consensus_state_only_changes_in_blocks` | `consensus-state-only-changes-in-blocks` (yes) |
| `no_out_of_block_consensus_writes` | `no-out-of-block-consensus-writes` (yes) |
| `refusals_no_mutate` | `refusals-do-not-mutate-first` (yes) |
| `minting_paths_are_counted` | `minting-paths-are-counted` (yes) |
| `economy_invariants` | `economy-invariants` (yes) |
| `hash_inputs_are_length_prefixed` | `hash-inputs-length-prefixed` (yes) |
| `domain_tags` | `domain-tags` (yes) |
| `genesis_schema` | `genesis-schema` (yes) |
| `metrics_are_written` | `metrics-are-written` (yes) |
| `no_idle_code` | `no-idle-code` (yes) |
| `capability_modules_are_wired` | `capability-wiring` (yes) |
| `gates_are_wired` | `gates-are-wired` (yes) |
| `tree_is_english` | `tree-is-english` (yes) |
| `no_unicode_dashes` | `no-unicode-dashes` (yes) |
| `no_upstream_brands` | `no-upstream-brands` (yes) |
| `pq_claims_are_backed` | `pq-claims-are-backed` (yes) |
| `binding_claims` | `binding-claims-match-reality` (yes) |
| `no_new_shell_gates` | `no-new-shell-gates` (yes) |
| `classical_crypto_is_paired` | `classical-crypto-is-paired` (yes) |
| `badges_current` | `badges-are-current` (yes) |
| `rejection_tests` | `rejection-tests-assert-rejection` (yes) |
| `forgery_tests` | `forgery-tests-are-named` (yes) |

## 16.3: the gates the directive adds

35 names. Five already exist under their own name, because the directive keeps a
gate by naming it in both tables (`economy_invariants`,
`classical_crypto_is_paired`, `bud_e2e`, `derived_content`,
`content_encryption_is_declared_and_bound`). The other 30 do not exist.

| Directive gate | Package | Present | Command-line name |
|---|---|---|---|
| `bud_e2e` | WP-21 | yes | `bud-e2e` |
| `content_encryption_is_declared_and_bound` | WP-22 | yes | `content-encryption-bound` |
| `derived_content` | WP-24 | yes | `derived-content-stays-byte-exact` |
| `economy_invariants` | WP-26 | yes | `economy-invariants` |
| `classical_crypto_is_paired` | WP-27 | yes | `classical-crypto-is-paired` |
| `no_legacy_storage` | WP-07 | no | - |
| `concept_names` | WP-05, WP-43 | no | - |
| `canonical_programs_reproduce` | WP-06 | no | - |
| `zkvm_refuses_untrusted_proofs` | WP-06 | no | - |
| `state_recovery_door` | WP-06 | no | - |
| `bud3_forbidden_phrases` | WP-10 | no | - |
| `bud3_object_is_universal` | WP-19 | no | - |
| `bud3_qr_is_presentation` | WP-19 | no | - |
| `bud3_placement` | WP-20 | no | - |
| `bud3_repair_fires` | WP-20 | no | - |
| `bud3_custody_proofs` | WP-20 | no | - |
| `bud3_paid_view` | WP-21 | no | - |
| `bud3_fee_uses_physical_bytes` | WP-25 | no | - |
| `bud3_custody_rewards` | WP-25 | no | - |
| `ee_workers_build_with_unwind` | WP-26 | no | - |
| `explorer_parity` | WP-40 | no | - |
| `explorer_patchset` | WP-40 | no | - |
| `no_float_in_consensus_paths` | WP-42 | no | - |
| `workflows_cover_every_workspace` | WP-42 | no | - |
| `readme_definition_block_is_verbatim` | WP-43 | no | - |
| `readme_has_no_placeholders` | WP-43 | no | - |
| `readme_claims_are_wired` | WP-43 | no | - |
| `proof_class_matches_witness` | WP-56 | no | - |
| `no_64bit_commitments` | WP-56 | no | - |
| `no_witness_in_public_inputs` | WP-56 | no | - |
| `commitments_carry_hash_suite` | WP-56 | no | - |
| `privacy_claims_cite_tests` | WP-56 | no | - |
| `no_unconstrained_air_columns` | WP-56 | no | - |
| `key_release_needs_consent_proof` | WP-56 | no | - |
| `consent_records_have_no_open_identities` | WP-56 | no | - |

## 5.4: the gates the directive rewrites or deletes

12 gates. Every one of them is still in the tree and still runs. The pairs below
are the directive's decision and the tree's state side by side.

| Gate in the tree | Command-line name | Directive decision | Replacement | Replacement in the tree |
|---|---|---|---|---|
| `three_is_recipe_only` | `three-is-recipe-only` | delete | `bud3_object_is_universal` | no |
| `zero_storage_frozen` | `zero-storage-bytes-are-frozen` | delete | `none (generative content is removed)` | n/a |
| `generated_content` | `generated-content-is-verifiable` | delete | `none (generative content is removed)` | n/a |
| `qr_is_derivative_only` | `qr-is-derivative-only` | rewrite | `bud3_qr_is_presentation` | no |
| `storage_priced` | `storage-is-priced-by-size` | rewrite | `bud3_fee_uses_physical_bytes` | no |
| `storage_provider_gate` | `storage-provider` | delete | `bud3_custody_proofs` | no |
| `storage_proof_boundary` | `storage-proof-production-boundary` | delete | `bud3_custody_proofs` | no |
| `coding_audit_samples_the_relationship` | `coding-audit-samples-the-relationship` | delete | `bud3_custody_proofs` | no |
| `paid_content` | `paid-content-cannot-be-read-for-free` | delete | `bud3_paid_view` | no |
| `shard_placement` | `shard-placement-is-sticky-and-staked` | rewrite | `bud3_placement` | no |
| `repair_fires` | `repair-fires-on-loss` | rewrite | `bud3_repair_fires` | no |
| `storage_penalties` | `storage-penalties-are-enforced` | rewrite | `bud3_custody_rewards` | no |

### Why none of the 12 was deleted in this change

Directive 5.1 item 4 says a removal may not lose a function: if the replacement does
not exist yet, the capability is moved first. Directive 5.4 repeats it in the other
direction: every new gate carries a canary that injects a real violation, and every
deleted gate leaves its workflow in the same change.

Ten of the 12 name a `bud3_*` replacement, and none of those replacements exists.
The other two are deletions with no replacement (`zero_storage_frozen`,
`generated_content`), and they belong to WP-07, which cannot start before WP-06
moves persistence out of `src/storage/` (5.2). Deleting a
gate today would take a red-green verdict away from a rule that still has code to
police: the legacy storage identifiers `ContentManifest`, `StorageProvider`,
`OpenDeal`, `AnswerCodingAudit` and the `bud_storage*` RPC names are all still in
this tree, so the gates that read them are still the only thing checking them.

The deletion therefore waits for WP-07, and WP-07 waits for the replacement gate.
Recorded here rather than in a comment on a pull request because the next reader of
this file is the agent that starts WP-07.

## Wiring audit

A gate that no workflow runs is a comment. The suite has four ways to fail that
check, and all four were measured.

| Check | Measurement | Result |
|---|---|---|
| Every module is a gate or a declared helper | modules against `GATES` entries | 140 modules: 136 gates, 4 helpers |
| A gate's replaced shell script is gone | the 74 `replaces:` values against `scripts/` | 74 of 74 scripts are gone; the directory no longer exists |
| A gate name a workflow calls exists in the table | 105 distinct names across `.github/workflows/*.yml` against the table | 0 unknown names |
| A gate that needs an argument is called with one | 21 gates have `run_log` or `run_args` | 21 of 21 are called with their argument |

The last check matters because `--all` deliberately skips those 21: a gate that
cannot run without a log path is left out of the walk rather than handed an empty
argument, and `--all --self-test` keeps them because a canary needs no argument. A
gate that needed one and was called by neither path would never run, and the suite
would report success over it.

The remaining 34 gates are not named by any workflow step. They run through `--all`
in the `gates` and `repo-lint` jobs, which walks the table in order and reports every
failing gate in one line at the end rather than stopping at the first. Naming a gate
in a step buys it a separate job and its own surface, not a verdict: `--all` already
gives the verdict.

## What a green suite would mean today

Two facts about the suite as it stands, both measured rather than inferred.

1. `tree-is-english` cannot pass while the binding directive sits in the tree. The
   directive is a 556 KB Turkish document at the repository root, it is not in
   `.github/turkish-baseline.txt`, and it is not in the gate's `ALLOWED_FILES`. Every
   line of it is a finding. Item 0.1 of the directive says the document does not
   enter the repository, so the tree and the document agree on what to do. The
   file has been removed in this change. Whether the gate then passes cannot be
   measured here: the gate is a Rust binary, this sandbox has no Rust toolchain,
   and the newest 100 CI runs completed zero times. What is measurable is that one
   named finding of the gate no longer has an input.
2. A suite that runs is the only way to know the verdict. Measured with
   `gh run list --workflow ci.yml --limit 100`: 41 runs queued or in progress, 59
   cancelled, 0 completed successfully. No gate verdict exists for any commit after
   `20140e87`, so nothing in this file may be read as a passing result.
