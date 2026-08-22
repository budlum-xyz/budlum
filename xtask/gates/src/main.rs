//! Repository gates, in Rust.
//!
//! # Why this crate exists
//!
//! The gates were shell. Eighteen thousand lines of it across seventy-four
//! `scripts/check-*.sh`, each one deciding whether a commit is allowed onto
//! `main`. That places them inside the trust boundary, and shell is a poor
//! language to put there:
//!
//!   * A misspelt variable is an empty string, not an error, so a check can
//!     silently examine nothing and report OK. `set -u` catches the unset
//!     case and not the misspelt-but-assigned one.
//!   * `grep -q` answers "does this text appear", which is the wrong question
//!     often enough that it let a wrongly scaled rate and a stale factor
//!     through two separate gates on this branch alone. Both were found by
//!     recomputing outside the gate, not by the gate.
//!   * There is no type between a path, a count and a label, so a gate that
//!     compares the wrong two things compiles and runs.
//!   * The canaries were themselves shell, so a broken canary and a working
//!     one look the same from the outside.
//!
//! Rust removes the first and third by construction, and makes the second a
//! matter of writing the arithmetic out rather than grepping for its answer.
//!
//! # Shape
//!
//! One binary, one gate per module, each exposing `run` and `self_test`.
//! Both return `Result<String, String>`: the `Ok` side is what a passing gate
//! prints, the `Err` side is the finding. Nothing calls `process::exit` from
//! inside a gate, so a gate can be called from a test.
//!
//! # Migration
//!
//! The shell gates are being replaced one at a time, not in a single sweep. A
//! gate moves when its Rust version reproduces every canary the shell version
//! had, which is checked by `--self-test`. Until a gate has moved, its shell
//! script stays wired and authoritative; a half-ported gate that runs in
//! neither language would be worse than the shell it replaced.

use std::path::{Path, PathBuf};

mod gates {
    pub mod accumulators_pinned;
    pub mod actionlint;
    pub mod air_selectors;
    pub mod ast_security_gates;
    pub mod badges_current;
    pub mod binding_claims;
    pub mod bit_decompositions;
    pub mod bns_gate;
    pub mod bns_names_are_safe_in_an_address_bar;
    pub mod bud_e2e;
    pub mod budscan_parity;
    pub mod budscan_patchset;
    pub mod capability_modules_are_wired;
    pub mod cargo_vet;
    pub mod chain_id_is_not_hardcoded;
    pub mod clippy_extra;
    pub mod coding_audit_samples_the_relationship;
    pub mod consensus_maps_ordered;
    pub mod containment_defaults;
    pub mod content_encryption_is_declared_and_bound;
    pub mod coverage;
    pub mod cross_table_checks;
    pub mod derived_content;
    pub mod docker_toolchain;
    pub mod domain_tags;
    pub mod economy_invariants;
    pub mod every_fuzz_target_is_run;
    pub mod every_opcode_forgery;
    pub mod evidence_provenance;
    pub mod exact_named_tests;
    pub mod fixture_integrity;
    pub mod forgery_tests;
    pub mod fork_choice_gate;
    pub mod fuzz_targets_wired;
    pub mod gates_are_wired;
    pub mod gating_flags;
    pub mod geiger;
    pub mod generated_content;
    pub mod git_deps_audited;
    pub mod gov_slash_evidence_is_validator_only;
    pub mod governance_invariants;
    pub mod guards_reachable;
    pub mod hash_inputs_are_length_prefixed;
    pub mod indexing_is_not_new;
    pub mod kani;
    pub mod lock_failures;
    pub mod logup_multipliers;
    pub mod lubot_reads;
    pub mod master_derivation;
    pub mod mermaid;
    pub mod named_tests;
    pub mod network_hardening_gate;
    pub mod no_conflict_markers;
    pub mod no_new_shell_gates;
    pub mod no_orphan_source_files;
    pub mod no_unicode_dashes;
    pub mod node_classification_gate;
    pub mod paid_content;
    pub mod pinned_downloads;
    pub mod poa_compliance_gate;
    pub mod readme_no_deny;
    pub mod reduction_claims;
    pub mod refusals_no_mutate;
    pub mod regeneration;
    pub mod rejection_tests;
    pub mod repair_fires;
    pub mod required_tests;
    pub mod rust_literals;
    pub mod security_parameters;
    pub mod security_scans_can_fail;
    pub mod self_derived_ids_cover_every_field;
    pub mod semver;
    pub mod shard_placement;
    pub mod slash_expression;
    pub mod source_reading;
    pub mod storage_penalties;
    pub mod storage_priced;
    pub mod storage_proof_boundary;
    pub mod storage_provider_gate;
    pub mod suppressions_are_justified;
    pub mod tee_trust_boundary_is_structural;
    pub mod the_image_builds_what_the_manifest_declares;
    pub mod threshold_rates;
    pub mod timing_safe;
    pub mod udeps;
    pub mod uncheckable_proof;
    pub mod untrusted_manifests;
    pub mod value_transfers;
    pub mod wallet_core_gate;
    pub mod wire_fields_are_signed;
    pub mod workflows_produce_jobs;
    pub mod zero_address_sender_is_verified;
    pub mod zero_storage_frozen;
    pub mod zero_tests_witness;
    pub mod zizmor;
}

/// A gate's plain run: inspect the repo root, return a verdict.
type Run = fn(&Path) -> Result<String, String>;
/// A gate's log run: inspect the repo root plus a cargo test log path.
type RunLog = fn(&Path, &Path) -> Result<String, String>;
/// A gate's argumented run: the repo root plus whatever the caller passed.
type RunArgs = fn(&Path, &[&str]) -> Result<String, String>;

/// One gate, as the runner sees it.
struct Gate {
    /// Name used on the command line and in CI job names.
    name: &'static str,
    /// The shell script this replaced, so the two can be compared during the
    /// migration and the old one deleted with evidence rather than hope.
    replaces: Option<&'static str>,
    run: Run,
    /// Gates that read a cargo test log take the log path as a second
    /// argument; `run` stays a placeholder that explains the requirement.
    run_log: Option<RunLog>,
    /// Gates that take extra positional arguments (a log path, two roots,
    /// a flag) receive them here; `run` stays a placeholder that explains
    /// the requirement.
    run_args: Option<RunArgs>,
    self_test: fn() -> Result<String, String>,
}

const GATES: &[Gate] = &[
    Gate {
        name: "capability-wiring",
        replaces: Some("check-capability-modules-are-wired.sh"),
        run: gates::capability_modules_are_wired::run,
        run_args: None,
        self_test: gates::capability_modules_are_wired::self_test,
        run_log: None,
    },
    Gate {
        name: "coding-audit-samples-the-relationship",
        replaces: Some("check-coding-audit-samples-the-relationship.sh"),
        run: gates::coding_audit_samples_the_relationship::run,
        run_args: None,
        self_test: gates::coding_audit_samples_the_relationship::self_test,
        run_log: None,
    },
    Gate {
        name: "content-encryption-bound",
        replaces: Some("check-content-encryption-is-declared-and-bound.sh"),
        run: gates::content_encryption_is_declared_and_bound::run,
        run_args: None,
        self_test: gates::content_encryption_is_declared_and_bound::self_test,
        run_log: None,
    },
    Gate {
        name: "mermaid",
        replaces: None,
        run: gates::mermaid::run,
        run_args: None,
        self_test: gates::mermaid::self_test,
        run_log: None,
    },
    Gate {
        name: "budscan-name-rule-parity",
        replaces: None,
        run: gates::budscan_parity::run,
        run_args: None,
        self_test: gates::budscan_parity::self_test,
        run_log: None,
    },
    Gate {
        name: "budscan-patchset",
        replaces: None,
        run: gates::budscan_patchset::run,
        run_args: None,
        self_test: gates::budscan_patchset::self_test,
        run_log: None,
    },
    Gate {
        name: "bns-names",
        replaces: None,
        run: gates::bns_names_are_safe_in_an_address_bar::run,
        run_args: None,
        self_test: gates::bns_names_are_safe_in_an_address_bar::self_test,
        run_log: None,
    },
    Gate {
        name: "security-scans-can-fail",
        replaces: None,
        run: gates::security_scans_can_fail::run,
        run_args: None,
        self_test: gates::security_scans_can_fail::self_test,
        run_log: None,
    },
    Gate {
        name: "security-parameters-are-derived",
        replaces: Some("check-security-parameters-are-derived.sh"),
        run: gates::security_parameters::run,
        run_log: None,
        run_args: None,
        self_test: gates::security_parameters::self_test,
    },
    Gate {
        name: "self-derived-ids-cover-every-field",
        replaces: Some("check-self-derived-ids-cover-every-field.sh"),
        run: gates::self_derived_ids_cover_every_field::run,
        run_args: None,
        self_test: gates::self_derived_ids_cover_every_field::self_test,
        run_log: None,
    },
    Gate {
        name: "shard-placement-is-sticky-and-staked",
        replaces: Some("check-shard-placement-is-sticky-and-staked.sh"),
        run: gates::shard_placement::run,
        run_log: None,
        run_args: None,
        self_test: gates::shard_placement::self_test,
    },
    Gate {
        name: "suppressions-are-justified",
        replaces: None,
        run: gates::suppressions_are_justified::run,
        run_args: None,
        self_test: gates::suppressions_are_justified::self_test,
        run_log: None,
    },
    Gate {
        name: "threshold-rates-share-one-scale",
        replaces: Some("check-threshold-rates-share-one-scale.sh"),
        run: gates::threshold_rates::run,
        run_args: None,
        self_test: gates::threshold_rates::self_test,
        run_log: None,
    },
    Gate {
        name: "workflows-produce-jobs",
        replaces: None,
        run: gates::workflows_produce_jobs::run,
        run_args: None,
        self_test: gates::workflows_produce_jobs::self_test,
        run_log: None,
    },
    Gate {
        name: "hash-inputs-length-prefixed",
        replaces: Some("check-hash-inputs-are-length-prefixed.sh"),
        run: gates::hash_inputs_are_length_prefixed::run,
        run_args: None,
        self_test: gates::hash_inputs_are_length_prefixed::self_test,
        run_log: None,
    },
    Gate {
        name: "wire-fields-are-signed",
        replaces: Some("check-wire-fields-are-signed.sh"),
        run: gates::wire_fields_are_signed::run,
        run_args: None,
        self_test: gates::wire_fields_are_signed::self_test,
        run_log: None,
    },
    Gate {
        name: "image-builds-the-manifest",
        replaces: None,
        run: gates::the_image_builds_what_the_manifest_declares::run,
        run_args: None,
        self_test: gates::the_image_builds_what_the_manifest_declares::self_test,
        run_log: None,
    },
    Gate {
        name: "every-fuzz-target-is-run",
        replaces: None,
        run: gates::every_fuzz_target_is_run::run,
        run_args: None,
        self_test: gates::every_fuzz_target_is_run::self_test,
        run_log: None,
    },
    Gate {
        name: "no-new-shell-gates",
        replaces: None,
        run: gates::no_new_shell_gates::run,
        run_args: None,
        self_test: gates::no_new_shell_gates::self_test,
        run_log: None,
    },
    Gate {
        name: "chain-id-is-not-hardcoded",
        replaces: None,
        run: gates::chain_id_is_not_hardcoded::run,
        run_args: None,
        self_test: gates::chain_id_is_not_hardcoded::self_test,
        run_log: None,
    },
    Gate {
        name: "indexing-is-not-new",
        replaces: None,
        run: gates::indexing_is_not_new::run,
        run_args: None,
        self_test: gates::indexing_is_not_new::self_test,
        run_log: None,
    },
    Gate {
        name: "no-orphan-source-files",
        replaces: Some("check-no-orphan-source-files.sh"),
        run: gates::no_orphan_source_files::run,
        run_args: None,
        self_test: gates::no_orphan_source_files::self_test,
        run_log: None,
    },
    Gate {
        name: "no-unicode-dashes",
        replaces: Some("check-no-unicode-dashes.sh"),
        run: gates::no_unicode_dashes::run,
        run_args: None,
        self_test: gates::no_unicode_dashes::self_test,
        run_log: None,
    },
    Gate {
        name: "no-conflict-markers",
        replaces: Some("check-no-conflict-markers-are-committed.sh"),
        run: gates::no_conflict_markers::run,
        run_args: None,
        self_test: gates::no_conflict_markers::self_test,
        run_log: None,
    },
    Gate {
        name: "fork-choice",
        replaces: Some("check-fork-choice-gate.sh"),
        run: |_| {
            Err(String::from(
                "fork-choice reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::fork_choice_gate::run),
        run_args: None,
        self_test: gates::fork_choice_gate::self_test,
    },
    Gate {
        name: "node-classification",
        replaces: Some("check-node-classification-gate.sh"),
        run: |_| {
            Err(String::from(
                "node-classification reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::node_classification_gate::run),
        run_args: None,
        self_test: gates::node_classification_gate::self_test,
    },
    Gate {
        name: "governance-invariants",
        replaces: Some("check-governance-invariants.sh"),
        run: |_| {
            Err(String::from(
                "governance-invariants reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::governance_invariants::run),
        run_args: None,
        self_test: gates::governance_invariants::self_test,
    },
    Gate {
        name: "poa-compliance",
        replaces: Some("check-poa-compliance-gate.sh"),
        run: |_| {
            Err(String::from(
                "poa-compliance reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::poa_compliance_gate::run),
        run_args: None,
        self_test: gates::poa_compliance_gate::self_test,
    },
    Gate {
        name: "storage-provider",
        replaces: Some("check-storage-provider-gate.sh"),
        run: |_| {
            Err(String::from(
                "storage-provider reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::storage_provider_gate::run),
        run_args: None,
        self_test: gates::storage_provider_gate::self_test,
    },
    Gate {
        name: "network-hardening",
        replaces: Some("check-network-hardening-gate.sh"),
        run: |_| {
            Err(String::from(
                "network-hardening reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::network_hardening_gate::run),
        run_args: None,
        self_test: gates::network_hardening_gate::self_test,
    },
    Gate {
        name: "economy-invariants",
        replaces: Some("check-economy-invariants.sh"),
        run: |_| {
            Err(String::from(
                "economy-invariants reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::economy_invariants::run),
        run_args: None,
        self_test: gates::economy_invariants::self_test,
    },
    Gate {
        name: "evidence-provenance-is-checked",
        replaces: Some("check-evidence-provenance-is-checked.sh"),
        run: gates::evidence_provenance::run,
        run_log: None,
        run_args: None,
        self_test: gates::evidence_provenance::self_test,
    },
    Gate {
        name: "timing-safe",
        replaces: Some("check-timing-safe.sh"),
        run: gates::timing_safe::run,
        run_log: None,
        run_args: None,
        self_test: gates::timing_safe::self_test,
    },
    Gate {
        name: "domain-tags",
        replaces: Some("check-domain-tags.sh"),
        run: gates::domain_tags::run,
        run_log: None,
        run_args: None,
        self_test: gates::domain_tags::self_test,
    },
    Gate {
        name: "regeneration",
        replaces: None,
        run: gates::regeneration::run,
        run_log: None,
        run_args: None,
        self_test: gates::regeneration::self_test,
    },
    Gate {
        name: "rejection-tests-assert-rejection",
        replaces: Some("check-rejection-tests-assert-rejection.sh"),
        run: gates::rejection_tests::run,
        run_log: None,
        run_args: None,
        self_test: gates::rejection_tests::self_test,
    },
    Gate {
        name: "geiger",
        replaces: Some("check-geiger.sh"),
        run: |_| {
            Err(String::from(
                "geiger reads a report file; pass its path as an argument",
            ))
        },
        run_log: Some(gates::geiger::run),
        run_args: None,
        self_test: gates::geiger::self_test,
    },
    Gate {
        name: "clippy-extra",
        replaces: Some("check-clippy-extra.sh"),
        run: |_| {
            Err(String::from(
                "clippy-extra reads a clippy JSON file; pass its path as an argument",
            ))
        },
        run_log: Some(gates::clippy_extra::run),
        run_args: None,
        self_test: gates::clippy_extra::self_test,
    },
    Gate {
        name: "cargo-vet",
        replaces: Some("check-cargo-vet.sh"),
        run: gates::cargo_vet::run,
        run_log: None,
        run_args: None,
        self_test: gates::cargo_vet::self_test,
    },
    Gate {
        name: "udeps",
        replaces: Some("check-udeps.sh"),
        run: |_| {
            Err(String::from(
                "udeps reads a udeps output file; pass its path as an argument",
            ))
        },
        run_log: Some(gates::udeps::run),
        run_args: None,
        self_test: gates::udeps::self_test,
    },
    Gate {
        name: "untrusted-manifests-are-fully-validated",
        replaces: Some("check-untrusted-manifests-are-fully-validated.sh"),
        run: gates::untrusted_manifests::run,
        run_log: None,
        run_args: None,
        self_test: gates::untrusted_manifests::self_test,
    },
    Gate {
        name: "coverage",
        replaces: Some("check-coverage.sh"),
        run: |_| {
            Err(String::from(
                "coverage reads a coverage report; pass its path as an argument",
            ))
        },
        run_log: Some(gates::coverage::run),
        run_args: None,
        self_test: gates::coverage::self_test,
    },
    Gate {
        name: "actionlint",
        replaces: Some("check-actionlint.sh"),
        run: gates::actionlint::run,
        run_log: None,
        run_args: None,
        self_test: gates::actionlint::self_test,
    },
    Gate {
        name: "zizmor",
        replaces: Some("check-zizmor.sh"),
        run: gates::zizmor::run,
        run_log: None,
        run_args: None,
        self_test: gates::zizmor::self_test,
    },
    Gate {
        name: "docker-toolchain-matches-pin",
        replaces: Some("check-docker-toolchain-matches-pin.sh"),
        run: gates::docker_toolchain::run,
        run_log: None,
        run_args: None,
        self_test: gates::docker_toolchain::self_test,
    },
    Gate {
        name: "bns-gate",
        replaces: Some("check-bns-gate.sh"),
        run: |_| {
            Err(String::from(
                "bns-gate reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::bns_gate::run),
        run_args: None,
        self_test: gates::bns_gate::self_test,
    },
    Gate {
        name: "bud-e2e",
        replaces: Some("check-bud-e2e.sh"),
        run: |_| {
            Err(String::from(
                "bud-e2e reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::bud_e2e::run),
        run_args: None,
        self_test: gates::bud_e2e::self_test,
    },
    Gate {
        name: "wallet-core-gate",
        replaces: Some("check-wallet-core-gate.sh"),
        run: |_| {
            Err(String::from(
                "wallet-core-gate reads a cargo test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::wallet_core_gate::run),
        run_args: None,
        self_test: gates::wallet_core_gate::self_test,
    },
    Gate {
        name: "derived-content-stays-byte-exact",
        replaces: Some("check-derived-content-stays-byte-exact.sh"),
        run: gates::derived_content::run,
        run_log: None,
        run_args: None,
        self_test: gates::derived_content::self_test,
    },
    Gate {
        name: "zero-storage-bytes-are-frozen",
        replaces: Some("check-zero-storage-bytes-are-frozen.sh"),
        run: gates::zero_storage_frozen::run,
        run_log: None,
        run_args: None,
        self_test: gates::zero_storage_frozen::self_test,
    },
    Gate {
        name: "repair-fires-on-loss",
        replaces: Some("check-repair-fires-on-loss.sh"),
        run: gates::repair_fires::run,
        run_log: None,
        run_args: None,
        self_test: gates::repair_fires::self_test,
    },
    Gate {
        name: "storage-proof-production-boundary",
        replaces: Some("check-storage-proof-production-boundary.sh"),
        run: gates::storage_proof_boundary::run,
        run_log: None,
        run_args: None,
        self_test: gates::storage_proof_boundary::self_test,
    },
    Gate {
        name: "badges-are-current",
        replaces: Some("check-badges-are-current.sh"),
        run: |_| {
            Err(String::from(
                "badges-are-current reads a test log; pass its path as an argument",
            ))
        },
        run_log: Some(gates::badges_current::run),
        run_args: None,
        self_test: gates::badges_current::self_test,
    },
    Gate {
        name: "containment-defaults",
        replaces: Some("check-containment-defaults.sh"),
        run: gates::containment_defaults::run,
        run_log: None,
        run_args: None,
        self_test: gates::containment_defaults::self_test,
    },
    Gate {
        name: "generated-content-is-verifiable",
        replaces: Some("check-generated-content-is-verifiable.sh"),
        run: gates::generated_content::run,
        run_log: None,
        run_args: None,
        self_test: gates::generated_content::self_test,
    },
    Gate {
        name: "storage-is-priced-by-size",
        replaces: Some("check-storage-is-priced-by-size.sh"),
        run: gates::storage_priced::run,
        run_log: None,
        run_args: None,
        self_test: gates::storage_priced::self_test,
    },
    Gate {
        name: "uncheckable-proof-paths-do-not-slash",
        replaces: Some("check-uncheckable-proof-paths-do-not-slash.sh"),
        run: gates::uncheckable_proof::run,
        run_log: None,
        run_args: None,
        self_test: gates::uncheckable_proof::self_test,
    },
    Gate {
        name: "value-transfers-are-priced-by-value",
        replaces: Some("check-value-transfers-are-priced-by-value.sh"),
        run: gates::value_transfers::run,
        run_log: None,
        run_args: None,
        self_test: gates::value_transfers::self_test,
    },
    Gate {
        name: "slash-expression-has-one-home",
        replaces: Some("check-slash-expression-has-one-home.sh"),
        run: gates::slash_expression::run,
        run_log: None,
        run_args: None,
        self_test: gates::slash_expression::self_test,
    },
    Gate {
        name: "refusals-do-not-mutate-first",
        replaces: Some("check-refusals-do-not-mutate-first.sh"),
        run: gates::refusals_no_mutate::run,
        run_log: None,
        run_args: None,
        self_test: gates::refusals_no_mutate::self_test,
    },
    Gate {
        name: "storage-penalties-are-enforced",
        replaces: Some("check-storage-penalties-are-enforced.sh"),
        run: gates::storage_penalties::run,
        run_log: None,
        run_args: None,
        self_test: gates::storage_penalties::self_test,
    },
    Gate {
        name: "a-derivation-cannot-outlive-its-master",
        replaces: Some("check-a-derivation-cannot-outlive-its-master.sh"),
        run: gates::master_derivation::run,
        run_log: None,
        run_args: None,
        self_test: gates::master_derivation::self_test,
    },
    Gate {
        name: "lubot-reads-but-does-not-generate",
        replaces: Some("check-lubot-reads-but-does-not-generate.sh"),
        run: gates::lubot_reads::run,
        run_log: None,
        run_args: None,
        self_test: gates::lubot_reads::self_test,
    },
    Gate {
        name: "pinned-downloads-are-really-pinned",
        replaces: Some("check-pinned-downloads-are-really-pinned.sh"),
        run: gates::pinned_downloads::run,
        run_log: None,
        run_args: None,
        self_test: gates::pinned_downloads::self_test,
    },
    Gate {
        name: "paid-content-cannot-be-read-for-free",
        replaces: Some("check-paid-content-cannot-be-read-for-free.sh"),
        run: gates::paid_content::run,
        run_log: None,
        run_args: None,
        self_test: gates::paid_content::self_test,
    },
    Gate {
        name: "reduction-claims-state-both-units",
        replaces: Some("check-reduction-claims-state-both-units.sh"),
        run: gates::reduction_claims::run,
        run_log: None,
        run_args: None,
        self_test: gates::reduction_claims::self_test,
    },
    Gate {
        name: "consensus-maps-are-ordered",
        replaces: Some("check-consensus-maps-are-ordered.sh"),
        run: gates::consensus_maps_ordered::run,
        run_log: None,
        run_args: None,
        self_test: gates::consensus_maps_ordered::self_test,
    },
    Gate {
        name: "required-tests-are-tests",
        replaces: Some("check-required-tests-are-tests.sh"),
        run: gates::required_tests::run,
        run_log: None,
        run_args: None,
        self_test: gates::required_tests::self_test,
    },
    Gate {
        name: "zero-tests-use-an-inverse-witness",
        replaces: Some("check-zero-tests-use-an-inverse-witness.sh"),
        run: gates::zero_tests_witness::run,
        run_log: None,
        run_args: None,
        self_test: gates::zero_tests_witness::self_test,
    },
    Gate {
        name: "gating-flags-are-pinned",
        replaces: Some("check-gating-flags-are-pinned.sh"),
        run: gates::gating_flags::run,
        run_log: None,
        run_args: None,
        self_test: gates::gating_flags::self_test,
    },
    Gate {
        name: "git-deps-are-audited-by-commit",
        replaces: Some("check-git-deps-are-audited-by-commit.sh"),
        run: gates::git_deps_audited::run,
        run_log: None,
        run_args: None,
        self_test: gates::git_deps_audited::self_test,
    },
    Gate {
        name: "fuzz-targets-are-wired",
        replaces: Some("check-fuzz-targets-are-wired.sh"),
        run: gates::fuzz_targets_wired::run,
        run_log: None,
        run_args: None,
        self_test: gates::fuzz_targets_wired::self_test,
    },
    Gate {
        name: "gates-are-wired",
        replaces: Some("check-gates-are-wired.sh"),
        run: gates::gates_are_wired::run,
        run_log: None,
        run_args: None,
        self_test: gates::gates_are_wired::self_test,
    },
    Gate {
        name: "readme-does-not-deny-shipped-code",
        replaces: Some("check-readme-does-not-deny-shipped-code.sh"),
        run: gates::readme_no_deny::run,
        run_log: None,
        run_args: None,
        self_test: gates::readme_no_deny::self_test,
    },
    Gate {
        name: "guards-are-reachable",
        replaces: Some("check-guards-are-reachable.sh"),
        run: gates::guards_reachable::run,
        run_log: None,
        run_args: None,
        self_test: gates::guards_reachable::self_test,
    },
    Gate {
        name: "cross-table-checks-use-last-row",
        replaces: Some("check-cross-table-checks-use-last-row.sh"),
        run: gates::cross_table_checks::run,
        run_log: None,
        run_args: None,
        self_test: gates::cross_table_checks::self_test,
    },
    Gate {
        name: "logup-multipliers-are-boolean",
        replaces: Some("check-logup-multipliers-are-boolean.sh"),
        run: gates::logup_multipliers::run,
        run_log: None,
        run_args: None,
        self_test: gates::logup_multipliers::self_test,
    },
    Gate {
        name: "accumulators-pin-their-first-row",
        replaces: Some("check-accumulators-pin-their-first-row.sh"),
        run: gates::accumulators_pinned::run,
        run_log: None,
        run_args: None,
        self_test: gates::accumulators_pinned::self_test,
    },
    Gate {
        name: "binding-claims-match-reality",
        replaces: Some("check-binding-claims-match-reality.sh"),
        run: gates::binding_claims::run,
        run_log: None,
        run_args: None,
        self_test: gates::binding_claims::self_test,
    },
    Gate {
        name: "bit-decompositions-are-canonical",
        replaces: Some("check-bit-decompositions-are-canonical.sh"),
        run: gates::bit_decompositions::run,
        run_log: None,
        run_args: None,
        self_test: gates::bit_decompositions::self_test,
    },
    Gate {
        name: "air-selectors-are-opcode-bound",
        replaces: Some("check-air-selectors-are-opcode-bound.sh"),
        run: gates::air_selectors::run,
        run_log: None,
        run_args: None,
        self_test: gates::air_selectors::self_test,
    },
    Gate {
        name: "forgery-tests-are-named",
        replaces: Some("check-forgery-tests-are-named.sh"),
        run: gates::forgery_tests::run,
        run_log: None,
        run_args: None,
        self_test: gates::forgery_tests::self_test,
    },
    Gate {
        name: "every-opcode-has-a-forgery-test",
        replaces: Some("check-every-opcode-has-a-forgery-test.sh"),
        run: gates::every_opcode_forgery::run,
        run_log: None,
        run_args: None,
        self_test: gates::every_opcode_forgery::self_test,
    },
    Gate {
        name: "lock-failures-do-not-open-a-bound",
        replaces: Some("check-lock-failures-do-not-open-a-bound.sh"),
        run: gates::lock_failures::run,
        run_log: None,
        run_args: None,
        self_test: gates::lock_failures::self_test,
    },
    Gate {
        name: "source-reading-tests-are-narrowed",
        replaces: Some("check-source-reading-tests-are-narrowed.sh"),
        run: gates::source_reading::run,
        run_log: None,
        run_args: None,
        self_test: gates::source_reading::self_test,
    },
    Gate {
        name: "kani",
        replaces: Some("check-kani.sh"),
        run: |_| {
            Err(String::from(
                "kani reads a Kani output log or emits harness names; pass the \
                 log path or --fast-names / --slow-names / --module-path",
            ))
        },
        run_log: None,
        run_args: Some(gates::kani::run_args),
        self_test: gates::kani::self_test,
    },
    Gate {
        name: "semver",
        replaces: Some("check-semver.sh"),
        run: |_| {
            Err(String::from(
                "semver compares a current checkout against a baseline; pass \
                 <current-root> <baseline-root>",
            ))
        },
        run_log: None,
        run_args: Some(gates::semver::run_args),
        self_test: gates::semver::self_test,
    },
    Gate {
        name: "ast-security-gates",
        replaces: None,
        run: gates::ast_security_gates::run,
        run_log: None,
        run_args: None,
        self_test: gates::ast_security_gates::self_test,
    },
    Gate {
        name: "zero-address-sender-verified",
        replaces: None,
        run: gates::zero_address_sender_is_verified::run,
        run_log: None,
        run_args: None,
        self_test: gates::zero_address_sender_is_verified::self_test,
    },
    Gate {
        name: "tee-trust-boundary-structural",
        replaces: None,
        run: gates::tee_trust_boundary_is_structural::run,
        run_log: None,
        run_args: None,
        self_test: gates::tee_trust_boundary_is_structural::self_test,
    },
    Gate {
        name: "gov-slash-evidence-validator-only",
        replaces: None,
        run: gates::gov_slash_evidence_is_validator_only::run,
        run_log: None,
        run_args: None,
        self_test: gates::gov_slash_evidence_is_validator_only::self_test,
    },
    Gate {
        name: "fixture-integrity",
        replaces: None,
        run: gates::fixture_integrity::run,
        run_log: None,
        run_args: None,
        self_test: gates::fixture_integrity::self_test,
    },
];

fn usage() -> String {
    let mut s = String::from(
        "usage:\n  \
         budlum-gates <gate>              run one gate\n  \
         budlum-gates <gate> --self-test  run one gate's canaries\n  \
         budlum-gates --all               run every gate\n  \
         budlum-gates --all --self-test   run every canary\n  \
         budlum-gates --list              name every gate\n\n\
         gates:\n",
    );
    for g in GATES {
        s.push_str("  ");
        s.push_str(g.name);
        if let Some(r) = g.replaces {
            s.push_str("  (replaces ");
            s.push_str(r);
            s.push(')');
        }
        s.push('\n');
    }
    s
}

/// Where the repository root is.
///
/// `BUDLUM_ROOT` wins so a canary can point the gate at a staged copy. The
/// fallback walks up from the binary's own directory rather than trusting the
/// current directory, because CI does not always run from the root.
fn repo_root() -> PathBuf {
    if let Ok(r) = std::env::var("BUDLUM_ROOT") {
        return PathBuf::from(r);
    }
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        if dir.join("docs/ARCHITECTURE.md").is_file() && dir.join("Cargo.toml").is_file() {
            return dir;
        }
        if !dir.pop() {
            return PathBuf::from(".");
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    let self_test = refs.contains(&"--self-test");
    let root = repo_root();

    let selected: Vec<&Gate> = match refs.first() {
        None => {
            eprint!("{}", usage());
            std::process::exit(2);
        }
        Some(&"--list") => {
            for g in GATES {
                println!("{}", g.name);
            }
            return;
        }
        // `--all` and a bare `--self-test` both mean every gate; the flag was
        // already read above, so the two arms are one. Gates that take a log
        // path or positional roots are left out: they cannot run without
        // their argument, and their CI steps call them directly.
        Some(&"--all" | &"--self-test") => GATES
            .iter()
            .filter(|g| g.run_log.is_none() && g.run_args.is_none())
            .collect(),
        Some(name) => {
            if let Some(g) = GATES.iter().find(|g| g.name == *name) {
                vec![g]
            } else {
                eprintln!("FAIL: no gate named `{name}`.\n");
                eprint!("{}", usage());
                std::process::exit(2);
            }
        }
    };

    let mut failed = 0usize;
    for g in selected {
        let outcome = if self_test {
            (g.self_test)()
        } else if let Some(run_args) = g.run_args {
            (run_args)(&root, &refs[1..])
        } else if let (Some(run_log), Some(log)) = (g.run_log, refs.get(1)) {
            run_log(&root, Path::new(log))
        } else {
            (g.run)(&root)
        };
        match outcome {
            Ok(msg) => println!("{msg}"),
            Err(msg) => {
                eprintln!("FAIL [{}]: {msg}", g.name);
                failed += 1;
            }
        }
    }

    if failed > 0 {
        std::process::exit(1);
    }
}
