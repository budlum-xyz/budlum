//! Every `#[allow(...)]` in the tree is listed here, or the build stops.
//!
//! # Why this exists
//!
//! The standing rule is that a check must not be softened: no `#[ignore]`, no
//! `|| true`, no raising a baseline. `#[allow(...)]` is the same act performed
//! on the compiler instead of on CI, and until now nothing counted them.
//!
//! Measured: forty-three in `src/`. Most are ordinary and two are worth
//! saying out loud.
//!
//! `src/network/proto_conversions.rs` turns off `clippy::all` for a whole
//! module. That is legitimate here, because the module is a single `include!`
//! of code `prost-build` generates and nobody edits, but "clippy is off for
//! this file" is exactly the sentence that should never be invisible.
//!
//! `src/crypto/pkcs11.rs` carries four `dead_code` allows on fields of the
//! HSM signer. That is the key-custody boundary. A field nothing reads is
//! either configuration that will be read later or configuration that is
//! silently ignored, and on that path the difference matters.
//!
//! # What the gate does
//!
//! It does not ban suppressions. A blanket ban would be a rule nobody could
//! follow, and it would push people to write worse code to avoid a lint
//! rather than to state why the lint is wrong here.
//!
//! It requires each one to be counted, per file and per lint, against the
//! table below. A file that grows a new suppression fails until the table
//! agrees, and a table entry that no longer matches anything fails too, so
//! the list cannot outlive what it describes. Same shape as `PENDING_REVIEW`
//! and the softener list, for the same reason: a suppression nobody can audit
//! is worse than the finding it hides.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// One file's suppression budget for one lint.
struct Budget {
    /// Path relative to the repository root.
    file: &'static str,
    /// The lint being silenced.
    lint: &'static str,
    /// How many occurrences are expected.
    count: usize,
    /// Why they are acceptable, in a sentence somebody can disagree with.
    reason: &'static str,
}

/// The measured inventory. Counted, not typed.
const BUDGETS: &[Budget] = &[
    Budget {
        file: "src/chain/blockchain.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "`last_block` returns `&Block` and the genesis block is written by the constructor, so there is no owned value to fall back to and no caller that could act on an `Option`; the invariant is enforced at construction rather than re-checked on every read",
    },
    Budget {
        file: "build.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "a build script runs before the crate exists; a failure here must stop the build, and a panic is the only channel cargo reads",
    },
    Budget {
        file: "budzero/bud-proof/src/bud_stark/prover.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "`prove` does not return a `Result` in this trait, so a shape violation the prover itself constructed has nowhere to go; the verifier-side counterpart of this check is a returned error, which is where adversary-supplied input arrives",
    },
    Budget {
        file: "budzero/bud-proof/src/bud_stark/prover.rs",
        lint: "clippy::multiple_bound_locations",
        count: 2,
        reason: "plonky3 generic bounds split between the signature and a where clause; rewriting them changes nothing at runtime and makes the signature harder to read against the upstream trait",
    },
    Budget {
        file: "budzero/bud-proof/src/bud_stark/prover.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a proving entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "budzero/bud-proof/src/bud_stark/prover.rs",
        lint: "clippy::type_complexity",
        count: 2,
        reason: "a plonky3 commitment/opening tuple whose shape is fixed by the upstream API; naming it locally would add an alias that has to be kept in step with the dependency",
    },
    Budget {
        file: "budzero/bud-proof/src/bud_stark/prover.rs",
        lint: "clippy::type_repetition_in_bounds",
        count: 2,
        reason: "plonky3 generic bounds split between the signature and a where clause; rewriting them changes nothing at runtime and makes the signature harder to read against the upstream trait",
    },
    Budget {
        file: "budzero/bud-proof/src/bud_stark/verifier.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a verification entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "budzero/bud-proof/src/bud_stark/verifier.rs",
        lint: "clippy::type_complexity",
        count: 1,
        reason: "a plonky3 commitment/opening tuple whose shape is fixed by the upstream API; naming it locally would add an alias that has to be kept in step with the dependency",
    },
    Budget {
        file: "budzero/bud-proof/src/plonky3_prover.rs",
        lint: "clippy::type_complexity",
        count: 1,
        reason: "a plonky3 commitment/opening tuple whose shape is fixed by the upstream API; naming it locally would add an alias that has to be kept in step with the dependency",
    },
    Budget {
        file: "budzero/bud-proof/src/trace_layout_tests.rs",
        lint: "clippy::unwrap_used",
        count: 1,
        reason: "a `#[cfg(test)]` module of shared trace fixtures whose helpers sit outside a `#[test]` body, so `allow-unwrap-in-tests` does not reach them",
    },
    Budget {
        file: "budzero/bud-proof/src/trace_layout_tests.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "a `#[cfg(test)]` module of shared trace fixtures whose helpers sit outside a `#[test]` body, so `allow-unwrap-in-tests` does not reach them",
    },
    Budget {
        file: "budzero/bud-cli/tests/toolchain_end_to_end.rs",
        lint: "clippy::unwrap_used",
        count: 1,
        reason: "an integration test or bench whose helpers sit outside a `#[test]` body, so `allow-unwrap-in-tests` in clippy.toml does not reach them; a panic here fails the test run, which is the reporting channel a test is supposed to use",
    },
    Budget {
        file: "budzero/bud-cli/tests/toolchain_end_to_end.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "an integration test or bench whose helpers sit outside a `#[test]` body, so `allow-unwrap-in-tests` in clippy.toml does not reach them; a panic here fails the test run, which is the reporting channel a test is supposed to use",
    },
    Budget {
        file: "budzero/bud-proof/tests/compiled_branching.rs",
        lint: "clippy::unwrap_used",
        count: 1,
        reason: "an integration test or bench whose helpers sit outside a `#[test]` body, so `allow-unwrap-in-tests` in clippy.toml does not reach them; a panic here fails the test run, which is the reporting channel a test is supposed to use",
    },
    Budget {
        file: "budzero/bud-proof/tests/compiled_branching.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "an integration test or bench whose helpers sit outside a `#[test]` body, so `allow-unwrap-in-tests` in clippy.toml does not reach them; a panic here fails the test run, which is the reporting channel a test is supposed to use",
    },
    Budget {
        file: "budzero/bud-proof/tests/fiat_shamir_binding.rs",
        lint: "clippy::unwrap_used",
        count: 1,
        reason: "an integration test or bench whose helpers sit outside a `#[test]` body, so `allow-unwrap-in-tests` in clippy.toml does not reach them; a panic here fails the test run, which is the reporting channel a test is supposed to use",
    },
    Budget {
        file: "budzero/bud-proof/tests/fiat_shamir_binding.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "an integration test or bench whose helpers sit outside a `#[test]` body, so `allow-unwrap-in-tests` in clippy.toml does not reach them; a panic here fails the test run, which is the reporting channel a test is supposed to use",
    },
    Budget {
        file: "budzero/bud-proof/tests/soundness_negatives.rs",
        lint: "clippy::unwrap_used",
        count: 1,
        reason: "an integration test or bench whose helpers sit outside a `#[test]` body, so `allow-unwrap-in-tests` in clippy.toml does not reach them; a panic here fails the test run, which is the reporting channel a test is supposed to use",
    },
    Budget {
        file: "budzero/bud-proof/tests/soundness_negatives.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "an integration test or bench whose helpers sit outside a `#[test]` body, so `allow-unwrap-in-tests` in clippy.toml does not reach them; a panic here fails the test run, which is the reporting channel a test is supposed to use",
    },
    Budget {
        file: "budzero/bud-vm/tests/trace_fixtures.rs",
        lint: "clippy::unwrap_used",
        count: 1,
        reason: "an integration test or bench whose helpers sit outside a `#[test]` body, so `allow-unwrap-in-tests` in clippy.toml does not reach them; a panic here fails the test run, which is the reporting channel a test is supposed to use",
    },
    Budget {
        file: "budzero/bud-vm/tests/trace_fixtures.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "an integration test or bench whose helpers sit outside a `#[test]` body, so `allow-unwrap-in-tests` in clippy.toml does not reach them; a panic here fails the test run, which is the reporting channel a test is supposed to use",
    },
    Budget {
        file: "benches/domain_throughput.rs",
        lint: "clippy::unwrap_used",
        count: 1,
        reason: "a benchmark harness where a panic aborts the measurement and nothing else; criterion has no error channel to return into",
    },
    Budget {
        file: "benches/domain_throughput.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "a benchmark harness where a panic aborts the measurement and nothing else; criterion has no error channel to return into",
    },
    Budget {
        file: "benches/micro/sig_verify.rs",
        lint: "clippy::unwrap_used",
        count: 1,
        reason: "a benchmark harness where a panic aborts the measurement and nothing else; criterion has no error channel to return into",
    },
    Budget {
        file: "benches/micro/sig_verify.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "a benchmark harness where a panic aborts the measurement and nothing else; criterion has no error channel to return into",
    },
    Budget {
        file: "benches/micro/timing_safe.rs",
        lint: "clippy::unwrap_used",
        count: 1,
        reason: "a benchmark harness where a panic aborts the measurement and nothing else; criterion has no error channel to return into",
    },
    Budget {
        file: "benches/micro/timing_safe.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "a benchmark harness where a panic aborts the measurement and nothing else; criterion has no error channel to return into",
    },
    Budget {
        file: "benches/single_node/internal_pipeline_tps.rs",
        lint: "clippy::unwrap_used",
        count: 1,
        reason: "a benchmark harness where a panic aborts the measurement and nothing else; criterion has no error channel to return into",
    },
    Budget {
        file: "benches/single_node/internal_pipeline_tps.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "a benchmark harness where a panic aborts the measurement and nothing else; criterion has no error channel to return into",
    },
    Budget {
        file: "budzero/bud-proof/benches/proof_baseline.rs",
        lint: "clippy::unwrap_used",
        count: 1,
        reason: "a benchmark harness where a panic aborts the measurement and nothing else; criterion has no error channel to return into",
    },
    Budget {
        file: "budzero/bud-proof/benches/proof_baseline.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "a benchmark harness where a panic aborts the measurement and nothing else; criterion has no error channel to return into",
    },
    Budget {
        file: "src/ai/registry.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/bin/bud.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
            Budget {
        file: "src/chain/blockchain.rs",
        lint: "clippy::too_many_arguments",
        count: 4,
        reason: "the bridge lock, verified-mint and settlement evidence entry points, whose arguments are all required and none of which groups into a meaningful struct; the storage escrow wrappers that were here left when deal opening and repair acceptance became `StorageTx` transactions, and the evidence path arrived with the slashing work",
    },
        Budget {
        file: "src/cross_domain/bridge.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "the lock arguments are the transfer's parameter set (route, indices, parties, amount, expiry); a struct would mirror them one for one",
    },
    Budget {
        file: "src/cross_domain/bridge_relayer.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "the pipeline lock mirrors the bridge lock parameter set one for one",
    },
    Budget {
        file: "src/cross_domain/external/registry.rs",
        lint: "clippy::too_many_arguments",
        count: 2,
        reason: "`register` takes the full admission surface (network, descriptor, bond, probes, height) and `check` re-verifies that same surface; both lists are load-bearing - dropping an argument silently narrows what admission covers - and a struct would let a caller omit a field by default",
    },
    Budget {
        file: "src/core/encoding.rs",
        lint: "clippy::absurd_extreme_comparisons",
        count: 1,
        reason: "a bound check that is trivially true on this target width and load-bearing on another",
    },
    Budget {
        file: "src/core/transaction.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/crypto/pkcs11.rs",
        lint: "dead_code",
        count: 1,
        reason: "fields or helpers read only under a feature or by a subset of tests; kept beside their siblings rather than deleted and rewritten",
    },
    Budget {
        file: "src/domain/storage_deal.rs",
        lint: "clippy::too_many_arguments",
        count: 5,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply. The fifth is `answer_coding_audit`: the answer, the audit it answers and the clock reading are three different things, and the column, the byte and the inclusion path have to stay three slices a caller cannot confuse",
    },
    Budget {
        file: "src/ai_inference/executor.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/ai_inference/mod.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/network/node.rs",
        lint: "clippy::large_enum_variant",
        count: 1,
        reason: "the large variant is the common case; boxing it would allocate on the hot path to satisfy a size lint",
    },
    Budget {
        file: "src/network/node.rs",
        lint: "clippy::single_match",
        count: 1,
        reason: "a match kept single-armed on purpose because the other arms are coming and an if-let would have to be rewritten",
    },
    Budget {
        file: "src/network/proto_conversions.rs",
        lint: "clippy::all",
        count: 1,
        reason: "wraps generated code that nobody edits by hand",
    },
    Budget {
        file: "src/network/proto_conversions.rs",
        lint: "clippy::pedantic",
        count: 1,
        reason: "prost-build output is machine-written; the module is a single include! and pedantic lints on generated getters (must_use_candidate, missing_const_for_fn) cannot be fixed by hand without editing OUT_DIR code",
    },
    Budget {
        file: "src/network/proto_conversions.rs",
        lint: "clippy::nursery",
        count: 1,
        reason: "prost-build output is machine-written; nursery lints on generated doc comments (doc_markdown) are not actionable in OUT_DIR code",
    },
    Budget {
        file: "src/pollen/data_rights.rs",
        lint: "clippy::too_many_arguments",
        count: 3,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/pollen/offers.rs",
        lint: "clippy::too_many_arguments",
        count: 4,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply; the fourth is the signed_purchase test helper mirroring the purchase preimage parameters",
    },
    Budget {
        file: "src/relayer/policy.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/rpc/api.rs",
        lint: "clippy::too_many_arguments",
        count: 2,
        reason: "a consensus or storage entry point whose arguments are all required and none of which groups into a meaningful struct; bundling them would hide which fields a caller must supply",
    },
    Budget {
        file: "src/tests/bench_performance.rs",
        lint: "dead_code",
        count: 2,
        reason: "fields or helpers read only under a feature or by a subset of tests; kept beside their siblings rather than deleted and rewritten",
    },
    Budget {
        file: "src/ai_inference/inference.rs",
        lint: "clippy::too_many_arguments",
        count: 1,
        reason: "build_ai_request is a closed-circuit inference entry point whose eight parameters are all required request fields (requester, model, input, fee, timing x2, grant, perception) and none of which groups into a meaningful struct without hiding which fields a caller must supply",
    },
    Budget {
        file: "src/light_client/mod.rs",
        lint: "clippy::missing_const_for_fn",
        count: 1,
        reason: "next_checkpoint_height cannot be const: the nightly jobs (udeps, determinism) reject trait calls inside const fns with E0658, and this fn was reverted from const in c72b911 for exactly that reason",
    },
    Budget {
        file: "src/storage/pact_binding.rs",
        lint: "clippy::missing_const_for_fn",
        count: 3,
        reason: "Pact::new, is_residual_only and PactRegistry::new cannot be const: the nightly jobs (udeps, determinism) reject trait calls inside const fns with E0658, and these fns were reverted from const in c72b911 for exactly that reason",
    },
    Budget {
        file: "budzero/bud-proof/benches/canonical_programs.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "an integration test or bench whose helpers sit outside a `#[test]` body, so `allow-unwrap-in-tests` in clippy.toml does not reach them; a panic here fails the bench run, which is the reporting channel a benchmark is supposed to use",
    },
    Budget {
        file: "budzero/bud-proof/benches/canonical_programs.rs",
        lint: "clippy::unwrap_used",
        count: 1,
        reason: "an integration test or bench whose helpers sit outside a `#[test]` body, so `allow-unwrap-in-tests` in clippy.toml does not reach them; a panic here fails the bench run, which is the reporting channel a benchmark is supposed to use",
    },
    Budget {
        file: "src/cross_domain/evm/sync_committee.rs",
        lint: "clippy::large_stack_arrays",
        count: 1,
        reason: "the mainnet known-answer fixture holds two 512-entry committee arrays on the stack exactly as the state they pin does; the size is fixed by Ethereum's SYNC_COMMITTEE_SIZE, the function is test-only, and a heap copy would obscure the byte-for-byte comparison the fixture exists for",
    },
    Budget {
        file: "src/crypto/primitives.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "`WalletKeyPair::address` derives from a generated ML-DSA-87 public key, and derivation only rejects malformed keys, so the panic path is unreachable; the expect beats the previous silent zero-address fallback, which would have let a malformed key spend as `[0u8; 32]`",
    },
    Budget {
        file: "crates/ai-inference/crates/ai-ops/src/logparse.rs",
        lint: "dead_code",
        count: 1,
        reason: "the module header says it is not wired yet (WIRING note), so its items have no caller; the allow is removed when the module is wired",
    },
    Budget {
        file: "crates/budscan/src/query.rs",
        lint: "clippy::too_many_lines",
        count: 1,
        reason: "one linear query dispatcher in the light-client crate that reads worse split into pieces called once each",
    },
    Budget {
        file: "xtask/gates/src/gates/ast_security_gates.rs",
        lint: "clippy::struct_excessive_bools",
        count: 2,
        reason: "two visitor state structs whose booleans are independent guard flags of one syn walk; a bit set would hide which guard each flag records",
    },
    Budget {
        file: "xtask/gates/src/gates/budscan_patchset.rs",
        lint: "clippy::too_many_lines",
        count: 1,
        reason: "the patch-set check is one linear sequence of independent verdicts; splitting it would scatter the failure messages that read in order",
    },

    Budget {
        file: "budzero/bud-proof/src/plonky3_prover.rs",
        lint: "clippy::multiple_bound_locations",
        count: 1,
        reason: "plonky3 generic bounds split between the signature and a where clause, as in the prover proper; rewriting them changes nothing at runtime and makes the signature harder to read against the upstream trait",
    },
    Budget {
        file: "budzero/bud-proof/src/plonky3_prover.rs",
        lint: "clippy::type_repetition_in_bounds",
        count: 1,
        reason: "the upstream plonky3 opening type repeats a generic the trait already fixes; a local alias would have to be kept in step with the dependency",
    },
    Budget {
        file: "src/crypto/pq_vector_tests.rs",
        lint: "clippy::type_complexity",
        count: 1,
        reason: "the test matrix row is the vector set itself; naming the tuple would hide which vector failed",
    },
    Budget {
        file: "src/crypto/scheme.rs",
        lint: "clippy::type_complexity",
        count: 1,
        reason: "the scheme registry row (id, lengths, family) mirrors the table format; an alias would add a second name for the same wire shape",
    },
    Budget {
        file: "src/domain/pq_canonical.rs",
        lint: "clippy::expect_used",
        count: 2,
        reason: "canonical fixtures are fixed constants written at authoring time; every adversary-facing read in this module still returns Result, and a fixture that fails to parse is a repository bug the panic should name loudly",
    },
    Budget {
        file: "src/settlement/anchor_ledger.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "the embedded anchor ledger parses at construction where there is no Result channel yet; the runtime entries all arrive through the verified emission path that returns errors",
    },
    Budget {
        file: "src/settlement/anchor_production.rs",
        lint: "clippy::type_complexity",
        count: 1,
        reason: "the production envelope tuple is fixed by the ceremony format; an alias would name the same shape twice and drift from the format table",
    },
    Budget {
        file: "src/settlement/cold_quorum.rs",
        lint: "clippy::type_complexity",
        count: 1,
        reason: "the cold-quorum roster shape (signers, keys, threshold) is fixed by the protocol table; a local alias would be a second definition",
    },
    Budget {
        file: "src/settlement/reseal.rs",
        lint: "clippy::expect_used",
        count: 1,
        reason: "the reseal fixture constants parse at authoring time; the adversarial path through this module returns Result",
    },
    Budget {
        file: "src/settlement/reseal.rs",
        lint: "clippy::type_complexity",
        count: 1,
        reason: "the reseal envelope tuple mirrors the wire format field for field",
    },
    Budget {
        file: "src/storage/db.rs",
        lint: "dead_code",
        count: 1,
        reason: "the cfg-gated reader exists for the on-disk format migration and no other cfg reaches it; removing it would strand rows written by the previous format",
    },
];

/// Lints that may never be suppressed anywhere.
///
/// One entry. `unsafe_code` is forbidden crate-wide by attribute, and an
/// `allow` would quietly undo that in one file.
const NEVER: &[(&str, &str)] = &[(
    "unsafe_code",
    "src/ and budzero/ carry #![forbid(unsafe_code)]. An allow here would undo \
     crate-wide forbiddance in one file, and the whole argument that this tree has \
     no first-party unsafe rests on that attribute holding everywhere.",
)];

/// A suppression found in the tree.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Found {
    file: String,
    lint: String,
}

/// Pull `#[allow(a, b)]` and `#![allow(c)]` out of one file.
fn allows_in(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // Match `#[allow(` or `#![allow(`.
        if chars[i] != '#' {
            i += 1;
            continue;
        }
        // The attribute must open its line. `"#[allow(..)]"` inside a string
        // fixture and `// #[allow(..)]` in a comment are not suppressions.
        let line_start = chars[..i]
            .iter()
            .rposition(|c| *c == '\n')
            .map_or(0, |p| p + 1);
        if chars[line_start..i].iter().any(|c| !c.is_whitespace()) {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        if j < chars.len() && chars[j] == '!' {
            j += 1;
        }
        if j >= chars.len() || chars[j] != '[' {
            i += 1;
            continue;
        }
        j += 1;
        while j < chars.len() && chars[j].is_whitespace() {
            j += 1;
        }
        let word_start = j;
        while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
            j += 1;
        }
        let kw: String = chars[word_start..j].iter().collect();
        while j < chars.len() && chars[j].is_whitespace() {
            j += 1;
        }
        if (kw != "allow" && kw != "expect") || j >= chars.len() || chars[j] != '(' {
            i += 1;
            continue;
        }
        j += 1;
        // Read to the matching close paren.
        let start = j;
        let mut depth = 1i32;
        while j < chars.len() && depth > 0 {
            if chars[j] == '(' {
                depth += 1;
            } else if chars[j] == ')' {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            j += 1;
        }
        let inner: String = chars[start..j.min(chars.len())].iter().collect();
        let lints = inner
            .find("reason")
            .map_or(inner.as_str(), |at| &inner[..at]);
        for lint in lints.split(',') {
            let l = lint.trim();
            if !l.is_empty() {
                out.push(l.to_string());
            }
        }
        i = j.max(i + 1);
    }
    out
}

fn collect_rs(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let Ok(p_kind) = e.file_type() else {
            continue;
        };
        let p = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if p_kind.is_dir() {
            if matches!(name.as_str(), ".git" | "target" | "node_modules") {
                continue;
            }
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("rs")) {
            out.push(p);
        }
    }
}

fn judge(found: &[Found]) -> Vec<String> {
    let mut problems = Vec::new();

    for (lint, why) in NEVER {
        for f in found.iter().filter(|f| f.lint == *lint) {
            problems.push(format!(
                "{}: `{}` may never be suppressed.\n    {why}",
                f.file, f.lint
            ));
        }
    }

    // Count what is there, per file and lint.
    let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for f in found {
        *counts.entry((f.file.clone(), f.lint.clone())).or_insert(0) += 1;
    }

    for b in BUDGETS {
        let key = (b.file.to_string(), b.lint.to_string());
        let actual = counts.remove(&key).unwrap_or(0);
        if actual == 0 {
            problems.push(format!(
                "{}: listed here as suppressing `{}` ({}), and nothing does. Either it \
                 was removed without shortening this list, or it moved. A justification \
                 for something that no longer exists is a suppression nobody can audit.",
                b.file, b.lint, b.reason
            ));
        } else if actual != b.count {
            problems.push(format!(
                "{}: `{}` is budgeted at {} and appears {} times. The list is a count, \
                 not a licence: a new one needs its own reason, and a removed one needs \
                 the number lowered.",
                b.file, b.lint, b.count, actual
            ));
        }
    }

    for ((file, lint), n) in counts {
        if NEVER.iter().any(|(l, _)| *l == lint) {
            continue;
        }
        problems.push(format!(
            "{file}: suppresses `{lint}` {n} time(s) and is not listed in this gate. \
             `#[allow(...)]` is the same act as `|| true`, performed on the compiler \
             instead of on CI. Add it with a reason, or remove the suppression."
        ));
    }
    problems
}

/// # Errors
///
/// Returns the suppressions that are unlisted, miscounted, or forbidden.
/// The trees this gate watches.
///
/// `src/` alone was the original scope, and it left three places where a
/// suppression was invisible: `benches/`, the `budzero/` workspace and
/// `build.rs`. A gate that watches part of the tree reports what it watched,
/// not what is true, so the scope is named here and the count below is the
/// count for all of it.
const SCANNED: &[&str] = &[
    "src", "benches", "budzero", "build.rs", "crates", "bud", "xtask", "fuzz", "kani", "examples",
];

pub fn run(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    for entry in SCANNED {
        let p = root.join(entry);
        if p.is_file() {
            files.push(p);
        } else {
            collect_rs(&p, &mut files);
        }
    }
    if files.is_empty() {
        return Err(String::from(
            "no .rs files found under the scanned trees; this gate is watching nothing.",
        ));
    }
    files.sort();

    let mut found = Vec::new();
    for f in &files {
        let src =
            std::fs::read_to_string(f).map_err(|e| format!("cannot read {}: {e}", f.display()))?;
        let rel = f.strip_prefix(root).unwrap_or(f).display().to_string();
        for lint in allows_in(&src) {
            found.push(Found {
                file: rel.clone(),
                lint,
            });
        }
    }

    let problems = judge(&found);
    if problems.is_empty() {
        return Ok(format!(
            "Suppression gate OK: {} `#[allow(...)]` across {} files, every one budgeted \
             with a reason, and nothing on the never-suppress list appears.",
            found.len(),
            files.len()
        ));
    }
    let mut msg = String::new();
    let _ = writeln!(msg, "{} finding(s):\n", problems.len());
    for p in &problems {
        let _ = writeln!(msg, "  {p}\n");
    }
    Err(msg)
}

/// # Errors
///
/// The canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    // Parsing.
    let src = "#[allow(dead_code)]\nfn a() {}\n#![allow(clippy::all, unused)]\nfn b() {}\n";
    let got = allows_in(src);
    if got != vec!["dead_code", "clippy::all", "unused"] {
        problems.push(format!("BROKEN: allows_in read {got:?}"));
    }
    let spelled = "#[ expect (clippy::a,\n    reason = \"x, y\")]\nfn c() {}\n";
    if allows_in(spelled) != vec!["clippy::a"] {
        problems.push(format!(
            "BROKEN: expect or spaced form read {:?}",
            allows_in(spelled)
        ));
    }
    if !allows_in("// #[allow(x)] in a comment\n").is_empty() {
        // A comment mentioning one is still text the parser sees; recorded
        // rather than fixed, because a suppression written in a comment is
        // not one and over-reporting here is the safe direction.
    }
    // A string fixture and a comment that show an attribute are not
    // suppressions; an indented attribute on its own line is.
    if !allows_in("let s = \"#[allow(dead_code)]\";\n// #[allow(x)]\n").is_empty() {
        problems.push(String::from(
            "BROKEN: a string or comment mention was counted as a suppression",
        ));
    }
    if allows_in("    #[allow(dead_code)]\n") != vec!["dead_code"] {
        problems.push(String::from("BROKEN: an indented attribute was not read"));
    }
    // The scope covers the crates the node links and the tools around it.
    for tree in ["crates", "bud", "xtask", "fuzz"] {
        if !SCANNED.contains(&tree) {
            problems.push(format!("BROKEN: {tree}/ is not scanned"));
        }
    }
    if !allows_in("fn f() {}\n").is_empty() {
        problems.push(String::from("BROKEN: a file with no allows reported some"));
    }

    // An unlisted suppression is refused.
    let unlisted = vec![Found {
        file: "src/brand/new.rs".to_string(),
        lint: "dead_code".to_string(),
    }];
    if !judge(&unlisted)
        .iter()
        .any(|p| p.contains("src/brand/new.rs") && p.contains("not listed"))
    {
        problems.push(String::from(
            "VACUOUS: an unlisted suppression was accepted",
        ));
    }

    // A forbidden lint is refused wherever it appears.
    let forbidden = vec![Found {
        file: "src/anything.rs".to_string(),
        lint: "unsafe_code".to_string(),
    }];
    if !judge(&forbidden)
        .iter()
        .any(|p| p.contains("may never be suppressed"))
    {
        problems.push(String::from("VACUOUS: an allow(unsafe_code) was accepted"));
    }

    // A budget that no longer matches anything is refused.
    if !judge(&[]).iter().any(|p| p.contains("and nothing does")) {
        problems.push(String::from(
            "VACUOUS: a budget matching nothing was accepted",
        ));
    }

    // The right count passes for that entry, and a wrong count does not.
    let one_over: Vec<Found> = BUDGETS
        .iter()
        .flat_map(|b| {
            let extra = usize::from(b.file == "src/crypto/pkcs11.rs");
            (0..b.count + extra).map(|_| Found {
                file: b.file.to_string(),
                lint: b.lint.to_string(),
            })
        })
        .collect();
    if !judge(&one_over)
        .iter()
        .any(|p| p.contains("src/crypto/pkcs11.rs") && p.contains("is budgeted at"))
    {
        problems.push(String::from(
            "VACUOUS: one suppression over budget was accepted",
        ));
    }

    // Exactly the budget passes.
    let exact: Vec<Found> = BUDGETS
        .iter()
        .flat_map(|b| {
            (0..b.count).map(|_| Found {
                file: b.file.to_string(),
                lint: b.lint.to_string(),
            })
        })
        .collect();
    let p = judge(&exact);
    if !p.is_empty() {
        problems.push(format!("BROKEN: the exact budget was rejected: {p:?}"));
    }

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "suppression gate self-test OK: an unlisted allow, an allow(unsafe_code), a budget \
         matching nothing and a count one over budget are all refused; the exact budget \
         passes and the parser reads inner and outer attributes.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() {
        super::self_test().expect("suppressions self-test");
    }
}
