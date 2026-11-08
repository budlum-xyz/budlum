//! Permanent regression locks for the lane-D findings that were found already
//! fixed, with the fix in the tree and no test behind it.
//!
//! The live verification walks 68 ledger rows and
//! reaches a status for each by reading the tree. Six of them came back
//! `closed - previously fixed` and one `closed by removal`: the code was
//! already right when this pass arrived, but nothing failed if it stopped
//! being right. A finding closed by reading is a finding one careless edit away
//! from being open again, so each of those six gets a test here.
//!
//! Two rows are deliberately absent, because they are already pinned and
//! duplicating a lock weakens it:
//!
//!   first entry. Pinned by `the_total_is_read_not_the_first_file` in
//!   `xtask/gates/src/gates/coverage.rs`, next to the code it protects.
//!   by `forwarded_headers_are_ignored_without_a_trusted_proxy` in
//!   `security_invariant_tests.rs` and by the extraction test in `src/rpc/server.rs`.
//!
//! Most of these tests read a file rather than call a function, and that is the
//! point: the property under lock lives in a configuration file or in the shape
//! the exception - it is a behavioural lock, because a signature property is
//! only real if it can be observed through the signer.

#[cfg(test)]
mod tests {
    ///
    /// The entries are anchored, so a tracked directory that happens to be
    /// called `data` deeper in the tree still works; unanchored patterns were
    /// the original bug.
    #[test]
    fn blg_005_the_secrets_and_data_directories_never_reach_git() {
        let ignore = include_str!("../../.gitignore");
        for entry in ["/secrets/", "/data/"] {
            assert!(
                ignore.lines().any(|line| line.trim() == entry),
                "the anchored `{entry}` entry is gone from .gitignore; a key \
                 file or a node database dropped in the repository root would \
                 be one `git add -A` away from being committed"
            );
        }
    }

    /// its command line.
    ///
    /// A core dump of a validator process holds key material, and a key passed
    /// as an argument is visible to every process on the host through
    /// `/proc/<pid>/cmdline`. The unit takes the key from a root-owned
    /// environment file and names the variable instead.
    #[test]
    fn blg_011_the_validator_unit_dumps_no_core_and_reads_the_key_by_name() {
        let unit = include_str!("../../ops/budlum-core.service");
        assert!(
            unit.lines().any(|line| line.trim() == "LimitCORE=0"),
            "LimitCORE=0 is gone from ops/budlum-core.service; a crash would \
             write a core dump containing key material"
        );
        assert!(
            unit.contains("Environment=BUDLUM_RPC_API_KEY_ENV=BUDLUM_RPC_API_KEY"),
            "the unit no longer names the key variable; confirm the key is \
             still read from an environment file rather than passed as an \
             argument, where it is world-readable through /proc"
        );
    }

    /// can audit.
    ///
    /// The finding was a `scripts/` directory of shell hooks that CI never ran
    /// and no document referenced - a green-looking gate that only worked on
    /// the machines where someone had remembered to install it. It is closed by
    /// removal: the same checks are `xtask` gates, which CI runs for everyone.
    #[test]
    fn blg_013_no_script_directory_is_the_documented_workflow() {
        let scripts = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts");
        assert!(
            !std::path::Path::new(scripts).exists(),
            "a scripts/ directory is back; if it holds checks, they belong in \
             xtask/gates where CI runs them, not in hooks that only exist on \
             machines where someone installed them"
        );

        let contributing = include_str!("../../docs/CONTRIBUTING.md").to_lowercase();
        assert!(
            !contributing.contains("pre-push") && !contributing.contains("prepush"),
            "docs/CONTRIBUTING.md documents a pre-push hook again; point it at \
             the xtask gates instead, so the check is the one CI enforces"
        );
    }

    /// sound is not a drill, it is a copy.
    ///
    /// The integrity check runs against the restored database and its exit
    /// status has to fail the drill. The shape under lock is the propagation:
    /// the child is spawned, then `map_err(...)?`, then the status check.
    #[test]
    fn blg_014_a_failed_integrity_check_fails_the_drill() {
        let drill = include_str!("../../xtask/tools/src/backup_drill.rs");
        let start = drill
            .find("\"--check-db\"")
            .unwrap_or_else(|| panic!("the --check-db invocation is gone from xtask/tools/src/backup_drill.rs"));
        // Look at the call site only, not the whole file: a status check
        // anywhere else would satisfy a weaker assertion.
        let tail = &drill[start..];
        let end = tail.find("\n}\n").unwrap_or(tail.len());
        let body = &tail[..end];

        assert!(
            body.contains("the integrity check could not be run"),
            "the --check-db child's spawn error is no longer turned into a \
             drill failure; a missing binary would read as a passed drill"
        );
        assert!(
            body.contains("if !check.status.success()"),
            "the --check-db exit status is no longer inspected; a corrupt \
             restore would pass the drill"
        );
    }

    /// is.
    ///
    /// "Research-grade, not audited" is the claim the repository is allowed to
    /// make. Both halves are locked, because they fail independently: a README
    /// can keep the warning banner and quietly grow an "audited" claim later.
    #[test]
    fn blg_092_the_readme_states_no_mainnet_and_no_audit() {
        let readme = include_str!("../../README.md");
        assert!(
            readme.contains("Budlum has not launched a mainnet and has not been audited."),
            "the no-mainnet, no-audit warning is gone from README.md; that is \
             the public framing rule, not decoration"
        );
        assert!(
            readme.contains("No external audit has been performed."),
            "README.md no longer states that no external audit has been \
             performed; no substitute claim is allowed to stand in for one"
        );
    }

    /// interchangeable.
    ///
    /// The original defect was one Ed25519 key hashing the message bare for all
    /// three, so a prevote over some bytes was also a valid precommit - and a
    /// valid block signature - over the same bytes. A validator could be
    /// replayed across vote types, and equivocation evidence could be
    /// reinterpreted. This is the behavioural lock: the three signatures over
    /// the same input must differ, which is only true while the domain
    /// separation tags stay distinct.
    #[test]
    fn blg_150_prevote_precommit_and_block_signatures_are_not_interchangeable() {
        use crate::crypto::primitives::KeyPair;
        use crate::crypto::signer::{ConsensusSigner, KeyPairSigner};

        let signer = KeyPairSigner::new(KeyPair::from_seed(&[7u8; 64]));
        let msg = b"the same bytes, three different meanings";

        let prevote = signer.sign_prevote(msg).expect("a prevote signs");
        let precommit = signer.sign_precommit(msg).expect("a precommit signs");
        let block = signer
            .sign_block(&crate::core::hash::calculate_hash_bytes(msg))
            .expect("a block signs");

        assert_ne!(
            prevote, precommit,
            "a prevote and a precommit over the same bytes produced the same \
             signature; the domain tags collapsed and votes are replayable \
             across types"
        );
        assert_ne!(
            prevote, block,
            "a prevote over these bytes is also a block signature over them; \
             the prevote domain tag is no longer applied"
        );
        assert_ne!(
            precommit, block,
            "a precommit over these bytes is also a block signature over them; \
             the precommit domain tag is no longer applied"
        );
    }

    /// The tags behind the behavioural lock above are registered and actually
    /// hashed into signatures.
    ///
    /// A tag that is declared but never applied separates nothing, and a tag
    /// that is applied but not registered sits outside the collision list the
    /// registry exists to check. Both halves are locked here.
    #[test]
    fn blg_150_the_vote_domain_tags_are_registered_and_distinct() {
        let tags = include_str!("../crypto/domain_tags.rs");
        for tag in ["BDLM_PREVOTE_ED25519_V1", "BDLM_PRECOMMIT_ED25519_V1"] {
            assert!(
                tags.contains(&format!("\"{tag}\"")),
                "{tag} is not in the registered domain-tag list"
            );
        }
        // Both tags must be applied at the signing sites, not just declared.
        // A tag that is registered but never hashed into a signature separates
        // nothing.
        let signer = include_str!("../crypto/signer.rs");
        for tag in ["BDLM_PREVOTE_ED25519_V1", "BDLM_PRECOMMIT_ED25519_V1"] {
            assert!(
                signer.contains(&format!("b\"{tag}\"")),
                "src/crypto/signer.rs no longer hashes {tag} into a signature; \
                 the vote types would collapse onto one another"
            );
        }
    }
}
