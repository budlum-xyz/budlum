//! Regression locks for an external review pass.
//!
//! Seven findings were raised from spec/config reading. Three were real and are
//! fixed; three were already handled and are pinned here so the same question
//! does not have to be re-derived from scratch next time; one was a
//! documentation gap.
//!
//! The tests for the "already handled" items are not busywork. Each of those
//! properties is one careless edit away from being false, and none of them
//! fails loudly when it breaks — a slashing replay silently double-slashes, a
//! spoofed header silently bypasses a rate limit. Naming them here turns a
//! reviewer's question into something CI answers.

#[cfg(test)]
mod tests {
    /// FIXED: the PQ backend is compile-time, but the key it emits is
    /// consensus data, so the chain records which one it was launched with.
    ///
    /// Dilithium5 public keys are 2592 bytes and ML-DSA-65 keys are 1952.
    /// `validate_public_key` is called on the validation path
    /// (`core/account.rs`, `core/transaction.rs`), so a node built with the
    /// wrong feature rejects every validator registration on the chain as a
    /// malformed key — a partition with no error naming its cause.
    #[test]
    fn genesis_pins_the_pq_scheme_and_mismatch_is_fatal() {
        use crate::chain::genesis::GenesisConfig;
        use crate::crypto::primitives::PQ_SCHEME_ID;

        // A chain launched with this build must be accepted.
        let mut cfg = GenesisConfig {
            pq_scheme: Some(PQ_SCHEME_ID.to_string()),
            ..GenesisConfig::default()
        };
        assert!(
            cfg.validate_pq_scheme().is_ok(),
            "a genesis recording this build's own scheme must validate"
        );

        // A chain launched with the other backend must be refused outright.
        let other = if PQ_SCHEME_ID == "dilithium5" {
            "ml-dsa-65"
        } else {
            "dilithium5"
        };
        cfg.pq_scheme = Some(other.to_string());
        let err = cfg
            .validate_pq_scheme()
            .expect_err("a PQ backend mismatch must be fatal, not a warning");
        assert!(
            err.contains(other) && err.contains(PQ_SCHEME_ID),
            "the error must name both schemes so an operator can act on it, got: {err}"
        );

        // Chains predating the field are not retroactively broken.
        cfg.pq_scheme = None;
        assert!(
            cfg.validate_pq_scheme().is_ok(),
            "a genesis without the field must not be rejected on a guess"
        );
    }

    /// FIXED: the shipped genesis files declare a scheme.
    ///
    /// The check above only bites when the field is present. If the mainnet
    /// genesis omitted it, the guard would pass vacuously on the one chain
    /// that matters most.
    #[test]
    fn shipped_genesis_files_declare_a_pq_scheme() {
        for path in [
            "config/mainnet-genesis.json",
            "config/testnet-genesis.json",
            "config/devnet-genesis.json",
        ] {
            let raw = std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("cannot read {path}: {error}"));
            let json: serde_json::Value = serde_json::from_str(&raw)
                .unwrap_or_else(|error| panic!("{path} is not valid JSON: {error}"));
            let scheme = json.get("pq_scheme").and_then(|v| v.as_str());
            assert!(
                scheme.is_some_and(|s| !s.is_empty()),
                "{path} does not pin pq_scheme; the startup guard would pass \
                 vacuously for this chain"
            );
        }
    }

    /// FIXED: consensus-visible writes are flushed, not left to sled's timer.
    ///
    /// sled fsyncs on its own schedule (~500ms by default). "Atomic" means a
    /// batch is all-or-nothing, not that it survived the power going out. A
    /// checkpoint lost to a crash lets the restarted node accept a reorg below
    /// a height it had already ruled out.
    #[test]
    fn consensus_writes_flush_before_returning() {
        let db_rs = include_str!("../storage/db.rs");

        for func in [
            "pub fn save_checkpoint",
            "pub fn save_finality_cert",
            "pub fn save_qc_blob",
        ] {
            let start = db_rs
                .find(func)
                .unwrap_or_else(|| panic!("{func} not found in storage/db.rs"));
            // Look at the function body only, not the whole file.
            let body = &db_rs[start..];
            let end = body.find("\n    pub fn ").unwrap_or(body.len());
            let body = &body[..end];
            assert!(
                body.contains(".flush()"),
                "{func} writes consensus-visible state without flushing; a crash \
                 within sled's fsync window would lose it"
            );
        }
    }

    /// FIXED: a checkpoint that fails to persist is an error, not a shrug.
    #[test]
    fn checkpoint_persistence_failure_is_not_swallowed() {
        let pos_rs = include_str!("../consensus/pos.rs");
        assert!(
            !pos_rs.contains("let _ = store.save_checkpoint"),
            "pos.rs discards the result of save_checkpoint; on restart the node \
             would not know the block was checkpointed and would accept a reorg \
             below it"
        );
        assert!(
            pos_rs.contains("save_checkpoint(&checkpoint)"),
            "the checkpoint write disappeared entirely"
        );
    }

    /// FIXED: the compose file people copy is authenticated.
    ///
    /// The README points at `docker-compose.yml` from a quick-start section.
    /// Shipping it with auth off, an empty IP allow-list and the public RPC
    /// port published means anyone who runs it on a routable host has an open
    /// JSON-RPC endpoint. The CI harness needs the opposite, so those settings
    /// live in an overlay that has to be named on the command line.
    #[test]
    fn default_compose_does_not_ship_an_open_rpc() {
        let base = include_str!("../../docker-compose.yml");

        assert!(
            !base.contains("BUDLUM_RPC_AUTH_REQUIRED=0"),
            "docker-compose.yml disables RPC auth; that belongs in \
             docker-compose.ci.yml, which a user has to opt into"
        );
        assert!(
            base.contains("BUDLUM_RPC_AUTH_REQUIRED=1"),
            "docker-compose.yml no longer states that auth is required"
        );
        assert!(
            !base.contains("\"8545:8545\""),
            "docker-compose.yml publishes the public RPC port to the host; the \
             CI overlay is the place for that"
        );

        // The overlay still has to carry the CI settings, or the smoke harness
        // silently loses its unauthenticated listener.
        let ci = include_str!("../../docker-compose.ci.yml");
        assert!(
            ci.contains("BUDLUM_RPC_AUTH_REQUIRED=0") && ci.contains("\"8545:8545\""),
            "docker-compose.ci.yml no longer provides the harness settings it \
             was split out to hold"
        );
    }

    /// NOT A FINDING, pinned: replaying slashing evidence cannot slash twice.
    ///
    /// `slash_validator` returns early when the validator is already flagged.
    /// Without that, resubmitting the same double-sign evidence in a later
    /// block would take stake again for one offence.
    #[test]
    fn slashing_the_same_validator_twice_is_a_no_op() {
        use crate::core::account::AccountState;
        use crate::core::address::Address;
        use crate::core::chain_config::FIXED_POINT_SCALE;

        let mut state = AccountState::new();
        let validator = Address::from([7u8; 32]);
        state.add_validator(validator, 1_000_000);

        let ten_percent = FIXED_POINT_SCALE / 10;
        let first = state
            .slash_validator(&validator, ten_percent, "double sign")
            .expect("validator exists");
        assert!(first > 0, "the first slash must actually take stake");

        let second = state
            .slash_validator(&validator, ten_percent, "replayed evidence")
            .expect("validator still exists");
        assert_eq!(
            second, 0,
            "replaying the same evidence slashed the validator a second time"
        );
    }

    /// NOT A FINDING, pinned: X-Forwarded-For is ignored unless the peer is a
    /// configured trusted proxy.
    ///
    /// If an empty `trusted_proxies` list meant "trust the header", per-IP rate
    /// limiting could be bypassed by anyone willing to set a header. The code
    /// is fail-closed; this keeps it that way.
    #[test]
    fn forwarded_headers_are_ignored_without_a_trusted_proxy() {
        let server_rs = include_str!("../rpc/server.rs");
        let marker = "if !config.trusted_proxies.is_empty() && request_came_from_trusted_proxy";
        assert!(
            server_rs.contains(marker),
            "the trusted-proxy guard around x-forwarded-for changed shape; \
             confirm an empty trusted_proxies list still means the header is \
             ignored rather than believed"
        );
    }

    /// NOT A FINDING, pinned: the operator RPC refuses to bind off-loopback.
    ///
    /// The reviewer's point stands that loopback is weaker than it looks inside
    /// a shared network namespace (a Kubernetes sidecar shares it). The bind
    /// restriction is real and enforced; the namespace caveat is documented in
    /// the production runbook rather than pretended away.
    #[test]
    fn operator_rpc_must_bind_loopback() {
        let server_rs = include_str!("../rpc/server.rs");
        assert!(
            server_rs.contains("operator RPC listener must bind to loopback"),
            "the operator-listener loopback check is gone; a non-loopback bind \
             would expose an unauthenticated admin surface"
        );
    }
}
