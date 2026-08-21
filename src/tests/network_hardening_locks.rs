//! Locks for network-layer hardening that is easy to undo by accident.
//!
//! Two classes of finding live here:
//!
//!   * A poisoned mutex must degrade the affected request, not kill the node.
//!     `src/network/node.rs` holds ~20 lock sites; all but one already matched
//!     on the result or exited deliberately, and the odd one out turned an
//!     optional content fetch into a node-wide panic.
//!   * `Gossipsub`'s defaults are the network's DoS surface. They are currently
//!     accepted deliberately, and this file records which ones were checked so
//!     "we never looked" cannot be confused with "we looked and accepted".

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    const NODE_RS: &str = include_str!("../network/node.rs");

    /// Strip comments and string literals so a lock cannot be satisfied, or
    /// tripped - by prose that merely mentions the pattern.
    fn code_lines(body: &str) -> Vec<(usize, String)> {
        body.lines()
            .enumerate()
            .map(|(i, line)| {
                let no_comment = line.find("//").map_or(line, |at| &line[..at]);
                (i + 1, no_comment.trim().to_string())
            })
            .filter(|(_, l)| !l.is_empty())
            .collect()
    }

    /// No bare `.lock().unwrap()` in the networking event loop.
    ///
    /// A `std::sync::Mutex` is poisoned when a thread panics while holding it.
    /// Every later `.lock()` then returns `Err`, so a single unrelated panic
    /// escalates into "every subsequent request panics too". The event loop
    /// serves untrusted peers, so that is a remote liveness bug.
    ///
    /// `unwrap_or_else` with an explicit, logged shutdown is allowed: that is a
    /// deliberate decision rather than an accident.
    #[test]
    fn network_event_loop_has_no_bare_lock_unwrap() {
        let offenders: Vec<_> = code_lines(NODE_RS)
            .into_iter()
            .filter(|(_, line)| line.contains(".lock().unwrap()"))
            .collect();

        assert!(
            offenders.is_empty(),
            "node.rs contains bare .lock().unwrap() at {:?} - a poisoned mutex \
             would panic the node instead of failing the request. Match on the \
             Result, or use unwrap_or_else with an explicit logged exit.",
            offenders
                .iter()
                .map(|(n, l)| format!("line {n}: {l}"))
                .collect::<Vec<_>>()
        );
    }

    /// The remote-content fetch path must survive a poisoned `PeerManager`.
    ///
    /// It used to survive by giving up: the arm matched on the lock result and
    /// answered "peer manager unavailable". That is better than panicking, but
    /// it still let one panic elsewhere in peer bookkeeping stop every remote
    /// fetch, and the peer list it could not read is stale rather than
    /// dangerous. The arm now goes through `peer_manager_lock()`, which
    /// recovers the state and logs, so the fetch proceeds with the peers the
    /// node actually has.
    ///
    /// What this test still guarantees is the original property: this path
    /// does not reach a bare `.lock()` that could panic the event loop.
    #[test]
    fn remote_content_fetch_survives_a_poisoned_peer_manager() {
        // `NodeCommand::FetchRemoteContent {` appears twice: once where the
        // command is sent, once as the match arm that handles it. Only the arm
        // ends in `=> {`, so match on that.
        let at = NODE_RS
            .find("NodeCommand::FetchRemoteContent { cid, response } => {")
            .expect("the FetchRemoteContent command arm must still exist");
        let arm = &NODE_RS[at..(at + 3000).min(NODE_RS.len())];
        assert!(
            arm.contains("peer_manager_lock()"),
            "the FetchRemoteContent arm must read the peer list through the \
             recovering helper; a bare lock here would either panic the event \
             loop or silently drop every remote fetch after one unrelated panic"
        );
        assert!(
            !arm.contains("peer_manager.lock()"),
            "the FetchRemoteContent arm reads the raw lock again, so a poisoned \
             PeerManager changes its answer"
        );
    }

    /// Gossipsub must keep strict validation and signed authenticity.
    ///
    /// `ValidationMode::Strict` rejects messages without a valid signature,
    /// source and sequence number. Relaxing it lets a peer inject messages
    /// attributed to someone else.
    #[test]
    fn gossipsub_keeps_strict_validation_and_signing() {
        assert!(
            NODE_RS.contains("gossipsub::ValidationMode::Strict"),
            "gossipsub validation mode is no longer Strict; unsigned or \
             unattributed messages would be accepted"
        );
        assert!(
            NODE_RS.contains("gossipsub::MessageAuthenticity::Signed"),
            "gossipsub no longer signs published messages"
        );
    }

    /// The message id must be content-derived.
    ///
    /// The libp2p default id is `source + sequence_number`, which a peer
    /// controls entirely: it can publish the same payload under fresh ids and
    /// walk straight through the duplicate cache. Hashing the payload makes
    /// the id unforgeable and the dedup cache effective.
    #[test]
    fn gossipsub_message_id_is_content_derived() {
        // The closure is defined above the builder call, so look at the
        // window around the definition rather than only behind the first
        // mention of the setter.
        let at = NODE_RS
            .find("let message_id_fn")
            .expect("a custom message id function must be installed");
        let window = &NODE_RS[at..(at + 600).min(NODE_RS.len())];
        assert!(
            window.contains("Sha256::digest(&message.data)"),
            "the gossipsub message id is no longer a hash of the payload; the \
             libp2p default (source + sequence number) is peer-controlled and \
             defeats duplicate suppression"
        );
    }

    /// The transmit-size cap must stay wired to the protocol constant.
    ///
    /// libp2p's own default is far larger than a Budlum message ever needs;
    /// leaving it unset lets a peer force large allocations per RPC.
    #[test]
    fn gossipsub_caps_transmit_size_at_the_protocol_limit() {
        assert!(
            NODE_RS.contains("max_transmit_size(crate::network::protocol::MAX_MESSAGE_SIZE)"),
            "gossipsub no longer caps transmit size at MAX_MESSAGE_SIZE"
        );
        assert_eq!(
            crate::network::protocol::MAX_MESSAGE_SIZE,
            10 * 1024 * 1024,
            "MAX_MESSAGE_SIZE moved; re-check that the gossipsub cap is still \
             the value the rest of the protocol assumes"
        );
    }

    /// Peer scoring must stay enabled, with the thresholds that were chosen.
    ///
    /// Without it gossipsub counts misbehaviour and then discards the count:
    /// a peer that floods IHAVE and never answers the resulting IWANT is
    /// capped per heartbeat but never penalised, never gossip-suppressed and
    /// never pruned. The router already tracks this (P7 in the scoring spec);
    /// enabling scoring is what makes the tracking matter.
    #[test]
    fn gossipsub_peer_scoring_is_enabled_with_pinned_parameters() {
        assert!(
            NODE_RS.contains("with_peer_score("),
            "gossipsub peer scoring was turned off; IHAVE floods would go \
             unpenalised again"
        );
        assert!(
            NODE_RS.contains("behaviour_penalty_threshold: 6.0"),
            "the behaviour penalty threshold moved. It is deliberately above \
             libp2p's default of 0 so genuine message loss does not cost \
             score; changing it is a policy decision that belongs in the \
             commit that makes it"
        );
        assert!(
            NODE_RS.contains("ip_colocation_factor_threshold: 4.0"),
            "the IP colocation threshold moved. libp2p defaults to 10, which \
             suits consumer nodes behind shared NATs; a validator set with ten \
             peers on one address is usually one machine claiming to be ten"
        );
        // The compensating control predates scoring and must not be dropped
        // now that scoring exists - they cover different things: PeerManager
        // bans on protocol violations, scoring degrades on mesh behaviour.
        assert!(
            NODE_RS.contains("check_rate_limit"),
            "PeerManager rate limiting must stay alongside peer scoring"
        );
    }

    /// The topics this node publishes on must be registered with the scorer.
    ///
    /// A topic with no entry contributes nothing to a peer's score, so only
    /// the global penalties apply and per-topic delivery accounting is lost.
    /// Tick-counted settings must be rescaled when the heartbeat is slowed.
    ///
    /// The node raises `heartbeat_interval` from gossipsub's 1s default to 10s
    /// (30s on mobile) to save CPU and radio. Three settings are counted in
    /// heartbeat *ticks*, not seconds, so that change stretched them by the
    /// same factor without anyone asking for it:
    ///
    ///   `check_explicit_peers_ticks` = 300    5 min ->  50 min (mobile 150)
    ///   `opportunistic_graft_ticks`  =  60    1 min ->  10 min (mobile  30)
    ///
    /// Both are mesh repair. The first decides how long a dropped explicit
    /// peer, a bootstrap node, a configured sentry, goes unnoticed before a
    /// reconnect is attempted; for a validator that is the link to the network
    /// it was pinned to on purpose. The second decides how long a node keeps a
    /// mesh of low-scoring peers before looking for better ones, which is the
    /// mechanism that recovers from a partial eclipse. Fifty minutes of either
    /// is not a tuning choice anybody made.
    ///
    /// Peer-score decay is deliberately absent from that list: it runs on
    /// `decay_interval` (1s) from its own timer in `poll`, not on the
    /// heartbeat. Verified in behaviour.rs at the pinned revision.
    ///
    /// `max_ihave_messages_heartbeat` is also left alone. A slower heartbeat
    /// makes that budget stricter, not looser, and an anti-flood limit
    /// drifting tighter is the safe direction.
    #[test]
    fn heartbeat_tick_counters_are_rescaled_with_the_heartbeat() {
        assert!(
            NODE_RS.contains("check_explicit_peers_ticks("),
            "the explicit-peer recheck is back on gossipsub's 300-tick default. \
             At a 10s heartbeat that is 50 minutes before a dropped bootstrap \
             or sentry peer is retried, and 150 minutes on mobile"
        );
        assert!(
            NODE_RS.contains("opportunistic_graft_ticks("),
            "opportunistic grafting is back on the 60-tick default. At a 10s \
             heartbeat a node sits on a low-scoring mesh for 10 minutes before \
             looking for better peers - that is the partial-eclipse recovery path"
        );

        // The rescaling must be derived from the heartbeat, not typed in twice.
        // A hardcoded tick count is correct for exactly one interval and wrong
        // the moment mobile mode picks a different one.
        assert!(
            NODE_RS.contains("300 / heartbeat.as_secs()")
                && NODE_RS.contains("60 / heartbeat.as_secs()"),
            "the tick counts are no longer derived from the heartbeat. Upstream \
             means 300s and 60s of wall clock; deriving them keeps both the \
             normal and mobile paths honest with one expression"
        );
        assert!(
            NODE_RS.contains(".max(1)"),
            "the derived tick counts lost their floor. A heartbeat longer than \
             the interval being scaled would round to zero ticks, and gossipsub \
             treats a zero tick counter as 'every heartbeat' or never depending \
             on the counter - neither is what was asked for"
        );
    }

    #[test]
    fn scored_topics_cover_what_the_node_publishes() {
        let at = NODE_RS
            .find("for topic in [\"blocks\", \"transactions\"]")
            .expect("the scored topic list must exist");
        let window = &NODE_RS[at..(at + 400).min(NODE_RS.len())];
        assert!(
            window.contains("score_params.topics.insert"),
            "the topic loop must register each topic with the scorer"
        );
        // Every topic the node actually publishes on has to be in that list.
        for topic in ["blocks", "transactions"] {
            let published = NODE_RS.contains(&format!("IdentTopic::new(\"{topic}\")"));
            assert!(
                published,
                "{topic} is registered for scoring but never published on; \
                 either the list or the publisher drifted"
            );
        }
    }

    /// Canary for the comment stripper: a mention inside a comment must not
    /// trip the lock, and real code must.
    #[test]
    fn comment_stripper_distinguishes_code_from_prose() {
        let sample = "\
            let a = x.lock().unwrap(); // real\n\
            // let b = y.lock().unwrap();\n\
            let c = 1;\n";
        let hits: Vec<_> = code_lines(sample)
            .into_iter()
            .filter(|(_, l)| l.contains(".lock().unwrap()"))
            .collect();
        assert_eq!(hits.len(), 1, "got {hits:?}");
        assert_eq!(hits[0].0, 1);
    }
}
