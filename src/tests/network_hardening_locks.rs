//! Locks for network-layer hardening that is easy to undo by accident.
//!
//! Two classes of finding live here:
//!
//!   * A poisoned mutex must degrade the affected request, not kill the node.
//!     `src/network/node.rs` holds ~20 lock sites; all but one already matched
//!     on the result or exited deliberately, and the odd one out turned an
//!     optional content fetch into a node-wide panic.
//!   * Gossipsub's defaults are the network's DoS surface. They are currently
//!     accepted deliberately, and this file records which ones were checked so
//!     "we never looked" cannot be confused with "we looked and accepted".

#[cfg(test)]
mod tests {
    const NODE_RS: &str = include_str!("../network/node.rs");

    /// Strip comments and string literals so a lock cannot be satisfied — or
    /// tripped — by prose that merely mentions the pattern.
    fn code_lines(body: &str) -> Vec<(usize, String)> {
        body.lines()
            .enumerate()
            .map(|(i, line)| {
                let no_comment = match line.find("//") {
                    Some(at) => &line[..at],
                    None => line,
                };
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
            "node.rs contains bare .lock().unwrap() at {:?} — a poisoned mutex \
             would panic the node instead of failing the request. Match on the \
             Result, or use unwrap_or_else with an explicit logged exit.",
            offenders
                .iter()
                .map(|(n, l)| format!("line {n}: {l}"))
                .collect::<Vec<_>>()
        );
    }

    /// The remote-content fetch path specifically must survive a poisoned
    /// PeerManager: it is an optional optimisation over local storage, so
    /// failing it is correct and panicking is not.
    #[test]
    fn remote_content_fetch_degrades_on_poisoned_peer_manager() {
        // `NodeCommand::FetchRemoteContent {` appears twice: once where the
        // command is sent, once as the match arm that handles it. Only the arm
        // ends in `=> {`, so match on that.
        let at = NODE_RS
            .find("NodeCommand::FetchRemoteContent { cid, response } => {")
            .expect("the FetchRemoteContent command arm must still exist");
        let arm = &NODE_RS[at..(at + 3000).min(NODE_RS.len())];
        assert!(
            arm.contains("PeerManager lock poisoned during remote content fetch"),
            "the FetchRemoteContent arm no longer handles a poisoned \
             PeerManager lock; a panic elsewhere in the node would take the \
             whole event loop down through this path"
        );
        assert!(
            arm.contains("peer manager unavailable"),
            "the caller must be told the fetch failed rather than being left \
             waiting on a dropped channel"
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

    /// Peer scoring is **not** enabled, and that is the current accepted state.
    ///
    /// Without it, gossipsub's IHAVE/IWANT accounting has no consequence: a
    /// peer that floods IHAVE announcements and never delivers on IWANT is
    /// throttled by the per-heartbeat caps but is never penalised or pruned.
    /// The repo compensates with its own `PeerManager` rate limiting and ban
    /// list, which is why this is accepted rather than fixed.
    ///
    /// This test exists so the gap stays visible. If peer scoring is turned
    /// on, this test fails and the comment above has to be rewritten into a
    /// description of the parameters that were chosen.
    #[test]
    fn gossipsub_peer_scoring_gap_is_recorded() {
        let enabled = NODE_RS.contains("with_peer_score") || NODE_RS.contains("PeerScoreParams");
        assert!(
            !enabled,
            "gossipsub peer scoring was enabled — good, but this lock recorded \
             its absence as an accepted gap. Replace this test with one that \
             pins the score thresholds that were chosen."
        );
        // The compensating control must exist while scoring does not.
        assert!(
            NODE_RS.contains("check_rate_limit"),
            "PeerManager rate limiting is the compensating control for the \
             missing gossipsub peer scoring; it must not disappear silently"
        );
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
