//! Garden: a temporary, isolated Budlum network that people join with an
//! invite and use like a social room.
//!
//! One person creates a Garden and becomes its host. Everyone who joins is a
//! validator of the Garden chain. Messages, posts and images travel through
//! that chain, so a participant learns how a blockchain works by using one.
//!
//! # Shape
//!
//! * `types`: chain identifiers, genesis, transactions, headers, votes.
//! * `state`: the deterministic state machine every validator executes.
//! * `invite`: the invite link, which is also the QR content.
//! * `storage`: the node-local content store behind the storage seam.
//! * `net`: the dedicated libp2p swarm and the wire protocol.
//! * `settlement`: the link to Budlum's domain registry and `PoA` adapter.
//! * `node`: the validator runtime that proposes, executes and votes.
//! * `service`: the node-level entry point behind the `bud_garden*` RPC.
//!
//! The library API is [`GardenService`] with [`GardenOptions`]. Everything
//! else is private to this module tree.
//!
//! # Rules the code enforces
//!
//! * A Garden is a sovereign `PoA` domain with its own chain id and genesis.
//!   Garden transactions are refused on every primary Budlum chain id.
//! * The Garden chain has no stake, no fee, no reward and no validator class.
//! * A block is final when more than two thirds of its electorate signed it
//!   and the host is among the signers. The chain therefore runs exactly
//!   while the host is connected, and the host cannot finalize alone.
//! * State changes only inside finalized blocks.
//! * The validator votes sign Budlum's own `PoA` commit message, so a Garden
//!   finality certificate is a `FinalityProof::PoA` that the existing
//!   adapter verifies. No bridge is involved.
//! * Garden data lives as long as the Garden. A node that leaves wipes its
//!   own disk; when the last validator leaves nothing is left anywhere.

mod invite;
mod net;
mod node;
mod record;
mod service;
mod settlement;
mod state;
mod storage;
#[cfg(test)]
mod testkit;
mod types;

pub use service::{GardenOptions, GardenService};
#[cfg(test)]
pub(crate) use types::garden_domain_id;
pub(crate) use types::is_garden_domain_id;

/// Put one small object down the B.U.D. 3.0 path and read it back.
///
/// Section 4 of the optimisation directive asks the first run of the phone
/// to prove it can carry an object before it joins anything, and to prove
/// it locally: no peer, no network. That is what this does. It codes the
/// object the way a real publication codes it, then rebuilds it from the
/// coded symbols rather than from the stored bytes, because reading the
/// bytes back would pass even if the coding path were dead.
///
/// It lives here, beside the Garden it tests, so the phone runs the same
/// object layer a Linux validator runs (9.1) instead of a copy made for
/// the app.
///
/// # Errors
///
/// Returns what failed, in words a person can read on a phone screen.
///
/// The object is coded, then an eighth of its symbols are thrown away and
/// it is rebuilt from the rest. That is the claim B.U.D. 3.0 makes, and it
/// is the only part of it worth testing.
/// WIRING: wired - the caller is `mobile/garden-ffi`, the phone's UniFFI
/// library, which runs this as the B.U.D. 3.0 step of the section 4 self
/// test before a Garden is created or joined. That crate builds against
/// this one by path but sits outside the directories this gate reads, so
/// the call it makes is invisible here.
pub fn self_test_object_round_trip() -> Result<(), String> {
    // Big enough to become more than one symbol, small enough that a
    // phone finishes it well inside the fifteen seconds section 4 allows.
    let object: Vec<u8> = (0..8192u32)
        .map(|i| u8::try_from(i % 251).unwrap_or_default())
        .collect();
    // In memory, and with a ceiling a phone can hold: the coded symbols of
    // an 8 KiB object fit many times over inside four mebibytes.
    let mut store = storage::GardenContentStore::open_with_limit(None, 1 << 20, 4 << 20)
        .map_err(|e| format!("the object store did not open: {e}"))?;
    let content_id = store
        .put(&object)
        .map_err(|e| format!("the object was not stored: {e}"))?;
    let (record, symbols) = store
        .coded_parts(&content_id)
        .ok_or_else(|| "the object was stored without a B.U.D. 3.0 coding".to_string())?;
    let made = symbols.len();
    // Throw pieces away before asking for it back. Rebuilding an object
    // from a complete set of symbols proves only that the coder can be
    // run backwards; it is the missing pieces that the whole scheme is
    // for, and a phone that cannot do this is not holding anything
    // safely. Every eighth symbol goes, source symbols included.
    let kept: Vec<_> = symbols
        .into_iter()
        .enumerate()
        .filter(|(index, _)| index % 8 != 0)
        .map(|(_, symbol)| symbol)
        .collect();
    let lost = made.saturating_sub(kept.len());
    if lost == 0 {
        return Err("the coding produced too few symbols to lose any".into());
    }
    let rebuilt = store
        .rebuild_coded(&content_id, &record, kept)
        .map_err(|e| format!("the object did not survive losing {lost} of {made} symbols: {e}"))?;
    if rebuilt != object {
        return Err(format!(
            "the object came back changed: {} bytes in, {} bytes out",
            object.len(),
            rebuilt.len()
        ));
    }
    Ok(())
}
