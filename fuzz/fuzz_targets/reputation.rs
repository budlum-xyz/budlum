#![no_main]

//! Task 11.12 / §3.4 — reputation/peer-score/ban fuzz.
//! Oracle: panic-freedom + score ∈ [MIN_SCORE, MAX_SCORE].

use budlum_core::network::peer_manager::{PeerManager, MAX_SCORE, MIN_SCORE};
use libfuzzer_sys::fuzz_target;
use libp2p::PeerId;

fuzz_target!(|data: &[u8]| {
    let mut pm = PeerManager::new();
    let peer = PeerId::random();
    let mut i = 0;

    fn take(data: &[u8], i: &mut usize) -> u8 {
        let b = data.get(*i).copied().unwrap_or(0);
        *i = i.saturating_add(1);
        b
    }

    let steps = (take(data, &mut i) as usize) % 32;
    for _ in 0..steps {
        let subnet = if take(data, &mut i) & 1 == 1 {
            Some([take(data, &mut i), take(data, &mut i), take(data, &mut i)])
        } else {
            None
        };
        match take(data, &mut i) % 6 {
            0 => { let _ = pm.note_connected(peer, subnet); }
            1 => { let _ = pm.note_disconnected(&peer); }
            2 => { let _ = pm.check_rate_limit(&peer); }
            3 => { pm.ban_peer(&peer); }
            4 => { pm.unban_peer(&peer); }
            _ => { pm.cleanup_expired_bans(); }
        }
        // Invariant: score ∈ [MIN_SCORE, MAX_SCORE].
        let score = pm.get_score(&peer);
        assert!((MIN_SCORE..=MAX_SCORE).contains(&score));
    }
});
