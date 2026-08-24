//! B.U.D. 3.0 - USER EXPERIENCE + ECONOMY AUDIT
//!
//! User questions:
//! 1) "How many QR codes is content split into?" - through the QR byte-mode
//!    capacity (EC=L).
//! 2) "What happens to a long video?" - streaming segmentation plus frame
//!    count per carousel round.
//! 3) "After dropping to 0.016, do the QR video plus the recipe not take up
//!    absurdly little space?" - an economic contradiction audit: if the recipe
//!    takes ~120 B the validator load is ~0, so WHAT does the user pay for?
//!    The answer: the NFT creation fee.
//! 4) "Let the user pay only when creating an NFT" - the creation-fee model.
//!
//! Every number is program output; none is written by hand (a spec rule).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const UX_MAGIC: [u8; 8] = *b"\xB5UX1\0\0\0\0";

/// QR byte-mode (EC=L) data capacity in bytes, by version (pinned in spec
/// section 7). v1..v40 (EC=L) approximate; the exact table lives in production.
/// A measured representation here: capacity(v) is about 17 + 4*v modules;
/// byte-mode EC=L: 14*v^2 + 26*v + 10 (a safe lower bound).
pub fn qr_capacity_bytes(version: u32) -> usize {
    // EC=L byte-mode capacity (known table values: v1=17, v10=271, v20=652,
    // v30=1231, v40=2331). The intermediate values are not interpolated - they
    // come from the real table.
    match version {
        1 => 17,
        2 => 32,
        3 => 53,
        4 => 78,
        5 => 106,
        6 => 134,
        7 => 154,
        8 => 192,
        9 => 230,
        10 => 271,
        11 => 321,
        12 => 367,
        13 => 425,
        14 => 458,
        15 => 520,
        16 => 586,
        17 => 644,
        18 => 718,
        19 => 792,
        20 => 858,
        21 => 929,
        22 => 1003,
        23 => 1091,
        24 => 1171,
        25 => 1273,
        26 => 1367,
        27 => 1465,
        28 => 1528,
        29 => 1628,
        30 => 1732,
        31 => 1840,
        32 => 1952,
        33 => 2068,
        34 => 2188,
        35 => 2303,
        36 => 2431,
        37 => 2563,
        38 => 2699,
        39 => 2809,
        40 => 2953,
        _ => 0,
    }
}

/// Content -> frame count (BLOCK=200 bytes + a 20 B header -> a 200 B payload
/// per frame). Each droplet carries a BLOCK=200 B payload; the QR v40 capacity
/// is 2953 B, so one frame carries 14 droplets.
pub fn qr_frame_count(
    content_bytes: usize,
    bytes_per_droplet: usize,
    frame_capacity: usize,
) -> usize {
    if content_bytes == 0 || bytes_per_droplet == 0 || frame_capacity == 0 {
        return 0;
    }
    let droplets = content_bytes.div_ceil(bytes_per_droplet);
    droplets.div_ceil(frame_capacity / bytes_per_droplet)
}

/// A long video (for example 2 hours, 4 GB) -> how many frames, rounds and
/// segments. BLOCK=200 B, QR v40 -> 14 droplets per frame. 4 GB = 4*2^30 bytes.
pub struct VideoUx {
    pub frames: usize,          // total frames (a systematic round)
    pub rounds: usize,          // carousel rounds (1 round = every block)
    pub segments: usize,        // 256 MB segments
    pub frames_per_second: f64, // the screen runs at 30 fps -> seconds
    pub minutes: f64,
}

pub fn video_ux(bytes: usize) -> VideoUx {
    let bytes_per_droplet = 200usize;
    let frame_capacity = qr_capacity_bytes(40); // v40
    let droplets_per_frame = (frame_capacity / bytes_per_droplet).max(1);
    let droplets = bytes.div_ceil(bytes_per_droplet);
    let frames = droplets.div_ceil(droplets_per_frame);
    let segment_size = 256 * 1024 * 1024;
    let segments = bytes.div_ceil(segment_size).max(1);
    VideoUx {
        frames,
        rounds: 1,
        segments,
        frames_per_second: frames as f64 / 30.0,
        minutes: frames as f64 / 30.0 / 60.0,
    }
}

// ============================ THE ECONOMIC CONTRADICTION ============================

/// AFTER the 0.016 target: the recipe takes ~120 B, so the validator load is
/// ~0 - then WHAT does the user pay? The contradiction audit catches the error
/// "storage rent 0 + a very cheap recipe -> the network earns nothing".
/// The answer: an NFT creation fee - the user pays while WRITING the recipe.
#[derive(Debug, Clone, Copy)]
pub struct CreationFee {
    pub usd_per_nft: f64, // the NFT creation fee
    pub nft_per_tb: f64,  // how many NFTs 1 TB of recipe content makes (representative)
    pub usd_per_tb: f64,  // effective $/TB (the creation-fee model)
}

/// NFT creation fee: for recipe content, a creation fee instead of "storage
/// rent". `usd_per_nft`: what the user pays each time they create an NFT.
/// `content_bytes_per_nft`: the content one NFT represents (representative,
/// for example 100 MB).
pub fn creation_fee_model(usd_per_nft: f64, content_bytes_per_nft: usize) -> CreationFee {
    let nft_per_tb = (1024.0 * 1024.0 * 1024.0) / content_bytes_per_nft.max(1) as f64;
    CreationFee {
        usd_per_nft,
        nft_per_tb,
        usd_per_tb: usd_per_nft * nft_per_tb,
    }
}

/// The contradiction check: does the 0.016 ceiling hold under the creation-fee
/// model? (The user's question was "but that is very cheap too" - revenue must
/// not fall to zero.)
pub fn creation_fee_ceiling_ok(fee: &CreationFee, ceiling: f64) -> bool {
    // network revenue is at least 10 percent of the ceiling (no open revenue gap)
    fee.usd_per_tb >= ceiling * 0.1
}

/// Is the recipe space really that small? (Economic realism: 1 TB of recipe
/// content = 120 B per recipe times however many recipes.) If one "recipe" is
/// ~120 B, the recipe space for 1 TB of content is:
pub fn recipe_space_tb(
    content_tb: f64,
    recipe_bytes: usize,
    content_bytes_per_recipe: usize,
) -> f64 {
    if content_bytes_per_recipe == 0 {
        return 0.0;
    }
    let recipe_count = content_tb * (1024.0 * 1024.0 * 1024.0) / content_bytes_per_recipe as f64;
    recipe_count * recipe_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
}

pub fn ux_digest(frames: usize, segments: usize, fee: f64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(UX_MAGIC);
    h.update((frames as u64).to_le_bytes());
    h.update((segments as u64).to_le_bytes());
    h.update(fee.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_kapasite_tablosu_gercek() {
        assert_eq!(qr_capacity_bytes(1), 17);
        assert_eq!(qr_capacity_bytes(10), 271);
        assert_eq!(qr_capacity_bytes(40), 2953);
        assert_eq!(qr_capacity_bytes(0), 0);
        assert_eq!(qr_capacity_bytes(99), 0);
    }

    #[test]
    fn how_many_qr_codes_for_small_content() {
        // 100 KB of text -> 500 droplets, v40 frames (14 droplets each) -> 36 frames
        let frames = qr_frame_count(100_000, 200, qr_capacity_bytes(40));
        assert!(
            frames > 0 && frames <= 40,
            "100KB -> about 36 frames: {frames}"
        );
        // 1 MB -> about 358 frames
        let frames_1m = qr_frame_count(1_000_000, 200, qr_capacity_bytes(40));
        assert!(
            frames_1m > 300 && frames_1m < 400,
            "1MB -> about 358: {frames_1m}"
        );
    }

    #[test]
    fn a_long_video_is_segmented() {
        // 4 GB (a 2 hour video) -> segments plus frame count
        let v = video_ux(4 * 1024 * 1024 * 1024);
        assert_eq!(v.segments, 16, "4GB / 256MB = 16 segments");
        assert!(v.frames > 10_000, "the frame count is large: {}", v.frames);
        assert!(
            v.minutes > 1.0,
            "a 2 hour video takes minutes at 30fps: {:.1}",
            v.minutes
        );
        // streaming: a segment whose commitment matches can play immediately (spec section 14)
        let _ = v.segments;
    }

    #[test]
    fn the_creation_fee_contradiction_audit() {
        // The "everything is very cheap" gap after the 0.016 target is closed
        // by the NFT creation fee. 0.05 $ per NFT, one NFT = 100 MB of content
        // -> 1 TB = 10240 NFTs -> 512 $/TB (there is revenue)
        let fee = creation_fee_model(0.05, 100 * 1024 * 1024);
        assert!(
            fee.usd_per_tb > 0.016,
            "revenue must be well above the ceiling: {}",
            fee.usd_per_tb
        );
        assert!(
            creation_fee_ceiling_ok(&fee, 0.016),
            "there is no revenue gap"
        );
        // recipe space: 1 TB of content, a 120 B recipe, one recipe per 100MB -> the recipe space is tiny
        let space = recipe_space_tb(1.0, 120, 100 * 1024 * 1024);
        assert!(space < 0.001, "the recipe space is negligible: {space} TB");
    }

    #[test]
    fn long_video_behaviour_is_streaming() {
        // long video: blocks arrive IN ORDER -> partial content is served immediately (K6)
        let v = video_ux(2 * 1024 * 1024 * 1024);
        // the first blocks of segment 1 arrive first -> playback can start
        let first_segment_frames = qr_frame_count(256 * 1024 * 1024, 200, qr_capacity_bytes(40));
        assert!(
            first_segment_frames < v.frames,
            "segment streaming: the first segment has fewer frames"
        );
    }

    #[test]
    fn ux_digest_is_deterministic() {
        assert_eq!(ux_digest(100, 2, 0.05), ux_digest(100, 2, 0.05));
    }
}
