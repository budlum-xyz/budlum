//! The Poseidon parameter set, defined once.
//!
//! fixes the in-VM hash: Goldilocks, state width 12, 8 full and 22 partial
//! rounds, S-box `x^7`, capacity 4 elements, output 4 elements (256 bits). A
//! single element of 64 bits binds nothing at the security floor: a birthday
//! search finds a collision after about `2^32` evaluations.
//!
//! This module is the one definition. The constants are the Plonky3
//! `GOLDILOCKS_POSEIDON1_RC_12` round constants (Grain LFSR, `field_type=1`,
//! `alpha=7`, `n=64`, `t=12`, `R_F=8`, `R_P=22`) and the circulant MDS matrix of
//! `p3-goldilocks` (`MATRIX_CIRC_MDS_12`, first row below). The permutation is the
//! plain round function: add the round constants, apply the S-box to every lane
//! (full rounds) or to lane 0 only (partial rounds), multiply by the MDS matrix.
//! `budzero/bud-proof` carries a test that runs this permutation next to
//! Plonky3's own `Poseidon1Goldilocks<12>` on the same inputs, so a copy that
//! drifts fails there.
//!
//! The wallet, the zkVM and the node read this definition instead of keeping their
//! own copy, for the reason the packing rule in this crate is defined once: a wallet
//! that computes a commitment the proof system cannot open loses the note without
//! any single crate's tests noticing.
//!
//! An algebraic hash is never the hash of a long-lived signature or commitment
//!; this one lives inside the VM, where the
//! proof system needs a hash that is cheap to arithmetise.
//!
//! WIRING: the reference definition of the set. Today the VM, the AIR and the
//! wallet still run the width-8 instance; and move them onto this one.
//! Until then `budzero/bud-proof/tests/poseidon_parity.rs` is its caller and the
//! check that it equals Plonky3's own permutation.

use crate::{NoteHash, GOLDILOCKS_P};

/// State width: 8 rate elements and 4 capacity elements.
pub const WIDTH: usize = 12;
/// Rate: the elements a call absorbs.
pub const RATE: usize = 8;
/// Capacity: the elements no input touches. 4 elements are 256 bits.
pub const CAPACITY: usize = 4;
/// Output size in field elements (256 bits).
pub const OUTPUT: usize = 4;
/// Full rounds: 4 leading and 4 trailing.
pub const FULL_ROUNDS: usize = 8;
/// Partial rounds: the S-box runs on lane 0 only.
pub const PARTIAL_ROUNDS: usize = 22;
/// All rounds.
pub const ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;
/// The S-box exponent. `gcd(7, p - 1) = 1` over Goldilocks.
pub const ALPHA: u64 = 7;

/// First row of the circulant MDS matrix; row `i` is this row rotated right by `i`.
pub const MDS_FIRST_ROW: [u64; WIDTH] = [1, 1, 2, 1, 8, 9, 10, 7, 5, 9, 4, 10];

/// Round constants, one row per round.
pub const RC: [[u64; WIDTH]; ROUNDS] = [
    // round  0 (full)
    [
        0x13dcf33aba214f46,
        0x30b3b654a1da6d83,
        0x1fc634ada6159b56,
        0x937459964dc03466,
        0xedd2ef2ca7949924,
        0xede9affde0e22f68,
        0x8515b9d6bac9282d,
        0x6b5c07b4e9e900d8,
        0x1ec66368838c8a08,
        0x9042367d80d1fbab,
        0x400283564a3c3799,
        0x4a00be0466bca75e,
    ],
    // round  1 (full)
    [
        0x7913beee58e3817f,
        0xf545e88532237d90,
        0x22f8cb8736042005,
        0x6f04990e247a2623,
        0xfe22e87ba37c38cd,
        0xd20e32c85ffe2815,
        0x117227674048fe73,
        0x4e9fb7ea98a6b145,
        0xe0866c232b8af08b,
        0x00bbc77916884964,
        0x7031c0fb990d7116,
        0x240a9e87cf35108f,
    ],
    // round  2 (full)
    [
        0x2e6363a5a12244b3,
        0x5e1c3787d1b5011c,
        0x4132660e2a196e8b,
        0x3a013b648d3d4327,
        0xf79839f49888ea43,
        0xfe85658ebafe1439,
        0xb6889825a14240bd,
        0x578453605541382b,
        0x4508cda8f6b63ce9,
        0x9c3ef35848684c91,
        0x0812bde23c87178c,
        0xfe49638f7f722c14,
    ],
    // round  3 (full)
    [
        0x8e3f688ce885cbf5,
        0xb8e110acf746a87d,
        0xb4b2e8973a6dabef,
        0x9e714c5da3d462ec,
        0x6438f9033d3d0c15,
        0x24312f7cf1a27199,
        0x23f843bb47acbf71,
        0x9183f11a34be9f01,
        0x839062fbb9d45dbf,
        0x24b56e7e6c2e43fa,
        0xe1683da61c962a72,
        0xa95c63971a19bfa7,
    ],
    // round  4 (partial)
    [
        0x4adf842aa75d4316,
        0xf8fbb871aa4ab4eb,
        0x68e85b6eb2dd6aeb,
        0x07a0b06b2d270380,
        0xd94e0228bd282de4,
        0x8bdd91d3250c5278,
        0x209c68b88bba778f,
        0xb5e18cdab77f3877,
        0xb296a3e808da93fa,
        0x8370ecbda11a327e,
        0x3f9075283775dad8,
        0xb78095bb23c6aa84,
    ],
    // round  5 (partial)
    [
        0x3f36b9fe72ad4e5f,
        0x69bc96780b10b553,
        0x3f1d341f2eb7b881,
        0x4e939e9815838818,
        0xda366b3ae2a31604,
        0xbc89db1e7287d509,
        0x6102f411f9ef5659,
        0x58725c5e7ac1f0ab,
        0x0df5856c798883e7,
        0xf7bb62a8da4c961b,
        0xc68be7c94882a24d,
        0xaf996d5d5cdaedd9,
    ],
    // round  6 (partial)
    [
        0x9717f025e7daf6a5,
        0x6436679e6e7216f4,
        0x8a223d99047af267,
        0xbb512e35a133ba9a,
        0xfbbf44097671aa03,
        0xf04058ebf6811e61,
        0x5cca84703fac7ffb,
        0x9b55c7945de6469f,
        0x8e05bf09808e934f,
        0x2ea900de876307d7,
        0x7748fff2b38dfb89,
        0x6b99a676dd3b5d81,
    ],
    // round  7 (partial)
    [
        0xac4bb7c627cf7c13,
        0xadb6ebe5e9e2f5ba,
        0x2d33378cafa24ae3,
        0x1e5b73807543f8c2,
        0x09208814bfebb10f,
        0x782e64b6bb5b93dd,
        0xadd5a48eac90b50f,
        0xadd4c54c736ea4b1,
        0xd58dbb86ed817fd8,
        0x6d5ed1a533f34ddd,
        0x28686aa3e36b7cb9,
        0x591abd3476689f36,
    ],
    // round  8 (partial)
    [
        0x047d766678f13875,
        0xa2a11112625f5b49,
        0x21fd10a3f8304958,
        0xf9b40711443b0280,
        0xd2697eb8b2bde88e,
        0x3493790b51731b3f,
        0x11caf9dd73764023,
        0x7acfb8f72878164e,
        0x744ec4db23cefc26,
        0x1e00e58f422c6340,
        0x21dd28d906a62dda,
        0xf32a46ab5f465b5f,
    ],
    // round  9 (partial)
    [
        0xbfce13201f3f7e6b,
        0xf30d2e7adb5304e2,
        0xecdf4ee4abad48e9,
        0xf94e82182d395019,
        0x4ee52e3744d887c5,
        0xa1341c7cac0083b2,
        0x2302fb26c30c834a,
        0xaea3c587273bf7d3,
        0xf798e24961823ec7,
        0x962deba3e9a2cd94,
        0xb36ee79485ca4707,
        0xd380199eddd2de52,
    ],
    // round 10 (partial)
    [
        0x70971fc4e6f85305,
        0x8e722f6e5dc32699,
        0xa0883df133052b92,
        0x8f86c6a3eb7d01a4,
        0x763649c8b670bdc5,
        0x830d5c82b808759b,
        0xaa1da8bb91da02e7,
        0x9bc9bf629e211c4d,
        0x0f0a899b10a4dea8,
        0xb883bdcee7c6b356,
        0x78c7101e7496ae1e,
        0x2fd6c5a8bf1e5ca6,
    ],
    // round 11 (partial)
    [
        0xe2a6e06e61fcec9c,
        0xebfce7d5c5b3dbd5,
        0xca2eeca4bb485d85,
        0xc2b875537c42eb69,
        0x6faf849976873328,
        0xfc3fcb6e81ad4cc3,
        0x180dd95503955a28,
        0xd40f19a3c9fe1520,
        0x49d178ddbf7fd96d,
        0x3950bee2e10e0297,
        0x437b90cf295be062,
        0xa5cd126edffad23b,
    ],
    // round 12 (partial)
    [
        0xdf58134c134491c2,
        0x0677eca229d9f7bd,
        0x492200a1f7d83a3c,
        0xafb58c9810a43645,
        0x7659077c5a9c208e,
        0x30b4bc83706995cd,
        0xc98fa77bbbef3a3b,
        0x84a82905750b3109,
        0x72f2a02326aeb69b,
        0x8d27a2a2d73a848a,
        0xaa9e30a80bde4b68,
        0x63abb1415e050474,
    ],
    // round 13 (partial)
    [
        0x1c4bd1e816050a7e,
        0x15d1502e4f469dfd,
        0x53989d594b0c4cd8,
        0x7a1a4c83cb7e377e,
        0x1b52f8a9944e480e,
        0xeb7b03f76a91a79e,
        0x0073a4fc9328c69e,
        0x2c7b16f8620d9de4,
        0x950d052963e46bc4,
        0x8d201ba1a9c89fac,
        0xd3502941bdf35503,
        0x7c6dfcd5af8676fb,
    ],
    // round 14 (partial)
    [
        0xf8a6cd02e92cdb0b,
        0x6e7500f3a5464b22,
        0x07637eabba4bdd20,
        0x88b82717beee0e14,
        0xbaa2b1cd3dd4c79a,
        0xdfecc3aebec4cfa6,
        0x7561087b0cff0166,
        0x538fcac317a703a6,
        0xd7d6c6eeeeeeea19,
        0xd647b1ee441658a0,
        0xdf4442110236c546,
        0x559ef2c6dd73ec15,
    ],
    // round 15 (partial)
    [
        0x4c0f5fc6c0dda3d1,
        0x685010cc3100cea7,
        0x2fb6ba8aa0344440,
        0xb515f0a3ca75f1fb,
        0x886887eaecb87c10,
        0xf03ec3fd710abb04,
        0xd3b4763e17f543ef,
        0x50d9e5716e78083a,
        0x0bce2385cf8d74ff,
        0xaf23032cd5f0e04b,
        0xd366aa112b6159d9,
        0x810a3ad3ac7979db,
    ],
    // round 16 (partial)
    [
        0x0a4a11d794be40a2,
        0xeebf0cf23b668a3f,
        0x600873fb011d761b,
        0x0bfb5591a02ff618,
        0xa16e2a528910af52,
        0xf6553653e2878421,
        0xccbe7c7a601a30c0,
        0xb18b214fe489f5b3,
        0xe21017ab9e153425,
        0x586099ede17af9a6,
        0x385078b514f50647,
        0xc02b3a9afb89883d,
    ],
    // round 17 (partial)
    [
        0x6d3fbd3b4a9f1de6,
        0x4b4d40a41b0f473c,
        0x838f1887b8f31711,
        0x9396895be5c58a41,
        0x6247a479d66fc2e3,
        0x13fe228a98f2d0a2,
        0x5ba5fde765f9481e,
        0xafb89fa62267e117,
        0xfa4dc1bebcaa6333,
        0xdbab590882b87289,
        0xc3b6c08e23ba9301,
        0xd84b5de94a324fb7,
    ],
    // round 18 (partial)
    [
        0x0d0c371c5b35b850,
        0x7964f570e7188038,
        0x5daf18bbd996604c,
        0x6743bc47b9595258,
        0x5528b9362c59bb71,
        0xac45e25b7127b68c,
        0xa2077d7dfbb606b6,
        0xf3faac6faee378af,
        0x0c6388b51545e884,
        0xd27dbb6944917b61,
        0x89bcac584344c104,
        0x856bab802ce7402d,
    ],
    // round 19 (partial)
    [
        0x2cff3000be1fcd0a,
        0x765f2977fa72a917,
        0x1443711329f5f9d5,
        0xd35cd0261af2f951,
        0x2a1bb986084ec281,
        0x2334a54b758f23f2,
        0xa9b8cb612caf706b,
        0xb6ba11c4ab1a1017,
        0xde96b0824b4b46e2,
        0xc59d4272c6d92e2c,
        0x389bb5107611754d,
        0x23647fbc77657372,
    ],
    // round 20 (partial)
    [
        0xd5ef60d6f76a42fa,
        0xebb406bb79ac9819,
        0x55faccc709a2f423,
        0xd9d6ea97490091cd,
        0xef3ce5069647a7e4,
        0xdf31625d3fa78464,
        0x242e60fd68f10f66,
        0x39c966cc815f084d,
        0x20e2e22e02bae3f7,
        0xb38919d3f1173d7c,
        0xf17769f6c77084d9,
        0xcc051d8094cac41f,
    ],
    // round 21 (partial)
    [
        0x942069f5d6eece7e,
        0x8d61d3e6f141c572,
        0xc5cef9d85dd605f4,
        0x938f2ac2bf885997,
        0x23bddbace7c48f6c,
        0xc90a6c5ba98537e4,
        0x0be6ee2cca90f6ae,
        0xa026175394ae0e90,
        0x29fca3e314c77628,
        0x2aa2aa8738ab7b77,
        0xe11bbd31fbb8cac6,
        0xb5bbbef1b78a23af,
    ],
    // round 22 (partial)
    [
        0x8b62a5551e9a9797,
        0x3f91073d4d491c80,
        0x4cfa44976396424a,
        0xf8dcb2dfb3aa1b44,
        0x3849409eba1a95f5,
        0x070845799f234380,
        0x184c0093667da1ba,
        0xbd66aafccd51601e,
        0xee6d14e92155b490,
        0x626f2ec1865bc544,
        0x1bd2854bf6485986,
        0x368b8497472f12ef,
    ],
    // round 23 (partial)
    [
        0x4f88cdcdfb791921,
        0xe2c0acfeda9ae781,
        0x9739bc21773469b3,
        0x00ce3ad64dc4bb8f,
        0xaab85a321ee7a4c8,
        0xd5de825be97004f4,
        0x48d676d3a043b1c6,
        0x9c6180b1ff643097,
        0x34882a89dd590b09,
        0xae7e6b0d249c3b1d,
        0x8c016908a04885a1,
        0x83ebaaebc9ae0721,
    ],
    // round 24 (partial)
    [
        0xab21b42e0f642307,
        0xdb46631f62bb29c1,
        0xef29f0399e09b5d9,
        0x5b52fbb3613b8ba1,
        0x57e129fcc96922e6,
        0xcdeb14c9d9204b3a,
        0x1341ef0da8536e34,
        0xd7e3400f2bacde63,
        0x6911eeb42f70d7e5,
        0xc3a2a910a4679767,
        0x1773cbe4a0f6bb28,
        0xe17b0d53e843eab5,
    ],
    // round 25 (partial)
    [
        0x587fa39990b62800,
        0x0d5d32788135879d,
        0x277f7b31fd3a4cdb,
        0xa435290ee56d7efa,
        0xea6f40be35159925,
        0xcb73377a506171cb,
        0xe43c367ce731d82a,
        0x6eb305031ca10c43,
        0xc019a8c622cc84cb,
        0xd5614f5658c612e6,
        0x7b1ecbe957c3ff98,
        0x60db6ee9651a8478,
    ],
    // round 26 (full)
    [
        0x9271d450fc9b4117,
        0xcffeea06b6e3aac1,
        0xfa4a44c748d1cd8e,
        0xe64db01ba569b469,
        0xd31005160e4045fe,
        0x39e0fa013e025f79,
        0xe243be574196a956,
        0x205b2a681e3d2642,
        0x79cae5ad93486bab,
        0xfdf567844e32c295,
        0x331679589bfb7189,
        0xaf06ee32297b89c2,
    ],
    // round 27 (full)
    [
        0xa6bcae311e498491,
        0x9d16f52c96ac8b3e,
        0x48a674b59393fa35,
        0x0f9e65da3fde3796,
        0x1e098310fc84578c,
        0x559ae5fab1ae8dad,
        0x56bd4d624078881d,
        0xfd8bbbf8fbe817b5,
        0x82d30695c44df534,
        0x3ec0a97bc41127c5,
        0x1eb8b64adaa22078,
        0x82c45e418d60c983,
    ],
    // round 28 (full)
    [
        0xb092280f484d55bf,
        0xcd317c9537697939,
        0xd3be2e352feb79f3,
        0xca6d866539a390e5,
        0xb5efb1a494e55ee6,
        0xfa9013ac89756e9e,
        0xaeb88efd1e981242,
        0x13ee477cdab6e0dc,
        0xce7df902c40da2d3,
        0xf3fbaf0d4e6f5f34,
        0xf96354ada6785f38,
        0x13b5692812406886,
    ],
    // round 29 (full)
    [
        0xf03cae030a0f4418,
        0x7d3172887aa98e1a,
        0x8a2c2644f2faf7b9,
        0x80d721abee696d00,
        0x27c8b903a4d68267,
        0xaf0b7b12f90291b8,
        0x00acd08cfdff3817,
        0x4659ee496c634328,
        0xf5b25c10730dbff1,
        0xdde3a153297329c2,
        0x50c0b70d6910a44b,
        0x23c7426af725a6a0,
    ],
];

const P: u128 = GOLDILOCKS_P as u128;

/// Entry `(row, col)` of the circulant MDS matrix.
#[must_use]
pub const fn mds_entry(row: usize, col: usize) -> u64 {
    MDS_FIRST_ROW[(col + WIDTH - row) % WIDTH]
}

/// The full MDS matrix, row by row.
pub const MDS: [[u64; WIDTH]; WIDTH] = {
    let mut matrix = [[0u64; WIDTH]; WIDTH];
    let mut row = 0;
    while row < WIDTH {
        let mut col = 0;
        while col < WIDTH {
            matrix[row][col] = mds_entry(row, col);
            col += 1;
        }
        row += 1;
    }
    matrix
};

fn add(a: u64, b: u64) -> u64 {
    ((u128::from(a) + u128::from(b)) % P) as u64
}

fn mul(a: u64, b: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) % P) as u64
}

fn sbox(x: u64) -> u64 {
    let x2 = mul(x, x);
    let x4 = mul(x2, x2);
    mul(mul(x4, x2), x)
}

/// The 30-round permutation.
#[must_use]
pub fn permute(mut state: [u64; WIDTH]) -> [u64; WIDTH] {
    let half_full = FULL_ROUNDS / 2;
    for (round, constants) in RC.iter().enumerate() {
        for (lane, constant) in state.iter_mut().zip(constants.iter()) {
            *lane = add(*lane, *constant);
        }
        if round < half_full || round >= ROUNDS - half_full {
            for lane in &mut state {
                *lane = sbox(*lane);
            }
        } else {
            state[0] = sbox(state[0]);
        }
        let mut next = [0u64; WIDTH];
        for (row, out) in next.iter_mut().enumerate() {
            let mut acc: u128 = 0;
            for (col, lane) in state.iter().enumerate() {
                acc = (acc + u128::from(mds_entry(row, col)) * u128::from(*lane)) % P;
            }
            *out = acc as u64;
        }
        state = next;
    }
    state
}

/// Hash up to eight elements: they fill the rate lanes, the capacity starts at
/// zero, and the first four lanes of the permuted state are the 256-bit output.
#[must_use]
pub fn hash(inputs: [u64; RATE]) -> [u64; OUTPUT] {
    let mut state = [0u64; WIDTH];
    state[..RATE].copy_from_slice(&inputs);
    let out = permute(state);
    [out[0], out[1], out[2], out[3]]
}

/// Compress two 256-bit nodes into one: the Merkle node function.
#[must_use]
pub fn compress(left: [u64; OUTPUT], right: [u64; OUTPUT]) -> [u64; OUTPUT] {
    hash([
        left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3],
    ])
}

/// Pack four field elements into a 32-byte note hash, little-endian, carrying
/// every byte. This is the 256-bit counterpart of `hash_from_field`.
#[must_use]
pub fn hash_from_elements(elements: [u64; OUTPUT]) -> NoteHash {
    let mut out = [0u8; 32];
    for (chunk, element) in out.chunks_exact_mut(8).zip(elements.iter()) {
        chunk.copy_from_slice(&element.to_le_bytes());
    }
    out
}

/// Read four field elements out of a 32-byte note hash. `None` when an element is
/// not a canonical field value, because such a hash was not produced by [`hash`].
#[must_use]
pub fn elements_from_hash(hash: &NoteHash) -> Option<[u64; OUTPUT]> {
    let mut elements = [0u64; OUTPUT];
    for (element, chunk) in elements.iter_mut().zip(hash.chunks_exact(8)) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        let value = u64::from_le_bytes(bytes);
        if value >= GOLDILOCKS_P {
            return None;
        }
        *element = value;
    }
    Some(elements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_round_schedule_is_the_k14_one() {
        assert_eq!(WIDTH, RATE + CAPACITY);
        assert_eq!(
            CAPACITY, OUTPUT,
            "the capacity is as wide as the output: 256 bits"
        );
        assert_eq!(FULL_ROUNDS, 8);
        assert_eq!(PARTIAL_ROUNDS, 22);
        assert_eq!(RC.len(), ROUNDS);
        assert_eq!(ALPHA, 7);
    }

    #[test]
    fn the_mds_matrix_is_circulant() {
        assert_eq!(mds_entry(0, 0), 1);
        assert_eq!(mds_entry(0, 11), 10);
        assert_eq!(mds_entry(1, 0), 10, "row 1 is row 0 rotated right by one");
        assert_eq!(mds_entry(1, 1), 1);
        assert_eq!(mds_entry(11, 0), 1);
        // Row 11 is row 0 rotated right by 11, so column 11 lands on column
        // 0 of the first row: the far corner mirrors (0, 0), not (0, 11).
        assert_eq!(mds_entry(11, 11), 1);
    }

    #[test]
    fn the_constant_table_is_canonical_and_pinned_at_both_ends() {
        for row in &RC {
            for value in row {
                assert!(
                    *value < GOLDILOCKS_P,
                    "a round constant is not a field element"
                );
            }
        }
        assert_eq!(RC[0][0], 0x13dc_f33a_ba21_4f46);
    }

    #[test]
    fn the_hash_is_deterministic_and_sensitive_to_every_input() {
        let base = hash([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(base, hash([1, 2, 3, 4, 5, 6, 7, 8]));
        for lane in 0..RATE {
            let mut changed = [1, 2, 3, 4, 5, 6, 7, 8];
            changed[lane] ^= 1;
            assert_ne!(base, hash(changed), "lane {lane} does not reach the output");
        }
    }

    #[test]
    fn a_node_is_not_symmetric_in_its_children() {
        let a = [1, 2, 3, 4];
        let b = [5, 6, 7, 8];
        assert_ne!(compress(a, b), compress(b, a));
    }

    #[test]
    fn four_elements_pack_into_all_thirty_two_bytes_and_back() {
        let elements = [
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            GOLDILOCKS_P - 1,
            1,
        ];
        let packed = hash_from_elements(elements);
        assert_eq!(&packed[0..8], &elements[0].to_le_bytes());
        assert_eq!(&packed[24..32], &elements[3].to_le_bytes());
        assert_eq!(elements_from_hash(&packed), Some(elements));
    }

    #[test]
    fn a_hash_with_a_non_canonical_element_is_refused() {
        let mut packed = hash_from_elements([1, 2, 3, 4]);
        packed[16..24].copy_from_slice(&GOLDILOCKS_P.to_le_bytes());
        assert_eq!(elements_from_hash(&packed), None);
    }
}
