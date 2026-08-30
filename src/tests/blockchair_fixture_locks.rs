//! Locks: regression against REAL chain vectors pulled from Blockchair.
//!
//! This file makes NO network call; every value is a committed fixture.
//! Source: the Blockchair API v2 (`api.blockchair.com`), pulled 2026-08-14.
//! The BTC endpoint is at height 962380; the ETH endpoint covers
//! 20000000-20000003. The merkle roots were cross-verified by two independent
//! computations - Blockchair's own `merkle_root` field and an independent local
//! computation - and the two are byte for byte equal.
//!
//! Honesty about scope: the `VerifyMerkle` circuit works in `BudZero`'s own hash
//! field; the merkle tests below are the endianness and pairing lock of our
//! Bitcoin-side root computation. The soundness of the circuit is OUTSIDE the
//! scope of this file - an external opcode review is pending.
//!
//! Test time is not runtime: the fixtures are refreshed by a one-off generation
//! and CI never calls the live API. Under no scenario is there a production
//! runtime dependency.

use crate::consensus::pow::U256;
use crate::core::address::Address;
use crate::cross_domain::evm::header::{verify_chain, EthHeader, HeaderError};
use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams, MessageKind};
use crate::cross_domain::nonce::ReplayNonceStore;
use sha2::{Digest, Sha256};

// ============ 1. BTC chainwork vectors ============
/// (height, block hash, chainwork - 64 hex characters, so 256 bits).
/// Endpoint: `/bitcoin/blocks?limit=1&q=id({height})`.
const BTC_CHAINWORK: &[(&str, &str, &str)] = &[
    (
        "0",
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        "0000000000000000000000000000000000000000000000000000000100010001",
    ),
    (
        "1",
        "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        "0000000000000000000000000000000000000000000000000000000200020002",
    ),
    (
        "100000",
        "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506",
        "0000000000000000000000000000000000000000000000000644cb7f5234089e",
    ),
    (
        "200000",
        "000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf",
        "00000000000000000000000000000000000000000000001ac073536b8dbae81c",
    ),
    (
        "400000",
        "000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f",
        "000000000000000000000000000000000000000000122a24b77c62cd76004cde",
    ),
    (
        "500000",
        "00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04",
        "000000000000000000000000000000000000000000cda532266f9147b519e933",
    ),
    (
        "700000",
        "0000000000000000000590fc0f3eba193a278534220b2b37e9849e1a770ca959",
        "0000000000000000000000000000000000000000216dd8dc61fdffabb624feeb",
    ),
    (
        "800000",
        "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054",
        "00000000000000000000000000000000000000004fc85ab3390629e495bf13d5",
    ),
    (
        "962380",
        "000000000000000000016c310bbbcd08f1e0ff5761344bdae091e3c877e9eae0",
        "00000000000000000000000000000000000000013f4fc1e7f9b0722fd010d0a9",
    ),
];

/// Converts a big-endian hex string into a `U256`; each set bit is a `pow2` term.
fn u256_from_hex_be(hex: &str) -> U256 {
    let mut acc = U256::ZERO;
    for (i, c) in hex.as_bytes().iter().rev().enumerate() {
        let nib = (*c as char).to_digit(16).expect("hex basamak");
        for b in 0..4 {
            if nib & (1u32 << b) != 0 {
                acc = acc.saturating_add(U256::pow2((u32::try_from(i).unwrap()) * 4 + b));
            }
        }
    }
    acc
}

/// Real chainwork values are monotonic - every block adds work - and are
/// currently below 2^128, so the reporting surface has to be lossless. For
/// artificial values above 2^128 the reporting HAS TO SATURATE while the
/// ordering must not; the two contracts are locked together. This is the
/// real-magnitude lock of the 128-bit saturation bug.
#[test]
fn real_bitcoin_chainwork_is_monotonic_and_reports_losslessly() {
    let mut prev: Option<(&str, U256)> = None;
    for &(height, hash, cw) in BTC_CHAINWORK {
        assert_eq!(cw.len(), 64, "chainwork has to be 256-bit: height {height}");
        assert_eq!(
            hash.len(),
            64,
            "the block hash has to be 256-bit: height {height}"
        );
        let value = u256_from_hex_be(cw);
        if let Some((prev_height, prev_value)) = prev {
            assert!(
                value > prev_value,
                "chainwork monotonicity broke: {height} vs {prev_height}"
            );
        }
        // Below u128 the reporting is lossless; if the saturation fired in the
        // wrong place the real ordering would already be broken.
        let low = value.saturating_to_u128();
        assert_ne!(low, u128::MAX, "height {height} fell into u128 saturation");
        prev = Some((height, value));
    }
    // The boundary behaviour above 2^128: the report saturates, the ordering does not.
    let big = U256::pow2(130);
    assert_eq!(big.saturating_to_u128(), u128::MAX);
    for &(_, _, cw) in BTC_CHAINWORK {
        assert!(
            big > u256_from_hex_be(cw),
            "2^130 is larger than every real chainwork"
        );
    }
}

// ============ 2. A real ETH header chain ============
/// (number, hash, parentHash, stateRoot, receiptsRoot) - Blockchair
/// The `decoded_raw_block` fields of `/ethereum/raw/block/{height}`.
const ETH_HEADERS: &[(u64, &str, &str, &str, &str)] = &[
    (
        20_000_000,
        "0xd24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f276183",
        "0xb390d63aac03bbef75de888d16bd56b91c9291c2a7e38d36ac24731351522bd1",
        "0x68421c2c599dc31396a09772a073fb421c4bd25ef1462914ef13e5dfa2d31c23",
        "0xb39f9f7a13a342751bd2c575eca303e224393d4e11d715866b114b7e824da608",
    ),
    (
        20_000_001,
        "0x5beb18a1746bc0f84fc98648fa2a76a182eef5be01aa27be289e3e84af6b6228",
        "0xd24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f276183",
        "0xea5f719798ed17ea9ac3a1ac4eb31f7426846c25de51e4c06423b1c14ad57d9f",
        "0x1a1bb7a9602aabcab27d6ff389e596b298500b2db0f70576d1ff7eff24a468ce",
    ),
    (
        20_000_002,
        "0x6de7477c53fabb6a4abf60e0731d95decca4528a892da13ecd416ac44e26f90b",
        "0x5beb18a1746bc0f84fc98648fa2a76a182eef5be01aa27be289e3e84af6b6228",
        "0x1e920a7dcf7a9686e3e61a69728b2fdc8754603b9541419005a692b34f0697a3",
        "0x0840aa33324ae35d62cc762e0d388ec9c39725e3d1a1e50e90887ac375c3a23e",
    ),
    (
        20_000_003,
        "0x0dc1297885ed49be3e406ca84925d5d4897ff40712485a26701449b0bc47c463",
        "0x6de7477c53fabb6a4abf60e0731d95decca4528a892da13ecd416ac44e26f90b",
        "0x8ce8ee8324d0431fd55adcda09778b59eb37f3a43cd14a2dbcba08863fbb6c27",
        "0xbddb85a4c0857a6bf5b491ae29c73235301bae39ee8341c50f96e8d0be9ba49d",
    ),
];

fn hex32(s: &str) -> [u8; 32] {
    let b = hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("hex32 input");
    assert_eq!(b.len(), 32, "32 bytes expected");
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    a
}

fn eth_header(row: &(u64, &str, &str, &str, &str)) -> EthHeader {
    EthHeader {
        parent_hash: hex32(row.2),
        number: row.0,
        state_root: hex32(row.3),
        receipts_root: hex32(row.4),
        hash: hex32(row.1),
    }
}

/// The fixture has to be a chain in itself: `parent_hash` points at the previous
/// hash and the number increases by one.
#[test]
fn real_ethereum_headers_form_a_linked_chain() {
    let rows: Vec<EthHeader> = ETH_HEADERS.iter().map(eth_header).collect();
    for w in rows.windows(2) {
        assert_eq!(w[1].parent_hash, w[0].hash, "the parent link broke");
        assert_eq!(w[1].number, w[0].number + 1, "the height skipped");
    }
}

/// The N-confirmation finality logic works on real chain blocks; insufficient
/// confirmations and a broken chain are refused fail-closed.
#[test]
fn real_ethereum_verify_chain_accepts_and_refuses() {
    let rows: Vec<EthHeader> = ETH_HEADERS.iter().map(eth_header).collect();
    assert!(
        verify_chain(&rows[0], &rows[1..4], 3).is_ok(),
        "3 real confirmations have to be accepted"
    );
    assert_eq!(
        verify_chain(&rows[0], &rows[1..4], 4),
        Err(HeaderError::InsufficientConfirmations),
        "4 onay gerekince red"
    );
    let mut broken = rows[1].clone();
    broken.parent_hash = [0u8; 32];
    assert_eq!(
        verify_chain(&rows[0], &[broken], 1),
        Err(HeaderError::ChainBroken),
        "a broken chain has to be refused"
    );
}

// ============ 3. Replay locks, with real transaction hashes ============
/// Real transaction hashes (the Blockchair `/multi/` endpoint, 2026-08-14),
/// used as the payload preimage, so the message ids derive from real chain
/// material. The scenario addresses are test placeholders.
const REPLAY_PAYLOAD_TXHASHES: &[&str] = &[
    "75cb3d596dacc93afa54e6e3c32519b6fb1df4867b74a14f628d56356131991a",
    "f38f4b36477743a87d348a5900bceaee13bdd49fba5bfd776cc9353cf7ce9bbb",
    "d6370f3638a92504c029414746eda58559fb4faac1f9d4cd764f61b46c302f80",
    "b569036b50137b375a680c6a8934a5193a2f1bed45b6767a7b073b943122a04f",
    "d1ff07ccaebacec1b9ec9aff3f2faa1221147f3ae1d1d1fcc5004da57d62b51c",
    "570c063ed8c47d7697c3cec2ed51aa17786e1de54bb36983ce0c618973806c93",
    "0x627b87a1be2cadcc4f47e8323efc6753978d099ee1cf496f643ba26ce7dcd1de",
    "69f3c0898c3cbd72652afacc5dffbbd4a8bb5526fc4a4c33b3bd810e06ebf568",
];
/// The real block heights of these transactions (`block_id`).
const REPLAY_SOURCE_HEIGHTS: &[u64] = &[
    962_384, 962_380, 962_374, 962_372, 962_364, 962_361, 25_749_980, 962_355,
];

#[test]
fn replay_store_uses_real_tx_derived_ids_and_refuses_double_apply() {
    let sender = Address::from([0xAA; 32]);
    let recipient = Address::from([0x17; 32]);

    let mut store = ReplayNonceStore::new();
    assert_eq!(store.next_nonce(1, 2, sender), 0);
    assert_eq!(store.next_nonce(1, 2, sender), 1);
    assert_eq!(
        store.next_nonce(1, 2, recipient),
        0,
        "a separate counter per sender"
    );

    let params = |i: usize| CrossDomainMessageParams {
        source_domain: 1, // ethereum
        target_domain: 2, // bitcoin
        source_height: REPLAY_SOURCE_HEIGHTS[i % REPLAY_SOURCE_HEIGHTS.len()],
        event_index: u32::try_from(i).unwrap(),
        nonce: i as u64,
        sender,
        recipient,
        payload_hash: hex32(REPLAY_PAYLOAD_TXHASHES[i]),
        kind: MessageKind::BridgeLock,
        expiry_height: REPLAY_SOURCE_HEIGHTS[i % REPLAY_SOURCE_HEIGHTS.len()].saturating_add(1000),
    };

    let msg0 = CrossDomainMessage::new(params(0));
    assert!(
        msg0.verify_id(),
        "an id derived from a real payload has to verify"
    );
    assert!(store.mark_processed_at(msg0.message_id, 0).is_ok());
    assert_eq!(
        store.mark_processed_at(msg0.message_id, 0),
        Err("Cross-domain message was already processed".to_string()),
        "applying it twice has to be refused - a replay"
    );
    assert!(store.is_processed(&msg0.message_id));
    assert_eq!(store.processed_count(), 1);

    let msg1 = CrossDomainMessage::new(params(1));
    assert_ne!(
        msg0.message_id, msg1.message_id,
        "a different real payload gives a different id"
    );
    assert!(store.mark_processed_at(msg1.message_id, 0).is_ok());
    assert_eq!(store.processed_count(), 2);
}

// ============ 4. Bitcoin merkle root vectors ============
/// (the block height, the expected `merkle_root`, the txid list).
/// The root comes from Blockchair's `merkle_root` field and equals an
/// independent local computation; the evidence is in the generation notes of
/// this file, 2026-08-14.
const MERKLE_VECTORS: &[(u32, &str, &[&str])] = &[
    (
        0,
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        &["4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"],
    ),
    (
        1,
        "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",
        &["0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"],
    ),
    (
        2,
        "9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5",
        &["9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5"],
    ),
    (
        3,
        "999e1c837c76a1b7fbb7e57baf87b309960f5ffefbf2a9b95dd890602272f644",
        &["999e1c837c76a1b7fbb7e57baf87b309960f5ffefbf2a9b95dd890602272f644"],
    ),
    (
        170,
        "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff",
        &[
            "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082",
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
        ],
    ),
    (
        470_000,
        "fa824d55bcb2242d5ec3a553392da96c1a664509673f5d0043950d0e957ce42f",
        &[
            "5e3fa917f856f38e36176640fa50e67d553460fd9566f3d000b490ce9c2117b0",
            "b7b423d9b00c6b3c7c64f972552e1aa35050db9ae574ad16070f3617270083e7",
            "8b8ca838997f3252f5177129b6876e4458148f17768290996f0d49d51f9db98e",
            "f2fe6db5c83bf17a5594d0c597397d36382a33acfc1dfaa45e24377c0d103165",
            "99b3bde44481477ac331fab2c42a78a77a403e61a67b78475b1961cfa422b4b8",
            "f8852458256a6698b6ac218c3b3e3e5ddef9581ddd66eb4a03b3d1e2e8541f7e",
            "6bc3a45de16e3ff66962d6bb13580d849936fa68903c46890e20083834b86f9a",
            "3ae0a20f0a6189723a5054bffc8625121de6c2933e0e51a91d3831d3fa5062ae",
            "7733fd01bf8f7bbbb9aca23849be6a3333f86c9ca3a50d464c02d1ddcd0d7b33",
            "62ec9c1d295239770043571f79ee619e32f1526ab8a3f6ecb6ef3f07b52a16fc",
            "7b5cc9a54791dccd2e960565fc810eb61b503733cee452b3b13cfdb565ccfe18",
            "04773d6883a9a3973ea73f5d7bb46153c296ff999da60edac4c30df709dc1e26",
            "d316b43f73f687294ec91d532e48c65589b477b769ce0a5e856c7d368305b7f6",
            "c988c82f19fd5756b96d4641c3e8134a16094c8549935f0215af449fa4c2a360",
            "890a9f83ccd67547c6d5b06c9ca370a47b6414fd77c351e5d6d9869013c5541a",
            "96a9d47f32b85bd8c13de3cf0cc48f2565d2f0ef5287618367081883cf818ad2",
            "09e92479b26543dd542268ea26d428e222535d60498acd92a1ee612bd4d62f85",
            "549b391e79c5290a71bb808fc4ef54e73dbe33c926cb29b0a074fd2f5a920daf",
            "4792ebd20229e18ab02f584091b93d64a5dc087d1ec4087480b64354a379c00e",
            "85025408033bc17ff36cfda61123116da8e9625cacf74d91c408403cf94b4fb1",
            "9a447649897768369396888a75e17e0521d70e660deee790334f2b583ef008d0",
            "8a09f7aff5cab0afcf8912a95f551fdf460c8569eb4814ef734281e979e2ca1c",
            "4c430b91c1f7b853edc425092bcb0d18c47535984403fcefc1a0c68442db9201",
            "d3472bb42d9ba24de196d05d3f33da18c012acd22a25cffc619fade5539f1f01",
            "b702ed885513d33c3f42279f9e209b6c3db8eace57b1a690e3fa48dd25fbcc1b",
            "f440a8c24240e54168390aaf64fcd592d4ad71ebeb81b6060988570e4f9a5389",
            "240265f66220ae599aa267f0f2c83744587aba3e56490323ce6bea8bb34dbf65",
            "a231700b097c0a1e86522f93afee4549db626a01e8a3e409783b4e68b4c8c16e",
            "e641d41f5a20af391a215c8a406fa6364af0f11ffe9bee135f0dd8dbf8c5151f",
            "dceeea3e97037548e8485d9cb92c6743a8b47cc3a678cb9a3131f7d592963d7f",
            "b7acafc8246f7a025b044642f88f2795e26c2b099dc3b5757dc1f50ebfd6d6aa",
            "247d1735bcc797d448829e281d12364bcab213556824c3489ddb35c4ff93a9ac",
            "d06cebe914cc1ec0ee7f9744816b725f31b42d76d423e0649cb63fe77e542a83",
            "b645a2fce0be1ce9b048e00d8e658ea2064a03a2814b56d1215afeacd34fa724",
            "3adebbc28e367dfa23fa7f874737910422e403f8c911408ae5c7dd229a6246bf",
            "666bfea6dd3bcc72e0a215201311f1a63abda05fd3226dd440069b1e505bff79",
            "63d301bc232a92c0aa5d334f4b19c3ffe1dc09742e1cc4968109899391a77317",
            "13966b698b5efec42194afed97cbd508b2875e84abed4bbde25e191a92530dd0",
            "257030870b655b9105e26f35b102b94cf04bea6028fbf11aa495cf29abaf1b59",
            "620134b52c1ea7e344352d949444e5060e43ba4b8cb30f48feaf2bd4d5281161",
            "7340b0442b6e444b3383965ee0536f6b9a0f1e9d84538ed46227f1103c857b4c",
            "e17f2581bc297507638a7d7945bc00cad62890795ec0002f9c3764263178633a",
            "cf852db2542f1aa336492e1148625f7b24a39c078e4f8c7e2a189bca2deab0cc",
            "859ef42ec6235777a7df5916cbe0bd0581b889e3d84eededb0ab126ec790096d",
            "a270a6cb4c5b9357298b6be8a2d5b277449c73c46c1cd4966ed308db545a91c5",
            "e56d3b66c0c5b1fbe0087880fb79f8dca408215ab37f6c13af8fab01785d080a",
            "7b8ea6e5c3064ab957b094c276289f00d17198b23a47557196b35c14ca848fb9",
            "c85934c160ce415622e89dce713cea67fe0aefbf2fa892d3f5a5b6cca88793c4",
            "c95354f4e7261f490773ec7a379561729b1f5df8755b7e9d5743609b498f5880",
            "348b7e8e75b534f836777821107b08a100f9e18f4f8ad369afb43dbf8dd59d57",
            "e9d4dc808a18f430b036d2600120508f2b27ccbcc76146a14b5f24687c19f9f9",
            "34bbcb8fedbafe9ae14dfddfbb00e64d4b13340cf08192ad392dbfad07b39e7d",
            "af860526d8832c7ca100cf312bbbe2bf3f9ef3f985648fe293e528b51cd85874",
            "d809cb1df2f4b37a43311a657be2aa6b99d162f54a3c02ac4e7a0b0c1d19cfa0",
            "0f77ef8525244cd45341d9ddcf9310a785e79ed6e963553b01e98620a6676d80",
            "e56a9e0f055ac664a561c21f5eaa2b0ca228259acf353b92f5d11fa0175b7081",
            "98b499102df72e621824a30dddfcfa143f013927d1a7f61fda6732e57ca907b5",
            "d6b4338b32a8dddb8daf2d2a34395297f97894e5c44b545306813fd5b96c30c1",
            "c7832a21f8c388161f5c888c39cb52aee0ca367a13fb3872e4c0087f1edb55e3",
            "7570ff09c52f355c9c57e73b229b529ea6d030d93764424174d67ec386f2b166",
            "ec6c565137d2214a0330cc0535b79860e1bc83ab3d835121b4f0b00f8984f125",
            "7105873bb31c75e21688b342a056ba94a2ef0b113d6d3e355e23c1d53502ee3d",
            "de102cfab246c562f4fa141a677c2cc2bc5eb7a40c800aa1529e0f7332c58464",
            "5e8404f5aca01b0e79405612c671c0ed25dd64841bc335a313e7346433724a01",
            "0bd2640386c38c57048663f17ef431a74a6d201752b7a80e4abf0565da409405",
            "25e8e8055e8b0b9e0c912869cb51c309b0e844221b02c8838091023bda9cf406",
            "f2ea77bde1d4ae4ffa804c1a96546e68e04d5a613a95c569d21bd85b624c560c",
            "e15984d3b3cfa268e8eeaa03493b35fcf40ff918c827394a811337f9f016e610",
            "a2c0b7f3eff864b5d6d9a4a5689d6145055b8d1ce531852fea6992e63ccde318",
            "4fff926fed6f1f8c9040ecfae8db1b18449b6d1e74fbd5f0f1dbd273b65e7d1a",
            "96a5a17c952126b2639d6ee83d63095198d94fc0d597a41a472e4325aaebcf1e",
            "26bf633dc4142af8605f12bc696a14b2d2d7db3e625a639e46dcddee44569222",
            "34721577fe8cd979b637547da0751cd8646a096c3819cd383a4a4409c2b69524",
            "9adcc24a0de77bffc2154649b424226b9372391a66a36e95f7ba372efdfa3336",
            "281a7a28df014513f4c4986b58752767c23f5bcfa50144c781fef68105f62637",
            "bcae765ee4967964a5c02c67bc5a8d964f04bacb8d48de3c6a6d6b751f9e5e38",
            "4c4c702cb863afbd10326537992959c2adad7ed829ec5dc39425b49212a7fc38",
            "97fc766424f0cd5675f67312dd5dd7960286f872c52c8c729a3871db9b7cff38",
            "26a99362a89c65169588069bf24f8e740d0d60bbc1bf571b0a38e18196e95139",
            "0726137d7df5b6f46e47f2fbe1acd46931d1139ef1c760c1c86b743375da5b39",
            "bddd8ba3b1e981cad14aaf88129617b2928045a719f300b342bc452d035eec42",
            "2d568c933d5d32067de75217190b7ae4c6815a9be0ba8de6abca930e69fe6c45",
            "34c7a7a52b33c65007eee43145516ea208719296949bdd4036734f122b8b424c",
            "70afd56a9dce966f973bacf07e6736fa2ee77c4faf26de780b89767b985c9351",
            "5282fe676ac8e79ea03d49a4a4cfeb3d153eb340f4e9d5896e541f5f039e9252",
            "4db9a3add2b30722ce3ffaf5a02851d1c703cf0ce2e2f96e83af84faf41ea15c",
            "55db1f1c2afb734b0b3146a824800754a4f1ae73715efe27f236ceaceb102365",
            "aad6a74d04dd108ecf047187501fa3c8a57746e4e6c3bf2ea4790e8b4256fa6c",
            "360cfb4d6702fbca34bb9f80d1cafe72f1abd460e4758343373b9e17e3ca3575",
            "bee05289bee2ae4db9850514a8b74e0b200c8d5ffb1e2264fc5fff873c919375",
            "8a67809d2adb0e695bc8fa1146f08fbcd1f7df32a1f541a06e80883c2796b890",
            "5cf5cfe5fef9bb3c3e936f46be11f6ee2520410ab0bf1908559b8798f9a6a194",
            "a35caa0e8f4f29097e2cd2f77bf0978325e0b5564740252303fccc23d36a3295",
            "080b202d70c70cc0c24268e03beb67f53f45d3a610b82a24a73e1decd6384197",
            "b6fade6fd9a4b7eba3615d66a4123f6a2a0482b715ff662b7a3117446e88ce98",
            "49da5d4edf39d7c24ae4e4406ab7bea585b70f3dcfb37963e90c42935bd2739f",
            "15abf49b58d19ff1e8565834c9eb47989c60ec3e6dbf6ca9fb988d9fbf75d1a9",
            "1c1828c29c263d840137ca983eb2d000468bca32892fab502ecc6bcf2be136af",
            "2e1c91090803de88ce0ad24eca17baa0b4b34f0772422270d287a0962d8402b3",
            "e145ad2f4586f86d4ad2cc2ae2a3fee39dbf303b3636c86b29e2a9556082cfb7",
            "9869ab7e86cef40e293733bb70d9d059a7d85e1a25dc79e93782c1c3d87aeec5",
            "f960e5b46f85f6d818b6ab04a42fd59e044ad2dfff867d036c372cf16d57f4cb",
            "2fdc9b462f58d525eaa2e6b25906b2fb0686dcfeeca78ccc19a85e9fd9f78bd3",
            "354fcc28a32c591cc754048dd4eda3d7de37dbccf4efddc81812b0c4b73b76d6",
            "4f829b8056aa71661ce43c7ae22aab12232fe2115ebd0b3923c0599a41ef6cd7",
            "5f1dfd8dcd0c2f263fb576ecfad1f6973bffa30e07cf22ddf49cf126b9ead9da",
            "bad6451c179b6d8678c779e9c450f0d4530752c436b888ca45962b3b4f4ce7dd",
            "7fda12ead99b11dd0956d10f813b22f4ada98e619088795df1635e4073ce89e7",
            "94735f5c9c6d0cd0cc3a4870ef56c86214b1d0e6ad6a6095af6ff6b5d73eddea",
            "4b5d0e8a06d52f1f6ab54bd0e729981a47a19c17d8b2b4576224059ff66fc2ef",
            "10d880954e748118c06341a9f61a8bc3816ae0e22d1baca84172f680f03e1bf5",
            "10a2d4ad8449eba9e4f78bac582750bdf2137e2910de75d45f186dd3f3eebefb",
            "44a61161b8b79958b53457e487bf196fe2c4b7f97e4cc5c77634cac9f08b58fd",
            "8c58552a8b4f5abbc6cf3a15411db680b3ce2f0fe1f8ec9227430eae6a22c7fd",
            "321575097f7bab7b4bd6561c93871acd2742abb25a99c6055bec90b14fee8a01",
            "a4c9b844289364dc299b770223ec41381c1477d0d2951528b6d3eadf28d8b603",
            "5d76a43b273e42f031520a8664e0150f8d68c0280864a67b3815b1c7a8403b16",
            "8807e749c3cde3d291d94e283f3e7ee55d0c2f81be415ad53f6f5b901ca4701c",
            "3fb3326c49b40a45dea12173e332421b6152f9c822693e38251ca9c00287581e",
            "ded57de136fcac958f35aa9429d6956559fca5fae40622783a6fd1b3a8430922",
            "0aecbda055a3052b0f1be16dde8be4d2d476d461d29c2869e1259c5bf815082b",
            "76688fb6ab6509a03ec39c76fdb4bb7e49d7411ee2b509b66c22adab0adb152c",
            "1220ac7397437a05ac89b7c11296e199cef8e36e5a67c16c3fe5dcc5c0a2812f",
            "a78af5c486ee41e8a9cce2f325964ed2ef95c88436c7cc194ad6e42d69ae8130",
            "abc8d8cf0a65e04e98d7baab6668d4b54eecc6e7043f531247fa9e0e0b770e36",
            "ca2af891ae189125f4c453fd631fe2a709ee98c7abce3617f03e4c5e14787437",
            "ef6729798fcfca17a0f4d3b1b0810a38e4d9a5fd5e733b13453a55026ab1263e",
            "1f2f6038acd8b7c0b575cb65a2876824c929ecbeb060af7e65b9948baaced445",
            "c65de245bc3f3b6bbcec6e8d344f97da51e741ef761479a8249260bd5503814c",
            "4a865b1d61bf6e4d3184c8cb1d078722fe38b322d8e4cd70499c237adf13ff4c",
            "92fe3e4e5732ea5cc4c9f3a82aeb1ee85bd378a27351b3ec661da8988eef3c54",
            "b8b2cb60ff9efac410f050878c437d8057676c57cdec45926076d28b7cd86454",
            "d9b235700cbc9a4a1c1ff5c9477e2ecf5fbfc18903f282e14b80e2fd6389555f",
            "f81a3bb7f5de91abe9f422d72a4b3952860107dc53e58859f85d76ae3f062d61",
            "e2c35d1ef30f155d74862a5f34818a25856b9fe107369a4f132a0470bbc08571",
            "7e9689883fa0059e8c3c094f17a2f8e869647969644ca381a2e1e56c626dfc71",
            "0a888eb90f35ce6c006f318500176574e53bef37331e2ba192a8c50f5e954376",
            "a6f6cacd1c1ebac1e6b284187580ae874bea6f0c03e56f60488b421c62533278",
            "b4aaa8e2eadafc6474fd100fed63a2c9ebd0bd37236281150fc0b6d701c73d86",
            "79bc2594ea3fbda4e7194d243925403eac35df851c40fe0357d3f01ebe04f589",
            "1f7ecceb95470ec00592210a6236a25ee9033473df555ec299b7e21bdbb8b18b",
            "d3b34496fdb628ca416331096c256d833f3e512f26a859f5fcb8c7e43e9d188e",
            "f8b61490ba7f70d46f6043a873fa173eb166b007c05a982b3602ef994179268e",
            "067583c35321c171c46f61161a63a033d731bf539701235e8dbc1a74c1b64fab",
            "24580a6fff5ae07f6b405e496bee20f6f1a08217c35991c650fcdd4edd1deebc",
            "aa5ac3ae7e1a185d075f7aae3aa0de8c07b351cb2077056974f3836c2e3b50dc",
            "22fa6cdbd8d2e6543608195a28629c4a5e6d2e0e6dc311288a87a28d18cf85dc",
            "b3fbf541a572af9d39ff2f48540e9e891734bbaf439e859f3062ddf2c5c27be4",
            "431bae122b82766964f3ce06a797dcd57197230d14ea8ca794f1c179e3a2ede5",
            "6b89d1b023e96bf91bb6b5fb1254d2b881f40b709f1a04e8f8657a5c0c0555e8",
            "88923e6c940689d56582a8ba8821309d9c70ccd24ed625694c6f4e66364ca3ec",
            "16036362500ecde791b826dcc932d652d51e55501d6d50260c05ad1c100b3aee",
            "37b807ee66804de4c682b55b1bcce1da86fa9c51783c6c9fbd4d9766d31475ee",
            "f5cc444ef0e8cf57166ded039c0236cb44b2bc6099a6a1266ceee06e8466e3f4",
            "205f5cfd06bcbd46b3202b69230a63ae4d376ff1f925b9916f74c29a413173f7",
            "71d1f423fec97cabbabec5798995efd51f61447fa474879e1f6e7977057ee8fe",
            "431fa81aa145eb85a5b8392225b6dfaad83c80763da268ce2d14511791743472",
            "f760dba66ea7256cd367b6e766bcf217b6630bceec714a84264b42781e2b1b6d",
            "4184eaf2b7af0a95db20c301bb1e0bc605900e9658a50bba5a4ab82d41bba761",
            "fef32b560b26106ec265c0b3e0484ad1fc1fecf98c41b9b15d9c152e065d207f",
            "4536adb2c749f01335f6d42d61a494abe120901d6f53d58201de0da9ffc3d340",
            "1f129ffbe830badd8cdfbed3647da893c15700ad3d2aeb34b554f0d09b3d1021",
            "aec133d0b85a3ad9ae8f00657a18e2ee51da86fefb21d35059232b185b464295",
            "19aeba8cdfff075d44d247aaa65022020b152a91f0fbe5a7bd20857e21a256e4",
            "956a714c2532a4ac2a2e5140efe147ef1cfcad5d30698323b49eabd90e5bce3b",
            "87c00cdbab2de13f8b588f587b9182a61ea056d32404e2c84da398bd756e2b85",
            "c99f110845c21a5c3fa9325326cd76c5f92203ed9ce70d830f34b95b4b711d4c",
            "c78e7525129226234765f1d17809394a167a4a30b8d536f1a9de2172b90f0c11",
            "0ec37cb64d7a80f833cbf8fb3f3aefca05b29bbcbb39c098401fb94ca319f182",
            "10d3d395f760335eb6282685d0378a824570f912b9fbc9c57a311927d3304ac9",
            "9ec98bd875c3dadee05725b5acebff80922dbb7ba807698860dbe877ca916cf7",
            "b0113d5c234069fe4d535f6872a755d79ce9ef062a9b08eefb82fc3b0c8e1b17",
            "a596d7196a8f804a5683a974f9b1eefb6a22d23af99c738ce7f81ec4d4f31772",
            "281755264f0422becdb586b3179df9e93611c717b3b0ded124eebc965b6e49f6",
            "39662a252210f51e8b39d280b0489ac1aeb98ba0859062858de90eb8add80bcc",
            "f42c57f8bd62b2dc45df5ee953d8bf0f80024a18e397ca6702770c5aa2254d3c",
            "09b6bd69feae8129d9929b9abbefbe99df4a06a0e73082231a165236eec4920a",
            "22d545e2cf446c11670fe6523d918e0c5adb5da0c3765116e49d9d3cf7b8a63a",
            "750b322244d336b201ec459afc7003a1762a1378549bf1f1a4735cc1b77b673c",
            "a5666f069cdc4efa100b2e7ed80aa5014a456b250babcf2dfd9fd1fe1d912bf8",
            "99c425746280481bab899d2bed2b493bcd28e14cffddfcd2f7aeea3bf3bba658",
            "e4e1c0615f18a398f07f4209e42fc948a1be552bcf5b4d271f841935006d2cb9",
            "9a6cc8e027f8bdd8a7c64b372beb7877aa42812828e95d3b3cb80657e5a609e8",
            "d7af9c6ac0264eac0e04cb59697608999de92a04b5d9bce377df6b65f95004b0",
            "b4060273afff74de642f4d029891886bfdac4e977cc8aa4c2307abc4a62771a8",
            "f79e28145b9369a49c29781e5948e6c5cead90230452897bd0b8a23e0441f2e5",
            "2e572e354a61e8a92212e79102d91d8843896776842a14f06198667cbb646785",
            "ce0394f2a81c8210d0a100d489efa7fd9d15aac2c0b463051820e993083ab7a2",
            "22ba853b823a8b199ae7b29cb7562cb3c6189d82f28064328d440a07411f5b27",
            "493c1abd1db8d7b76c0a1cc7f13243646e965485682314dd1e28719037c4daa4",
            "9252afff7ad620f9e53905d78f9d9de2908e2a9fbd7c08c2a3c15415af38ebd7",
            "6054f03dbd3bc7fc3ef3d7abd9ce43c693971cffa933ef9291a8301cb304f880",
            "d3c3d3b0bdd43b15a1682f0db128347caed3c3ab962874c50b6d65d39f137435",
            "3a854cb3081a6ad169a3739bb4decec2cdb89b5495cab928b80ac2e08503f552",
            "f2cb2953fb4358fe67d0f901b1a911b12cd6cb70d924c8f46b4b8f4144e99f64",
            "3ea5fa894ceb41ff581868163828a82b877ebf56e13ecf42f2c8722c1182d204",
            "bfa953b353b6a2dd008d9693a0aa11ab7c48a7236b116ca9b9aec0714b3581a5",
            "65fd592022ddfe005d157f929bb4d420400585ef26f40678a57a7bb0d838c7a7",
            "e306420ce5823d4cd59d7a50dbd7ddb903275d830611046c910e705b47a0d9b6",
            "c04ab054a0e8218e896da05300088a731d79c60a982b2b046a2424f9e1f5a8fa",
            "83c954797acd5fa6a1ae435f2644224ba7639044c6a3b4ea97703cb06fdfcc43",
            "93620fcc7ce781b0d0bd21386b1a84710469dbf1f70c4ba1f95d412f8443283b",
            "cc6e038061c758484f1fedfbe860a78ebc7253e403710eca62d00b2e59ad24ed",
            "0c0fb248f81c17449a71778b61b0facf00e70c7196e81719cea2910aaf7cbf3f",
            "e6d8f5e10b7d9318e1606c5519e6f74789fa2022f49c99b85c3d9774b08994c0",
            "08bed74fb1b885d74ff8807c50b4c85a6d270834a9d6474998058eaa302209f7",
            "e31e61f75f09e65fab2d9808f67f2cc1f148c14296f924ea729a20c99b0bb186",
            "a22ca111ad88f8ef4545020e7979448acea0893c13ada766582ea558e64abf51",
            "2da2169b65c6e454cb955ff6bc72e9e5495bdf9e49ba0245806e418e1772bd75",
            "e58bb83500468ec057499ce39f3c6bb0c8415c000f2723d10248add0e906f98a",
            "0476a05de9b12e2bf89c95f0a835c5ca08cfc8cd1cf43f552490e225f3b509cb",
            "32671e73a9b3ccc3ff787410ebf8e92f1921545201734b07334fc92d020237e9",
            "12a7727a90e7e60e3fbb6bfc8bcc05fe116d661a8a9afa2d096a2931188281d1",
            "35881d529be416e3412f974b99a58ee6784d0b34140c98a388f01f7788c9446e",
            "9b7974af0733cf061bef68c0858751eec07544fabc222a7c14d35f6ccb926caf",
            "2a4245616c52f6cd17a11a8ad4953ba74946ab3632990c700068db1bc169c55b",
            "bcbb3a36d97f516274ceb93b18af617df865f1735914dd1bc31bb74ce8e8ad3e",
            "21f23ff67c757fde1e4319ccb94856cdef3968ab306c8d2997250f54ad1b898c",
            "01b821b62f1f7157449d7edcd4725db5ec4bb23456cdaf5109d3aaa3a42346bc",
            "d414cf7594f428ba083f897646e5c541777fa45be0a5f3a2ffba89c923fc3567",
            "1cc7569e1b94f2b1f7acbb32f07d487ddffd877a693874c60526115110e4a706",
            "70414cead0c84fd8570359128b39ce3f77e9e730aa6a1b16fffe45639c195b68",
            "bcb60286d3548490a9d6c9f23d3f0b688e7abf4e545c84cb243a5494640169e4",
            "6efbee89d120303f690a77cc01142d5e25eb9ed1ccd59711a51ad98116871341",
            "82f90d0ce02587cba0dcded21f7740a127fb28206ef999b5740402180dbca718",
            "31d50aa5829b4e5b6b984b19c0da4805602cd6f2cf4c6daf920c278515680554",
            "01cb56e500b834bee79ddbe0e091a1f8c86433f07d98316ed7990b0ae2aec858",
            "1df3cc061c167f3609fc775c961f0f9a7cdcc69a14a5e5d4fc458d7acc3ca4e2",
            "a2a4e78c7ecf9e5a550418aa7ddfab0211a5fd7d44ed463b3318506b9d0d5808",
            "c5600b1e3693bd71e8f3164edc57da37394b8f5e2c46b92de5c80e6565cc851b",
            "f7162ed8e571a7d5c12a096605b907445a7acb1d79af0b6ec59d5b771d4f1641",
            "fab15e7b7bc7e02b7141ddef3a27145bf6802ab75cc00a47e75f8a72557d69c5",
            "86a60fa9841c16015628cf4e7a7691fd735804367af20f4d8490d6683f5dc23f",
            "a16eb8e890926628409d2ca0d45773aa3fe8ea84f5158cf362417367c25c9899",
            "2e684830cfa02876dab783d8d7243328b75aac2c2111225e80cfc931918e065d",
            "c758568b0bcf332f4cb857dc2669839cbb7b0da62500abf318b38726a496d1d0",
            "55af87d37ae07adc747428c7cac4b479cc0053ba4ca2a0feffa91a1142b5aabe",
            "780ce0b88d6e1303b8541ec40624a36e53b1a592e0965a0d6810b28a70031491",
            "af331649527935b6e14344131343d332addc143de4195f7c86964f89b5e4d785",
            "5beb93b3b247c467fe7466e9bc61744111b60c19869b9bffa38e4f1504795a42",
            "d21d7b433bd79194e8c4ae5343934b32ba9ec4078fbf1c802ae3ee72f1abc4bd",
            "7d8a4779bf0762b09861471a3b24557ba01731a122d2ea2c5f63d746bf6fa52c",
            "d7a2efaccfcb8d27ac160f36a62682e7aa6e0f511afa98d729f077e90a69bbc8",
            "85737eee6c256dba382a94b8f6b77d08e4dcd3799d9fbe18a2b38cced6d310b5",
            "7c4caa1a543f1ed146600319a402f58b697a9cfa41d9d32239f69b47c85b7df3",
            "0ee13ec85101e323f824a994836b5d083ae8828d82e6cf25482cb4364b6c26fa",
            "90241215533fee5250206139d1ced9db132c5b6a83c7e99dbb3c25e72c37bc69",
            "19f2bc7f4e49627b4b60ba8c27fae60ddcae6e60bb7911b84c5ba25eca8cb152",
            "989ad1d72f41b0a39052777853190e07a2d2c21dce0b6da98f87eb5cc121d5e6",
            "72a176f035a269b173bfbfca55b26df4afaa548c65c31c655083117f417ac902",
            "fd8e2b11655270e90d1f1184660409e14cae6b3fd200df59f5e772bc8b49cd26",
            "b89b527e180c142799b10a75388ce8d629e0961bcb6acdd7b7081e6ed63dcc3f",
            "462f106768022e70c950d42a277684f2ed687526a5a74b79c21bf4df35c12a62",
            "6c0f2b94ab3e543f1a94a39dd65e8684ef0a8eb9f58454b23b8ffb42152598ab",
            "236e2ab6c7b91cf3c3ecb1b26155aa7f78b2c70802497fe232f1041fcfeac6c3",
            "121a38b578a5ac94f90ce26840bb3d8f6227b0ed24fa9c2afea7135f7cd28655",
            "9a59b5c6b7235db749903f2afc96fe97750381081fe4bf03b79e5fc6633b9494",
            "1d5e334902287bbda0e2ceb3f5d4520be1082de83d8a72f7a7e59ad48bfd39ff",
            "419063afcede15e5ff98e2827133243a6161f9f92415ec54e04683c6d8ad17c7",
            "ba77fa6c062553234e13fc05d09a05c0fb7b696af432fbcdc37d64e2b25d41aa",
            "2792d18de437d7d8141f5727ccacff3070c383ea79cf6430c9a130fc6c26d0fc",
            "e78d11dae8a55c11047b7fe0d3be52d06805a7e4231658614a2b32d9052ad308",
            "c6b1237485627b42d3066c49ee1889e314b4edbbc39e09ea9125f5facaa90370",
            "b80afa51732586854eca518972d400c9089dbe6af2348d318b2dfdbfa24860c5",
            "c525f4fac1e39522622e1ce895c395237373903cec1f1d69eb213142d58e611a",
            "2e8296911c57da6f57e3aba4d0d51637c3b1eec236b7625d95c6e972a84c5fe7",
            "f1b22620cf8a269932cd769ed2fbed22b24c4a3d67a042fa672be8b36fb4b1e8",
            "a95c21cb2da07dbdf5f75f93931fc00ee2c58bad24b0717aaf878d220b00bc65",
            "74323a64e163a7846bd9e6b52bf385d062fe3041d751e05a0cc43b422dc483da",
            "907994cfb7128b3ccd6aeb2e20771a0e28ee890a41c4f050eaa2e7f55248814b",
            "094b158a8047a12491209c51015736f234630d7228150bd2fedfaf6284ead670",
            "47b5afabe826afe6bc65e17d8530f6f7043ec21c7e5d33f7b7e00c8bf9ca340a",
            "98be0de1bc27fdfcd8f9ffec28e093028959cf80fcc1fb2dd969f4f987808949",
            "3ac620f69e5e29c7e9a3799518156fdc2e0c8b1702cd9c3fe78617054c051490",
            "9d084bb94b9365c09c547e2579fb0027d3944a421847bff6e8547c5ecfdcc653",
            "f8c861ab971ecc703e16cc7bf3794931bb60a8cf46fbd028efd602fa609be7d0",
            "9c95b3ccb2dbbd4aaf7416010988486aa946143074d3b75da0d7ddec690ae6c8",
            "aea309248ea6bcbf92a46783e4eb28b7b4291c25cfac03fb38853a3f61dbd43f",
            "9e07480ecb08af4cb3827784433b16b0b90c9db249c8b84306fa01f7d2db9f2b",
            "9d1486b578fbbf76e36ddcf10a37bc75252e9a5bfb4607a47d5c399d32b1f37c",
            "0a2a93a45671dda8b778c00729b534ad4563cdc770802c4c96b7e2448bac9e29",
            "13d7af188707ce2d9bb6807438d98e0f304dc19cecbf0c68c73718be18b31b1c",
            "5ec5ed41b6cc287545937e3d7d88770c6a36a1a63fc9b9fa5b08a0184dc3c7a4",
            "1da78bc63b1416c506aa32d367b90e23b7eb89016c51c1ff8bca3a6da70ae23b",
            "154a335d7501a0df8258cd97b75724368d77dd48ac84a7cb0754651b4127506c",
            "defe52427e58713ad0e854a3377c90a81f0a38b8fe051e997877c3260953605b",
            "acd7aace6f30da94a8f7db5e1af931dc8df47150c3051a5860299333b5c1ed8c",
            "e61b92e9d85eadb04a527c2ec6c8cab1f318d56a32d0d99394b7abcd1d417774",
            "14dc831ef4fc7de580323e308f5469bd744b2b966912610bd0c02002cd059b76",
            "d0e33f5ae2f7f672ff5187d3442eb39c20450aee5f4168623f059b3601e8a47e",
            "743ff2e458391f3b2ab685ae3bec50cd262a7b8992f2dc844ebda126e639e126",
            "41b0bf0233785b303249520f6ee3d4711d18782ee134960711477727321fac1e",
            "26490e28f58b0060eb729d68ddd87e73c2960827e6963e2e847ac788a859cec4",
            "3e412f54002755d8f4bb34eec262fb86698916c4bd6b01987aaad91a4d063c1d",
            "55cb00aefdcaf19d191f8bbf429301b396e5ad1fcb87df697c5f25058d65d29e",
            "ffe01b291c4af698258297b41a394945720148f416a85a6ead0caa2aa9ad0142",
            "2ddd0f4ee073f32a3a348fc2f1e2c84be01be28b40bf64e529ee9656168e0649",
            "a87cc8ab6f74f0c74d7b5302201ca9ede8168430567755b98337caefe1e3e396",
            "c5ef36340f29ece4b9e537584d6ab22fe8fc62fed97d5c9496de6338b70412ce",
            "7afbdf120e0676a5a0fa9f8f86e81fe7a58492f93a7e2e7af321f1edf1d587e7",
            "738592360f986d4f8a1abddad409a0d290097a889344f87de61bbea8e3bca10e",
            "b7f2a3a1e7fd051a98f4e6226717e7f3557191d56153308c5c9e03b821294415",
            "e5bf9654b1ac266ade6f1bae5891d31160bb36ad7f9793d2c33cfed02b907464",
            "e65000a3dddddbf1d4d4c833caa038b9f614478044659bb8dd841f9d293bf146",
            "5ac20a45e80a1bd385ad992c3ff0063d3aaf13143161184980159929eff55e38",
            "7f170b762085483e04cfc13037970b2a0335ea8c68b66606e7f8e2323cf67b79",
            "9b1ca43c5ea22d776e158e94061b96008f77c56cdfb5a349339d59756d71a491",
            "a13110b63428c79606b0a4c0fb3f2e0b8e083304ea1167a302f96213d7383511",
            "80234a80e5ae32334946b72c4fdaf532216db3d29e4bdba23458aa6c021c7638",
            "400b52cfdde05bf7ab0f6bb927ace5cf0b72c0f0e45c983cb22b537d3e09c807",
            "c23855f3433c5d03781a65dbc129120e23377f035985fa2bfae95c49002a506a",
            "aca48dc7530fb82a95f5ff67d5a476e00ca442d382dec450f88e96589c2ef3ad",
            "df1b8b84b47194bda0fbad216b892ca681a6a5bc7727e59f2b7040b8718424d4",
            "000af0070f849b1e7d00c064579a7f68f4d4169112b09a145a13a37198861ce1",
            "0f9f9e6c4eba45de6d01b1444f99dafbc17a9fe46999225a0ed23dcf4e593e7b",
            "28285ffa4f2c4842fca189dd4b54c290cb870f6123fb8cb5be1c8221654ee224",
            "5807c73dd369a8f6ce3b51016540f2b83895eca9e4c7db4997b0f6746cfab62b",
            "261e0f5690338d563d6cc00c229617cadf2bc963f11e9b1ee98cab39a3aa5a47",
            "77976f741132ac99e539b841054045bcdf8f1997d8c3271d1b6f65141785b404",
            "1148d144331095c90f20e709ac13287e2ecb6c6b06101f0ccdbfd065576062a4",
            "c605465acef86046209b9fd79b82c375900b108aa30b44242d6a5b975e0fac0b",
            "90b88c6a2d8874ecd3b646e865115558e58e02d741ea9d5326812f7cbc418b15",
            "3d9967881a788aea6e32cbbc780835c8931188151873a4c3bfa3b3f4169e8c22",
            "3084d001a9292194eafffd36040f5d2b332cef3fe7c6550d06c55eb4674cf43d",
            "f36a82216458d3be9288d6038edbbe683535a312bece1a8196a8227ffa094545",
            "cc5278680d67ddde0c36115058ce8143343821ec5cc8976c848bd7c8afa0d650",
            "49ffdd92348968b0d30db78373ea0b6797462815ed966513042069d243f562eb",
            "0a559235dcd72542f808eee97e8c18a4ec5979dca7048dec576fe73af29e42fa",
            "f71d087aee617f427f3f61483654ccddd5531026f8335bf1a284c555cd8956bc",
            "6cd727c09a4b0c505233e7937c2ee5f0dfdfb2c23671e841722c7f23cc83b719",
            "0912c8721815da61fa82f931233d93ba8b8c5b211b6bd298259670dd2e21d6b7",
            "7005437e9ccdb28f44256aaee1934ba8b2de2e0bd7755147a84ef218fcffd4fb",
            "69ecaa0b4f4d37da778a10f669ec0940f6f3a1017f399eef152021f7bf8d0251",
            "85655ee85b53ede823b96237ed0ef215928da531f65ac7cea34b32fd92786911",
            "5caefe2d584176fdcf26c4e20223f953090ef2427ec64f9fa416376204608761",
            "c56874b5a3be138dd1b4df7b1f7ebe641690da126712bbd50539c78485f77738",
            "afdcfd65dbe1ccf15968aa1e604dd88d80a2064290a183d2f222ff4b6f72dbf6",
            "dc1982b516baaa30f2c70b56a82c8e3b48ff017b64d97b8ac4faac7fd399027a",
            "06997360d0b9ddd0a28126d1f41763288c7753c776e9ec128773ace307d0ac35",
            "72112201ea18c5ea2b1755e0ec53e423e0ba8473f15fd5d806337e7742d4d98b",
            "8099e9b894582822dcdd2f098bcfa7df45b2cd732a2478d4b03420a6a0a42fb8",
            "8dcc823f28088c66d6646fc98411a0f6d4fa3e89b65cfd5d03397b49ad53d3dd",
            "c50d44f0d47d5cd0ec1f226e6a8dbe0328dc38011ccefa6a3e14d51d49257649",
            "9dfb1851387b00cde97a5877ffc027d63007acdf1d0f5aef78336ea17f76f5c5",
            "769a9f1cdb3abb2ee7390b9bd78a97783c5a229268ef56031ce66d725ef19d72",
            "634095f3df4ba4c6c1b5e82a0fdfe5f068be93af8b05010067ffef376ef0bba6",
            "e9be4622cc12c9ae55cba3a511b7275a31c9942bad0b6f95b50699956569f382",
            "e93d07031d41c30a87c49a0df45977dfe0b2c66e85e61a6e08e5471296239e4f",
            "41c552c10b6b10cadaf7714d388a40fbf9036b826a9cb282713130d14d846d52",
            "c4b0df38da960d185dba11364f9c0b8c63e0b5845c3d40600cb1b72895509d0a",
            "b229cf393dbeae066b6b5e8c7cfd6ae59d13739265a38a2825c01394fa39fccf",
            "7e32cec97b9e9ecb39549a89e9f6a0f2974e7c2298249d3b95faa01483ff14d4",
            "726905070244d1019a9a1db8ca684dd73ad7d9185c41232c704be5e32119c4e6",
            "150dc0d46693bcedf17e1a71efc3566a5271feb208faea1c0a2f25bfaf023d21",
            "10b4048d83bde70c0fd742eec211af7f32b3fa4cd019c4362f333a8095a70e6b",
            "09ed579a9ebc9f07b471a03eecde9445a12184d10547a0b6d9feb5e4f4be43a5",
            "11f666934341017fbb1f08767d7205d89bb2591ac30c87d4925b375e7028d5ce",
            "3f66976bf15c4c41d9462a74987363fd363be3514b6f6758c48d9eb5642b7ddd",
            "eda939fc52665ea02eee18db79edfee6946f44872a8d51384db44349dea722ac",
            "466671e6bae402aa96bd722c6836a47f48a6521c3c316fe42fde73e0d13ef48a",
            "3676b34e7d4ab3f1821f45511d3103244fa45643fce9353c8849d36bfaf5a807",
            "b894c8c42d42415519b4050dfedcd8d7cde74bda1c829dd19e90c64eb1e104ce",
            "1aa84f7d0d2ccce3578bcab86173689ea96b77b805a7fb7ff0425bf3a8dde110",
            "8cef6cb1e2cd292b604a5af6f693599eaa3ed594156a83c53b4b91461b48be6d",
            "08f82a7558634eb15a20139369a0de55c422a34ebc946bc7e3f085016145cf1b",
            "379f0235608b11da5a71154f4da286ce37cb64d53d1777488a603051d34b8fdd",
            "2e158c533329dec81ce66df0aa0c2d06d8a22a94bab1ffba2c9d909a88cbff57",
            "856a4b7eea233974f95a10a98fa68cdf3bcee6c53cfc908036c19540fd7f3a9e",
            "22c6bd59a12ef42221b344af029d0fe96e28c5ef90611e25b8e30fdfdc2bc207",
            "1362d7e71232a0d9ab804f0d23a54b58554bb355dc656dc61e229a73c24285a8",
            "4abc3433ba5e49d46bed00620b13ffa8bcf47ab4fda06fc5777fe77b5bccba2b",
            "a3513fb35b80b50e7675cba72e9a67a8b35abf338da1c1d26f204a6dad228872",
            "8c52c9300743953eac1fc1ddd60dee7b89d7ea13934bc5c38883fd2026e170b4",
            "e51620dfe47b0eef0c0f6fbb68d33d3f9cc5c5c197b4cd32c69fa69a70c03c0a",
            "c1d62361222c1049791ca07ed2c6c8646710151011f4998e8d682e70e9337608",
            "0ca60adad8dcb7ba615685416110f1445b188557a09edcf0cca9620db36379d0",
            "0164ff8d04b3da0309ef2f7527f47aa362efe69c4fee6a5b6a92391c069d8b2d",
            "188e2d5d442e7c4b5b717d2db83229200b3b17027dae646365487829755062f9",
            "c45c218fef592884cfdc29452084419ac656ebfd40633a0448c07ac477133566",
            "f1a896b3aae3cb71b89533310c362f55730d8739bca4c3476a1241d83ef1cf2f",
            "3f0499e6adfb6eab4e4a29e9df4debebb13a9c896acae5abe1ecd8704378303e",
            "12de1b2e06a623a6041dd64516a5adbb8c9f0a5123a7ec503963885bebd0e5e6",
            "49d642c8bd028b5d18edf8150bee5bad9116855b4994d320c88f1f06d0cb4956",
            "52249e89e912b8d72c70159d672bc1cf1084f8437cf3605943150e6b6b9b76c5",
            "07190a0ed035c8408781545ae9ae5b01d2ea22486dff1a1c4b89712f7b988f80",
            "7d13c5d8dd8337724adebf3c05e73d79b9c98e4c092228c4bc07471b9d7b930e",
            "720759ab818a4c1721cbf37f8a808bbbc0a3b3666ba77489f9138e1cc48f6742",
            "d4de227b9c2a60a617beaa77014335bfc0a059806dcbc62688986507ca39ec56",
            "c997b78957c4177a4700ef21edfed2231f34bcafe600ac5cf19c43a874642fdc",
            "e8384fea9c73472a0c70ce0a06ed57514351758f64c438d848729f270cf19c73",
            "1429575cfa45999761c7f2e7e25c00ffdd04bd1590dba08eaac96d2fa702a4ac",
            "104d2305eb74ad94ad02fedca5c0d177238933687d2b5c5b1a2fec5a7fffc43e",
            "bb0d25ee79c77ce02d126bc776524df5fd6d48e39e91085e28629e7925544945",
            "854a60c00600c1a207c289253a05ec25190c9ec7323f125be42d78d21711e0ad",
            "eaee75812cf41c160f2c593497253ee15a420a506b4e99a6ff56d61364357fe0",
            "01591bbc14d1d691fa81be2002ca55f6d5d6e8a4599a41ed7468e34fe0cdd188",
            "e0b5b0a8ae4b7cdb9a45d72a709e41822af960f11c8b6445cca421645aa42dda",
            "1a64762b0ba753812da96b522df9eb7f562c0d529d49282d022f05b8c6d88010",
            "f50a125633fe2e446b086baeb7ec71962d247447d497063f1c98b4645de8f77f",
            "ae02ba6c5fe1d5c384e42495cc09dfff22417d1033c44fe7f19b8ce32dc2485e",
            "403c880bfd28b4404dbc9173a2489b34b8579e0cce918ac193aa9286565b8cef",
            "a18ad6668b1f1b001fb6190c360367dc93ed87e8884fb87934ed7142d84d496b",
            "f50edfffef196684478260490e5fd0efba0d584b58068b1968c1d235e60daa09",
            "2612465e96667df7cb88e36c6638f4bf9e64e13b8a06d9669aae5b33c5e57f87",
            "f26c06f337d6cc4bd0f84d6b8c816680fca17aa29660f3ac6aa564b574db228d",
            "4f97483ba1835aa2b536523894f874d6c628da0cac3bd9e228c5a4007873528f",
            "b39d0fd991ac0ea409427b5c6a25ebcc11b8901b9b950dd3ddf0dbd738cff392",
            "8d6e6cff4b8d84545165e9d72b593c2c12857353af6fa8e4190d8730a79d6fb2",
            "2fb45fd964369de7b289bbbb35af8ca7b3d3e4f76c711b1370c64e968f2eede3",
            "d07254ee661accb56c106ca1dd9c32eb5e609bf02c2260379a2b8cea999455e7",
            "920b26398482af2c8ff1fb5f202d4583298fd3392e2042d755d824350de433fd",
            "9d68146e51920e0fbddd2ecee7f4dc2f0515fc8286ce6133188fe30e59e903ff",
            "3e03170f73b30c13149cb136bef5dc2d4ea3689bf1ad6c71688e19e6fe6bb0fc",
        ],
    ),
];

/// The Bitcoin double SHA-256, used in the merkle pairing.
fn btc_double_sha256(data: &[u8]) -> [u8; 32] {
    let mut h1 = Sha256::new();
    h1.update(data);
    let first: [u8; 32] = h1.finalize().into();
    let mut h2 = Sha256::new();
    h2.update(first);
    h2.finalize().into()
}

/// The Bitcoin merkle root: the txids arrive in hash presentation (big endian),
/// the pairing runs over little-endian bytes, and with an odd number of nodes the
/// last element is duplicated. The root is returned in hash presentation (big
/// endian).
fn btc_merkle_root(txids: &[&str]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = txids
        .iter()
        .map(|t| {
            let mut b = hex::decode(t).expect("txid hex");
            b.reverse();
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        })
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&left);
            buf.extend_from_slice(&right);
            next.push(btc_double_sha256(&buf));
            i += 2;
        }
        level = next;
    }
    let mut root = level[0];
    root.reverse();
    root
}

#[test]
fn real_bitcoin_merkle_roots_match_committed_vectors() {
    for &(height, expected, txids) in MERKLE_VECTORS {
        let got = hex::encode(btc_merkle_root(txids));
        assert_eq!(got, expected, "merkle root mismatch: block {height}");
    }
}

/// In a single-leaf block the root equals the txid, with no pairing - the
/// endianness lock.
#[test]
fn bitcoin_merkle_single_leaf_equals_txid() {
    for &(height, expected, txids) in MERKLE_VECTORS {
        if txids.len() == 1 {
            assert_eq!(expected, txids[0], "tek-yaprak blok {height}");
        }
    }
}
