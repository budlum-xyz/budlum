// Fuzz target: blockchain serialization roundtrip.
//
// This fuzz target exercises the serialization functions in the `blockchain`
// module. The purpose: feed adversarial bytes to the decoders the node
// actually runs (bincode over `Block` and `BlockHeader`, the same encoding
// whose bytes are hashed into block hashes and state roots) and check that
// nothing panics. Whatever decodes must roundtrip: re-encode, re-decode,
// compare.
//
// Running it manually (not in CI):
//   cargo +nightly install cargo-fuzz
//   cargo +nightly fuzz run fuzz_blockchain_serialize
//
// Acceptance criteria:
// - the build is clean (cargo check, nightly)
// - the target is fuzzable (libfuzzer starts)

#![no_main]

use budlum_core::core::block::{Block, BlockHeader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Block: adversarial decode, then a roundtrip on whatever survives.
    if let Ok(block) = bincode::deserialize::<Block>(data) {
        let encoded = bincode::serialize(&block).expect("a block that decoded must re-encode");
        let decoded: Block = bincode::deserialize(&encoded).expect("re-encoded bytes must decode");
        assert_eq!(block, decoded, "block roundtrip must be lossless");
        // The header derived from a decoded block decodes too.
        let header = BlockHeader::from_block(&block);
        let header_bytes = bincode::serialize(&header).expect("a derived header must encode");
        let header_back: BlockHeader =
            bincode::deserialize(&header_bytes).expect("header roundtrip decodes");
        assert_eq!(header, header_back, "header roundtrip must be lossless");
    }

    // Header on its own: it is stored and transmitted independently.
    if let Ok(header) = bincode::deserialize::<BlockHeader>(data) {
        let encoded = bincode::serialize(&header).expect("a header that decoded must re-encode");
        let decoded: BlockHeader =
            bincode::deserialize(&encoded).expect("re-encoded bytes must decode");
        assert_eq!(header, decoded, "header roundtrip must be lossless");
    }
});
