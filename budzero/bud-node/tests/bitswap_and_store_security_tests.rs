//! Security regression tests for `bud-node` Bitswap framing, response
//! validation, and `MemoryContentStore` capacity-zero enforcement.

use bud_node::bitswap::{decode_response, encode_response, BitswapResponse, BudBitswap};
use bud_node::store::{ContentId, ContentStore, MemoryContentStore, StoreError};
use std::sync::Arc;

#[test]
fn decode_response_refuses_trailing_bytes_and_not_found_with_data() {
    let payload = b"canonical-chunk".to_vec();
    let cid = ContentId::of(&payload);
    let ok_resp = BitswapResponse {
        cid,
        data: payload,
        not_found: false,
    };
    let mut wire = encode_response(&ok_resp).expect("encode");
    assert!(decode_response(&wire).is_ok());

    // Appending trailing garbage bytes must fail closed (matching decode_request).
    wire.extend_from_slice(b"TRAILING_GARBAGE");
    assert!(
        decode_response(&wire).is_err(),
        "Bitswap decode_response must refuse trailing bytes"
    );

    // Contradictory `not_found: true` carrying non-empty data must fail closed.
    let contradictory = BitswapResponse {
        cid,
        data: b"unsolicited-bytes".to_vec(),
        not_found: true,
    };
    let wire_bad = encode_response(&contradictory).expect("encode");
    assert!(
        decode_response(&wire_bad).is_err(),
        "not_found=true with non-empty data must fail closed"
    );
}

#[test]
fn handle_response_refuses_empty_data_for_non_empty_cid_and_mismatched_not_found() {
    let store = Arc::new(MemoryContentStore::new(16));
    let bitswap = BudBitswap::new(store.clone());
    let real_cid = ContentId::of(b"non-empty-chunk");

    // A peer claiming found (`not_found: false`) with empty `data` for a non-empty CID
    // MUST fail with IntegrityMismatch rather than silently returning Ok(()).
    let fake_empty = BitswapResponse {
        cid: real_cid,
        data: Vec::new(),
        not_found: false,
    };
    let err = bitswap
        .handle_response(real_cid, fake_empty)
        .expect_err("empty data with not_found=false for a non-empty CID must be rejected");
    assert!(matches!(err, StoreError::IntegrityMismatch { .. }));

    // A peer sending `not_found: true` with a DIFFERENT CID must be rejected.
    let wrong_not_found = BitswapResponse {
        cid: ContentId::of(b"other"),
        data: Vec::new(),
        not_found: true,
    };
    let err2 = bitswap
        .handle_response(real_cid, wrong_not_found)
        .expect_err("not_found response naming an unrelated CID must be rejected");
    assert!(matches!(err2, StoreError::UnexpectedCid { .. }));

    // Honest `not_found: true` matching `requested_cid` with empty data succeeds without storing.
    let honest_miss = BitswapResponse {
        cid: real_cid,
        data: Vec::new(),
        not_found: true,
    };
    assert!(bitswap.handle_response(real_cid, honest_miss).is_ok());
    assert!(!store.has(&real_cid));
}

#[test]
fn memory_content_store_zero_capacity_refuses_all_inserts() {
    let store = MemoryContentStore::new(0);
    let empty_cid = ContentId::of(b"");
    assert!(
        store.put(empty_cid, Vec::new()).is_err(),
        "zero-capacity MemoryContentStore must refuse even the empty chunk"
    );
    assert_eq!(store.len(), 0);
}
