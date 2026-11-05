//! Framing contract of the worker socket (directive 8.3.2 item 6, WP-09 tests).

// A panic is how a test reports a broken invariant; the node-wide panic gate is for
// production code (the same exemption the root manifest documents for tests).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use budlum_uel_abi::frame::{
    decode_frame, encode_frame, read_frame, write_frame, FrameError, ABI_VERSION, MAX_FRAME_BYTES,
};
use budlum_uel_abi::pb;

fn hello(version: u32, request_id: u64, ee: u32) -> pb::Envelope {
    pb::Envelope {
        abi_version: version,
        request_id,
        body: Some(pb::envelope::Body::Hello(pb::Hello { ee })),
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn uel_abi_frames_are_bounded() {
    // The limit is the directive's 16 MiB.
    assert_eq!(MAX_FRAME_BYTES, 16 * 1024 * 1024);

    // A length header above the limit is refused from the header alone: the
    // reader holds only four bytes, so nothing was (or could be) allocated.
    let too_big = u32::try_from(MAX_FRAME_BYTES + 1).expect("fits u32");
    let header = too_big.to_be_bytes();
    let mut reader = &header[..];
    assert!(matches!(
        read_frame(&mut reader),
        Err(FrameError::TooLarge { len }) if len == MAX_FRAME_BYTES + 1
    ));
    assert!(matches!(
        decode_frame(&header),
        Err(FrameError::TooLarge { .. })
    ));

    // A length header that promises more than the stream holds is a truncation.
    let mut short = 100u32.to_be_bytes().to_vec();
    short.extend_from_slice(&[0u8; 10]);
    assert!(matches!(
        read_frame(&mut &short[..]),
        Err(FrameError::Truncated)
    ));
    assert!(matches!(decode_frame(&short), Err(FrameError::Truncated)));
    // Fewer than four header bytes is a truncation too.
    assert!(matches!(
        decode_frame(&[0u8, 0, 1]),
        Err(FrameError::Truncated)
    ));

    // An empty frame carries no envelope.
    let zero = 0u32.to_be_bytes();
    assert!(matches!(decode_frame(&zero), Err(FrameError::Empty)));

    // The encoder refuses a body that would not fit in a frame.
    let big = pb::Envelope {
        abi_version: ABI_VERSION,
        request_id: 1,
        body: Some(pb::envelope::Body::ValidateDeployRequest(
            pb::ValidateDeployRequest {
                code: vec![0u8; MAX_FRAME_BYTES],
            },
        )),
    };
    assert!(matches!(
        encode_frame(&big),
        Err(FrameError::TooLarge { .. })
    ));

    // The largest legal frame round-trips.
    let mut fits = pb::Envelope {
        abi_version: ABI_VERSION,
        request_id: 1,
        body: Some(pb::envelope::Body::ValidateDeployRequest(
            pb::ValidateDeployRequest { code: Vec::new() },
        )),
    };
    let overhead = prost::Message::encoded_len(&fits);
    // code adds a tag byte and a 4-byte length varint at this size.
    let code_len = MAX_FRAME_BYTES - overhead - 8;
    if let Some(pb::envelope::Body::ValidateDeployRequest(request)) = fits.body.as_mut() {
        request.code = vec![7u8; code_len];
    }
    let bytes = encode_frame(&fits).expect("a frame under the limit encodes");
    assert!(bytes.len() <= MAX_FRAME_BYTES + 4);
    let (decoded, used) = decode_frame(&bytes).expect("and decodes");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded, fits);
}

#[test]
fn uel_abi_version_mismatch_refused() {
    for wrong in [ABI_VERSION + 1, ABI_VERSION + 1000, u32::MAX] {
        let mut frame = Vec::new();
        write_frame(&mut frame, &hello(wrong, 1, 1)).expect_err("a writer refuses a wrong version");
        // A peer on another version produces such bytes anyway; build them by hand.
        let env = hello(wrong, 1, 1);
        let body = prost::Message::encode_to_vec(&env);
        let mut wire = u32::try_from(body.len())
            .expect("small")
            .to_be_bytes()
            .to_vec();
        wire.extend_from_slice(&body);
        assert!(matches!(
            read_frame(&mut &wire[..]),
            Err(FrameError::VersionMismatch { got, want }) if got == wrong && want == ABI_VERSION
        ));
        assert!(matches!(
            decode_frame(&wire),
            Err(FrameError::VersionMismatch { .. })
        ));
    }
    // No version field at all reads as version 0.
    let body = vec![0x10, 0x01];
    let mut wire = u32::try_from(body.len())
        .expect("small")
        .to_be_bytes()
        .to_vec();
    wire.extend_from_slice(&body);
    assert!(matches!(
        decode_frame(&wire),
        Err(FrameError::VersionMismatch { got: 0, .. })
    ));
    // The version is judged before the body is: a future body this version
    // cannot parse is still reported as a version mismatch.
    let mut future = vec![0x08, 0x63];
    future.extend_from_slice(&[0xFF; 12]);
    let mut wire = u32::try_from(future.len())
        .expect("small")
        .to_be_bytes()
        .to_vec();
    wire.extend_from_slice(&future);
    assert!(matches!(
        decode_frame(&wire),
        Err(FrameError::VersionMismatch { got: 0x63, .. })
    ));
}

#[test]
fn uel_abi_golden_messages() {
    // Hand-derived: field 1 varint (08 01), field 2 varint (10 07), field 10
    // length-delimited (52 02) holding Hello { ee = 1 } (08 01).
    let golden_hello = unhex("000000080801100752020801");
    assert_eq!(
        encode_frame(&hello(ABI_VERSION, 7, 1)).expect("encodes"),
        golden_hello
    );
    assert_eq!(
        decode_frame(&golden_hello).expect("decodes").0,
        hello(ABI_VERSION, 7, 1)
    );

    // Hand-derived: field 18 is tag 0x92 0x01; HostResponse { ok: {} } is 12 00.
    let ok = pb::Envelope {
        abi_version: ABI_VERSION,
        request_id: 9,
        body: Some(pb::envelope::Body::HostResponse(pb::HostResponse {
            result: Some(pb::host_response::Result::Ok(pb::HostEmpty {})),
        })),
    };
    let golden_ok = unhex("00000009080110099201021200");
    assert_eq!(encode_frame(&ok).expect("encodes"), golden_ok);
    assert_eq!(decode_frame(&golden_ok).expect("decodes").0, ok);

    // An execute request: pinned from the encoder once the two hand-derived
    // vectors above agreed with it. Any change to ee.proto that moves a byte
    // here is a wire break and must bump ABI_VERSION.
    let request = pb::Envelope {
        abi_version: ABI_VERSION,
        request_id: 0x0102,
        body: Some(pb::envelope::Body::ExecuteRequest(pb::ExecuteRequest {
            ctx: Some(pb::BlockContext {
                chain_id: 45261,
                height: 10,
                timestamp_ms: 1_700_000_000_000,
            }),
            call: Some(pb::Call {
                kind: pb::CallKind::Call as i32,
                caller: Some(pb::Identity {
                    ee: 1,
                    id: vec![0xAA; 20],
                }),
                target: Some(pb::Identity {
                    ee: 1,
                    id: vec![0xBB; 20],
                }),
                value: Some(pb::Amount { hi: 0, lo: 5 }),
                input: vec![1, 2, 3],
                gas_limit: 21_000,
                depth: 0,
                tx_hash: vec![0xCC; 32],
            }),
        })),
    };
    let golden_request = unhex(GOLDEN_EXECUTE_REQUEST);
    assert_eq!(encode_frame(&request).expect("encodes"), golden_request);
    assert_eq!(decode_frame(&golden_request).expect("decodes").0, request);
}

const GOLDEN_EXECUTE_REQUEST: &str =
    "0000007d08011082026a760a0d08cde102100a1880d095ffbc3112650801121808011214aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1a1808011214bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb220210052a030102033088a4014220cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
