//! The bounded reader refuses the wrong file type, and the wire decoder
//! refuses counts and payloads that exceed their ceilings.
//!
//! Six doors, two layers: `read_to_string_bounded` (size ceiling, symlink
//! targets, FIFO refusal) and the bounded bincode path behind
//! `TryFrom<ProtoTransaction>` (count hints, payload ceiling, trailing
//! bytes).

use budlum_core::core::address::Address;
use budlum_core::core::bounded_read::{read_to_string_bounded, BoundedReadError};
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::crypto::primitives::KeyPair;
use budlum_core::network::proto_conversions::pb;
use budlum_core::network::protocol::MAX_TX_SIZE;
use budlum_core::registry::{IdentityRecord, IdentityTx, MethodKind, VerificationMethod};

fn scratch(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bud_bounded_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("scratch file");
    path
}

/// A file over the ceiling is refused with the size that was actually there,
/// so the operator learns both the limit and the overshoot.
#[test]
fn a_file_over_the_ceiling_is_refused_with_the_actual_size() {
    let path = scratch("big.txt", &b"a".repeat(100));
    let err = read_to_string_bounded(&path, 10).expect_err("must refuse");
    match err {
        BoundedReadError::TooLarge {
            limit,
            actual: Some(actual),
            ..
        } => {
            assert_eq!(limit, 10);
            assert_eq!(actual, 100);
        }
        other => panic!("expected TooLarge with the actual size, got {other:?}"),
    }
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

/// A FIFO opened for reading blocks forever without a writer: the bounded
/// reader must refuse the file type BEFORE the open, not discover the
/// problem by blocking forever. The call runs on a thread so a regression
/// shows up as a failed assertion within the timeout instead of wedging
/// the suite.
#[test]
fn a_path_that_is_not_a_regular_file_is_refused_instead_of_blocking() {
    let dir = std::env::temp_dir().join(format!("bud_bounded_fifo_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let fifo = dir.join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo is available in the test environment");
    assert!(status.success());

    let (tx, rx) = std::sync::mpsc::channel();
    let fifo_clone = fifo.clone();
    std::thread::spawn(move || {
        let result = read_to_string_bounded(&fifo_clone, 64);
        let _ = tx.send(result.map(|_| ()).map_err(|e| format!("{e}")));
    });
    let outcome = rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .expect("a FIFO path must be refused promptly, not opened (which would block)");
    let message = outcome.expect_err("a FIFO is not a regular file and must never be read as one");
    assert!(!message.contains("is not there"), "{message}");

    std::fs::remove_dir_all(&dir).ok();
}

/// A symlink is followed, and its target's bytes count against the limit:
/// the ceiling is about what would be read, not about the link's own size.
#[test]
fn a_symlink_to_an_oversized_target_is_still_over_the_ceiling() {
    let dir = std::env::temp_dir().join(format!("bud_bounded_link_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let target = dir.join("target.txt");
    std::fs::write(&target, b"0123456789").expect("target file");
    let link = dir.join("link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let error =
        read_to_string_bounded(&link, 4).expect_err("the target's bytes count against the limit");
    assert!(matches!(
        error,
        BoundedReadError::TooLarge {
            actual: Some(10),
            limit: 4,
            ..
        }
    ));
    std::fs::remove_dir_all(&dir).ok();
}

/// A declared count is not a promise. Bincode hands the count hint to Serde
/// before any element is read; the guard refuses a hint the payload-derived
/// budget cannot pay for, before a visitor can reserve capacity for it.
#[test]
fn an_identity_methods_count_hint_over_the_item_budget_is_refused() {
    let keypair = KeyPair::generate().expect("generate keypair");
    let from = Address::from(keypair.public_key_bytes());
    let record = IdentityRecord::new(
        from,
        vec![VerificationMethod::new([1u8; 32], MethodKind::MlDsa87)],
        vec![],
        0,
    )
    .expect("valid one-method record");
    let mut tx = Transaction::new_with_fee(from, Address::zero(), 0, 1, 0, vec![]);
    tx.tx_type = TransactionType::Identity(IdentityTx::Register { record });
    tx.sign(&keypair);

    let mut proto_tx = pb::ProtoTransaction::from(&tx);
    let Some(pb::proto_transaction::TypePayload::Identity(payload)) =
        proto_tx.type_payload.as_mut()
    else {
        panic!("identity transaction must encode as an identity payload");
    };
    // Enum tag 0 (Register), a64-character hex subject address, then a
    // methods count of u64::MAX where the payload-derived budget can only
    // pay for what is already on the wire.
    let mut hostile = Vec::new();
    hostile.extend_from_slice(&0u32.to_le_bytes());
    hostile.extend_from_slice(&64u64.to_le_bytes());
    hostile.extend_from_slice(&b"a".repeat(64));
    hostile.extend_from_slice(&u64::MAX.to_le_bytes());
    payload.data = hostile;

    let err = Transaction::try_from(proto_tx).expect_err("a forged count must be refused");
    assert!(err.contains("sequence item count"), "{err}");
    assert!(err.contains("IdentityTx payload"), "{err}");
}

/// The byte ceiling is checked before the decoder is entered, so an
/// oversized payload is refused by size rather than by whatever the decoder
/// would make of its prefix.
#[test]
fn an_identity_payload_over_the_wire_byte_ceiling_is_refused_before_parsing() {
    let keypair = KeyPair::generate().expect("generate keypair");
    let from = Address::from(keypair.public_key_bytes());
    let record = IdentityRecord::new(
        from,
        vec![VerificationMethod::new([1u8; 32], MethodKind::MlDsa87)],
        vec![],
        0,
    )
    .expect("valid one-method record");
    let mut tx = Transaction::new_with_fee(from, Address::zero(), 0, 1, 0, vec![]);
    tx.tx_type = TransactionType::Identity(IdentityTx::Register { record });
    tx.sign(&keypair);

    let mut proto_tx = pb::ProtoTransaction::from(&tx);
    let Some(pb::proto_transaction::TypePayload::Identity(payload)) =
        proto_tx.type_payload.as_mut()
    else {
        panic!("identity transaction must encode as an identity payload");
    };
    payload.data = vec![0u8; MAX_TX_SIZE + 1];

    let err =
        Transaction::try_from(proto_tx).expect_err("a payload over the ceiling must be refused");
    assert!(err.contains("payload length"), "{err}");
    assert!(err.contains("exceeds"), "{err}");
}

/// Bytes after a complete value are ignored rather than rejected, because
/// that is what `bincode::deserialize` did on the wire this replaced: the
/// decoder stays compatible while the ceilings stay enforced.
#[test]
fn trailing_bytes_after_a_complete_identity_payload_stay_tolerated() {
    let keypair = KeyPair::generate().expect("generate keypair");
    let from = Address::from(keypair.public_key_bytes());
    let record = IdentityRecord::new(
        from,
        vec![VerificationMethod::new([1u8; 32], MethodKind::MlDsa87)],
        vec![],
        0,
    )
    .expect("valid one-method record");
    let mut tx = Transaction::new_with_fee(from, Address::zero(), 0, 1, 0, vec![]);
    tx.tx_type = TransactionType::Identity(IdentityTx::Register { record });
    tx.sign(&keypair);

    let mut proto_tx = pb::ProtoTransaction::from(&tx);
    let Some(pb::proto_transaction::TypePayload::Identity(payload)) =
        proto_tx.type_payload.as_mut()
    else {
        panic!("identity transaction must encode as an identity payload");
    };
    let clean_len = payload.data.len();
    payload.data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let hostile_len = payload.data.len();

    let back = Transaction::try_from(proto_tx).expect("trailing bytes stay tolerated");
    assert_eq!(back.tx_type, tx.tx_type);
    assert!(hostile_len > clean_len);
}
