//! A failed host callback is a transport failure, not an engine revert.
//!
//! MockEe deliberately converts ordinary HostError values into reverts. These
//! tests ensure that a broken or malformed coordinator reply cannot enter that
//! deterministic path and produce an execution receipt.

// Assertions may panic in this test target. Production retains the crate-wide
// unwrap/expect denial; this is not an allowance for worker or coordinator code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use budlum_uel_abi::frame::{read_frame, write_frame, FrameError, ABI_VERSION};
use budlum_uel_abi::mock::{op, MockEe};
use budlum_uel_abi::pb;
use budlum_uel_abi::transport::{serve_connection, ServeEnd, TransportError, WATCHDOG};
use budlum_uel_abi::{BlockContext, BudAmount, EeCall, EeCallKind, EeId, EeIdentity};
use std::os::unix::net::UnixStream;
use std::thread::{self, JoinHandle};

fn envelope(id: u64, body: pb::envelope::Body) -> pb::Envelope {
    pb::Envelope {
        abi_version: ABI_VERSION,
        request_id: id,
        body: Some(body),
    }
}

fn start_read_request() -> (UnixStream, JoinHandle<Result<ServeEnd, TransportError>>) {
    let (mut peer, worker_stream) = UnixStream::pair().expect("socket pair");
    let worker =
        thread::spawn(move || serve_connection(worker_stream, &mut MockEe::new(EeId::EVM)));
    write_frame(
        &mut peer,
        &envelope(1, pb::envelope::Body::Hello(pb::Hello { ee: 1 })),
    )
    .expect("hello");
    assert!(matches!(
        read_frame(&mut peer).expect("hello reply").body,
        Some(pb::envelope::Body::Hello(_))
    ));
    let identity = EeIdentity::new(EeId::EVM, vec![1; 20]).expect("identity");
    let call = EeCall {
        kind: EeCallKind::Call,
        caller: identity.clone(),
        target: identity,
        value: BudAmount(0),
        input: vec![op::READ, 7],
        gas_limit: 100_000,
        depth: 0,
        tx_hash: [9; 32],
    };
    let ctx = BlockContext {
        chain_id: 45261,
        height: 1,
        timestamp_ms: 1,
    };
    write_frame(
        &mut peer,
        &envelope(
            2,
            pb::envelope::Body::ExecuteRequest(pb::ExecuteRequest {
                ctx: Some((&ctx).into()),
                call: Some((&call).into()),
            }),
        ),
    )
    .expect("execute");
    let host = read_frame(&mut peer).expect("host request");
    assert_eq!(host.request_id, 2);
    assert!(matches!(
        host.body,
        Some(pb::envelope::Body::HostRequest(pb::HostRequest {
            op: Some(pb::host_request::Op::Read(_))
        }))
    ));
    (peer, worker)
}

fn assert_no_receipt(mut peer: UnixStream, worker: JoinHandle<Result<ServeEnd, TransportError>>) {
    peer.set_read_timeout(Some(WATCHDOG + std::time::Duration::from_secs(1)))
        .expect("read timeout");
    let terminal = read_frame(&mut peer);
    // The old code either waits indefinitely for the coordinator or turns
    // the failure into a deterministic MockEe revert. Neither is a receipt.
    assert!(
        matches!(terminal, Err(FrameError::Closed)),
        "broken host callback produced {terminal:?}"
    );
    drop(peer);
    assert!(worker.join().expect("worker").is_err());
}

#[test]
fn uel_abi_worker_host_reply_has_a_watchdog() {
    let (peer, worker) = start_read_request();
    assert_no_receipt(peer, worker);
}

#[test]
fn uel_abi_worker_rejects_malformed_host_replies() {
    for case in 0..3 {
        let (mut peer, worker) = start_read_request();
        let result = match case {
            0 => None,
            1 => Some(pb::host_response::Result::Balance(pb::Amount {
                hi: 0,
                lo: 1,
            })),
            _ => Some(pb::host_response::Result::Error(pb::HostError {
                code: 99,
                message: "undefined error code".into(),
            })),
        };
        write_frame(
            &mut peer,
            &envelope(
                2,
                pb::envelope::Body::HostResponse(pb::HostResponse { result }),
            ),
        )
        .expect("malformed host reply");
        assert_no_receipt(peer, worker);
    }
}

#[test]
fn uel_abi_valid_host_refusal_remains_deterministic() {
    let (mut peer, worker) = start_read_request();
    write_frame(
        &mut peer,
        &envelope(
            2,
            pb::envelope::Body::HostResponse(pb::HostResponse {
                result: Some(pb::host_response::Result::Error(pb::HostError {
                    code: pb::HostErrorCode::Denied as i32,
                    message: "policy refusal".into(),
                })),
            }),
        ),
    )
    .expect("valid host refusal");
    let reply = read_frame(&mut peer).expect("execution receipt");
    let Some(pb::envelope::Body::ExecuteResponse(response)) = reply.body else {
        panic!("expected an execution receipt");
    };
    let Some(pb::execute_response::Result::Outcome(outcome)) = response.result else {
        panic!("expected a deterministic outcome");
    };
    assert_eq!(outcome.status, pb::OutcomeStatus::Revert as i32);
    drop(peer);
    assert_eq!(
        worker.join().expect("worker").expect("clean end"),
        ServeEnd::Closed
    );
}
