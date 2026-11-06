//! Worker-side frame and deploy-validation boundaries.

use budlum_uel_abi::frame::{read_frame, write_frame, FrameError, ABI_VERSION};
use budlum_uel_abi::mock::MockEe;
use budlum_uel_abi::pb;
use budlum_uel_abi::transport::{serve_connection, TransportError};
use budlum_uel_abi::{
    BlockContext, CodeInfo, EeCall, EeFault, EeId, EeOutcome, EeQuery, EeRefusal,
    ExecutionEnvironment, HostApi, HostRead,
};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

fn envelope(id: u64, body: pb::envelope::Body) -> pb::Envelope {
    pb::Envelope {
        abi_version: ABI_VERSION,
        request_id: id,
        body: Some(body),
    }
}

struct PanicValidate(MockEe);

impl ExecutionEnvironment for PanicValidate {
    fn id(&self) -> EeId {
        self.0.id()
    }

    fn validate_deploy(&self, _code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        panic!("injected deploy-validation panic")
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        self.0.execute(ctx, call, host)
    }

    fn query(
        &self,
        ctx: &BlockContext,
        query: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        self.0.query(ctx, query, host)
    }
}

#[test]
fn uel_abi_worker_catches_deploy_validation_panics() {
    let (mut peer, worker_stream) = UnixStream::pair().expect("socket pair");
    let worker = thread::spawn(move || {
        serve_connection(worker_stream, &mut PanicValidate(MockEe::new(EeId::EVM)))
    });
    write_frame(
        &mut peer,
        &envelope(1, pb::envelope::Body::Hello(pb::Hello { ee: 1 })),
    )
    .expect("hello");
    read_frame(&mut peer).expect("hello reply");
    write_frame(
        &mut peer,
        &envelope(
            2,
            pb::envelope::Body::ValidateDeployRequest(pb::ValidateDeployRequest {
                code: b"code".to_vec(),
            }),
        ),
    )
    .expect("validate request");
    peer.set_read_timeout(Some(Duration::from_secs(1)))
        .expect("read timeout");
    let terminal = read_frame(&mut peer);
    assert!(
        matches!(terminal, Err(FrameError::Closed)),
        "a caught validation panic must close the connection, got {terminal:?}"
    );
    drop(peer);
    assert!(matches!(
        worker.join().expect("serve_connection must catch the panic"),
        Err(TransportError::Protocol(_))
    ));
}

#[test]
fn uel_abi_worker_partial_frame_has_a_deadline_after_first_byte() {
    let (mut peer, worker_stream) = UnixStream::pair().expect("socket pair");
    let worker = thread::spawn(move || serve_connection(worker_stream, &mut MockEe::new(EeId::EVM)));
    let started = Instant::now();
    // A nonzero leading byte promises a body; four zero bytes would instead
    // form a complete empty frame and test the wrong boundary.
    peer.write_all(&[1]).expect("first length byte");
    // Keep the frame incomplete past the two-second watchdog. An idle
    // connection may wait for its first byte, but a started frame may not.
    for _ in 0..60 {
        thread::sleep(Duration::from_millis(50));
        if peer.write_all(&[0]).is_err() {
            break;
        }
    }
    drop(peer);
    let result = worker.join().expect("worker");
    assert!(matches!(
        result,
        Err(TransportError::Frame(FrameError::Timeout))
    ));
    assert!(started.elapsed() < Duration::from_millis(2800));
}
