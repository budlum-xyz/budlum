//! The coordinator <-> worker round trip over a real Unix socket, with the mock
//! environment on the worker side.

// A panic is how a test reports a broken invariant; the node-wide panic gate is for
// production code (the same exemption the root manifest documents for tests).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use budlum_uel_abi::frame::{read_frame, write_frame, ABI_VERSION};
use budlum_uel_abi::mock::{op, MemoryHost, MockEe, MOCK_NAMESPACE};
use budlum_uel_abi::pb;
use budlum_uel_abi::transport::{
    panic_digest, serve_connection, EeClient, ServeEnd, TransportError,
};
use budlum_uel_abi::{
    BlockContext, BudAmount, EeCall, EeCallKind, EeId, EeIdentity, EeQuery, HostRead, Namespace,
    OutcomeStatus, RefusalCode, UniversalResult, WireError,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

static SOCKET_SEQ: AtomicU32 = AtomicU32::new(0);

fn socket_path() -> PathBuf {
    let n = SOCKET_SEQ.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("uel-abi-{}-{n}.sock", std::process::id()))
}

/// A worker that builds a fresh engine per connection, as a restarted worker
/// process does, and keeps accepting after a fault.
fn spawn_worker(factory: impl Fn() -> MockEe + Send + 'static) -> PathBuf {
    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let mut ee = factory();
            let _ = serve_connection(stream, &mut ee);
        }
    });
    path
}

fn ctx() -> BlockContext {
    BlockContext {
        chain_id: 45261,
        height: 7,
        timestamp_ms: 1_700_000_000_000,
    }
}

fn who(byte: u8) -> EeIdentity {
    EeIdentity::new(EeId::EVM, vec![byte; 20]).expect("identity")
}

fn call(input: Vec<u8>) -> EeCall {
    EeCall {
        kind: EeCallKind::Call,
        caller: who(1),
        target: who(2),
        value: BudAmount(0),
        input,
        gas_limit: 1_000_000,
        depth: 0,
        tx_hash: [9u8; 32],
    }
}

fn ns() -> Namespace {
    Namespace::new(MOCK_NAMESPACE).expect("ns")
}

#[test]
fn uel_abi_mock_round_trip() {
    let path = spawn_worker(|| MockEe::new(EeId::EVM));
    let mut client = EeClient::new(&path, EeId::EVM);
    let mut host = MemoryHost::new(10_000_000);

    // Deploy validation: info, then the two refusals.
    let info = client.validate_deploy(b"code").unwrap().unwrap();
    assert_eq!(info.abi_tag, "mock/1");
    let refusal = client.validate_deploy(b"").unwrap().unwrap_err();
    assert_eq!(refusal.code, RefusalCode::InvalidCode);
    let big = vec![0u8; budlum_uel_abi::mock::MOCK_MAX_CODE_BYTES + 1];
    assert_eq!(
        client.validate_deploy(&big).unwrap().unwrap_err().code,
        RefusalCode::TooLarge
    );

    // Echo.
    let out = client
        .execute(&ctx(), &call(vec![op::ECHO, 5, 6]), &mut host)
        .unwrap()
        .unwrap();
    assert_eq!(out.status, OutcomeStatus::Success);
    assert_eq!(out.output, vec![5, 6]);

    // A write reaches the coordinator's host, and a read comes back from it.
    let out = client
        .execute(&ctx(), &call(vec![op::WRITE, 3, 0xAA, 0xBB]), &mut host)
        .unwrap()
        .unwrap();
    assert_eq!(out.status, OutcomeStatus::Success);
    assert_eq!(host.read(&ns(), &[3]).unwrap(), Some(vec![0xAA, 0xBB]));
    let out = client
        .execute(&ctx(), &call(vec![op::READ, 3]), &mut host)
        .unwrap()
        .unwrap();
    assert_eq!(out.output, vec![0xAA, 0xBB]);

    // Gas is charged on the coordinator, and base gas is part of gas_used.
    assert!(host.gas_charged <= 10_000_000);
    let out = client
        .execute(&ctx(), &call(vec![op::REVERT, 1]), &mut host)
        .unwrap()
        .unwrap();
    assert_eq!(out.status, OutcomeStatus::Revert);
    assert_eq!(out.output, vec![1]);

    // Logs and transfers.
    client
        .execute(&ctx(), &call(vec![op::LOG, 4, 1, 2]), &mut host)
        .unwrap()
        .unwrap();
    assert_eq!(host.logs.len(), 1);
    assert_eq!(host.logs[0].topics, vec![vec![4u8]]);
    assert_eq!(host.logs[0].data, vec![1, 2]);
    host.balances.insert(who(1), 500);
    let mut transfer = call(vec![op::TRANSFER]);
    transfer.value = BudAmount(300);
    let out = client
        .execute(&ctx(), &transfer, &mut host)
        .unwrap()
        .unwrap();
    assert_eq!(out.status, OutcomeStatus::Success);
    assert_eq!(host.balances[&who(1)], 200);
    assert_eq!(host.balances[&who(2)], 300);
    transfer.value = BudAmount(1_000);
    let out = client
        .execute(&ctx(), &transfer, &mut host)
        .unwrap()
        .unwrap();
    assert_eq!(out.status, OutcomeStatus::Revert, "a short balance reverts");
    assert_eq!(host.balances[&who(1)], 200);

    // A universal call goes back to the coordinator and its result returns.
    let mut host = MemoryHost::new(10_000_000).with_universal_handler(Box::new(|c| {
        Ok(UniversalResult {
            success: true,
            output: [c.input.as_slice(), &[c.to_ee.0]].concat(),
            gas_used: 7,
        })
    }));
    let out = client
        .execute(&ctx(), &call(vec![op::UNIVERSAL, 3, 9, 9]), &mut host)
        .unwrap()
        .unwrap();
    assert_eq!(out.output, vec![9, 9, 3]);
    assert_eq!(out.gas_used, budlum_uel_abi::mock::MOCK_BASE_GAS + 7);
    assert_eq!(host.universal_calls.len(), 1);
    assert_eq!(host.universal_calls[0].to_ee, EeId::SVM);

    // Out of gas: the host refuses the charge and the environment reports it.
    let mut poor = MemoryHost::new(50);
    let mut input = vec![op::CHARGE];
    input.extend_from_slice(&1_000u64.to_be_bytes());
    let out = client
        .execute(&ctx(), &call(input), &mut poor)
        .unwrap()
        .unwrap();
    assert_eq!(out.status, OutcomeStatus::OutOfGas);

    // A query reads through the read-only host.
    let query = EeQuery {
        target: who(2),
        input: vec![3],
    };
    assert_eq!(
        client
            .query(&ctx(), &query, &host_with(3, &[1, 2]))
            .unwrap()
            .unwrap(),
        vec![1, 2]
    );
    let refusal = client
        .query(
            &ctx(),
            &EeQuery {
                target: who(2),
                input: vec![],
            },
            &host_with(3, &[]),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, RefusalCode::Unsupported);
}

fn host_with(key: u8, value: &[u8]) -> MemoryHost {
    let mut host = MemoryHost::new(0);
    host.state
        .insert((MOCK_NAMESPACE.to_string(), vec![key]), value.to_vec());
    host
}

#[test]
fn uel_abi_panic_becomes_a_fault_and_the_worker_restarts() {
    let first = Arc::new(AtomicU32::new(0));
    let flag = Arc::clone(&first);
    let path = spawn_worker(move || {
        // Only the first engine instance is told to panic: the restarted worker is clean.
        if flag.fetch_add(1, Ordering::SeqCst) == 0 {
            MockEe::new(EeId::EVM).with_panic_on_call(1)
        } else {
            MockEe::new(EeId::EVM)
        }
    });
    let mut client = EeClient::new(&path, EeId::EVM);
    let mut host = MemoryHost::new(1_000_000);

    let fault = client
        .execute(&ctx(), &call(vec![op::ECHO, 1]), &mut host)
        .expect("a caught panic is not a transport failure")
        .expect_err("the engine panicked");
    assert_eq!(fault.ee, EeId::EVM);
    assert_eq!(
        fault.panic_digest,
        panic_digest(EeId::EVM, "mock environment injected panic")
    );
    assert_ne!(
        fault.panic_digest,
        panic_digest(EeId::SVM, "mock environment injected panic"),
        "the digest is bound to the environment"
    );

    // The next call finds the worker restarted and reconnects by itself.
    let out = client
        .execute(&ctx(), &call(vec![op::ECHO, 2]), &mut host)
        .unwrap()
        .unwrap();
    assert_eq!(out.output, vec![2]);
    assert_eq!(
        first.load(Ordering::SeqCst),
        2,
        "a second engine instance served"
    );

    // The opcode-driven panic and the injected fault take the same road.
    let fault = client
        .execute(&ctx(), &call(vec![op::PANIC]), &mut host)
        .unwrap()
        .unwrap_err();
    assert_eq!(fault.ee, EeId::EVM);
}

#[test]
fn uel_abi_a_returned_fault_is_a_fault() {
    let path = spawn_worker(|| MockEe::new(EeId::MOVE).with_fault_on_call(1));
    let mut client = EeClient::new(&path, EeId::MOVE);
    let mut host = MemoryHost::new(1_000);
    let fault = client
        .execute(&ctx(), &call(vec![op::ECHO]), &mut host)
        .unwrap()
        .unwrap_err();
    assert_eq!(fault.ee, EeId::MOVE);
}

#[test]
fn uel_abi_watchdog_trips_the_nondeterministic_class() {
    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            // Handshake, then go silent.
            let Ok(hello) = read_frame(&mut stream) else {
                return;
            };
            let reply = pb::Envelope {
                abi_version: ABI_VERSION,
                request_id: hello.request_id,
                body: Some(pb::envelope::Body::Hello(pb::Hello { ee: 1 })),
            };
            let _ = write_frame(&mut stream, &reply);
            let _ = read_frame(&mut stream);
            thread::sleep(Duration::from_secs(5));
        }
    });
    let mut client = EeClient::new(&path, EeId::EVM).with_timeout(Duration::from_millis(300));
    let mut host = MemoryHost::new(1_000);
    let started = std::time::Instant::now();
    let error = client
        .execute(&ctx(), &call(vec![op::ECHO]), &mut host)
        .expect_err("a silent worker is a transport failure, never an outcome");
    assert_eq!(error, TransportError::Timeout);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!client.is_connected(), "a failed call drops the connection");
    assert_eq!(budlum_uel_abi::transport::WATCHDOG, Duration::from_secs(2));
}

#[test]
fn uel_abi_wrong_environment_is_refused() {
    let path = spawn_worker(|| MockEe::new(EeId::WASM));
    let mut client = EeClient::new(&path, EeId::EVM);
    let error = client.validate_deploy(b"x").unwrap_err();
    assert_eq!(
        error,
        TransportError::WrongEnvironment {
            expected: EeId::EVM,
            got: EeId::WASM
        }
    );
}

#[test]
fn uel_abi_a_worker_on_another_abi_version_is_refused() {
    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let Ok(hello) = read_frame(&mut stream) else {
                return;
            };
            // Speak version 2 by hand: the writer in this crate refuses to.
            let reply = pb::Envelope {
                abi_version: ABI_VERSION + 1,
                request_id: hello.request_id,
                body: Some(pb::envelope::Body::Hello(pb::Hello { ee: 1 })),
            };
            let body = prost::Message::encode_to_vec(&reply);
            let mut wire = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
            wire.extend_from_slice(&body);
            let _ = std::io::Write::write_all(&mut stream, &wire);
        }
    });
    let mut client = EeClient::new(&path, EeId::EVM);
    let error = client.validate_deploy(b"x").unwrap_err();
    assert!(matches!(
        error,
        TransportError::Frame(budlum_uel_abi::frame::FrameError::VersionMismatch { got, want })
            if got == ABI_VERSION + 1 && want == ABI_VERSION
    ));
    assert!(!client.is_connected());
}

#[test]
fn uel_abi_no_worker_is_a_connect_error() {
    let path = socket_path();
    let mut client = EeClient::new(&path, EeId::EVM);
    assert!(matches!(
        client.validate_deploy(b"x"),
        Err(TransportError::Connect(_))
    ));
}

#[test]
fn uel_abi_a_query_cannot_write() {
    // A fake worker sends a write host request during a query; the coordinator
    // must answer Denied and the query still completes.
    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind");
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let hello = read_frame(&mut stream).expect("hello");
        write_frame(
            &mut stream,
            &pb::Envelope {
                abi_version: ABI_VERSION,
                request_id: hello.request_id,
                body: Some(pb::envelope::Body::Hello(pb::Hello { ee: 1 })),
            },
        )
        .expect("hello reply");
        let request = read_frame(&mut stream).expect("query");
        let id = request.request_id;
        write_frame(
            &mut stream,
            &pb::Envelope {
                abi_version: ABI_VERSION,
                request_id: id,
                body: Some(pb::envelope::Body::HostRequest(pb::HostRequest {
                    op: Some(pb::host_request::Op::Write(pb::HostWrite {
                        namespace: "mock/state".into(),
                        key: vec![1],
                        has_value: true,
                        value: vec![2],
                    })),
                })),
            },
        )
        .expect("host request");
        let answer = read_frame(&mut stream).expect("host response");
        tx.send(answer).expect("send");
        write_frame(
            &mut stream,
            &pb::Envelope {
                abi_version: ABI_VERSION,
                request_id: id,
                body: Some(pb::envelope::Body::QueryResponse(pb::QueryResponse {
                    result: Some(pb::query_response::Result::Output(vec![1])),
                })),
            },
        )
        .expect("query response");
    });
    let mut client = EeClient::new(&path, EeId::EVM);
    let host = MemoryHost::new(0);
    let output = client
        .query(
            &ctx(),
            &EeQuery {
                target: who(2),
                input: vec![1],
            },
            &host,
        )
        .unwrap()
        .unwrap();
    assert_eq!(output, vec![1]);
    let answer = rx.recv().expect("answer");
    let Some(pb::envelope::Body::HostResponse(response)) = answer.body else {
        panic!("not a host response");
    };
    let Some(pb::host_response::Result::Error(error)) = response.result else {
        panic!("a write in a query was not refused");
    };
    assert_eq!(error.code, pb::HostErrorCode::Denied as i32);
    assert!(host.state.is_empty());
}

#[test]
fn uel_abi_wire_values_are_bounded() {
    assert_eq!(Namespace::new(""), Err(WireError::BadNamespace));
    assert_eq!(Namespace::new("Upper"), Err(WireError::BadNamespace));
    assert_eq!(
        Namespace::new(&"a".repeat(65)),
        Err(WireError::BadNamespace)
    );
    assert!(Namespace::new("uel/alias").is_ok());
    assert!(EeIdentity::new(EeId::EVM, vec![0; 65]).is_err());
    assert!(EeIdentity::new(EeId::EVM, vec![0; 64]).is_ok());

    // From the wire: a bad tx hash length, an undefined enum, too many topics, an id past a byte.
    let mut bad_call: pb::Call = (&call(vec![])).into();
    bad_call.tx_hash = vec![0; 31];
    assert!(EeCall::try_from(bad_call).is_err());
    let mut bad_kind: pb::Call = (&call(vec![])).into();
    bad_kind.kind = 99;
    assert!(matches!(
        EeCall::try_from(bad_kind),
        Err(WireError::BadEnum { .. })
    ));
    let log = pb::Log {
        emitter: Some((&who(1)).into()),
        topics: vec![vec![0]; 9],
        data: vec![],
    };
    assert!(budlum_uel_abi::EeLog::try_from(log).is_err());
    let id = pb::Identity {
        ee: 300,
        id: vec![],
    };
    assert_eq!(EeIdentity::try_from(id), Err(WireError::BadEeId));
    let missing = pb::Call::default();
    assert!(matches!(
        EeCall::try_from(missing),
        Err(WireError::BadEnum { .. } | WireError::Missing { .. })
    ));
    let _: Option<UnixStream> = None;
    let _ = ServeEnd::Closed;
}
