//! Regression locks for the request budget and connection poisoning.
//!
//! These peers deliberately misbehave. A timeout must remain a transport error,
//! and a response that cannot be consumed must not leave a reusable connection.

// Test assertions may panic; production keeps the crate-wide panic denial.

#![cfg(unix)]

#[cfg(test)]
mod suite {
    use budlum_uel_abi::EeId;
    use budlum_uel_abi::frame::{ABI_VERSION, read_frame, write_frame};
    use budlum_uel_abi::mock::MockEe;
    use budlum_uel_abi::pb;
    use budlum_uel_abi::transport::{EeClient, TransportError, serve_connection};
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    static SOCKET_SEQ: AtomicU32 = AtomicU32::new(0);

    fn spawn_peer(peer: impl FnOnce(UnixStream) + Send + 'static) -> (PathBuf, JoinHandle<()>) {
        let path = std::env::temp_dir().join(format!(
            "uel-deadline-{}-{}.sock",
            std::process::id(),
            SOCKET_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            peer(stream);
        });
        (path, worker)
    }

    fn hello(id: u64) -> pb::Envelope {
        pb::Envelope {
            abi_version: ABI_VERSION,
            request_id: id,
            body: Some(pb::envelope::Body::Hello(pb::Hello { ee: 1 })),
        }
    }

    fn handshake(stream: &mut UnixStream) -> u64 {
        let request = read_frame(stream).expect("hello request");
        write_frame(stream, &hello(request.request_id)).expect("hello response");
        read_frame(stream).expect("deployment request").request_id
    }

    fn assert_dribble_times_out(before_request: bool) {
        let (path, worker) = spawn_peer(move |mut stream| {
            let request = read_frame(&mut stream).expect("hello");
            if !before_request {
                write_frame(&mut stream, &hello(request.request_id)).expect("hello reply");
                read_frame(&mut stream).expect("deployment request");
            }
            // A valid length bound, followed by a byte well inside the old
            // per-read timeout. The frame never finishes. Socket timeouts alone
            // reset on every byte and therefore do not enforce a request budget.
            stream.write_all(&64u32.to_be_bytes()).expect("header");
            stream.write_all(&[0x08]).expect("first byte");
            for _ in 0..12 {
                thread::sleep(Duration::from_millis(40));
                if stream.write_all(&[0]).is_err() {
                    return;
                }
            }
        });
        let mut client = EeClient::new(&path, EeId::EVM).with_timeout(Duration::from_millis(200));
        let started = Instant::now();
        let error = client
            .validate_deploy(b"code")
            .expect_err("an incomplete frame is not a deployment verdict");
        assert_eq!(error, TransportError::Timeout);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!client.is_connected());
        drop(client);
        worker.join().expect("peer");
        std::fs::remove_file(path).expect("remove socket");
    }

    #[test]
    fn uel_abi_handshake_dribble_uses_an_absolute_deadline() {
        assert_dribble_times_out(true);
    }

    #[test]
    fn uel_abi_response_dribble_uses_an_absolute_deadline() {
        assert_dribble_times_out(false);
    }

    #[test]
    fn uel_abi_reconnect_handshake_shares_the_request_budget() {
        let (path, worker) = spawn_peer(move |mut stream| {
            let request = read_frame(&mut stream).expect("hello");
            thread::sleep(Duration::from_millis(400));
            if write_frame(&mut stream, &hello(request.request_id)).is_err() {
                return;
            }
            // Stay connected after reading the deployment: an early peer close
            // races the client's deadline and tests EOF instead of budget sharing.
            let _ = read_frame(&mut stream);
            let mut byte = [0u8];
            let _ = stream.read(&mut byte);
        });
        let mut client = EeClient::new(&path, EeId::EVM).with_timeout(Duration::from_millis(500));
        let started = Instant::now();
        assert_eq!(
            client.validate_deploy(b"code").expect_err("silent worker"),
            TransportError::Timeout
        );
        // Without a shared budget this waits approximately 400 + 500 ms. The
        // bound leaves room for scheduler delay without accepting that reset.
        assert!(started.elapsed() < Duration::from_millis(800));
        assert!(!client.is_connected());
        drop(client);
        worker.join().expect("peer");
        std::fs::remove_file(path).expect("remove socket");
    }

    #[test]
    fn uel_abi_unrepresentable_deadline_does_not_panic() {
        let (path, worker) = spawn_peer(move |stream| {
            let _ = serve_connection(stream, &mut MockEe::new(EeId::EVM));
        });
        let mut client = EeClient::new(&path, EeId::EVM);
        client
            .validate_deploy(b"first")
            .expect("transport")
            .expect("code");
        client = client.with_timeout(Duration::MAX);
        assert_eq!(
            client
                .validate_deploy(b"second")
                .expect_err("invalid budget"),
            TransportError::Timeout
        );
        assert!(!client.is_connected());
        drop(client);
        worker.join().expect("peer");
        std::fs::remove_file(path).expect("remove socket");
    }

    #[test]
    fn uel_abi_unusable_final_response_poisons_the_connection() {
        for case in 0..3 {
            let (path, worker) = spawn_peer(move |mut stream| {
                let id = handshake(&mut stream);
                let result = match case {
                    0 => None,
                    1 => Some(pb::validate_deploy_response::Result::Info(pb::CodeInfo {
                        code_hash: vec![0; 31],
                        abi_tag: "invalid/1".into(),
                    })),
                    _ => {
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
                        .expect("wrong response type");
                        return;
                    }
                };
                write_frame(
                    &mut stream,
                    &pb::Envelope {
                        abi_version: ABI_VERSION,
                        request_id: id,
                        body: Some(pb::envelope::Body::ValidateDeployResponse(
                            pb::ValidateDeployResponse { result },
                        )),
                    },
                )
                .expect("deployment response");
            });
            let mut client = EeClient::new(&path, EeId::EVM);
            assert!(client.validate_deploy(b"code").is_err(), "case {case}");
            assert!(
                !client.is_connected(),
                "case {case} retained a poisoned stream"
            );
            drop(client);
            worker.join().expect("peer");
            std::fs::remove_file(path).expect("remove socket");
        }
    }
}
