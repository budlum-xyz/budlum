//! The Unix-domain-socket transport between the coordinator and a worker
//! .
//!
//! Two roles. [`EeClient`] is the coordinator's side: it connects, handshakes,
//! sends a request and, while the worker executes, answers the worker's host
//! requests from a [`HostApi`]. [`serve_connection`] is the worker's side.
//!
//! The error classes follow the UEL error model. What an environment decides
//! (outcome, refusal, caught panic) is `Ok`. Everything this module can fail at
//! (a dead socket, a missed deadline, a protocol violation) is a
//! [`TransportError`]: the non-deterministic class, on which the coordinator
//! must not write anything.

use crate::frame::{read_frame, write_frame, FrameError, ABI_VERSION};
use crate::host::{ExecutionEnvironment, HostApi, HostRead};
use crate::pb;
use crate::types::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeFault, EeId, EeIdentity, EeLog, EeOutcome,
    EeQuery, EeRefusal, HostError, Namespace, OutOfGas, RefusalCode, UniversalCall,
    UniversalResult, WireError,
};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// The wall-clock guard on one request. It only ever trips
/// the non-deterministic class; gas is what ends a call deterministically.
pub const WATCHDOG: Duration = Duration::from_secs(2);

/// A transport failure: the non-deterministic error class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Framing failed (includes version mismatch and oversize frames).
    Frame(FrameError),
    /// A message did not satisfy the type it should become.
    Wire(WireError),
    /// The peer broke the protocol.
    Protocol(String),
    /// The worker serves another environment than the one expected.
    WrongEnvironment {
        /// What the coordinator expected.
        expected: EeId,
        /// What the worker said it is.
        got: EeId,
    },
    /// The socket could not be opened.
    Connect(io::ErrorKind),
    /// The deadline passed.
    Timeout,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "{e}"),
            Self::Wire(e) => write!(f, "{e}"),
            Self::Protocol(m) => write!(f, "protocol violation: {m}"),
            Self::WrongEnvironment { expected, got } => write!(
                f,
                "worker serves environment {} but {} was expected",
                got.0, expected.0
            ),
            Self::Connect(kind) => write!(f, "cannot connect: {kind}"),
            Self::Timeout => write!(f, "worker did not answer in time"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<FrameError> for TransportError {
    fn from(error: FrameError) -> Self {
        match error {
            FrameError::Timeout => Self::Timeout,
            other => Self::Frame(other),
        }
    }
}

impl From<WireError> for TransportError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

fn envelope(request_id: u64, body: pb::envelope::Body) -> pb::Envelope {
    pb::Envelope {
        abi_version: ABI_VERSION,
        request_id,
        body: Some(body),
    }
}

/// Socket timeouts apply to each system call, not to a whole frame. Refresh
/// the timeout from one absolute deadline before every read and write so a
/// peer cannot extend the budget by delivering one byte at a time.
struct DeadlineIo<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl DeadlineIo<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "UEL transport deadline expired",
            ));
        }
        Ok(remaining)
    }
}

impl Read for DeadlineIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buf)
    }
}

impl Write for DeadlineIo<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}

/// The digest an environment reports for a caught panic. Domain-separated and
/// bound to the environment, so two environments panicking with one message
/// still differ.
#[must_use]
pub fn panic_digest(ee: EeId, message: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_UEL_PANIC_V1");
    hasher.update([ee.0]);
    hasher.update(message.as_bytes());
    hasher.finalize().into()
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic".to_string()
    }
}

// ---------------------------------------------------------------------------
// Coordinator side
// ---------------------------------------------------------------------------

/// What the coordinator lets a worker do while a request is in flight.
enum HostAccess<'a> {
    Full(&'a mut dyn HostApi),
    ReadOnly(&'a dyn HostRead),
}

fn host_error(error: &HostError) -> pb::HostResponse {
    pb::HostResponse {
        result: Some(pb::host_response::Result::Error(error.into())),
    }
}

fn host_ok() -> pb::HostResponse {
    pb::HostResponse {
        result: Some(pb::host_response::Result::Ok(pb::HostEmpty {})),
    }
}

fn identity_arg(value: Option<pb::Identity>) -> Result<EeIdentity, HostError> {
    value
        .ok_or_else(|| HostError::Invalid("missing identity".into()))?
        .try_into()
        .map_err(|e: WireError| HostError::Invalid(e.to_string()))
}

fn answer_host_request(access: &mut HostAccess<'_>, request: pb::HostRequest) -> pb::HostResponse {
    use pb::host_request::Op;
    let Some(op) = request.op else {
        return host_error(&HostError::Invalid("empty host request".into()));
    };
    let denied = || host_error(&HostError::Denied("not allowed in a read-only call".into()));
    let result: Result<pb::HostResponse, HostError> = match op {
        Op::Read(read) => Namespace::new(&read.namespace)
            .map_err(|e| HostError::Invalid(e.to_string()))
            .and_then(|ns| {
                let reader: &dyn HostRead = match access {
                    HostAccess::Full(host) => &**host,
                    HostAccess::ReadOnly(host) => *host,
                };
                reader.read(&ns, &read.key)
            })
            .map(|value| pb::HostResponse {
                result: Some(pb::host_response::Result::Read(pb::HostReadResult {
                    has_value: value.is_some(),
                    value: value.unwrap_or_default(),
                })),
            }),
        Op::BudBalance(who) => identity_arg(Some(who)).and_then(|who| {
            let reader: &dyn HostRead = match access {
                HostAccess::Full(host) => &**host,
                HostAccess::ReadOnly(host) => *host,
            };
            reader.bud_balance(&who).map(|amount| pb::HostResponse {
                result: Some(pb::host_response::Result::Balance(amount.into())),
            })
        }),
        other => {
            let HostAccess::Full(host) = access else {
                return denied();
            };
            match other {
                Op::Write(write) => Namespace::new(&write.namespace)
                    .map_err(|e| HostError::Invalid(e.to_string()))
                    .and_then(|ns| {
                        let value = write.has_value.then_some(write.value.as_slice());
                        host.write(&ns, &write.key, value)
                    })
                    .map(|()| host_ok()),
                Op::UniversalCall(call) => UniversalCall::try_from(call)
                    .map_err(|e| HostError::Invalid(e.to_string()))
                    .and_then(|call| host.universal_call(call))
                    .map(|result| pb::HostResponse {
                        result: Some(pb::host_response::Result::Universal((&result).into())),
                    }),
                Op::EmitLog(log) => EeLog::try_from(log)
                    .map_err(|e| HostError::Invalid(e.to_string()))
                    .and_then(|log| host.emit_log(log))
                    .map(|()| host_ok()),
                Op::Charge(charge) => host
                    .charge(charge.bgu)
                    .map_err(|OutOfGas| HostError::OutOfGas)
                    .map(|()| host_ok()),
                Op::BudTransfer(transfer) => {
                    let parts = identity_arg(transfer.from)
                        .and_then(|from| identity_arg(transfer.to).map(|to| (from, to)));
                    let amount = transfer.attos.map(BudAmount::from);
                    match (parts, amount) {
                        (Ok((from, to)), Some(amount)) => {
                            host.bud_transfer(&from, &to, amount.0).map(|()| host_ok())
                        }
                        (Err(e), _) => Err(e),
                        (_, None) => Err(HostError::Invalid("missing amount".into())),
                    }
                }
                Op::Read(_) | Op::BudBalance(_) => Err(HostError::Invalid("unreachable".into())),
            }
        }
    };
    result.unwrap_or_else(|e| host_error(&e))
}

/// The coordinator's handle on one worker.
///
/// The connection is opened lazily and re-opened after any failure, so a
/// restarted worker is picked up by the next call. A failed call is never
/// retried here: the UEL error model puts the three-attempt retry above this layer,
/// at the block.
pub struct EeClient {
    socket: PathBuf,
    expected: EeId,
    timeout: Duration,
    stream: Option<UnixStream>,
    next_request: u64,
}

impl EeClient {
    /// A client for the worker at `socket`, which must serve `expected`.
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>, expected: EeId) -> Self {
        Self {
            socket: socket.into(),
            expected,
            timeout: WATCHDOG,
            stream: None,
            next_request: 1,
        }
    }

    /// Replaces the total transport budget (the default is [`WATCHDOG`]).
    /// The budget includes a reconnect handshake, request writes, host
    /// callbacks and response reads. It cannot preempt arbitrary host code.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Whether a connection is currently open.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    fn take_request_id(&mut self) -> u64 {
        let id = self.next_request;
        self.next_request = self.next_request.wrapping_add(1);
        id
    }

    fn connect(&mut self, deadline: Instant) -> Result<(), TransportError> {
        let mut stream =
            UnixStream::connect(&self.socket).map_err(|e| TransportError::Connect(e.kind()))?;
        let id = self.take_request_id();
        write_frame(
            &mut DeadlineIo {
                stream: &mut stream,
                deadline,
            },
            &envelope(
                id,
                pb::envelope::Body::Hello(pb::Hello {
                    ee: u32::from(self.expected.0),
                }),
            ),
        )?;
        let reply = read_frame(&mut DeadlineIo {
            stream: &mut stream,
            deadline,
        })?;
        if reply.request_id != id {
            return Err(TransportError::Protocol(format!(
                "handshake response for request {} while waiting for {id}",
                reply.request_id
            )));
        }
        let Some(pb::envelope::Body::Hello(hello)) = reply.body else {
            return Err(TransportError::Protocol(
                "handshake reply is not a hello".into(),
            ));
        };
        let got = u8::try_from(hello.ee)
            .map(EeId)
            .map_err(|_| TransportError::Wire(WireError::BadEeId))?;
        if got != self.expected {
            return Err(TransportError::WrongEnvironment {
                expected: self.expected,
                got,
            });
        }
        self.stream = Some(stream);
        Ok(())
    }

    /// Starts one request. An unrepresentable Instant is a timeout, not a
    /// panic in the node. Checked arithmetic also handles Duration::MAX.
    fn begin_request(
        &mut self,
        body: pb::envelope::Body,
    ) -> Result<(u64, Instant), TransportError> {
        let deadline = match Instant::now().checked_add(self.timeout) {
            Some(deadline) => deadline,
            None => {
                self.stream = None;
                return Err(TransportError::Timeout);
            }
        };
        let id = self.open_request(body, deadline)?;
        Ok((id, deadline))
    }

    /// Sends one request frame, connecting if needed. A failed write may have
    /// delivered a prefix or even the complete frame, so it is never retried.
    fn open_request(
        &mut self,
        body: pb::envelope::Body,
        deadline: Instant,
    ) -> Result<u64, TransportError> {
        if self.stream.is_none() {
            self.connect(deadline)?;
        }
        let id = self.take_request_id();
        let result = match self.stream.as_mut() {
            Some(stream) => write_frame(
                &mut DeadlineIo { stream, deadline },
                &envelope(id, body),
            ),
            None => return Err(TransportError::Protocol("no connection".into())),
        };
        if let Err(error) = result {
            self.stream = None;
            return Err(error.into());
        }
        Ok(id)
    }

    /// A malformed final response is as untrustworthy as a failed read.
    /// Drop the connection even when framing and request correlation passed.
    fn finish<T>(
        &mut self,
        result: Result<T, TransportError>,
    ) -> Result<T, TransportError> {
        if result.is_err() {
            self.stream = None;
        }
        result
    }

    /// Reads frames until the final response for `id`, answering host requests.
    fn drive(
        &mut self,
        id: u64,
        mut access: Option<HostAccess<'_>>,
        deadline: Instant,
    ) -> Result<pb::envelope::Body, TransportError> {
        let result = (|| {
            let stream = self
                .stream
                .as_mut()
                .ok_or_else(|| TransportError::Protocol("no connection".into()))?;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(TransportError::Timeout);
                }
                let frame = read_frame(&mut DeadlineIo {
                    stream: &mut *stream,
                    deadline,
                })?;
                if frame.request_id != id {
                    return Err(TransportError::Protocol(format!(
                        "response for request {} while waiting for {id}",
                        frame.request_id
                    )));
                }
                match frame.body {
                    Some(pb::envelope::Body::HostRequest(request)) => {
                        let response = match access.as_mut() {
                            Some(access) => answer_host_request(access, request),
                            None => {
                                host_error(&HostError::Denied("this request has no host".into()))
                            }
                        };
                        write_frame(
                            &mut DeadlineIo {
                                stream: &mut *stream,
                                deadline,
                            },
                            &envelope(id, pb::envelope::Body::HostResponse(response)),
                        )?;
                    }
                    Some(body) => return Ok(body),
                    None => return Err(TransportError::Protocol("empty envelope body".into())),
                }
            }
        })();
        if result.is_err() {
            // Whatever state the stream is in, it is not trustworthy now.
            self.stream = None;
        }
        result
    }

    /// Asks the worker to validate deploy code.
    ///
    /// # Errors
    ///
    /// A [`TransportError`] on any socket or protocol failure.
    pub fn validate_deploy(
        &mut self,
        code: &[u8],
    ) -> Result<Result<CodeInfo, EeRefusal>, TransportError> {
        let (id, deadline) = self.begin_request(pb::envelope::Body::ValidateDeployRequest(
            pb::ValidateDeployRequest {
                code: code.to_vec(),
            },
        ))?;
        let result = self.drive(id, None, deadline).and_then(|body| match body {
            pb::envelope::Body::ValidateDeployResponse(response) => match response.result {
                Some(pb::validate_deploy_response::Result::Info(info)) => Ok(Ok(info.try_into()?)),
                Some(pb::validate_deploy_response::Result::Refusal(refusal)) => {
                    Ok(Err(refusal.try_into()?))
                }
                None => Err(TransportError::Protocol("empty validate response".into())),
            },
            _ => Err(TransportError::Protocol(
                "unexpected response to validate".into(),
            )),
        });
        self.finish(result)
    }

    /// Runs one call on the worker, serving its host requests from `host`.
    ///
    /// The outer `Result` is the transport (non-deterministic class); the inner
    /// one is the environment's own verdict.
    ///
    /// # Errors
    ///
    /// A [`TransportError`] on any socket or protocol failure.
    pub fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<Result<EeOutcome, EeFault>, TransportError> {
        let (id, deadline) =
            self.begin_request(pb::envelope::Body::ExecuteRequest(pb::ExecuteRequest {
                ctx: Some(ctx.into()),
                call: Some(call.into()),
            }))?;
        let result = self
            .drive(id, Some(HostAccess::Full(host)), deadline)
            .and_then(|body| match body {
                pb::envelope::Body::ExecuteResponse(response) => match response.result {
                    Some(pb::execute_response::Result::Outcome(outcome)) => {
                        Ok(Ok(outcome.try_into()?))
                    }
                    Some(pb::execute_response::Result::Fault(fault)) => {
                        let fault = fault.try_into()?;
                        // Convert before dropping: even a malformed fault is
                        // an untrustworthy connection, not a reusable stream.
                        self.stream = None;
                        Ok(Err(fault))
                    }
                    None => Err(TransportError::Protocol("empty execute response".into())),
                },
                _ => Err(TransportError::Protocol(
                    "unexpected response to execute".into(),
                )),
            });
        self.finish(result)
    }

    /// Runs a read-only query on the worker.
    ///
    /// # Errors
    ///
    /// A [`TransportError`] on any socket or protocol failure.
    pub fn query(
        &mut self,
        ctx: &BlockContext,
        query: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Result<Vec<u8>, EeRefusal>, TransportError> {
        let mut request: pb::QueryRequest = query.into();
        request.ctx = Some(ctx.into());
        let (id, deadline) = self.begin_request(pb::envelope::Body::QueryRequest(request))?;
        let result = self
            .drive(id, Some(HostAccess::ReadOnly(host)), deadline)
            .and_then(|body| match body {
                pb::envelope::Body::QueryResponse(response) => match response.result {
                    Some(pb::query_response::Result::Output(output)) => Ok(Ok(output)),
                    Some(pb::query_response::Result::Refusal(refusal)) => {
                        Ok(Err(refusal.try_into()?))
                    }
                    None => Err(TransportError::Protocol("empty query response".into())),
                },
                _ => Err(TransportError::Protocol(
                    "unexpected response to query".into(),
                )),
            });
        self.finish(result)
    }
}

// ---------------------------------------------------------------------------
// Worker side
// ---------------------------------------------------------------------------

/// How a served connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeEnd {
    /// The coordinator closed the connection.
    Closed,
    /// The engine panicked and the fault was reported. The worker process
    /// restarts: its engine state is not trusted any more.
    Faulted,
}

/// The worker's proxy for the coordinator: every call is a host request over
/// the same connection, answered while the execute is in flight.
struct RemoteHost<'a> {
    stream: RefCell<&'a mut UnixStream>,
    request_id: u64,
    broken: Cell<bool>,
}

impl RemoteHost<'_> {
    fn call(&self, op: pb::host_request::Op) -> Result<pb::HostResponse, HostError> {
        if self.broken.get() {
            return Err(HostError::Denied("connection lost".into()));
        }
        let mut stream = self.stream.borrow_mut();
        let request = envelope(
            self.request_id,
            pb::envelope::Body::HostRequest(pb::HostRequest { op: Some(op) }),
        );
        let outcome = write_frame(&mut **stream, &request).and_then(|()| read_frame(&mut **stream));
        match outcome {
            Ok(frame) if frame.request_id == self.request_id => match frame.body {
                Some(pb::envelope::Body::HostResponse(response)) => Ok(response),
                _ => {
                    self.broken.set(true);
                    Err(HostError::Invalid("expected a host response".into()))
                }
            },
            _ => {
                // The coordinator treats a broken connection as the
                // non-deterministic class and discards whatever the engine
                // concludes from here, so any error value is as good as another.
                self.broken.set(true);
                Err(HostError::Denied("connection lost".into()))
            }
        }
    }

    fn expect_ok(&self, op: pb::host_request::Op) -> Result<(), HostError> {
        match self.call(op)?.result {
            Some(pb::host_response::Result::Ok(_)) => Ok(()),
            Some(pb::host_response::Result::Error(e)) => Err(e
                .try_into()
                .unwrap_or_else(|e: WireError| HostError::Invalid(e.to_string()))),
            _ => Err(HostError::Invalid("unexpected host response".into())),
        }
    }
}

impl HostRead for RemoteHost<'_> {
    fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
        let response = self.call(pb::host_request::Op::Read(pb::HostRead {
            namespace: ns.as_str().to_string(),
            key: key.to_vec(),
        }))?;
        match response.result {
            Some(pb::host_response::Result::Read(read)) => Ok(read.has_value.then_some(read.value)),
            Some(pb::host_response::Result::Error(e)) => Err(e
                .try_into()
                .unwrap_or_else(|e: WireError| HostError::Invalid(e.to_string()))),
            _ => Err(HostError::Invalid("unexpected host response".into())),
        }
    }

    fn bud_balance(&self, who: &EeIdentity) -> Result<BudAmount, HostError> {
        let response = self.call(pb::host_request::Op::BudBalance(who.into()))?;
        match response.result {
            Some(pb::host_response::Result::Balance(amount)) => Ok(amount.into()),
            Some(pb::host_response::Result::Error(e)) => Err(e
                .try_into()
                .unwrap_or_else(|e: WireError| HostError::Invalid(e.to_string()))),
            _ => Err(HostError::Invalid("unexpected host response".into())),
        }
    }
}

impl HostApi for RemoteHost<'_> {
    fn write(&mut self, ns: &Namespace, key: &[u8], value: Option<&[u8]>) -> Result<(), HostError> {
        self.expect_ok(pb::host_request::Op::Write(pb::HostWrite {
            namespace: ns.as_str().to_string(),
            key: key.to_vec(),
            has_value: value.is_some(),
            value: value.map(<[u8]>::to_vec).unwrap_or_default(),
        }))
    }

    fn universal_call(&mut self, call: UniversalCall) -> Result<UniversalResult, HostError> {
        let response = self.call(pb::host_request::Op::UniversalCall((&call).into()))?;
        match response.result {
            Some(pb::host_response::Result::Universal(result)) => Ok(result.into()),
            Some(pb::host_response::Result::Error(e)) => Err(e
                .try_into()
                .unwrap_or_else(|e: WireError| HostError::Invalid(e.to_string()))),
            _ => Err(HostError::Invalid("unexpected host response".into())),
        }
    }

    fn emit_log(&mut self, log: EeLog) -> Result<(), HostError> {
        self.expect_ok(pb::host_request::Op::EmitLog((&log).into()))
    }

    fn charge(&mut self, bgu: u64) -> Result<(), OutOfGas> {
        // Any failure to charge, including a lost connection, stops the call:
        // an engine must never run on gas it could not pay for.
        self.expect_ok(pb::host_request::Op::Charge(pb::HostCharge { bgu }))
            .map_err(|_| OutOfGas)
    }

    fn bud_transfer(
        &mut self,
        from: &EeIdentity,
        to: &EeIdentity,
        attos: u128,
    ) -> Result<(), HostError> {
        self.expect_ok(pb::host_request::Op::BudTransfer(pb::HostTransfer {
            from: Some(from.into()),
            to: Some(to.into()),
            attos: Some(BudAmount(attos).into()),
        }))
    }
}

fn refusal_response(code: RefusalCode, message: &str) -> EeRefusal {
    EeRefusal {
        code,
        message: message.to_string(),
    }
}

/// Serves one coordinator connection with `ee` until it closes or the engine
/// panics.
///
/// # Errors
///
/// A [`TransportError`] when the handshake or a frame fails, or the
/// coordinator broke the protocol. The worker then drops the connection.
pub fn serve_connection(
    mut stream: UnixStream,
    ee: &mut dyn ExecutionEnvironment,
) -> Result<ServeEnd, TransportError> {
    let hello = read_frame(&mut stream)?;
    match hello.body {
        Some(pb::envelope::Body::Hello(_)) => {}
        _ => {
            return Err(TransportError::Protocol(
                "first frame is not a hello".into(),
            ))
        }
    }
    write_frame(
        &mut stream,
        &envelope(
            hello.request_id,
            pb::envelope::Body::Hello(pb::Hello {
                ee: u32::from(ee.id().0),
            }),
        ),
    )?;

    loop {
        let frame = match read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(FrameError::Closed) => return Ok(ServeEnd::Closed),
            Err(error) => return Err(error.into()),
        };
        let id = frame.request_id;
        match frame.body {
            Some(pb::envelope::Body::ValidateDeployRequest(request)) => {
                let result = match ee.validate_deploy(&request.code) {
                    Ok(info) => pb::validate_deploy_response::Result::Info((&info).into()),
                    Err(refusal) => {
                        pb::validate_deploy_response::Result::Refusal((&refusal).into())
                    }
                };
                write_frame(
                    &mut stream,
                    &envelope(
                        id,
                        pb::envelope::Body::ValidateDeployResponse(pb::ValidateDeployResponse {
                            result: Some(result),
                        }),
                    ),
                )?;
            }
            Some(pb::envelope::Body::ExecuteRequest(request)) => {
                let ctx: BlockContext = request
                    .ctx
                    .ok_or(WireError::Missing {
                        field: "execute.ctx",
                    })?
                    .into();
                let call = EeCall::try_from(request.call.ok_or(WireError::Missing {
                    field: "execute.call",
                })?)?;
                let ee_id = ee.id();
                let (verdict, lost) = {
                    let mut host = RemoteHost {
                        stream: RefCell::new(&mut stream),
                        request_id: id,
                        broken: Cell::new(false),
                    };
                    let verdict =
                        catch_unwind(AssertUnwindSafe(|| ee.execute(&ctx, &call, &mut host)));
                    (verdict, host.broken.get())
                };
                if lost {
                    return Err(TransportError::Protocol(
                        "connection lost while a call was in flight".into(),
                    ));
                }
                let (result, faulted) = match verdict {
                    Ok(Ok(outcome)) => (
                        pb::execute_response::Result::Outcome((&outcome).into()),
                        false,
                    ),
                    Ok(Err(fault)) => (pb::execute_response::Result::Fault((&fault).into()), true),
                    Err(payload) => {
                        let fault = EeFault {
                            ee: ee_id,
                            panic_digest: panic_digest(ee_id, &panic_message(&*payload)),
                        };
                        (pb::execute_response::Result::Fault((&fault).into()), true)
                    }
                };
                write_frame(
                    &mut stream,
                    &envelope(
                        id,
                        pb::envelope::Body::ExecuteResponse(pb::ExecuteResponse {
                            result: Some(result),
                        }),
                    ),
                )?;
                if faulted {
                    return Ok(ServeEnd::Faulted);
                }
            }
            Some(pb::envelope::Body::QueryRequest(request)) => {
                let ctx: BlockContext = request
                    .ctx
                    .ok_or(WireError::Missing { field: "query.ctx" })?
                    .into();
                let query = EeQuery {
                    target: request
                        .target
                        .ok_or(WireError::Missing {
                            field: "query.target",
                        })?
                        .try_into()?,
                    input: request.input,
                };
                let (verdict, lost) = {
                    let host = RemoteHost {
                        stream: RefCell::new(&mut stream),
                        request_id: id,
                        broken: Cell::new(false),
                    };
                    let verdict = catch_unwind(AssertUnwindSafe(|| ee.query(&ctx, &query, &host)));
                    (verdict, host.broken.get())
                };
                if lost {
                    return Err(TransportError::Protocol(
                        "connection lost while a query was in flight".into(),
                    ));
                }
                let (result, faulted) = match verdict {
                    Ok(Ok(output)) => (pb::query_response::Result::Output(output), false),
                    Ok(Err(refusal)) => (
                        pb::query_response::Result::Refusal((&refusal).into()),
                        false,
                    ),
                    Err(payload) => {
                        let message = panic_message(&*payload);
                        (
                            pb::query_response::Result::Refusal(
                                (&refusal_response(
                                    RefusalCode::Unsupported,
                                    &format!(
                                        "engine panic {:02x?}",
                                        &panic_digest(ee.id(), &message)[..4]
                                    ),
                                ))
                                    .into(),
                            ),
                            true,
                        )
                    }
                };
                write_frame(
                    &mut stream,
                    &envelope(
                        id,
                        pb::envelope::Body::QueryResponse(pb::QueryResponse {
                            result: Some(result),
                        }),
                    ),
                )?;
                if faulted {
                    return Ok(ServeEnd::Faulted);
                }
            }
            _ => {
                return Err(TransportError::Protocol(
                    "a worker accepts only validate, execute and query requests".into(),
                ))
            }
        }
    }
}
