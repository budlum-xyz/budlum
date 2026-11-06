//! `budlum-ee-svm` Unix-domain-socket worker daemon (`WP-31`).

#![forbid(unsafe_code)]

use std::env;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

use budlum_ee_svm::SvmWorker;
use budlum_uel_abi::transport::{serve_connection, ServeEnd};

fn parse_socket_arg() -> Result<PathBuf, String> {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--socket" {
            if let Some(val) = args.next() {
                return Ok(PathBuf::from(val));
            }
            return Err("missing path after --socket".into());
        }
        if let Some(rest) = arg.strip_prefix("--socket=") {
            if !rest.is_empty() {
                return Ok(PathBuf::from(rest));
            }
        }
    }
    Err("usage: budlum-ee-svm --socket <unix-socket-path>".into())
}

fn main() -> ExitCode {
    let sock_path = match parse_socket_arg() {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("budlum-ee-svm: {msg}");
            return ExitCode::from(2);
        }
    };

    let stream = match UnixStream::connect(&sock_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "budlum-ee-svm: connect {} failed: {err}",
                sock_path.display()
            );
            return ExitCode::from(1);
        }
    };

    let mut worker = SvmWorker;
    match serve_connection(stream, &mut worker) {
        Ok(ServeEnd::Disconnected | ServeEnd::Shutdown) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("budlum-ee-svm: transport error: {err}");
            ExitCode::from(1)
        }
    }
}
