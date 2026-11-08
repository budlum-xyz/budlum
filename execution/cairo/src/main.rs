//! `budlum-ee-cairo` Unix-domain-socket worker daemon.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::ExitCode;

use budlum_ee_cairo::CairoWorker;
use budlum_uel_abi::transport::{serve_connection, ServeEnd};

fn parse_socket_arg() -> Result<PathBuf, String> {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--socket" {
            return args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "missing value after --socket".to_string());
        }
        if let Some(val) = arg.strip_prefix("--socket=") {
            if !val.is_empty() {
                return Ok(PathBuf::from(val));
            }
        }
    }
    Err("usage: budlum-ee-cairo --socket <unix-socket-path>".into())
}

fn main() -> ExitCode {
    let socket_path = match parse_socket_arg() {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }
    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(err) => {
            eprintln!("failed to bind {}: {err}", socket_path.display());
            return ExitCode::from(1);
        }
    };

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let mut worker = CairoWorker::new();
                if matches!(serve_connection(stream, &mut worker), Ok(ServeEnd::Faulted)) {
                    return ExitCode::from(75);
                }
            }
            Err(err) => {
                eprintln!("accept error: {err}");
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}
