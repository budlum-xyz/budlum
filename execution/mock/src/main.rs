//! Standalone Unix-socket worker binary serving [`budlum_uel_abi::mock::MockEe`].
//!
//! Usage: `budlum-ee-mock <socket-path> [ee-id-u8]`

use budlum_uel_abi::EeId;
use std::process::ExitCode;

#[cfg(unix)]
fn run_unix() -> ExitCode {
    use budlum_uel_abi::mock::MockEe;
    use budlum_uel_abi::transport::{serve_connection, ServeEnd};
    use std::os::unix::net::UnixListener;

    let mut args = std::env::args().skip(1);
    let Some(socket_path) = args.next() else {
        eprintln!("usage: budlum-ee-mock <socket-path> [ee-id-u8]");
        return ExitCode::from(2);
    };
    let ee_byte = match args.next() {
        Some(raw) => match raw.parse::<u8>() {
            Ok(id) => id,
            Err(err) => {
                eprintln!("invalid ee-id `{raw}`: {err}");
                return ExitCode::from(2);
            }
        },
        None => EeId::EVM.0,
    };

    let _ = std::fs::remove_file(&socket_path);
    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(err) => {
            eprintln!("failed to bind UEL worker socket `{socket_path}`: {err}");
            return ExitCode::from(1);
        }
    };

    let mut env = MockEe::new(EeId(ee_byte));
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(err) => {
                eprintln!("accept failed on `{socket_path}`: {err}");
                return ExitCode::from(1);
            }
        };
        match serve_connection(stream, &mut env) {
            Ok(ServeEnd::Closed) => {}
            Ok(ServeEnd::Faulted) => {
                // Exit cleanly after reporting an engine panic so the supervisor
                // spawns a fresh worker process with untainted state.
                return ExitCode::SUCCESS;
            }
            Err(err) => {
                eprintln!("transport error on `{socket_path}`: {err}");
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}

#[cfg(not(unix))]
fn run_unix() -> ExitCode {
    eprintln!("budlum-ee-mock requires Unix domain sockets (`cfg(unix)`)");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    run_unix()
}
