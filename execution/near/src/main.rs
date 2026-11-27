//! `budlum-ee-near` Unix-domain-socket worker daemon.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::ExitCode;

use budlum_ee_near::NearWasmWorker;
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
    Err("usage: budlum-ee-near --socket <unix-socket-path>".into())
}

fn bind_worker_socket(socket_path: &std::path::Path) -> Result<UnixListener, String> {
    use std::io::ErrorKind;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    if socket_path.as_os_str().is_empty() {
        return Err("empty socket path".into());
    }
    match fs::symlink_metadata(socket_path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(format!(
                    "refusing to remove non-socket path {}",
                    socket_path.display()
                ));
            }
            fs::remove_file(socket_path).map_err(|e| {
                format!(
                    "failed to remove stale socket {}: {e}",
                    socket_path.display()
                )
            })?;
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!("failed to inspect {}: {e}", socket_path.display()));
        }
    }
    let listener = UnixListener::bind(socket_path)
        .map_err(|e| format!("failed to bind {}: {e}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to secure socket {}: {e}", socket_path.display()))?;
    Ok(listener)
}

fn main() -> ExitCode {
    let socket_path = match parse_socket_arg() {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    let listener = match bind_worker_socket(&socket_path) {
        Ok(l) => l,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(1);
        }
    };

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let mut worker = NearWasmWorker::new();
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
