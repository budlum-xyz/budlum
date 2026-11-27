//! `budlum-ee-wasm` Unix-domain-socket worker daemon.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use budlum_ee_wasm::WasmWorker;
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
    Err("usage: budlum-ee-wasm --socket <unix-socket-path>".into())
}

fn bind_worker_socket(socket_path: &Path) -> Result<UnixListener, String> {
    if let Ok(meta) = fs::symlink_metadata(socket_path) {
        if !meta.file_type().is_socket() {
            return Err(format!(
                "refusing to unlink non-socket path {}",
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
    let listener = UnixListener::bind(socket_path)
        .map_err(|e| format!("failed to bind {}: {e}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to chmod 0600 {}: {e}", socket_path.display()))?;
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
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let mut worker = WasmWorker;
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

#[cfg(test)]
mod tests {
    use super::bind_worker_socket;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    #[test]
    fn bind_worker_socket_sets_mode_0600_and_refuses_symlinks_or_files() {
        let dir = std::env::temp_dir().join(format!("budlum-wasm-uds-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let regular = dir.join("important.txt");
        fs::write(&regular, b"keep").expect("write");
        assert!(bind_worker_socket(&regular).is_err());
        assert_eq!(fs::read(&regular).expect("still intact"), b"keep");

        let link = dir.join("sock.lnk");
        symlink(&regular, &link).expect("symlink");
        assert!(bind_worker_socket(&link).is_err());
        assert_eq!(fs::read(&regular).expect("target intact"), b"keep");

        let sock = dir.join("worker.sock");
        let listener = bind_worker_socket(&sock).expect("bind");
        let mode = fs::symlink_metadata(&sock)
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        drop(listener);
        let _ = fs::remove_dir_all(&dir);
    }
}
