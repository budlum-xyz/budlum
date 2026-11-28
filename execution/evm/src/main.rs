//! `budlum-ee-evm` Unix-domain-socket worker daemon.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use budlum_ee_evm::EvmWorker;
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
    Err("usage: budlum-ee-evm --socket <unix-socket-path>".into())
}

fn bind_worker_socket(socket_path: &Path) -> Result<UnixListener, String> {
    if socket_path.as_os_str().is_empty() {
        return Err("socket path cannot be empty".into());
    }
    match fs::symlink_metadata(socket_path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(format!(
                    "refusing to unlink non-socket path {}",
                    socket_path.display()
                ));
            }
            fs::remove_file(socket_path).map_err(|err| {
                format!(
                    "failed to remove stale socket {}: {err}",
                    socket_path.display()
                )
            })?;
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "failed to inspect socket path {}: {err}",
                socket_path.display()
            ));
        }
    }
    let listener = UnixListener::bind(socket_path)
        .map_err(|err| format!("failed to bind {}: {err}", socket_path.display()))?;
    if let Err(err) = fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)) {
        drop(listener);
        let _ = fs::remove_file(socket_path);
        return Err(format!(
            "failed to chmod 0600 on socket {}: {err}",
            socket_path.display()
        ));
    }
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
                let mut worker = EvmWorker;
                if matches!(serve_connection(stream, &mut worker), Ok(ServeEnd::Faulted)) {
                    // Engine panicked: exit cleanly so supervisor restarts fresh process state.
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
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn evmee05_socket_bind_refuses_regular_file_symlink_and_enforces_0600() {
        let dir =
            std::env::temp_dir().join(format!("budlum-ee-evm-sock-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");

        // 1. Regular file at socket path must NOT be unlinked; bind must refuse.
        let reg = dir.join("important.dat");
        fs::write(&reg, b"do-not-delete").expect("write reg");
        assert!(
            bind_worker_socket(&reg).is_err(),
            "bind_worker_socket must refuse an existing regular file"
        );
        assert_eq!(
            fs::read(&reg).ok().as_deref(),
            Some(b"do-not-delete".as_slice()),
            "existing regular file must survive refused bind"
        );

        // 2. Symlink at socket path must NOT be unlinked or followed.
        let link = dir.join("evil.sock");
        symlink(&reg, &link).expect("symlink");
        assert!(
            bind_worker_socket(&link).is_err(),
            "bind_worker_socket must refuse a symlink"
        );
        assert!(
            fs::symlink_metadata(&link).is_ok(),
            "refused symlink must not be unlinked"
        );

        // 3. Fresh socket bind succeeds and sets strict 0600 owner-only permissions.
        let sock = dir.join("worker.sock");
        let listener = bind_worker_socket(&sock).expect("bind fresh socket");
        let mode = fs::symlink_metadata(&sock)
            .expect("stat sock")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "worker socket must enforce 0600 permissions");
        drop(listener);

        // 4. Stale Unix socket IS cleanly replaced on re-bind.
        let listener2 = bind_worker_socket(&sock).expect("rebind stale unix socket");
        drop(listener2);
        let _ = fs::remove_dir_all(&dir);
    }
}
