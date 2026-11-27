//! `budlum-ee-move` Unix-domain-socket worker daemon.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use budlum_ee_move::MoveWorker;
use budlum_uel_abi::transport::{serve_connection, ServeEnd};

fn parse_socket_arg_from<I>(mut args: I) -> Result<PathBuf, String>
where
    I: Iterator<Item = String>,
{
    while let Some(arg) = args.next() {
        if arg == "--socket" {
            return match args.next() {
                Some(val) if !val.is_empty() => Ok(PathBuf::from(val)),
                _ => Err("missing value after --socket".to_string()),
            };
        }
        if let Some(val) = arg.strip_prefix("--socket=") {
            if !val.is_empty() {
                return Ok(PathBuf::from(val));
            }
            return Err("empty value after --socket=".to_string());
        }
    }
    Err("usage: budlum-ee-move --socket <unix-socket-path>".into())
}

fn parse_socket_arg() -> Result<PathBuf, String> {
    parse_socket_arg_from(env::args().skip(1))
}

/// Bind the worker Unix domain socket safely:
/// - uses `symlink_metadata` (`lstat`, never follows symlinks) before touching any existing path;
/// - refuses to unlink regular files, symlinks, directories, or FIFOs;
/// - removes only a pre-existing stale Unix socket;
/// - locks socket file permissions to owner-only `0o600`.
fn bind_worker_socket(socket_path: &Path) -> Result<UnixListener, String> {
    if socket_path.as_os_str().is_empty() {
        return Err("socket path must not be empty".to_string());
    }
    match fs::symlink_metadata(socket_path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() || !ft.is_socket() {
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
            "failed to set 0600 permissions on {}: {err}",
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
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let mut worker = MoveWorker::new();
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
    use super::*;
    use std::os::unix::fs::symlink;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "budlum-ee-move-main-{}-{}-{label}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn bind_worker_socket_refuses_regular_file_without_deleting_it() {
        let dir = temp_dir("regfile");
        let victim = dir.join("important.dat");
        assert!(fs::write(&victim, b"precious").is_ok());

        let err = bind_worker_socket(&victim).unwrap_err();
        assert!(err.contains("non-socket"));
        assert_eq!(
            fs::read(&victim).ok().as_deref(),
            Some(b"precious".as_slice())
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bind_worker_socket_refuses_symlink_without_touching_target() {
        let dir = temp_dir("symlink");
        let target = dir.join("target.sock");
        let _existing = UnixListener::bind(&target).ok();
        let link = dir.join("link.sock");
        assert!(symlink(&target, &link).is_ok());

        let err = bind_worker_socket(&link).unwrap_err();
        assert!(err.contains("non-socket"));
        assert!(fs::symlink_metadata(&link)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false));
        assert!(fs::symlink_metadata(&target).is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bind_worker_socket_replaces_stale_socket_and_sets_mode_0600() {
        let dir = temp_dir("stale");
        let sock = dir.join("worker.sock");
        {
            let stale = UnixListener::bind(&sock);
            assert!(stale.is_ok());
        }

        let listener = bind_worker_socket(&sock);
        assert!(listener.is_ok());
        let mode = fs::symlink_metadata(&sock)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0);
        assert_eq!(mode, 0o600);

        drop(listener);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bind_worker_socket_rejects_empty_path() {
        let err = bind_worker_socket(Path::new("")).unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn parse_socket_arg_rejects_empty_values() {
        assert!(
            parse_socket_arg_from(["--socket".to_string(), String::new()].into_iter()).is_err()
        );
        assert!(parse_socket_arg_from(["--socket=".to_string()].into_iter()).is_err());
        assert_eq!(
            parse_socket_arg_from(["--socket=/tmp/m.sock".to_string()].into_iter()).ok(),
            Some(PathBuf::from("/tmp/m.sock"))
        );
    }
}
