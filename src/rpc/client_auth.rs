//! Client side of the operator RPC gate: where a caller's `x-api-key` comes
//! from.
//!
//! `RpcSecurityConfig` defaults to `auth_required = true`, and the server reads
//! the expected key from an environment variable at startup. Nothing on the
//! client side sent the header, so every shipped client - the `bud` CLI, the
//! faucet's node client, the mobile reader - got `401 Unauthorized` from a
//! correctly configured node. RT-002: `bud query status` answered with `RPC
//! response parse: expected value at line 1 column 1`, because the body it
//! tried to parse as JSON was the word `Unauthorized`. The gate is right; the
//! clients were incomplete.
//!
//! # Where the key comes from
//!
//! A file, named by the `BUDLUM_RPC_API_KEY_FILE` environment variable. The
//! environment carries a *path*, never the secret: an environment variable is
//! readable from `/proc/<pid>/environ` by the same user and is inherited by
//! every child process, and a command-line argument is visible in `ps` to the
//! whole machine. Neither is a place for a credential.
//!
//! The file must not be readable by group or others on Unix, for the same
//! reason the CLI refuses a world-readable signing seed: a key that any local
//! user can read is a key that has leaked.
//!
//! When the variable is unset the caller sends no key, which is what a node
//! running `auth_required = false` expects.

use std::path::{Path, PathBuf};

/// Environment variable naming the file that holds the operator RPC API key.
pub const API_KEY_FILE_ENV: &str = "BUDLUM_RPC_API_KEY_FILE";

/// The longest key this client will read.
///
/// The server compares the header in constant time and does not bound its own
/// configured key; a client-side ceiling keeps a misconfigured path (a
/// directory listing, a log file, a whole disk image) from being read into
/// memory and sent as a header.
const MAX_API_KEY_BYTES: u64 = 4 * 1024;

/// The path named by [`API_KEY_FILE_ENV`], if the variable is set.
///
/// # Errors
/// Returns an error when the variable is set but empty - an empty `--rpc-key`
/// path is a configuration mistake that would otherwise silently fall back to
/// an unauthenticated request against a node that then answers `401`.
fn api_key_file_from_env() -> Result<Option<PathBuf>, String> {
    match std::env::var(API_KEY_FILE_ENV) {
        Ok(value) if value.trim().is_empty() => Err(format!(
            "{API_KEY_FILE_ENV} is set but empty; unset it or point it at the file holding the \
             operator RPC key"
        )),
        Ok(value) => Ok(Some(PathBuf::from(value.trim()))),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!(
            "{API_KEY_FILE_ENV} is not valid UTF-8; it must name a file path"
        )),
    }
}

/// Read the key named by [`API_KEY_FILE_ENV`].
///
/// `Ok(None)` means "no key configured", which is a valid deployment against a
/// node with the gate disabled.
///
/// # Errors
/// Returns an error - never the key itself - when the file cannot be read, is
/// larger than `MAX_API_KEY_BYTES`, is readable by group or others, or holds
/// nothing but whitespace.
pub fn api_key_from_env() -> Result<Option<String>, String> {
    match api_key_file_from_env()? {
        Some(path) => read_api_key(&path).map(Some),
        None => Ok(None),
    }
}

/// Read an API key from `path`.
///
/// Trailing whitespace and the trailing newline an editor adds are trimmed; a
/// key containing a control character or a line break is refused, because a
/// header value cannot carry one and a key file that holds two lines is not a
/// key file.
///
/// # Errors
/// As [`api_key_from_env`], for the given path.
fn read_api_key(path: &Path) -> Result<String, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| format!("cannot stat RPC key file {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "RPC key file {} is not a regular file",
            path.display()
        ));
    }
    check_secret_file_mode(path)?;
    if metadata.len() > MAX_API_KEY_BYTES {
        return Err(format!(
            "RPC key file {} is larger than {MAX_API_KEY_BYTES} bytes; it does not hold a key",
            path.display()
        ));
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read RPC key file {}: {e}", path.display()))?;
    let key = raw.trim();
    if key.is_empty() {
        return Err(format!("RPC key file {} is empty", path.display()));
    }
    if key.chars().any(|c| c.is_control()) {
        return Err(format!(
            "RPC key file {} holds a control character; a header value cannot carry one",
            path.display()
        ));
    }
    Ok(key.to_string())
}

/// Refuse a key file that group or others can read (Unix only).
#[cfg(unix)]
fn check_secret_file_mode(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)
        .map_err(|e| format!("cannot stat RPC key file {}: {e}", path.display()))?;
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "RPC key file {} is readable by group or others (mode {:o}); run: chmod 600 {}",
            path.display(),
            mode & 0o777,
            path.display()
        ));
    }
    Ok(())
}

/// Non-Unix builds have no POSIX mode bits to check.
#[cfg(not(unix))]
fn check_secret_file_mode(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempKey {
        dir: PathBuf,
    }

    impl TempKey {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "budlum-rpc-key-{}-{tag}-{}",
                std::process::id(),
                crate::consensus::now_millis()
            ));
            std::fs::create_dir_all(&dir).expect("temp dir");
            Self { dir }
        }

        fn write(&self, name: &str, contents: &[u8]) -> PathBuf {
            let path = self.dir.join(name);
            std::fs::write(&path, contents).expect("write key file");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("key fixtures are 0600");
            }
            path
        }
    }

    impl Drop for TempKey {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn a_key_file_is_read_with_its_trailing_newline_trimmed() {
        let temp = TempKey::new("trim");
        let path = temp.write("key", b"s3cret-operator-key\n");
        assert_eq!(
            read_api_key(&path).expect("mode is 600 and the file holds a key"),
            "s3cret-operator-key"
        );
    }

    #[test]
    fn a_key_file_with_no_key_is_refused() {
        let temp = TempKey::new("empty");
        let path = temp.write("key", b"  \n\t\n");
        let error = read_api_key(&path).expect_err("an empty key file is a misconfiguration");
        assert!(error.contains("empty"), "got: {error}");
    }

    #[test]
    fn a_key_file_with_a_second_line_is_refused() {
        let temp = TempKey::new("two-lines");
        let path = temp.write("key", b"first\nsecond\n");
        let error = read_api_key(&path).expect_err("a header value cannot carry a line break");
        assert!(error.contains("control character"), "got: {error}");
    }

    #[test]
    fn an_oversized_key_file_is_refused_without_reading_it() {
        let temp = TempKey::new("huge");
        let path = temp.write("key", &vec![b'a'; (MAX_API_KEY_BYTES as usize) + 1]);
        let error = read_api_key(&path).expect_err("a key file that large is not a key");
        assert!(error.contains("larger than"), "got: {error}");
    }

    #[test]
    fn a_directory_is_not_a_key_file() {
        let temp = TempKey::new("dir");
        let error = read_api_key(&temp.dir).expect_err("a directory is not a key");
        assert!(error.contains("not a regular file"), "got: {error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_group_readable_key_file_is_refused_and_the_refusal_names_the_fix() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempKey::new("mode");
        let path = temp.write("key", b"a-key-that-leaked\n");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod the fixture");
        let error = read_api_key(&path).expect_err("a world-readable key has leaked");
        assert!(error.contains("chmod 600"), "got: {error}");
        assert!(
            !error.contains("a-key-that-leaked"),
            "a refusal must never echo the secret: {error}"
        );
    }

    /// The environment is process-global, so this test owns the variable for its
    /// duration and restores it afterwards. Nothing else in the crate reads it.
    #[test]
    fn the_environment_names_a_file_and_never_carries_the_key() {
        let previous = std::env::var(API_KEY_FILE_ENV).ok();
        std::env::remove_var(API_KEY_FILE_ENV);
        assert_eq!(
            api_key_file_from_env().expect("unset is not an error"),
            None
        );
        assert_eq!(
            api_key_from_env().expect("no key configured"),
            None,
            "an unset variable means an unauthenticated client, not an empty key"
        );

        std::env::set_var(API_KEY_FILE_ENV, "   ");
        let error = api_key_file_from_env().expect_err("an empty path is a mistake");
        assert!(error.contains("set but empty"), "got: {error}");

        std::env::set_var(API_KEY_FILE_ENV, "/nonexistent/rpc.key");
        let error = api_key_from_env().expect_err("the file does not exist");
        assert!(error.contains("cannot stat"), "got: {error}");

        match previous {
            Some(value) => std::env::set_var(API_KEY_FILE_ENV, value),
            None => std::env::remove_var(API_KEY_FILE_ENV),
        }
    }
}
