//! Atomic, owner-only key-file writes (BLG-004).
//!
//! A key file is secret material on disk. Two properties are not optional:
//!
//! * **Atomic.** A crash midway through a write must not leave a short, empty
//!   or half-old file behind. The bytes go to a sibling temporary file, are
//!   flushed to disk, and then replace the target with one `rename`. On the
//!   same filesystem a rename is a single directory entry swap, so a reader
//!   sees either the old file or the new one, never a mixture.
//! * **Narrow.** The file is owner-read/write only (`0o600`). A file that
//!   already existed with wider bits must not keep them: the temporary file is
//!   created with `0o600` and the rename makes it the target, so the mode is
//!   decided by the new file and never inherited from the old one.
//!
//! The previous shape lived as a private helper in `primitives.rs` and was
//! correct there, but it was the only writer: every other key-shaped file in
//! the tree either wrote itself with `std::fs::write` (mode decided by the
//! process umask, atomicity not addressed) or chmod'ed after the fact, where a
//! window exists in which the bytes are on disk and the mode is still wide.
//! One definition, called by every writer, is the rule this module exists to
//! hold (directive K-4: one definition of a primitive).

use std::io::Write;
use std::path::{Path, PathBuf};

/// Write `bytes` to `path` atomically and with mode `0o600`.
///
/// A stale `<name>.tmp` left by an interrupted earlier write is removed first:
/// `create_new` refuses to reuse it, and refusing the write over a leftover
/// would make one crash permanent.
///
/// # Errors
///
/// An I/O error from removing the stale temporary, creating or writing the new
/// one, syncing it, or renaming it over the target. A failure never leaves the
/// temporary file behind and never partially overwrites the target.
///
/// # Security
///
/// `bytes` holds secret material. The caller owns the buffer and must wipe it
/// after this call returns; this module does not retain a copy.
pub fn write_atomic_owner_only(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let tmp_path = sibling_temp_path(path)?;
    match std::fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    // Wide bits cannot appear even for an instant: the mode is set at
    // creation, not corrected afterwards.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = options.open(&tmp_path).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp_path, path)
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

/// The mode a key file is allowed to have: owner read/write, nothing else.
pub const KEY_FILE_MODE: u32 = 0o600;

/// The bits of a key file's mode that may be set. Anything outside this mask is
/// access for a group member or for any other user on the host.
pub const KEY_FILE_FORBIDDEN_MASK: u32 = 0o077;

/// Refuse to read a key file that is readable or writable by anyone but its
/// owner.
///
/// # The asymmetry this closes
///
/// The write side has been owner-only since the first hardening pass, and the
/// wallet has refused a wide key file since its own review
/// (`wallet::open_key_file`). The validator readers did not: `ValidatorKeys::load`
/// and `KeyPair::load` opened whatever path they were given, so a key generated
/// by an older build - or copied in with `cp` and the process umask - was read
/// with its `0o644` intact and the node ran happily on a world-readable secret.
/// Checking on load is not enough on its own (a secret read once has already
/// leaked if an attacker had the read), but it is the only place that can tell
/// an operator "this file was exposed" instead of staying silent about it.
///
/// # Errors
///
/// An I/O error from `metadata`, or [`std::io::ErrorKind::PermissionDenied`]
/// naming the file, its mode and the required one. The message is the operator's
/// whole remedy: a refusal that does not say `chmod 600` is a refusal an
/// operator cannot act on.
#[cfg(unix)]
pub fn require_owner_only(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & KEY_FILE_FORBIDDEN_MASK != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} has mode {:03o}; group and others must have no access (chmod 600)",
                path.display(),
                mode & 0o777
            ),
        ));
    }
    Ok(())
}

/// Not a Unix host: file modes do not exist, so there is nothing to refuse.
///
/// # Errors
///
/// Never. The signature matches the Unix version so callers need no `cfg`.
#[cfg(not(unix))]
pub fn require_owner_only(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

/// The sibling temporary path a write of `path` goes through.
///
/// # Errors
///
/// [`std::io::ErrorKind::InvalidInput`] when `path` has no file name (the root
/// directory, or a path ending in `..`).
fn sibling_temp_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "key path has no file name",
        )
    })?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(".tmp");
    Ok(path.with_file_name(tmp_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    /// The bytes land, and they land owner-only.
    #[cfg(unix)]
    #[test]
    fn a_new_file_is_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("k.bin");
        write_atomic_owner_only(&path, b"secret").expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"secret");
        assert_eq!(mode_of(&path), 0o600);
        // One file, no sibling left behind.
        assert_eq!(std::fs::read_dir(dir.path()).expect("read_dir").count(), 1);
    }

    /// BLG-004: rewriting a key file narrows an existing wide mode. This is the
    /// regression the finding names - a rewrite used to keep `0o644`.
    #[cfg(unix)]
    #[test]
    fn blg_004_a_rewrite_narrows_a_wide_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("k.bin");
        std::fs::write(&path, b"old").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert_eq!(mode_of(&path), 0o644, "the seed must start wide");

        write_atomic_owner_only(&path, b"new").expect("rewrite");
        assert_eq!(mode_of(&path), 0o600, "the rewrite must narrow the mode");
        assert_eq!(std::fs::read(&path).expect("read"), b"new");
    }

    /// BLG-004, the read side: a key file that group or others can read is
    /// refused by name, with the mode and the remedy in the message.
    #[cfg(unix)]
    #[test]
    fn blg_004_a_wide_mode_key_file_is_not_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("k.bin");
        std::fs::write(&path, b"secret").expect("seed");

        for wide in [0o644u32, 0o640, 0o604, 0o660, 0o700] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(wide)).expect("chmod");
            let err = require_owner_only(&path).expect_err("a wide mode may not be read");
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
            let message = err.to_string();
            assert!(
                message.contains("chmod 600"),
                "the refusal must carry the remedy, got: {message}"
            );
            assert!(
                message.contains(&format!("{wide:03o}")),
                "the refusal must carry the mode it saw, got: {message}"
            );
        }

        for narrow in [0o600u32, 0o400, 0o000] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(narrow))
                .expect("chmod");
            require_owner_only(&path).expect("nothing outside 0o600 is set");
        }
    }

    /// A key file this build wrote always passes its own read check: the two
    /// halves of BLG-004 have to agree, or every saved key becomes unloadable.
    #[cfg(unix)]
    #[test]
    fn what_the_writer_produces_the_reader_accepts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("k.bin");
        write_atomic_owner_only(&path, b"secret").expect("write");
        require_owner_only(&path).expect("a file this writer made must pass the reader");
    }

    /// The reader refuses a path that is not there with the I/O error rather
    /// than a permission verdict, so a missing key is not reported as a wide one.
    #[test]
    fn a_missing_key_file_is_an_io_error_not_a_mode_verdict() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = require_owner_only(&dir.path().join("absent.bin")).expect_err("must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    /// A stale temporary from an interrupted write does not block the next one.
    #[test]
    fn a_stale_temporary_does_not_block_a_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("k.bin");
        std::fs::write(dir.path().join("k.bin.tmp"), b"stale").expect("seed temp");
        write_atomic_owner_only(&path, b"fresh").expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"fresh");
        assert!(!dir.path().join("k.bin.tmp").exists());
    }

    /// A path with no file name is refused, not silently written elsewhere.
    #[test]
    fn a_path_without_a_file_name_is_refused() {
        let err = write_atomic_owner_only(Path::new("/"), b"x").expect_err("must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// A failed write leaves no temporary behind and does not touch the target.
    #[test]
    fn a_failed_write_leaves_the_target_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("k.bin");
        std::fs::write(&path, b"keep-me").expect("seed");
        // A directory squatting on the temporary name cannot be removed as a
        // file, so the write stops before it creates anything: the refusal
        // path is exercised and the target is never opened for writing.
        let blocker = dir.path().join("k.bin.tmp");
        std::fs::create_dir(&blocker).expect("blocker dir");
        let result = write_atomic_owner_only(&path, b"new");
        assert!(result.is_err(), "a squatting directory must stop the write");
        assert_eq!(std::fs::read(&path).expect("read"), b"keep-me");
        // The blocker is the caller's directory; the writer removed its own
        // temporary only, so the target is intact and no file remains.
        assert!(blocker.is_dir());
    }
}
