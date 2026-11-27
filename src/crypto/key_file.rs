//! Atomic, owner-only key-file writes and symlink-free, FD-pinned reads.
//!
//! A key file is secret material on disk. Two properties are not optional:
//!
//! * **Atomic.** A crash midway through a write must not leave a short, empty
//!   or half-old file behind. The bytes go to a uniquely named sibling
//!   temporary file (`<name>.<pid>.<seq>.tmp`) created with `create_new`,
//!   are flushed to disk, and then replace the target with one `rename`. On
//!   the same filesystem a rename is a single directory entry swap, so a
//!   reader sees either the old file or the new one, never a mixture.
//! * **Narrow and pinned.** Writes set mode `0o600` at creation time. Reads
//!   inspect `symlink_metadata`, refuse symbolic links and non-regular files,
//!   open the descriptor with `O_NOFOLLOW` where available, verify `(dev, ino)`
//!   and regular-file status via `fstat` on the open descriptor, check mode
//!   `0o077 == 0` on the same descriptor for owner-only files, and read with
//!   a hard byte cap.
//!
//! Convenience: exposed for CLI, RPC, SDK, and multi-VM runtime callers.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Write `bytes` to `path` atomically and with mode `0o600`.
///
/// Each attempt chooses a unique sibling temporary name
/// `<name>.<pid>.<seq>.tmp` opened with `create_new(true)` rather than
/// unlinking a fixed `.tmp` path beforehand, so concurrent callers or
/// pre-existing `.tmp` entries cannot collide or race a symlink swap.
///
/// # Errors
///
/// An I/O error from creating or writing the temporary file, syncing it, or
/// renaming it over the target. A failure never leaves the temporary file
/// behind and never partially overwrites the target.
///
/// # Security
///
/// `bytes` holds secret material. The caller owns the buffer and must wipe it
/// after this call returns; this module does not retain a copy.
pub fn write_atomic_owner_only(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let tmp_path = unique_temp_path(path)?;
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

/// Open `path` as a regular file without following symlinks and pin the open
/// descriptor to the inspected directory entry.
///
/// Rejects symlinks (`symlink_metadata` + `O_NOFOLLOW` on Linux/BSD),
/// non-regular files (directories, FIFOs, sockets, device nodes), and
/// `(dev, ino)` swaps between `lstat` and `fstat` on the open descriptor.
///
/// # Errors
///
/// An I/O error when the file cannot be opened or violates the regular-file
/// and non-symlink invariants.
pub fn open_regular_pinned(path: &Path) -> Result<std::fs::File, std::io::Error> {
    let lmeta = std::fs::symlink_metadata(path)?;
    if lmeta.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is a symbolic link; refusing to follow", path.display()),
        ));
    }
    if !lmeta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(target_os = "linux")]
        options.custom_flags(0o400_000);
        #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "dragonfly"))]
        options.custom_flags(0x0100);
    }

    let file = options.open(path)?;
    let fmeta = file.metadata()?;
    if !fmeta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (fmeta.dev(), fmeta.ino()) != (lmeta.dev(), lmeta.ino()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} changed between inspection and open", path.display()),
            ));
        }
    }
    Ok(file)
}

/// Open `path` pinned as a regular file and verify on the open descriptor
/// that group and others have no permissions (`mode & 0o077 == 0`).
///
/// Checking permissions via `fstat` on the already-opened descriptor closes the
/// TOCTOU race between path-based `stat` checks and subsequent reads.
///
/// # Errors
///
/// [`std::io::ErrorKind::InvalidInput`] on symlinks or non-regular files,
/// [`std::io::ErrorKind::PermissionDenied`] when `mode & 0o077 != 0`, or the
/// underlying I/O error.
pub fn open_owner_only_pinned(path: &Path) -> Result<std::fs::File, std::io::Error> {
    let file = open_regular_pinned(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata()?.permissions().mode();
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
    }
    Ok(file)
}

fn read_pinned_bounded(
    file: std::fs::File,
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, std::io::Error> {
    let max_u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    let meta = file.metadata()?;
    if meta.len() > max_u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{label} {} exceeds {max_bytes}-byte limit", path.display()),
        ));
    }
    let mut buf = Vec::new();
    file.take(max_u64.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{label} {} exceeds {max_bytes}-byte limit", path.display()),
        ));
    }
    Ok(buf)
}

/// Open `path` pinned without following symlinks and read at most `max_bytes`.
///
/// # Errors
///
/// Returns an error if `path` is missing, a symlink, non-regular, or larger
/// than `max_bytes`.
pub fn read_regular_bounded(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, std::io::Error> {
    let file = open_regular_pinned(path)?;
    read_pinned_bounded(file, path, max_bytes, label)
}

/// Open `path` pinned as owner-only regular file and read at most `max_bytes`
/// into a zeroizing buffer.
///
/// # Errors
///
/// Returns an error if `path` is missing, a symlink, non-regular, readable or
/// writable by group/others, or larger than `max_bytes`.
pub fn read_owner_only_bounded(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, std::io::Error> {
    let file = open_owner_only_pinned(path)?;
    read_pinned_bounded(file, path, max_bytes, label).map(Zeroizing::new)
}

/// Refuse to read a key file that is readable or writable by anyone but its
/// owner, or that is a symlink or non-regular file.
///
/// # Errors
///
/// An I/O error from inspecting/opening `path`, or
/// [`std::io::ErrorKind::PermissionDenied`] naming the file, its mode and
/// `chmod 600`.
pub fn require_owner_only(path: &Path) -> Result<(), std::io::Error> {
    open_owner_only_pinned(path).map(|_| ())
}

/// A unique sibling temporary path `<name>.<pid>.<seq>.tmp` for `path`.
///
/// # Errors
///
/// [`std::io::ErrorKind::InvalidInput`] when `path` has no file name (the root
/// directory, or a path ending in `..`).
fn unique_temp_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "key path has no file name",
        )
    })?;
    let seq = TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut tmp_name = OsString::from(file_name);
    tmp_name.push(format!(".{}.{seq}.tmp", std::process::id()));
    Ok(path.with_file_name(tmp_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(path)
            .expect("symlink_metadata")
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

    /// Rewriting a key file narrows an existing wide mode.
    #[cfg(unix)]
    #[test]
    fn a_rewrite_narrows_a_wide_mode() {
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

    /// A key file that group or others can read is refused by name, with the
    /// mode and the remedy in the message.
    #[cfg(unix)]
    #[test]
    fn a_wide_mode_key_file_is_not_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("k.bin");
        std::fs::write(&path, b"secret").expect("seed");

        for wide in [0o644u32, 0o640, 0o604, 0o660] {
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

        for narrow in [0o600u32, 0o400, 0o000, 0o700] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(narrow))
                .expect("chmod");
            require_owner_only(&path).expect("nothing outside 0o600 is set");
        }
    }

    /// A key file this build wrote always passes its own read check.
    #[cfg(unix)]
    #[test]
    fn what_the_writer_produces_the_reader_accepts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("k.bin");
        write_atomic_owner_only(&path, b"secret").expect("write");
        require_owner_only(&path).expect("a file this writer made must pass the reader");
        let read_back = read_owner_only_bounded(&path, 64, "key").expect("bounded read");
        assert_eq!(read_back.as_slice(), b"secret");
    }

    /// The reader refuses a path that is not there with NotFound.
    #[test]
    fn a_missing_key_file_is_an_io_error_not_a_mode_verdict() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = require_owner_only(&dir.path().join("absent.bin")).expect_err("must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    /// A stale temporary from an earlier write never blocks the next unique write.
    #[test]
    fn a_stale_temporary_does_not_block_a_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("k.bin");
        std::fs::write(dir.path().join("k.bin.tmp"), b"stale").expect("seed temp");
        write_atomic_owner_only(&path, b"fresh").expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"fresh");
        assert!(!dir
            .path()
            .join(format!("k.bin.{}.0.tmp", std::process::id()))
            .exists());
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
        let blocker_dir = dir.path().join("k.bin");
        std::fs::create_dir(&blocker_dir).expect("target directory");
        let inner = blocker_dir.join("keep");
        std::fs::write(&inner, b"keep-me").expect("seed");
        // Renaming a temporary file over an existing directory fails cleanly and
        // unlinks the temporary without altering the directory or its contents.
        let result = write_atomic_owner_only(&blocker_dir, b"new");
        assert!(result.is_err(), "cannot replace a directory with a file");
        assert_eq!(std::fs::read(&inner).expect("read"), b"keep-me");
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "no temporary file may remain");
    }

    /// Pinned readers reject symlinks, directories, and oversized regular files.
    #[cfg(unix)]
    #[test]
    fn pinned_readers_reject_symlinks_directories_and_oversized_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("real.bin");
        let link = dir.path().join("link.bin");
        let subdir = dir.path().join("subdir");
        std::fs::create_dir(&subdir).expect("mkdir");
        std::fs::write(&target, b"0123456789").expect("write");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        symlink(&target, &link).expect("symlink");

        assert_eq!(
            open_regular_pinned(&link)
                .expect_err("symlink regular")
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            open_owner_only_pinned(&link)
                .expect_err("symlink owner")
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            open_regular_pinned(&subdir)
                .expect_err("dir regular")
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            read_regular_bounded(&target, 5, "test file")
                .expect_err("oversized regular")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_owner_only_bounded(&target, 5, "test key")
                .expect_err("oversized owner")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_regular_bounded(&target, 10, "test file").expect("exact bound"),
            b"0123456789"
        );
    }
}
