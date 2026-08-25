//! Reading an operator-supplied file without letting its size choose the
//! allocation.
//!
//! # The shape of the problem
//!
//! [`std::fs::read_to_string`] allocates whatever the file happens to contain.
//! On a path the operator controls that is usually fine, and it is exactly how
//! the node loaded its snapshots, its vote history, its ban list, its relayer
//! cursor and `budlum.toml`. The size of each of those is decided by something
//! the node itself wrote earlier, so nobody chose a limit.
//!
//! That reasoning holds right up until the file is not what the node wrote.
//! A snapshot directory is a directory: anything that can place a file there
//! decides the size of an allocation inside the node. The failure is not a
//! parse error, which every one of these call sites already handles - it is
//! the allocation that happens *before* the parser is ever reached. A 4 GiB
//! file on a 1984 MB host is an abort, and an abort during snapshot recovery
//! is downtime at exactly the moment the operator is trying to recover.
//!
//! This is the same class as the mempool ceiling (a count bound and a size
//! bound are two different bounds) and the gossip score table: a number that
//! is small in every real run is still unbounded if nothing states the bound.
//!
//! # What a ceiling here is and is not
//!
//! It is not a security boundary. Anything that can write into the node's data
//! directory has already won. The ceiling exists so that a file that is the
//! wrong size fails as a *diagnosable refusal* rather than as an allocator
//! abort:
//!
//!   * the caller gets an error naming the path, the limit and the actual size,
//!   * the error arrives before the memory is committed, not after,
//!   * every existing caller already has an error path for "this file is not
//!     usable", so the refusal flows into behaviour that was already written
//!     and tested.
//!
//! # Why the size is checked before the read, and again during it
//!
//! [`std::fs::metadata`] is a hint, not a guarantee: the file can grow between
//! the check and the read, and on some filesystems the reported length is a
//! lie (`/proc` reports zero for files with content). So the metadata check is
//! a fast rejection, and the read itself is bounded by [`std::io::Read::take`],
//! which is what actually enforces the limit. Neither alone is enough:
//! metadata alone can be raced, and `take` alone would read a whole gigabyte
//! before noticing.
//!
//! Reading `limit + 1` bytes is deliberate. A read that stops exactly at the
//! limit cannot tell a file that fits from a file that was truncated to fit,
//! and silently truncating a snapshot is worse than refusing it: the parser
//! would then reject valid-looking prefix data with a confusing error, or
//! worse, accept it.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;

/// The ceiling for a state snapshot.
///
/// Snapshots are the largest thing on this list: they carry the full account
/// set. 512 MiB is far above any snapshot this chain has produced and far
/// below the point where reading one aborts the process.
pub const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

/// The ceiling for a small operator-supplied control file.
///
/// The vote history is two integers, the relayer cursor is one, and a
/// `budlum.toml` is a hand-written config. 1 MiB is several thousand times
/// what any of them needs; the point is that the number exists, not that it
/// is tight.
pub const MAX_CONTROL_FILE_BYTES: u64 = 1024 * 1024;

/// The ceiling for the persisted ban list.
///
/// This one grows with the peer set rather than being a fixed handful of
/// fields, so it gets its own, larger number: 16 MiB holds far more bans than
/// the peer manager will ever hold in memory.
pub const MAX_BAN_LIST_BYTES: u64 = 16 * 1024 * 1024;

/// Why a bounded read refused.
#[derive(Debug)]
pub enum BoundedReadError {
    /// The file could not be opened or read.
    Io {
        /// The path that was being read.
        path: std::path::PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The file is larger than the ceiling for its kind.
    TooLarge {
        /// The path that was being read.
        path: std::path::PathBuf,
        /// The ceiling that applied.
        limit: u64,
        /// What was actually there, when it could be determined.
        ///
        /// `None` when the length is only known to exceed the limit, which is
        /// the case when the ceiling was hit during the read rather than by
        /// the metadata check.
        actual: Option<u64>,
    },
    /// The file is not valid UTF-8.
    ///
    /// [`std::fs::read_to_string`] returns this as an [`std::io::Error`] of
    /// kind `InvalidData`. It is separated here because "this file is binary"
    /// and "this file could not be read" lead an operator to different places.
    NotUtf8 {
        /// The path that was being read.
        path: std::path::PathBuf,
    },
}

impl std::fmt::Display for BoundedReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            Self::TooLarge {
                path,
                limit,
                actual,
            } => match actual {
                Some(n) => write!(
                    f,
                    "{} is {n} bytes, over the {limit}-byte ceiling for this file",
                    path.display()
                ),
                None => write!(
                    f,
                    "{} is over the {limit}-byte ceiling for this file",
                    path.display()
                ),
            },
            Self::NotUtf8 { path } => {
                write!(f, "{} is not valid UTF-8", path.display())
            }
        }
    }
}

impl BoundedReadError {
    /// Is this "the file is not there", as opposed to "the file is unusable"?
    ///
    /// Every caller of [`read_to_string_bounded`] in this tree draws that
    /// distinction and draws it deliberately: an absent vote history, ban list
    /// or relayer cursor is the normal state on a first boot and must stay
    /// silent, while a file that exists and cannot be used is an operator
    /// problem and must be logged. Collapsing the two would either spam a
    /// clean first boot with warnings or hide a corrupt file behind the same
    /// silence as a missing one.
    ///
    /// A file that is over its ceiling is emphatically NOT missing: it is
    /// present and wrong, which is the case this whole module exists to make
    /// visible.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        match self {
            Self::Io { source, .. } => source.kind() == std::io::ErrorKind::NotFound,
            Self::TooLarge { .. } | Self::NotUtf8 { .. } => false,
        }
    }
}

impl std::error::Error for BoundedReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::TooLarge { .. } | Self::NotUtf8 { .. } => None,
        }
    }
}

/// Read `path` to a [`String`], refusing to allocate more than `limit` bytes.
///
/// This is [`std::fs::read_to_string`] with the one property that function
/// does not have: the caller, rather than whoever wrote the file, decides the
/// largest allocation it can cause.
///
/// # Errors
///
/// [`BoundedReadError::TooLarge`] when the file exceeds `limit`, before the
/// memory is committed; [`BoundedReadError::NotUtf8`] when the bytes are not
/// UTF-8; [`BoundedReadError::Io`] for anything else.
pub fn read_to_string_bounded(path: &Path, limit: u64) -> Result<String, BoundedReadError> {
    let file = File::open(path).map_err(|source| BoundedReadError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    // The fast rejection. A file that is already too big is refused without
    // reading a byte of it. This is a hint and not the enforcement: see the
    // module docs on why it is not sufficient on its own.
    if let Ok(meta) = file.metadata() {
        let len = meta.len();
        if len > limit {
            return Err(BoundedReadError::TooLarge {
                path: path.to_path_buf(),
                limit,
                actual: Some(len),
            });
        }
    }

    // The enforcement. `limit + 1` so that hitting the ceiling is
    // distinguishable from fitting exactly inside it; see the module docs.
    let mut buf = Vec::new();
    let read_limit = limit.saturating_add(1);
    file.take(read_limit)
        .read_to_end(&mut buf)
        .map_err(|source| BoundedReadError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    if buf.len() as u64 > limit {
        return Err(BoundedReadError::TooLarge {
            path: path.to_path_buf(),
            limit,
            actual: None,
        });
    }

    String::from_utf8(buf).map_err(|_| BoundedReadError::NotUtf8 {
        path: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn scratch(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .subsec_nanos();
        let dir = std::env::temp_dir().join(format!(
            "budlum-bounded-{}-{nanos}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(bytes).expect("write");
        path
    }

    #[test]
    fn a_file_inside_the_ceiling_is_returned_whole() {
        let path = scratch("small.json", b"{\"last_prevote_height\":7}");
        let got = read_to_string_bounded(&path, MAX_CONTROL_FILE_BYTES).expect("must read");
        assert_eq!(got, "{\"last_prevote_height\":7}");
    }

    /// The boundary itself is inside the ceiling, not over it.
    ///
    /// An off-by-one here would refuse a file that is exactly the documented
    /// size, which is the size an operator would produce when told the limit.
    #[test]
    fn a_file_exactly_at_the_ceiling_is_accepted() {
        let path = scratch("exact.txt", &b"a".repeat(64));
        let got = read_to_string_bounded(&path, 64).expect("64 bytes must fit a 64-byte ceiling");
        assert_eq!(got.len(), 64);
    }

    /// One byte over is refused, and the refusal names what was found.
    #[test]
    fn one_byte_over_the_ceiling_is_refused() {
        let path = scratch("over.txt", &b"a".repeat(65));
        let err = read_to_string_bounded(&path, 64).expect_err("65 bytes must not fit");
        match err {
            BoundedReadError::TooLarge {
                limit,
                actual: Some(n),
                ..
            } => {
                assert_eq!(limit, 64);
                assert_eq!(n, 65);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    /// The ceiling must hold when the reported length is a lie.
    ///
    /// This is the property the metadata check alone does not have, and it is
    /// the reason the read is bounded as well. `/proc` files report a length
    /// of zero and then produce content, so a `/proc` file sails straight past
    /// the metadata check and can only be stopped by the read itself.
    ///
    /// This test earns its place by mutation: replacing `limit + 1` with
    /// `limit` in the read bound - the silent-truncation bug - leaves every
    /// other test in this module green and fails only this one. A version of
    /// this test written against an ordinary small file with a limit of zero
    /// does NOT fail on that mutant, because the metadata check rejects the
    /// file before the read is reached. Measured, not assumed.
    #[test]
    fn the_read_enforces_the_ceiling_when_metadata_lies() {
        let proc_file = std::path::Path::new("/proc/self/status");
        if !proc_file.exists() {
            // Not Linux; the property is unobservable here rather than untrue.
            return;
        }
        assert_eq!(
            std::fs::metadata(proc_file).expect("stat").len(),
            0,
            "this test needs a file whose reported length is a lie"
        );

        let err = read_to_string_bounded(proc_file, 16)
            .expect_err("a file with content must not fit in 16 bytes");
        match err {
            // `actual: None` is the signature of the read path having done the
            // rejecting: the metadata check reports a size, the read cannot.
            BoundedReadError::TooLarge {
                limit,
                actual: None,
                ..
            } => assert_eq!(limit, 16),
            other => panic!("the read path must be what refuses, got {other:?}"),
        }

        // And a generous ceiling still returns the content, so the refusal
        // above is about the size and not about `/proc` being unreadable.
        let ok = read_to_string_bounded(proc_file, MAX_CONTROL_FILE_BYTES)
            .expect("a /proc file fits inside the control-file ceiling");
        assert!(ok.contains("Name:"), "content must come back whole");
    }

    /// A refusal must not be reported as a successful empty read.
    ///
    /// Truncating to the ceiling is the tempting implementation and the wrong
    /// one: the parser would then see a prefix of a snapshot and report a
    /// syntax error, sending the operator to look at the wrong thing.
    #[test]
    fn an_oversized_file_is_refused_rather_than_truncated() {
        let path = scratch("trunc.json", &b"{\"a\":\"".repeat(200));
        let err = read_to_string_bounded(&path, 32).expect_err("must refuse");
        assert!(matches!(err, BoundedReadError::TooLarge { .. }));
    }

    #[test]
    fn non_utf8_is_named_as_such() {
        let path = scratch("binary.bin", &[0xff, 0xfe, 0x00]);
        let err = read_to_string_bounded(&path, 1024).expect_err("must refuse");
        assert!(matches!(err, BoundedReadError::NotUtf8 { .. }));
    }

    #[test]
    fn a_missing_file_is_an_io_error_naming_the_path() {
        let path = std::path::Path::new("/nonexistent/budlum/never/here.json");
        let err = read_to_string_bounded(path, 1024).expect_err("must fail");
        match err {
            BoundedReadError::Io { path: p, .. } => assert_eq!(p, path),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    /// The message has to carry the three things an operator needs.
    #[test]
    fn the_refusal_names_the_path_the_limit_and_the_size() {
        let path = scratch("msg.txt", &b"a".repeat(100));
        let err = read_to_string_bounded(&path, 10).expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("msg.txt"), "must name the path: {msg}");
        assert!(msg.contains("10"), "must name the limit: {msg}");
        assert!(msg.contains("100"), "must name the actual size: {msg}");
    }

    /// An absent file is "not found"; an oversized one is not.
    ///
    /// Three call sites branch on this to decide between silence and a
    /// warning. If an oversized file ever answered `true` here it would be
    /// swallowed as a normal first boot, which is precisely the silence this
    /// module was written to remove.
    #[test]
    fn oversize_is_not_reported_as_a_missing_file() {
        let missing = read_to_string_bounded(
            std::path::Path::new("/nonexistent/budlum/never/here.json"),
            1024,
        )
        .expect_err("must fail");
        assert!(missing.is_not_found(), "an absent file is not-found");

        let path = scratch("present-but-huge.txt", &b"a".repeat(100));
        let oversize = read_to_string_bounded(&path, 10).expect_err("must refuse");
        assert!(
            !oversize.is_not_found(),
            "an oversized file is present and wrong, not missing"
        );

        let binary = scratch("present-but-binary.bin", &[0xff, 0xfe]);
        let not_utf8 = read_to_string_bounded(&binary, 1024).expect_err("must refuse");
        assert!(
            !not_utf8.is_not_found(),
            "a binary file is present and wrong, not missing"
        );
    }

    /// The ceilings must be ordered by what they hold, or one of them is wrong.
    #[test]
    fn the_ceilings_are_ordered_by_what_they_carry() {
        assert!(MAX_CONTROL_FILE_BYTES < MAX_BAN_LIST_BYTES);
        assert!(MAX_BAN_LIST_BYTES < MAX_SNAPSHOT_BYTES);
    }
}
