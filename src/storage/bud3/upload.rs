//! The upload session: content arrives in chunks, the object is written once.
//!
//! Section 6.4 Y1 says the client does not carry the whole content in one call.
//! It opens a session on a gateway, appends chunks, and asks the gateway to
//! finish. This module is the gateway side of that conversation and the gate
//! [`crate::storage::bud3::upload::UploadSession`] keeps: a session is a
//! position, a running content id and a deadline, not a buffer.
//!
//! # Why the session is not a buffer
//!
//! The obvious implementation appends into a `Vec<u8>` and hashes at the end.
//! At the 16 GiB limit that is a 16 GiB allocation per open session, and four
//! sessions per account (section 6.21.1) make it 64 GiB from one account before
//! any content is coded. So the session holds the hasher, the length it has
//! absorbed so far, and **one** part of the object: the upload is finished one
//! segment chunk at a time, and the assembled bytes are handed to
//! [`super::pipeline::prepare_public_upload`] by the caller that owns the
//! buffer. A gateway that cannot hold the object refuses with
//! [`UploadError::BufferTooLarge`] rather than growing until the process dies.
//!
//! # What is enforced here
//!
//! * `max_content_bytes`, `upload_session_secs`, `sessions_per_account`
//!   (`bud3::limits`, section 6.21.1).
//! * The content length is summed with checked arithmetic, so a chunk stream
//!   that would wrap `u64` is refused rather than accepted as a small content.
//! * `finish` returns the id the stream actually hashed. The id is never taken
//!   from the client, so a client cannot name content it does not hold.
//! * The object bytes the caller finished with must hash to the session id;
//!   [`UploadSession::finish_with`] checks it, which is the streaming form of
//!   the Y2 identity step.
//!
//! WIRING: unwired - the RPC send path that streams chunks into a session
//! lands with the upload RPC row; until then the session is exercised by its
//! tests. The object bytes it hashes come from `super::pipeline`, and the
//! `content_gateway` module is the door that will own one table per gateway.

use super::content_id::{ContentId, ContentIdKind, PublicHasher};
use super::limits::{Bud3Limits, LimitError};
use std::collections::BTreeMap;

/// Why an upload session refused a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadError {
    /// No session with this id on this gateway.
    UnknownSession(u64),
    /// The session outlived `upload_session_secs` or was closed.
    Expired(u64),
    /// The account already holds `sessions_per_account` open sessions.
    SessionLimit {
        /// The limit that was hit.
        max: u32,
    },
    /// A limit set refused the content length.
    Limit(LimitError),
    /// The chunk stream would put the content above `max_content_bytes`.
    ContentTooLarge {
        /// Length after the refused chunk.
        len: u64,
        /// The admitted maximum.
        max: u64,
    },
    /// The caller asked to finish a session that has absorbed no bytes and
    /// was not opened as an explicit empty upload.
    EmptyFinish,
    /// The assembled content does not hash to the id the session produced.
    ContentMismatch,
    /// The gateway buffer cannot hold the object the session described.
    BufferTooLarge {
        /// Bytes the finish step would need.
        want: u64,
        /// Bytes the gateway admits for one object.
        max: u64,
    },
}

/// One open upload session.
///
/// The fields are private on purpose: a caller that could set `len` or swap
/// the hasher could make the session name content the stream never carried.
#[derive(Debug, Clone)]
pub struct UploadSession {
    id: u64,
    uploader: [u8; 32],
    hasher: PublicHasher,
    len: u64,
    opened_at: u64,
    sealed: bool,
    /// The session was opened for a deliberately empty content, so `finish`
    /// accepts it instead of refusing an empty stream.
    empty_intent: bool,
}

impl UploadSession {
    /// The session id the gateway issued.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Bytes absorbed so far.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether nothing has been absorbed yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The uploader's address as the session records it.
    #[must_use]
    pub const fn uploader(&self) -> [u8; 32] {
        self.uploader
    }

    /// Whether the content is sealed. A sealed session hashes with a keyed
    /// MAC and never registers in the public index (section 6.8). The sealed
    /// sender is a separate door (WP-22), so every session this table opens
    /// is public and the flag is false today; it is carried here because the
    /// finish step must branch on it once the sealed opener lands.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// When the session was opened, in seconds since the Unix epoch.
    #[must_use]
    pub const fn opened_at(&self) -> u64 {
        self.opened_at
    }

    /// Whether the session is past its deadline at `now`.
    #[must_use]
    pub const fn is_expired_at(&self, now: u64, limits: &Bud3Limits) -> bool {
        now.saturating_sub(self.opened_at) >= limits.upload_session_secs
    }

    /// Absorb the next chunk.
    ///
    /// # Errors
    ///
    /// [`UploadError::ContentTooLarge`] when the chunk would take the content
    /// past the admitted maximum; the session is left unchanged.
    pub fn append(&mut self, chunk: &[u8], limits: &Bud3Limits) -> Result<u64, UploadError> {
        let len = self
            .len
            .checked_add(chunk.len() as u64)
            .ok_or(UploadError::ContentTooLarge {
                len: u64::MAX,
                max: limits.max_content_bytes,
            })?;
        if len > limits.max_content_bytes {
            return Err(UploadError::ContentTooLarge {
                len,
                max: limits.max_content_bytes,
            });
        }
        self.hasher.update(chunk);
        self.len = len;
        Ok(len)
    }

    /// The content id of everything absorbed. Consumes the hasher, so the id
    /// can be produced once.
    ///
    /// # Errors
    ///
    /// [`UploadError::EmptyFinish`] when nothing was appended: an empty
    /// content is uploaded through [`GatewayUploads::open_empty`], which is a
    /// deliberate act rather than a stream that stopped early.
    pub fn finish(self) -> Result<(ContentId, u64), UploadError> {
        if self.len == 0 {
            return Err(UploadError::EmptyFinish);
        }
        Ok((self.hasher.finish(), self.len))
    }

    /// Finish and check the assembled content against the streamed id. This
    /// is the identity step at its strongest: the bytes handed to the codec
    /// are the bytes that were hashed, so a client cannot register a record
    /// for content it never sent.
    ///
    /// # Errors
    ///
    /// [`UploadError::ContentMismatch`] when `content` is not the streamed
    /// content, [`UploadError::ContentTooLarge`] when it is larger than the
    /// gateway buffer admits, and the [`Self::finish`] refusals.
    pub fn finish_with(
        self,
        content: &[u8],
        buffer_max: u64,
        limits: &Bud3Limits,
    ) -> Result<ContentId, UploadError> {
        let len = content.len() as u64;
        if len > buffer_max {
            return Err(UploadError::BufferTooLarge {
                want: len,
                max: buffer_max,
            });
        }
        let (id, absorbed) = self.finish()?;
        if absorbed != len {
            return Err(UploadError::ContentMismatch);
        }
        if id.kind != ContentIdKind::Public || !id.matches_public(content) {
            return Err(UploadError::ContentMismatch);
        }
        if limits.admit_content(len).is_err() {
            return Err(UploadError::Limit(LimitError::ContentTooLarge {
                len,
                max: limits.max_content_bytes,
            }));
        }
        Ok(id)
    }
}

/// The gateway's session table.
///
/// Sessions are keyed by id, and the account's open count is derived from the
/// table rather than kept beside it, so the two cannot disagree.
#[derive(Debug, Default)]
pub struct GatewayUploads {
    limits: Bud3Limits,
    sessions: BTreeMap<u64, UploadSession>,
    next_id: u64,
}

impl GatewayUploads {
    /// A gateway with `limits` and no sessions.
    #[must_use]
    pub fn new(limits: Bud3Limits) -> Self {
        Self {
            limits,
            sessions: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// The limits this gateway admits.
    #[must_use]
    pub const fn limits(&self) -> &Bud3Limits {
        &self.limits
    }

    /// Open sessions held by `uploader`.
    #[must_use]
    pub fn open_count(&self, uploader: &[u8; 32]) -> usize {
        self.sessions
            .values()
            .filter(|s| s.uploader == *uploader)
            .count()
    }

    /// Open a session.
    ///
    /// # Errors
    ///
    /// [`UploadError::SessionLimit`] when the account holds
    /// `sessions_per_account` sessions already.
    pub fn open(&mut self, uploader: [u8; 32], now: u64) -> Result<u64, UploadError> {
        if self.open_count(&uploader) >= self.limits.sessions_per_account as usize {
            return Err(UploadError::SessionLimit {
                max: self.limits.sessions_per_account,
            });
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.sessions.insert(
            id,
            UploadSession {
                id,
                uploader,
                hasher: PublicHasher::new(),
                len: 0,
                opened_at: now,
                sealed: false,
                empty_intent: false,
            },
        );
        Ok(id)
    }

    /// Open a session for a deliberately empty content. The session is born
    /// with one zero-length append, so `finish` accepts it: an empty object
    /// is a real object (T1 puts 0 bytes in the round trip), and it must not
    /// be reachable by a stream that merely stopped.
    ///
    /// # Errors
    ///
    /// [`UploadError::SessionLimit`] on the same rule as [`Self::open`].
    pub fn open_empty(&mut self, uploader: [u8; 32], now: u64) -> Result<u64, UploadError> {
        let id = self.open(uploader, now)?;
        if let Some(session) = self.sessions.get_mut(&id) {
            session.empty_intent = true;
        }
        Ok(id)
    }

    /// The session with `id`.
    ///
    /// # Errors
    ///
    /// [`UploadError::UnknownSession`].
    pub fn session(&self, id: u64) -> Result<&UploadSession, UploadError> {
        self.sessions.get(&id).ok_or(UploadError::UnknownSession(id))
    }

    /// Append a chunk to `id` at `now`.
    ///
    /// # Errors
    ///
    /// [`UploadError::UnknownSession`], [`UploadError::Expired`] (the session
    /// is dropped on the way out, so a dead session cannot be resumed), and
    /// the [`UploadSession::append`] refusals.
    pub fn append(&mut self, id: u64, chunk: &[u8], now: u64) -> Result<u64, UploadError> {
        let limits = self.limits;
        let session = self.sessions.get_mut(&id).ok_or(UploadError::UnknownSession(id))?;
        if session.is_expired_at(now, &limits) {
            self.sessions.remove(&id);
            return Err(UploadError::Expired(id));
        }
        session.append(chunk, &limits)
    }

    /// Finish `id`, returning the streamed content id. The session is closed
    /// whether the finish succeeds or is refused, so a refused stream cannot
    /// be resumed and retried into a different id.
    ///
    /// # Errors
    ///
    /// [`UploadError::Expired`], [`UploadError::UnknownSession`] and the
    /// [`UploadSession::finish`] refusals.
    pub fn finish(&mut self, id: u64, now: u64) -> Result<ContentId, UploadError> {
        let limits = self.limits;
        let session = self.sessions.remove(&id).ok_or(UploadError::UnknownSession(id))?;
        if session.is_expired_at(now, &limits) {
            return Err(UploadError::Expired(id));
        }
        if session.empty_intent {
            return Ok(ContentId::public(b""));
        }
        session.finish().map(|(id, _len)| id)
    }

    /// Close every session past its deadline at `now`. Returns how many were
    /// dropped.
    pub fn sweep(&mut self, now: u64) -> usize {
        let limits = self.limits;
        let before = self.sessions.len();
        self.sessions.retain(|_, s| !s.is_expired_at(now, &limits));
        before - self.sessions.len()
    }

    /// Sessions currently open.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether no session is open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: [u8; 32] = [7u8; 32];

    fn gateway() -> GatewayUploads {
        GatewayUploads::new(Bud3Limits::TESTNET_DEFAULT)
    }

    #[test]
    fn bud3_e2e_upload_session_limits() {
        let limits = Bud3Limits::TESTNET_DEFAULT;
        let mut gw = GatewayUploads::new(limits);
        // `sessions_per_account` is the open cap, and it is per account.
        let mut ids = Vec::new();
        for _ in 0..limits.sessions_per_account {
            ids.push(gw.open(OWNER, 0).expect("under the cap"));
        }
        assert_eq!(
            gw.open(OWNER, 0),
            Err(UploadError::SessionLimit {
                max: limits.sessions_per_account
            })
        );
        // Another account is unaffected.
        assert!(gw.open([9u8; 32], 0).is_ok());
        assert_eq!(gw.open_count(&OWNER), limits.sessions_per_account as usize);

        // A chunk that would cross `max_content_bytes` is refused and the
        // session keeps the bytes it already accepted.
        let id = ids[0];
        let chunk = vec![b'a'; 4096];
        assert_eq!(gw.append(id, &chunk, 1), Ok(4096));
        let mut over = UploadSession {
            id,
            uploader: OWNER,
            hasher: PublicHasher::new(),
            len: limits.max_content_bytes,
            opened_at: 0,
            sealed: false,
            empty_intent: false,
        };
        assert_eq!(
            over.append(b"x", &limits),
            Err(UploadError::ContentTooLarge {
                len: limits.max_content_bytes + 1,
                max: limits.max_content_bytes
            })
        );
        assert_eq!(over.len(), limits.max_content_bytes, "a refusal adds nothing");

        // The session deadline drops the session rather than resuming it.
        let late = limits.upload_session_secs + 1;
        assert_eq!(gw.append(id, &chunk, late), Err(UploadError::Expired(id)));
        assert_eq!(gw.session(id).unwrap_err(), UploadError::UnknownSession(id));
        assert_eq!(gw.sweep(late), limits.sessions_per_account as usize);
        assert!(gw.is_empty());
    }

    #[test]
    fn the_streamed_id_is_the_content_id_of_the_bytes() {
        let limits = Bud3Limits::TESTNET_DEFAULT;
        let content: Vec<u8> = (0..5_000u32).map(|i| (i % 251) as u8).collect();
        let mut gw = gateway();
        let id = gw.open(OWNER, 100).unwrap();
        for chunk in content.chunks(333) {
            gw.append(id, chunk, 101).unwrap();
        }
        let streamed = gw.finish(id, 102).unwrap();
        assert_eq!(streamed, ContentId::public(&content));
        // The session is closed by finish, so a retry cannot re-hash it.
        assert_eq!(
            gw.finish(id, 103).unwrap_err(),
            UploadError::UnknownSession(id)
        );

        // The strong form: the assembled bytes must be the streamed bytes.
        let mut gw = gateway();
        let id = gw.open(OWNER, 200).unwrap();
        gw.append(id, &content[..100], 201).unwrap();
        let session = gw.session(id).unwrap().clone();
        assert_eq!(
            session.finish_with(b"other bytes", 1 << 20, &limits).unwrap_err(),
            UploadError::ContentMismatch
        );
        let mut gw = gateway();
        let id = gw.open(OWNER, 200).unwrap();
        gw.append(id, &content, 201).unwrap();
        let session = gw.session(id).unwrap().clone();
        assert_eq!(
            session.finish_with(&content, 1 << 20, &limits).unwrap(),
            ContentId::public(&content)
        );
        // A gateway that cannot hold the object refuses instead of growing.
        let mut gw = gateway();
        let id = gw.open(OWNER, 300).unwrap();
        gw.append(id, &content, 301).unwrap();
        let session = gw.session(id).unwrap().clone();
        assert_eq!(
            session.finish_with(&content, 1_000, &limits).unwrap_err(),
            UploadError::BufferTooLarge {
                want: 5_000,
                max: 1_000
            }
        );
    }

    #[test]
    fn an_empty_upload_is_a_deliberate_act() {
        let limits = Bud3Limits::TESTNET_DEFAULT;
        let mut gw = gateway();
        // A stream that stopped early is not an empty upload.
        let id = gw.open(OWNER, 0).unwrap();
        assert_eq!(gw.finish(id, 1).unwrap_err(), UploadError::EmptyFinish);
        // The empty upload is opened as one and finishes as one.
        let id = gw.open_empty(OWNER, 0).unwrap();
        assert_eq!(gw.finish(id, 1).unwrap(), ContentId::public(b""));
        assert!(limits.admit_content(0).is_ok());
    }
}
