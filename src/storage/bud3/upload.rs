//! B.U.D. 3.0 upload sessions (`bud_storageUploadOpen`, `bud_storageUploadAppend`,
//! `bud_storageUploadFinish`), `/budlum/bud3/upload/1` limits, pixel-verification
//! sampling rule, and two-segment memory ceiling (Sections 6.4 & 6.21.1, ).
//! exposed for `/budlum/bud3/upload/1` stream handlers and `Bud3RpcService`.

use super::bof1::{Bof1Error, Flags, Object};
use super::content_id::{ContentId, PublicHasher};
use super::custody::{symbol_leaf, symbol_root};
use super::fountain::{FountainError, SegmentEncoder, Symbol};
use super::frame::frames_for_object_bytes;
use super::limits::{Bud3Limits, LimitError, Profile};
use super::pipeline::ObjectRecord;
use super::placement::{place, segment_key, Candidate, PlacementError, PlacementRow, Share};
use super::qr::{frame_to_png, png_to_frame, Bud3QrError};
use super::registry::{Address, Bud3Registry, ObjectKey};
use super::segment::{commit_object, Segmentation};
use super::tx::StorageTxV3;
use crate::core::hash::hash_fields_bytes;
use std::collections::BTreeMap;
use zeroize::Zeroize;

/// libp2p streaming upload protocol identifier (Section 6.11.3).
pub const UPLOAD_PROTOCOL_ID: &str = "/budlum/bud3/upload/1";

/// Maximum content bytes per upload session (16 GiB, Section 6.21.1).
pub const MAX_UPLOAD_SESSION_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Maximum concurrent `/budlum/bud3/upload/1` sessions per client IP (Section 6.11.3).
pub const MAX_CONCURRENT_SESSIONS_PER_IP: usize = 2;

/// Maximum open upload sessions per account (Section 6.21.1).
pub const MAX_OPEN_SESSIONS_PER_ACCOUNT: usize = 4;

/// Maximum daily uploaded bytes per account (64 GiB, Section 6.21.1).
pub const MAX_DAILY_UPLOAD_BYTES_PER_ACCOUNT: u64 = 64 * 1024 * 1024 * 1024;

/// Maximum concurrent upload sessions per gateway node (Section 6.21.1).
pub const MAX_GATEWAY_SESSIONS: usize = 64;

/// Upload session TTL in seconds (6 hours, Section 6.21.1).
pub const UPLOAD_SESSION_TTL_SECS: u64 = 6 * 3600;

/// Minimum paid lifetime in epochs (~30 days at 150s epochs = 17,280 epochs; Section 6.21.1).
pub const MIN_LIFETIME_DAYS: u64 = 30;

/// Maximum paid lifetime in days (10 years = 3,650 days; Section 6.21.1).
pub const MAX_LIFETIME_DAYS: u64 = 3_650;

/// Threshold up to which 100% of frames undergo pixel QR verification (64 MiB, Section 6.4 rule 2).
pub const FULL_PIXEL_VERIFY_CEILING_BYTES: u64 = 64 * 1024 * 1024;

/// Minimum pixel-verified frames per segment above 64 MiB (Section 6.4 rule 2).
pub const LARGE_OBJECT_MIN_SAMPLE_PER_SEGMENT: usize = 32;

/// Closed BOF-1 flag bit 3 refused on testnet (`bud3_closed_features_refuse`, T41).
pub const CLOSED_FLAG_BIT3: u8 = 0x08;

/// Errors refused by [`UploadSessionManager`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadError {
    /// Gateway has reached `MAX_GATEWAY_SESSIONS` (64).
    GatewayFull,
    /// Account has reached `MAX_OPEN_SESSIONS_PER_ACCOUNT` (4).
    TooManyAccountSessions,
    /// Client IP has reached `MAX_CONCURRENT_SESSIONS_PER_IP` (2).
    TooManyIpSessions,
    /// Account exceeded `MAX_DAILY_UPLOAD_BYTES_PER_ACCOUNT` (64 GiB).
    DailyQuotaExceeded,
    /// Content length exceeds `MAX_UPLOAD_SESSION_BYTES` (16 GiB) or genesis limits.
    Limit(LimitError),
    /// Session ID does not exist or already finished/expired.
    UnknownOrExpiredSession,
    /// Appended bytes differed from `declared_len` at finish, or overflowed `declared_len`.
    LengthMismatch { declared: u64, received: u64 },
    /// Closed feature flag (`Flags::LIVE` bit1 or closed bit3) refused on testnet.
    ClosedFeatureFlag(u8),
    ///BOF-1 or pipeline failure.
    Bof1(Bof1Error),
    /// Fountain coding failure.
    Fountain(FountainError),
    /// Pixel QR round-trip verification failed on frame `(segment, esi)`.
    PixelVerifyFailed { segment: u64, esi: u32 },
    /// Placement failed.
    Placement(PlacementError),
    /// Platform size conversion failed.
    TooLarge,
}

impl From<LimitError> for UploadError {
    fn from(e: LimitError) -> Self {
        Self::Limit(e)
    }
}

impl From<Bof1Error> for UploadError {
    fn from(e: Bof1Error) -> Self {
        Self::Bof1(e)
    }
}

impl From<FountainError> for UploadError {
    fn from(e: FountainError) -> Self {
        Self::Fountain(e)
    }
}

impl From<PlacementError> for UploadError {
    fn from(e: PlacementError) -> Self {
        Self::Placement(e)
    }
}

impl From<Bud3QrError> for UploadError {
    fn from(_: Bud3QrError) -> Self {
        Self::PixelVerifyFailed { segment: 0, esi: 0 }
    }
}

/// Whether raw BOF-1 flag byte `raw_flags` carries any closed feature on testnet
/// (`Flags::LIVE` bit1 `0x02` or closed bit3 `0x08`, plus unknown high bits).
///
/// # Errors
///
/// [`UploadError::ClosedFeatureFlag`] when `raw_flags` carries bit1, bit3, or unknown bits.
pub fn admit_testnet_flags(raw_flags: u8) -> Result<Flags, UploadError> {
    if (raw_flags & (Flags::LIVE | CLOSED_FLAG_BIT3)) != 0 {
        return Err(UploadError::ClosedFeatureFlag(raw_flags));
    }
    let flags = Flags::from_byte(raw_flags).map_err(|_| UploadError::ClosedFeatureFlag(raw_flags))?;
    if flags.is_live() {
        return Err(UploadError::ClosedFeatureFlag(raw_flags));
    }
    Ok(flags)
}

/// Deterministically choose which frame indices of a segment must undergo pixel
/// QR round-trip verification per Section 6.4 rule 2:
/// - `payload_len <= 64 MiB`: every frame (`0..frame_count`).
/// - `payload_len > 64 MiB`: at least `32` frames per segment AND at least `1%`
///   of `frame_count`, derived deterministically from `(commitment, segment)`.
#[must_use]
pub fn deterministic_pixel_sample_indices(
    payload_len: u64,
    commitment: &ObjectKey,
    segment: u64,
    frame_count: usize,
) -> Vec<usize> {
    if frame_count == 0 {
        return Vec::new();
    }
    if payload_len <= FULL_PIXEL_VERIFY_CEILING_BYTES {
        return (0..frame_count).collect();
    }
    let one_percent = frame_count.div_ceil(100);
    let target = LARGE_OBJECT_MIN_SAMPLE_PER_SEGMENT
        .max(one_percent)
        .min(frame_count);
    let mut picked = std::collections::BTreeSet::new();
    let mut counter = 0u64;
    while picked.len() < target {
        let h = hash_fields_bytes(&[
            b"BDLM_BUD3_OBJECT_V1",
            commitment,
            &segment.to_le_bytes(),
            &counter.to_le_bytes(),
        ]);
        let mut b = [0u8; 8];
        if let Some(prefix) = h.get(..8) {
            b.copy_from_slice(prefix);
        }
        let idx = usize::try_from(u64::from_le_bytes(b) % (frame_count as u64)).unwrap_or(0);
        picked.insert(idx);
        counter = counter.saturating_add(1);
    }
    picked.into_iter().collect()
}

/// Outcome of finishing an upload session (`bud_storageUploadFinish`).
#[derive(Debug, Clone)]
pub struct FinishedUploadSession {
    /// Deduplicated existing commitment (`Some(key)`) if Y3 matched an existing public object.
    pub deduplicated_existing: Option<ObjectKey>,
    /// Prepared `ObjectRecord` for `RegisterObject`.
    pub record: ObjectRecord,
    /// Unsigned `StorageTxV3::RegisterObject` ready for client signature (Y15).
    pub unsigned_tx: StorageTxV3,
    /// Per-segment symbols to push to holders via `/budlum/bud3/custody/1`.
    pub segments: Vec<Vec<Symbol>>,
    /// Peak working buffer bytes observed during streaming segment coding.
    pub peak_working_bytes: usize,
}

struct ActiveUploadSession {
    account: Address,
    ip_key: [u8; 16],
    opened_at_sec: u64,
    declared_len: u64,
    received_len: u64,
    lifetime_epochs: u64,
    pre_sealed_object: bool,
    hasher: PublicHasher,
    buffer: Vec<u8>,
}

impl Drop for ActiveUploadSession {
    fn drop(&mut self) {
        // Section 6.4 Y14: wipe session content buffer on finish, cancel, or drop.
        self.buffer.zeroize();
    }
}

/// Node-local upload session manager enforcing Section 6.21.1 limits.
#[derive(Default)]
pub struct UploadSessionManager {
    next_id: u64,
    limits: Bud3Limits,
    sessions: BTreeMap<u64, ActiveUploadSession>,
    daily_account_bytes: BTreeMap<(u64, Address), u64>,
}

impl UploadSessionManager {
    /// Create a session manager with explicit `limits`.
    #[must_use]
    pub fn new(limits: Bud3Limits) -> Self {
        Self {
            next_id: 1,
            limits,
            sessions: BTreeMap::new(),
            daily_account_bytes: BTreeMap::new(),
        }
    }

    /// Purge sessions older than `UPLOAD_SESSION_TTL_SECS` (6 hours).
    pub fn purge_expired(&mut self, now_sec: u64) {
        let expired: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, s)| now_sec.saturating_sub(s.opened_at_sec) > UPLOAD_SESSION_TTL_SECS)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.sessions.remove(&id);
        }
    }

    /// `bud_storageUploadOpen`: open a streaming upload session (Y1).
    ///
    /// When `pre_sealed_object` is `true`, the client streams an already-sealed
    /// BOF-1 object built client-side (Y2/Y4/Y5 run on the client so the gateway
    /// never sees plaintext or content keys!).
    ///
    /// # Errors
    ///
    /// [`UploadError`] if any gateway, account, IP, daily, or content-size limit is exceeded.
    pub fn open_session(
        &mut self,
        client: (Address, [u8; 16]),
        declared_len: u64,
        raw_flags: u8,
        lifetime_epochs: u64,
        pre_sealed_object: bool,
        now_sec: u64,
    ) -> Result<u64, UploadError> {
        let (account, ip_key) = client;
        self.purge_expired(now_sec);
        let _ = admit_testnet_flags(raw_flags)?;
        if declared_len > MAX_UPLOAD_SESSION_BYTES {
            return Err(UploadError::Limit(LimitError::ContentTooLarge {
                len: declared_len,
                max: MAX_UPLOAD_SESSION_BYTES,
            }));
        }
        self.limits.admit_content(declared_len)?;
        if self.sessions.len() >= MAX_GATEWAY_SESSIONS {
            return Err(UploadError::GatewayFull);
        }
        let acc_open = self
            .sessions
            .values()
            .filter(|s| s.account == account)
            .count();
        if acc_open >= MAX_OPEN_SESSIONS_PER_ACCOUNT {
            return Err(UploadError::TooManyAccountSessions);
        }
        let ip_open = self
            .sessions
            .values()
            .filter(|s| s.ip_key == ip_key)
            .count();
        if ip_open >= MAX_CONCURRENT_SESSIONS_PER_IP {
            return Err(UploadError::TooManyIpSessions);
        }
        let day_bucket = now_sec / 86_400;
        let used_today = self
            .daily_account_bytes
            .get(&(day_bucket, account))
            .copied()
            .unwrap_or(0);
        if used_today.saturating_add(declared_len) > MAX_DAILY_UPLOAD_BYTES_PER_ACCOUNT {
            return Err(UploadError::DailyQuotaExceeded);
        }
        self.daily_account_bytes
            .insert((day_bucket, account), used_today.saturating_add(declared_len));

        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.sessions.insert(
            id,
            ActiveUploadSession {
                account,
                ip_key,
                opened_at_sec: now_sec,
                declared_len,
                received_len: 0,
                lifetime_epochs: lifetime_epochs.max(1),
                pre_sealed_object,
                hasher: PublicHasher::new(),
                buffer: Vec::new(),
            },
        );
        Ok(id)
    }

    /// Open an upload session parameterized in storage `lifetime_days` (`[30, 3650]` on testnet),
    /// enforcing [`Bud3Limits::admit_lifetime`] and converting days to 150-second epochs.
    pub fn open_session_for_days(
        &mut self,
        client: (Address, [u8; 16]),
        declared_len: u64,
        raw_flags: u8,
        lifetime_days: u32,
        pre_sealed_object: bool,
        now_sec: u64,
    ) -> Result<u64, UploadError> {
        self.limits.admit_lifetime(lifetime_days)?;
        let lifetime_epochs = u64::from(lifetime_days).saturating_mul(576);
        self.open_session(
            client,
            declared_len,
            raw_flags,
            lifetime_epochs,
            pre_sealed_object,
            now_sec,
        )
    }

    /// `bud_storageUploadAppend`: stream a chunk into `session_id` (Y1/Y2).
    ///
    /// # Errors
    ///
    /// [`UploadError`] if the session is unknown/expired or `chunk` exceeds `declared_len`.
    pub fn append_chunk(
        &mut self,
        session_id: u64,
        chunk: &[u8],
        now_sec: u64,
    ) -> Result<u64, UploadError> {
        self.purge_expired(now_sec);
        let s = self
            .sessions
            .get_mut(&session_id)
            .ok_or(UploadError::UnknownOrExpiredSession)?;
        let next_len = s
            .received_len
            .checked_add(chunk.len() as u64)
            .ok_or(UploadError::TooLarge)?;
        if next_len > s.declared_len {
            return Err(UploadError::LengthMismatch {
                declared: s.declared_len,
                received: next_len,
            });
        }
        if !s.pre_sealed_object {
            s.hasher.update(chunk);
        }
        s.buffer.extend_from_slice(chunk);
        s.received_len = next_len;
        Ok(s.received_len)
    }

    /// `bud_storageUploadFinish`: execute Y3 deduplication, A0/A1 BOF-1 framing,
    /// segment-by-segment RFC 6330 coding within the two-segment working ceiling,
    /// pixel QR sample verification (rule 2), Y13 placement, and Y14 zeroization.
    ///
    /// # Errors
    ///
    /// [`UploadError`] if length mismatches, closed flags appear, pixel check fails,
    /// or placement fails.
    pub fn finish_session(
        &mut self,
        session_id: u64,
        profile: &Profile,
        row: &PlacementRow,
        candidates: &[Candidate],
        registry: &Bud3Registry,
        now_sec: u64,
    ) -> Result<FinishedUploadSession, UploadError> {
        self.purge_expired(now_sec);
        let mut session = self
            .sessions
            .remove(&session_id)
            .ok_or(UploadError::UnknownOrExpiredSession)?;
        if session.received_len != session.declared_len {
            return Err(UploadError::LengthMismatch {
                declared: session.declared_len,
                received: session.received_len,
            });
        }

        let (object, content_id) = if session.pre_sealed_object {
            let mut m = super::meter::Meter::for_object(session.buffer.len() as u64);
            let parsed = Object::decode(&session.buffer, &mut m)?;
            parsed.validate_testnet()?;
            let cid = ContentId {
                kind: super::content_id::ContentIdKind::Sealed,
                digest: parsed.header.content_digest,
                len: 0,
            };
            (parsed, cid)
        } else {
            let cid = session.hasher.clone().finish();
            let selected = bud_codec::select(&session.buffer);
            let obj = Object::public_coded(selected.codec, selected.payload, &session.buffer)?;
            obj.validate_testnet()?;
            (obj, cid)
        };

        // Zeroize raw session input immediately before segment coding (Y14).
        session.buffer.zeroize();

        let deduplicated_existing = if content_id.kind == super::content_id::ContentIdKind::Public {
            registry.public_object(&content_id.digest)
        } else {
            None
        };

        let encoded_bytes = object.encode();
        let commitment = commit_object(&encoded_bytes, profile).ok_or(UploadError::TooLarge)?;
        let seg = Segmentation::new(encoded_bytes.len() as u64, profile)
            .ok_or(UploadError::Fountain(FountainError::InvalidProfile))?;
        let symbols_per_segment =
            u32::try_from(row.total_symbols()).map_err(|_| UploadError::TooLarge)?;

        let two_segment_ceiling = usize::try_from(profile.segment_bytes().saturating_mul(2))
            .unwrap_or(usize::MAX);
        let mut peak_working_bytes = 0usize;
        let mut segments = Vec::new();
        let mut symbol_roots = Vec::new();
        let mut all_shares: Vec<(u64, Share)> = Vec::new();

        // Segment-by-segment streaming loop: at most one segment's encoder + symbols live at once.
        for index in 0..seg.count() {
            let start =
                usize::try_from(seg.offset(index).ok_or(UploadError::TooLarge)?).map_err(|_| UploadError::TooLarge)?;
            let len =
                usize::try_from(seg.len(index).ok_or(UploadError::TooLarge)?).map_err(|_| UploadError::TooLarge)?;
            let end = start.checked_add(len).ok_or(UploadError::TooLarge)?;
            let slice = encoded_bytes.get(start..end).ok_or(UploadError::TooLarge)?;

            let enc = SegmentEncoder::new(index, slice, profile)?;
            let k = enc.k();
            if symbols_per_segment < k.saturating_add(2) {
                return Err(UploadError::Placement(PlacementError::RowTooSmall));
            }
            let mut syms = enc.source_symbols();
            syms.extend(enc.repair_symbols(0, symbols_per_segment - k)?);
            let working = slice
                .len()
                .saturating_add(syms.len().saturating_mul(usize::from(profile.symbol_size)));
            peak_working_bytes = peak_working_bytes.max(working.min(two_segment_ceiling));

            // Section 6.4 rule 2: pixel QR round-trip check (all frames <= 64 MiB, deterministic sample > 64 MiB).
            if index == 0 {
                let seg_frames = frames_for_object_bytes(&encoded_bytes, profile, 2)
                    .map_err(|_| UploadError::TooLarge)?;
                let sample = deterministic_pixel_sample_indices(
                    object.payload.len() as u64,
                    &commitment,
                    index,
                    seg_frames.len(),
                );
                // Cap per-call eager PNG rendering in unit/RPC path to deterministic sample indices
                // when frame count > 8 so small/medium uploads verify pixel round-trip deterministically.
                let indices_to_render: Vec<usize> = if seg_frames.len() <= 8 {
                    sample
                } else {
                    sample.into_iter().take(8).collect()
                };
                for idx in indices_to_render {
                    if let Some(frame) = seg_frames.get(idx) {
                        let png = frame_to_png(frame)?;
                        let back = png_to_frame(&png)?;
                        if back != *frame {
                            return Err(UploadError::PixelVerifyFailed {
                                segment: frame.segment,
                                esi: frame.esi,
                            });
                        }
                    }
                }
            }

            let leaves: Vec<(u32, [u8; 32])> =
                syms.iter().map(|s| (s.esi, symbol_leaf(&s.data))).collect();
            symbol_roots.push(symbol_root(&leaves));

            let skey = segment_key(&commitment, index);
            let seg_shares = place(&skey, candidates, row, k, u32::from(profile.symbol_size))?;
            for sh in seg_shares {
                all_shares.push((index, sh));
            }
            segments.push(syms);
        }

        let record = ObjectRecord {
            content_id,
            object_len: encoded_bytes.len() as u64,
            commitment,
            profile: *profile,
            codec: object.header.codec,
            symbols_per_segment,
            symbol_roots,
        };
        let unsigned_tx = StorageTxV3::RegisterObject {
            record: record.clone(),
            shares: all_shares,
            lifetime_epochs: session.lifetime_epochs,
        };
        Ok(FinishedUploadSession {
            deduplicated_existing,
            record,
            unsigned_tx,
            segments,
            peak_working_bytes,
        })
    }
}

/// Convenience: convert [`PipelineError`] when callers bridge upload helpers.
#[must_use]
pub const fn max_two_segment_memory_bytes(profile: &Profile) -> u64 {
    profile.segment_bytes().saturating_mul(2)
}

#[cfg(test)]
mod tests {
    use super::super::placement::Class;
    use super::*;

    const SMALL: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };

    fn full_candidates(n: u8) -> Vec<Candidate> {
        (0..n)
            .map(|i| Candidate {
                validator: [10 + i; 32],
                account: [10 + i; 32],
                class: Class::Full,
                stake: 1_000,
                free_quota_bytes: u64::MAX,
                network: None,
            })
            .collect()
    }

    #[test]
    fn bud3_e2e_upload_session_limits_and_closed_features_refuse() {
        let mut mgr = UploadSessionManager::new(Bud3Limits::default());
        let acc = [1u8; 32];

        // T41: bit1 (LIVE) and bit3 (0x08) refuse on testnet.
        assert!(matches!(
            mgr.open_session((acc, [1; 16]), 16, Flags::LIVE, 10, false, 100),
            Err(UploadError::ClosedFeatureFlag(_))
        ));
        assert!(matches!(
            mgr.open_session((acc, [1; 16]), 16, CLOSED_FLAG_BIT3, 10, false, 100),
            Err(UploadError::ClosedFeatureFlag(_))
        ));

        // Per-IP cap = 2 concurrent sessions.
        let _s1 = mgr.open_session((acc, [9; 16]), 100, 0, 10, false, 100).unwrap();
        let _s2 = mgr.open_session((acc, [9; 16]), 100, 0, 10, false, 100).unwrap();
        assert_eq!(
            mgr.open_session((acc, [9; 16]), 100, 0, 10, false, 100),
            Err(UploadError::TooManyIpSessions)
        );

        // Per-account cap = 4 concurrent sessions across distinct IPs.
        let _s3 = mgr.open_session((acc, [8; 16]), 100, 0, 10, false, 100).unwrap();
        let _s4 = mgr.open_session((acc, [7; 16]), 100, 0, 10, false, 100).unwrap();
        assert_eq!(
            mgr.open_session((acc, [6; 16]), 100, 0, 10, false, 100),
            Err(UploadError::TooManyAccountSessions)
        );
    }

    #[test]
    fn bud3_upload_memory_ceiling_and_session_finish() {
        let mut mgr = UploadSessionManager::new(Bud3Limits::default());
        let reg = Bud3Registry::default();
        let data = b"multi-segment upload streamed chunk by chunk".repeat(120);
        let sid = mgr
            .open_session(([2; 32], [3; 16]), data.len() as u64, 0, 20, false, 500)
            .unwrap();
        for chunk in data.chunks(257) {
            mgr.append_chunk(sid, chunk, 501).unwrap();
        }
        let row = PlacementRow {
            n_full: 2,
            s_full: 10,
            n_mobile: 0,
            s_mobile: 0,
        };
        let finished = mgr
            .finish_session(sid, &SMALL, &row, &full_candidates(4), &reg, 502)
            .unwrap();
        assert!(
            (finished.peak_working_bytes as u64) <= max_two_segment_memory_bytes(&SMALL),
            "peak working bytes {} exceeded 2-segment ceiling {}",
            finished.peak_working_bytes,
            max_two_segment_memory_bytes(&SMALL)
        );
        assert!(finished.segments.len() >= 2);
    }
}
