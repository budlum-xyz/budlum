//! Profiles and the B.U.D. 3.0 limits.
//!
//! Every limit is a genesis parameter. The values in
//! [`Bud3Limits::TESTNET_DEFAULT`] are starting points: governance changes
//! them once measurements arrive. The segment ceiling is not a parameter: it
//! follows from the profile (`k_max` x `symbol_size`).

use serde::{Deserialize, Serialize};

/// Registered profile id. P0 is 0.
pub type ProfileId = u16;

/// One GiB.
pub const GIB: u64 = 1 << 30;

/// The RFC 6330 ceiling of source symbols in one source block.
pub const RFC6330_MAX_SOURCE_SYMBOLS: u32 = 56_403;

/// A transfer profile: the QR and fountain parameters an object is coded with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// Registered id.
    pub id: ProfileId,
    /// QR version of one frame.
    pub qr_version: u8,
    /// Symbol size in bytes: the payload of one QR frame.
    pub symbol_size: u16,
    /// Frames per second of the optical video.
    pub fps: u16,
    /// Source symbols per segment.
    pub k_max: u32,
}

impl Profile {
    /// P0, the canonical profile: QR version 40, ECC L, byte mode, symbol 2911
    /// bytes, 10 fps, `K_MAX` 4096. Identity, storage symbols and the logical
    /// path use it.
    pub const P0: Self = Self {
        id: 0,
        qr_version: 40,
        symbol_size: 2911,
        fps: 10,
        k_max: 4096,
    };

    /// The registered profile with this id. Only P0 is registered: P1 (the
    /// optical profile) is derived per request and never written in an object.
    #[must_use]
    pub const fn by_id(id: ProfileId) -> Option<Self> {
        match id {
            0 => Some(Self::P0),
            _ => None,
        }
    }

    /// The largest segment in bytes.
    #[must_use]
    pub const fn segment_bytes(&self) -> u64 {
        self.k_max as u64 * self.symbol_size as u64
    }

    /// Whether the parameters are usable for RFC 6330 coding.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.symbol_size > 0 && self.k_max > 0 && self.k_max <= RFC6330_MAX_SOURCE_SYMBOLS
    }
}

/// The B.U.D. 3.0 limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bud3Limits {
    /// Largest content in bytes.
    pub max_content_bytes: u64,
    /// Largest aggregation volume in bytes. Small objects share one volume
    /// (section 6.12 item 6), and the volume is coded as one segment, so the
    /// effective capacity is the smaller of this and the segment.
    pub volume_bytes: u64,
    /// Lifetime of an upload session, in seconds.
    pub upload_session_secs: u64,
    /// Open upload sessions per account.
    pub sessions_per_account: u32,
    /// Bytes one account may upload per day.
    pub daily_upload_bytes_per_account: u64,
    /// Concurrent sessions per gateway.
    pub sessions_per_gateway: u32,
    /// Shortest storage lifetime, in days.
    pub min_lifetime_days: u32,
    /// Longest storage lifetime, in days.
    pub max_lifetime_days: u32,
    /// Smallest mobile custody quota in bytes.
    pub mobile_quota_min_bytes: u64,
    /// Largest mobile custody quota in bytes.
    pub mobile_quota_max_bytes: u64,
}

/// Why a limit set or a request against it was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitError {
    /// A minimum is above its maximum, or a limit is zero.
    Inconsistent(&'static str),
    /// The content is larger than `max_content_bytes`.
    ContentTooLarge { len: u64, max: u64 },
    /// The lifetime is outside `[min, max]`.
    LifetimeOutOfRange { days: u32 },
    /// The mobile quota is outside `[min, max]`.
    QuotaOutOfRange { bytes: u64 },
}

impl Bud3Limits {
    /// TESTNET-DEFAULT values.
    pub const TESTNET_DEFAULT: Self = Self {
        max_content_bytes: 16 * GIB,
        volume_bytes: super::volume::DEFAULT_VOLUME_BYTES,
        upload_session_secs: 6 * 3600,
        sessions_per_account: 4,
        daily_upload_bytes_per_account: 64 * GIB,
        sessions_per_gateway: 64,
        min_lifetime_days: 30,
        max_lifetime_days: 3650,
        mobile_quota_min_bytes: GIB,
        mobile_quota_max_bytes: 64 * GIB,
    };

    /// Check that the set is internally consistent. Genesis loading calls
    /// this, so a bad parameter file never starts a chain.
    ///
    /// # Errors
    ///
    /// [`LimitError::Inconsistent`] naming the first bad field.
    pub const fn validate(&self) -> Result<(), LimitError> {
        if self.max_content_bytes == 0 {
            return Err(LimitError::Inconsistent("max_content_bytes is zero"));
        }
        if self.volume_bytes == 0 {
            return Err(LimitError::Inconsistent("volume_bytes is zero"));
        }
        if self.upload_session_secs == 0 {
            return Err(LimitError::Inconsistent("upload_session_secs is zero"));
        }
        if self.sessions_per_account == 0 || self.sessions_per_gateway == 0 {
            return Err(LimitError::Inconsistent("a session limit is zero"));
        }
        if self.daily_upload_bytes_per_account < self.max_content_bytes {
            return Err(LimitError::Inconsistent(
                "the daily upload limit is below one maximum content",
            ));
        }
        if self.min_lifetime_days == 0 || self.min_lifetime_days > self.max_lifetime_days {
            return Err(LimitError::Inconsistent("lifetime bounds"));
        }
        if self.mobile_quota_min_bytes == 0
            || self.mobile_quota_min_bytes > self.mobile_quota_max_bytes
        {
            return Err(LimitError::Inconsistent("mobile quota bounds"));
        }
        Ok(())
    }

    /// Admit a content length.
    ///
    /// # Errors
    ///
    /// [`LimitError::ContentTooLarge`].
    pub const fn admit_content(&self, len: u64) -> Result<(), LimitError> {
        if len > self.max_content_bytes {
            return Err(LimitError::ContentTooLarge {
                len,
                max: self.max_content_bytes,
            });
        }
        Ok(())
    }

    /// Admit a storage lifetime.
    ///
    /// # Errors
    ///
    /// [`LimitError::LifetimeOutOfRange`].
    pub const fn admit_lifetime(&self, days: u32) -> Result<(), LimitError> {
        if days < self.min_lifetime_days || days > self.max_lifetime_days {
            return Err(LimitError::LifetimeOutOfRange { days });
        }
        Ok(())
    }

    /// Admit a mobile custody quota.
    ///
    /// # Errors
    ///
    /// [`LimitError::QuotaOutOfRange`].
    pub const fn admit_mobile_quota(&self, bytes: u64) -> Result<(), LimitError> {
        if bytes < self.mobile_quota_min_bytes || bytes > self.mobile_quota_max_bytes {
            return Err(LimitError::QuotaOutOfRange { bytes });
        }
        Ok(())
    }
}

impl Default for Bud3Limits {
    fn default() -> Self {
        Self::TESTNET_DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p0_matches_the_canonical_profile() {
        let p = Profile::P0;
        assert_eq!(
            (p.id, p.qr_version, p.symbol_size, p.fps, p.k_max),
            (0, 40, 2911, 10, 4096)
        );
        assert!(p.is_valid());
        // About 11.9 MB per segment.
        assert_eq!(p.segment_bytes(), 11_923_456);
        assert_eq!(Profile::by_id(0), Some(Profile::P0));
        assert_eq!(Profile::by_id(1), None, "P1 is never written in an object");
    }

    #[test]
    fn profiles_above_the_rfc_ceiling_are_invalid() {
        let mut p = Profile::P0;
        p.k_max = RFC6330_MAX_SOURCE_SYMBOLS + 1;
        assert!(!p.is_valid());
        p.k_max = 0;
        assert!(!p.is_valid());
    }

    #[test]
    fn bud3_limits_are_genesis_parameters() {
        let l = Bud3Limits::default();
        assert_eq!(l, Bud3Limits::TESTNET_DEFAULT);
        assert!(l.validate().is_ok());
        assert_eq!(l.max_content_bytes, 16 * GIB);
        assert_eq!(l.volume_bytes, super::super::volume::DEFAULT_VOLUME_BYTES);
        assert_eq!(l.upload_session_secs, 21_600);
        assert_eq!(l.max_lifetime_days, 3650);

        // The set round-trips through the genesis encoding unchanged.
        let json = serde_json::to_string(&l).unwrap();
        let back: Bud3Limits = serde_json::from_str(&json).unwrap();
        assert_eq!(back, l);

        let mut bad = l;
        bad.min_lifetime_days = bad.max_lifetime_days + 1;
        assert!(bad.validate().is_err());
        let mut bad = l;
        bad.daily_upload_bytes_per_account = bad.max_content_bytes - 1;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn requests_outside_the_limits_are_refused() {
        let l = Bud3Limits::TESTNET_DEFAULT;
        assert!(l.admit_content(16 * GIB).is_ok());
        assert_eq!(
            l.admit_content(16 * GIB + 1),
            Err(LimitError::ContentTooLarge {
                len: 16 * GIB + 1,
                max: 16 * GIB
            })
        );
        assert!(l.admit_lifetime(29).is_err());
        assert!(l.admit_lifetime(30).is_ok());
        assert!(l.admit_lifetime(3651).is_err());
        assert!(l.admit_mobile_quota(GIB - 1).is_err());
        assert!(l.admit_mobile_quota(64 * GIB).is_ok());
    }
}
