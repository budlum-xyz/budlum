//! Custody quota and the free-space floor (section 7.9.5).

/// One gibibyte.
pub const GIB: u64 = 1024 * 1024 * 1024;
/// Smallest user quota.
pub const QUOTA_MIN_BYTES: u64 = GIB;
/// Largest user quota.
pub const QUOTA_MAX_BYTES: u64 = 64 * GIB;
/// Default user quota (section 7.9.4).
pub const QUOTA_DEFAULT_BYTES: u64 = 4 * GIB;
/// Free-space floor: 2 GB (decimal), section 7.9.5 and R-34.
pub const FREE_SPACE_FLOOR_BYTES: u64 = 2_000_000_000;

/// Whether `stored` plus `incoming` fits in `quota`.
#[must_use]
pub fn fits(stored: u64, incoming: u64, quota: u64) -> bool {
    stored.saturating_add(incoming) <= quota
}

/// Whether free space is below the 2 GB floor.
#[must_use]
pub fn below_floor(available_bytes: u64) -> bool {
    available_bytes < FREE_SPACE_FLOOR_BYTES
}

#[cfg(test)]
mod tests {
    use super::fits;

    #[test]
    fn mobile_quota_overflow_is_a_refusal() {
        assert!(!fits(u64::MAX, 1, u64::MAX));
        assert!(!fits(u64::MAX - 1, 2, u64::MAX));
        assert!(fits(u64::MAX - 1, 1, u64::MAX));
        assert!(fits(32, 32, 64));
        assert!(!fits(32, 33, 64));
    }
}
