//! A9 - Three pipe step / frame meter (plan §CH A9).
//!
//! WIRING: charged by `storage::emit::qr_feed_preview`, which spends this
//! meter against the drop bound of a request before it transforms, packs or
//! carousels anything, so an over-budget body is refused rather than encoded and
//! then rejected.
//!
//! Catalogue generators already meter `step_budget`. The content-QR pipe needs
//! its own counters so a reveal session cannot free-ride unbounded encode.
//! This is an **accounting shape**, not a fee market - pricing tables stay
//! with tokenomics.

/// Work units charged for pipe operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThreeMeter {
    /// A1 pack invocations.
    pub packs: u64,
    /// A2 drops produced or ingested.
    pub drops: u64,
    /// A3 frames produced or ingested.
    pub frames: u64,
    /// G1 seal/open operations.
    pub seals: u64,
    /// Hard budget; `None` = unlimited (lab).
    pub budget: Option<u64>,
}

/// Meter errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeterError {
    /// Budget exhausted.
    BudgetExceeded {
        /// Attempted total weight.
        used: u64,
        /// Configured budget.
        budget: u64,
    },
}

impl std::fmt::Display for MeterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BudgetExceeded { used, budget } => {
                write!(f, "three meter budget exceeded used={used} budget={budget}")
            }
        }
    }
}

impl std::error::Error for MeterError {}

impl ThreeMeter {
    /// New meter with optional total weight budget.
    #[must_use]
    pub const fn with_budget(budget: Option<u64>) -> Self {
        Self {
            packs: 0,
            drops: 0,
            frames: 0,
            seals: 0,
            budget,
        }
    }

    /// Weighted usage: pack=1, drop=1, frame=2, seal=4 (encode cost bias).
    #[must_use]
    pub const fn weight(self) -> u64 {
        self.packs
            .saturating_add(self.drops)
            .saturating_add(self.frames.saturating_mul(2))
            .saturating_add(self.seals.saturating_mul(4))
    }

    const fn charge(&mut self, add_weight: u64) -> Result<(), MeterError> {
        let used = self.weight().saturating_add(add_weight);
        if let Some(b) = self.budget {
            if used > b {
                return Err(MeterError::BudgetExceeded { used, budget: b });
            }
        }
        Ok(())
    }

    /// Record one pack.
    /// # Errors
    ///
    /// Propagates `MeterError` from the step that failed; its variants name the refused
    /// conditions.
    pub fn record_pack(&mut self) -> Result<(), MeterError> {
        self.charge(1)?;
        self.packs = self.packs.saturating_add(1);
        Ok(())
    }

    /// Record `n` drops.
    /// # Errors
    ///
    /// Propagates `MeterError` from the step that failed; its variants name the refused
    /// conditions.
    pub fn record_drops(&mut self, n: u64) -> Result<(), MeterError> {
        self.charge(n)?;
        self.drops = self.drops.saturating_add(n);
        Ok(())
    }

    /// Record `n` frames.
    /// # Errors
    ///
    /// Propagates `MeterError` from the step that failed; its variants name the refused
    /// conditions.
    pub fn record_frames(&mut self, n: u64) -> Result<(), MeterError> {
        self.charge(n.saturating_mul(2))?;
        self.frames = self.frames.saturating_add(n);
        Ok(())
    }

    /// Record one seal/open.
    /// # Errors
    ///
    /// Propagates `MeterError` from the step that failed; its variants name the refused
    /// conditions.
    pub fn record_seal(&mut self) -> Result<(), MeterError> {
        self.charge(4)?;
        self.seals = self.seals.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_trips() {
        let mut m = ThreeMeter::with_budget(Some(5));
        m.record_pack().unwrap(); // 1
        m.record_frames(2).unwrap(); // +4 → 5
        assert_eq!(
            m.record_pack().unwrap_err(),
            MeterError::BudgetExceeded { used: 6, budget: 5 }
        );
    }

    #[test]
    fn unlimited_lab() {
        let mut m = ThreeMeter::with_budget(None);
        for _ in 0..1000 {
            m.record_drops(10).unwrap();
        }
        assert!(m.weight() > 0);
    }
}
