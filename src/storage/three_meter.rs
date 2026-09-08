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

    pub const fn charge(&mut self, add_weight: u64) -> Result<(), MeterError> {
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
    pub fn budget_trips() {
        let mut m = ThreeMeter::with_budget(Some(5));
        m.record_pack().unwrap(); // 1
        m.record_frames(2).unwrap(); // +4 → 5
        assert_eq!(
            m.record_pack().unwrap_err(),
            MeterError::BudgetExceeded { used: 6, budget: 5 }
        );
    }

    #[test]
    pub fn unlimited_lab() {
        let mut m = ThreeMeter::with_budget(None);
        for _ in 0..1000 {
            m.record_drops(10).unwrap();
        }
        assert!(m.weight() > 0);
    }
}

/// `E6`: CPU/Step Budget Meter for Data Regeneration.
///
/// Prevents decompression bombs, unbounded loop execution, and algorithmic
/// complexity attacks during recursive recipe expansion and data
/// regeneration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegenerationBudgetMeter {
    pub max_cpu_steps: u64,
    pub max_memory_bytes: usize,
    pub max_recursion_depth: u32,
    pub cpu_steps_used: u64,
    pub memory_used: usize,
    pub current_depth: u32,
}

impl RegenerationBudgetMeter {
    #[must_use]
    pub const fn new(
        max_cpu_steps: u64,
        max_memory_bytes: usize,
        max_recursion_depth: u32,
    ) -> Self {
        Self {
            max_cpu_steps,
            max_memory_bytes,
            max_recursion_depth,
            cpu_steps_used: 0,
            memory_used: 0,
            current_depth: 0,
        }
    }

    /// # Errors
    ///
    /// [`MeterError::BudgetExceeded`] when the steps would pass the budget.
    pub const fn consume_steps(&mut self, steps: u64) -> Result<(), MeterError> {
        let used = self.cpu_steps_used.saturating_add(steps);
        if used > self.max_cpu_steps {
            return Err(MeterError::BudgetExceeded {
                used,
                budget: self.max_cpu_steps,
            });
        }
        self.cpu_steps_used = used;
        Ok(())
    }

    /// # Errors
    ///
    /// [`MeterError::BudgetExceeded`] when the allocation would pass the cap.
    pub const fn track_memory(&mut self, bytes: usize) -> Result<(), MeterError> {
        let used = self.memory_used.saturating_add(bytes);
        if used > self.max_memory_bytes {
            return Err(MeterError::BudgetExceeded {
                used: used as u64,
                budget: self.max_memory_bytes as u64,
            });
        }
        self.memory_used = used;
        Ok(())
    }

    /// # Errors
    ///
    /// [`MeterError::BudgetExceeded`] at the recursion-depth cap.
    // The two u32->u64 casts keep this fn const: `From<u32> for u64` is not
    // const-callable yet, and the widening cast cannot lose information.
    pub fn enter_recursion(&mut self) -> Result<(), MeterError> {
        if self.current_depth >= self.max_recursion_depth {
            return Err(MeterError::BudgetExceeded {
                used: u64::from(self.current_depth) + 1,
                budget: u64::from(self.max_recursion_depth),
            });
        }
        self.current_depth += 1;
        Ok(())
    }

    pub const fn exit_recursion(&mut self) {
        self.current_depth = self.current_depth.saturating_sub(1);
    }
}

#[cfg(test)]
mod regen_tests {
    use super::*;

    #[test]
    pub fn regeneration_budget_enforcement() {
        let mut meter = RegenerationBudgetMeter::new(1000, 4096, 5);
        assert!(meter.consume_steps(500).is_ok());
        assert!(meter.consume_steps(600).is_err());

        assert!(meter.track_memory(2048).is_ok());
        assert!(meter.track_memory(3000).is_err());

        for _ in 0..5 {
            assert!(meter.enter_recursion().is_ok());
        }
        assert!(meter.enter_recursion().is_err());
        meter.exit_recursion();
        assert!(meter.enter_recursion().is_ok());
    }
}
