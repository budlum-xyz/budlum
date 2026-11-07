//! The parser and decoder budget.
//!
//! Every B.U.D. 3.0 parser and decoder runs under a [`Meter`]. A meter holds a
//! byte budget (memory the path may allocate) and a step budget (work the path
//! may do). A path charges the meter before it allocates or loops, so an
//! untrusted length can never make it allocate first and check later.
//! Convenience: public deterministic decode budget meter inspection helpers.

/// A spent budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeterError {
    /// The byte budget would go below zero.
    Bytes { asked: u64, left: u64 },
    /// The step budget would go below zero.
    Steps { asked: u64, left: u64 },
}

impl core::fmt::Display for MeterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bytes { asked, left } => {
                write!(f, "byte budget exhausted: asked {asked}, {left} left")
            }
            Self::Steps { asked, left } => {
                write!(f, "step budget exhausted: asked {asked}, {left} left")
            }
        }
    }
}

/// A byte and step budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meter {
    bytes_left: u64,
    steps_left: u64,
}

impl Meter {
    /// A meter with the given budgets.
    #[must_use]
    pub const fn new(bytes: u64, steps: u64) -> Self {
        Self {
            bytes_left: bytes,
            steps_left: steps,
        }
    }

    /// The budget for one BOF-1 object of at most `max_object_bytes`: the
    /// object may be held once, and the parser does a bounded number of steps
    /// per header field.
    #[must_use]
    pub const fn for_object(max_object_bytes: u64) -> Self {
        Self::new(max_object_bytes, 1024)
    }

    /// Charge an allocation of `n` bytes.
    ///
    /// # Errors
    ///
    /// [`MeterError::Bytes`] when the budget does not cover `n`; the meter is
    /// left unchanged.
    pub const fn charge_bytes(&mut self, n: u64) -> Result<(), MeterError> {
        if n > self.bytes_left {
            return Err(MeterError::Bytes {
                asked: n,
                left: self.bytes_left,
            });
        }
        self.bytes_left -= n;
        Ok(())
    }

    /// Charge `n` steps of work.
    ///
    /// # Errors
    ///
    /// [`MeterError::Steps`] when the budget does not cover `n`; the meter is
    /// left unchanged.
    pub const fn charge_steps(&mut self, n: u64) -> Result<(), MeterError> {
        if n > self.steps_left {
            return Err(MeterError::Steps {
                asked: n,
                left: self.steps_left,
            });
        }
        self.steps_left -= n;
        Ok(())
    }

    /// Bytes left.
    #[must_use]
    pub const fn bytes_left(&self) -> u64 {
        self.bytes_left
    }

    /// Steps left.
    #[must_use]
    pub const fn steps_left(&self) -> u64 {
        self.steps_left
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meter_charges_and_refuses_without_changing_state() {
        let mut m = Meter::new(10, 2);
        assert!(m.charge_bytes(4).is_ok());
        assert_eq!(m.bytes_left(), 6);
        assert_eq!(
            m.charge_bytes(7),
            Err(MeterError::Bytes { asked: 7, left: 6 })
        );
        assert_eq!(m.bytes_left(), 6, "a refused charge leaves the budget");
        assert!(m.charge_steps(2).is_ok());
        assert_eq!(
            m.charge_steps(1),
            Err(MeterError::Steps { asked: 1, left: 0 })
        );
        assert_eq!(m.steps_left(), 0);
    }

    #[test]
    fn meter_error_names_the_budget() {
        let e = MeterError::Bytes { asked: 9, left: 1 };
        assert_eq!(e.to_string(), "byte budget exhausted: asked 9, 1 left");
    }
}
