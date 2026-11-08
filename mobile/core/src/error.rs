//! Stable error codes for the mobile core.

use core::fmt;

/// A refused mobile-core operation: a stable code and a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreError {
    /// Stable machine code.
    pub code: &'static str,
    /// Human-readable reason.
    pub message: String,
}

impl CoreError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CoreError {}
