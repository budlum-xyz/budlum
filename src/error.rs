use crate::cross_domain::BridgeError;
use crate::domain::DomainError;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum BudlumError {
    Storage { code: &'static str, message: String },
    Consensus { code: &'static str, message: String },
    Settlement { code: &'static str, message: String },
    Bridge { code: &'static str, message: String },
    Network { code: &'static str, message: String },
    Rpc { code: &'static str, message: String },
    Validation { code: &'static str, message: String },
}

pub type BudlumResult<T> = Result<T, BudlumError>;

impl BudlumError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Storage { code, .. }
            | Self::Consensus { code, .. }
            | Self::Settlement { code, .. }
            | Self::Bridge { code, .. }
            | Self::Network { code, .. }
            | Self::Rpc { code, .. }
            | Self::Validation { code, .. } => code,
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Storage { message, .. }
            | Self::Consensus { message, .. }
            | Self::Settlement { message, .. }
            | Self::Bridge { message, .. }
            | Self::Network { message, .. }
            | Self::Rpc { message, .. }
            | Self::Validation { message, .. } => message,
        }
    }

    pub fn settlement(code: &'static str, message: impl Into<String>) -> Self {
        Self::Settlement {
            code,
            message: message.into(),
        }
    }

    pub fn validation(code: &'static str, message: impl Into<String>) -> Self {
        Self::Validation {
            code,
            message: message.into(),
        }
    }
}

impl Display for BudlumError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for BudlumError {}

impl From<std::io::Error> for BudlumError {
    fn from(value: std::io::Error) -> Self {
        Self::Storage {
            code: "storage_error",
            message: value.to_string(),
        }
    }
}

impl From<BridgeError> for BudlumError {
    fn from(value: BridgeError) -> Self {
        Self::Bridge {
            code: "bridge_error",
            message: value.to_string(),
        }
    }
}

impl From<DomainError> for BudlumError {
    fn from(value: DomainError) -> Self {
        Self::Settlement {
            code: "domain_error",
            message: value.to_string(),
        }
    }
}
