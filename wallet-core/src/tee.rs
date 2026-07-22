//! TEE execution-time confidentiality surface (D2 Bölüm 10 #5).
//!
//! Real SGX/Nitro enclave integration is a separate hardware/SDK track.
//! This module defines the wallet-facing contract and a **fail-closed**
//! default: if the user opts into TEE, plaintext signing/transfer paths
//! must not silently proceed without an enclave backend.

use crate::WalletError;

/// Which TEE backend the wallet intends to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TeeBackendKind {
    #[default]
    None,
    ClientSgx,
    ServerNitro,
}

impl TeeBackendKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSgx => "client",
            Self::ServerNitro => "server",
        }
    }
}

/// Capability probe result for a concrete TEE runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeeRuntimeStatus {
    pub kind: TeeBackendKind,
    pub available: bool,
    pub detail: String,
}

/// Wallet-side TEE runtime. Production builds plug in SGX/Nitro adapters;
/// the default is unavailable (fail-closed).
pub trait TeeRuntime: Send + Sync {
    fn status(&self) -> TeeRuntimeStatus;

    /// Seal plaintext for enclave-side handling. Default: unavailable.
    fn seal_private_intent(&self, _plaintext: &[u8]) -> Result<Vec<u8>, WalletError> {
        Err(WalletError::TeeUnavailable(self.status().detail))
    }
}

/// Default runtime: always unavailable. Used until a real enclave is wired.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableTeeRuntime {
    pub preferred: TeeBackendKind,
}

impl UnavailableTeeRuntime {
    #[must_use]
    pub fn for_backend(kind: TeeBackendKind) -> Self {
        Self { preferred: kind }
    }
}

impl TeeRuntime for UnavailableTeeRuntime {
    fn status(&self) -> TeeRuntimeStatus {
        let name = self.preferred.as_str();
        TeeRuntimeStatus {
            kind: self.preferred,
            available: false,
            detail: format!(
                "TEE backend '{name}' is not linked in this build \
                 (SGX/Nitro runtime pending). Fail-closed: refusing \
                 plaintext path while tee_enabled=true."
            ),
        }
    }
}
