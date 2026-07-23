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

// ── ARENA2 (2026-07-23): TEE SDK extension — attestation + mock runtime ──
//
// Production: UnavailableTeeRuntime (fail-closed) remains the default.
// Testing: MockTeeRuntime provides deterministic seal/attest for CI.
// Future: Real SGX/Nitro adapters implement TeeRuntime + TeeAttester.

/// TEE attestation report — binds enclave measurement to runtime data.
/// Production attestations are signed by the enclave hardware root of trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeeAttestation {
    /// Enclave measurement hash (MRENCLAVE / Nitro PCR0).
    pub measurement: [u8; 32],
    /// User-defined report data (typically a commitment hash).
    pub report_data: [u8; 32],
    /// Attestation timestamp (unix seconds).
    pub timestamp: u64,
    /// Backend identifier.
    pub backend: TeeBackendKind,
}

impl TeeAttestation {
    /// Validate that the attestation binds to the expected measurement.
    pub fn verify_measurement(&self, expected: &[u8; 32]) -> bool {
        self.measurement == *expected
    }

    /// Validate that the report data matches expected commitment.
    pub fn verify_report_data(&self, expected: &[u8; 32]) -> bool {
        self.report_data == *expected
    }
}

/// Extended TEE runtime with attestation capability.
pub trait TeeAttester: TeeRuntime {
    /// Produce an attestation binding `report_data` to the enclave measurement.
    fn attest(&self, report_data: [u8; 32]) -> Result<TeeAttestation, WalletError>;
}

/// Mock TEE runtime for testing ONLY. NOT for production use.
/// Provides deterministic seal/attest with a fixed measurement.
/// Production builds must use UnavailableTeeRuntime or a real SGX/Nitro adapter.
#[cfg(test)]
pub mod mock {
    use super::*;

    /// Fixed test measurement hash (deterministic for CI).
    pub const MOCK_MEASUREMENT: [u8; 32] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
    ];

    pub struct MockTeeRuntime {
        pub kind: TeeBackendKind,
    }

    impl MockTeeRuntime {
        pub fn new(kind: TeeBackendKind) -> Self {
            Self { kind }
        }
    }

    impl TeeRuntime for MockTeeRuntime {
        fn status(&self) -> TeeRuntimeStatus {
            TeeRuntimeStatus {
                kind: self.kind,
                available: true,
                detail: format!("mock {} (test only)", self.kind.as_str()),
            }
        }

        fn seal_private_intent(&self, plaintext: &[u8]) -> Result<Vec<u8>, WalletError> {
            // Mock seal: prefix with 0xSEAL marker + length + plaintext.
            // NOT cryptographically secure — test only.
            let mut sealed = Vec::with_capacity(4 + 4 + plaintext.len());
            sealed.extend_from_slice(&[0x5E, 0xA1, 0xED, 0x00]);
            sealed.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
            sealed.extend_from_slice(plaintext);
            Ok(sealed)
        }
    }

    impl TeeAttester for MockTeeRuntime {
        fn attest(&self, report_data: [u8; 32]) -> Result<TeeAttestation, WalletError> {
            Ok(TeeAttestation {
                measurement: MOCK_MEASUREMENT,
                report_data,
                timestamp: 0, // deterministic for tests
                backend: self.kind,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn mock_seal_roundtrip() {
            let rt = MockTeeRuntime::new(TeeBackendKind::ClientSgx);
            assert!(rt.status().available);
            let sealed = rt.seal_private_intent(b"test-intent").unwrap();
            assert!(sealed.starts_with(&[0x5E, 0xA1, 0xED, 0x00]));
            let len = u32::from_le_bytes(sealed[4..8].try_into().unwrap()) as usize;
            assert_eq!(&sealed[8..8 + len], b"test-intent");
        }

        #[test]
        fn mock_attest_binds_measurement() {
            let rt = MockTeeRuntime::new(TeeBackendKind::ServerNitro);
            let data = [42u8; 32];
            let att = rt.attest(data).unwrap();
            assert!(att.verify_measurement(&MOCK_MEASUREMENT));
            assert!(att.verify_report_data(&data));
            assert_eq!(att.backend, TeeBackendKind::ServerNitro);
        }

        #[test]
        fn mock_attest_wrong_measurement_fails() {
            let rt = MockTeeRuntime::new(TeeBackendKind::ClientSgx);
            let att = rt.attest([0u8; 32]).unwrap();
            assert!(!att.verify_measurement(&[0xFF; 32]));
        }

        #[test]
        fn unavailable_runtime_rejects_seal() {
            let rt = UnavailableTeeRuntime::for_backend(TeeBackendKind::ClientSgx);
            assert!(!rt.status().available);
            assert!(rt.seal_private_intent(b"test").is_err());
        }
    }
}
