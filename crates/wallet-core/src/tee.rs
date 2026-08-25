//! The TEE execution-time confidentiality surface (section 10, item 5).
//!
//! Real SGX/Nitro enclave integration is a separate hardware/SDK track.
//! This module defines the wallet-facing contract and a **fail-closed**
//! Default: if the user opts into TEE, plaintext signing/transfer paths
//! Must not silently proceed without an enclave backend.
//!
//! Trust boundary (CWE-347): the runtime
//! that runs in the enclave must not also be the thing that proves it ran in
//! an enclave. A self-attesting software runtime can echo any report data and
//! any measurement it likes, so comparing fields on an object the runtime
//! itself produced enforces nothing. The split is therefore:
//!
//!   * [`TeeQuoter`] produces a **raw hardware quote** (bytes) bound to a
//!     report_data. It never produces parsed attestation fields.
//!   * [`TeeQuoteVerifier`] verifies that quote against the hardware root of
//!     trust (Intel/AMD attestation root) and only then parses the trusted
//!     fields out of it. The wallet owns the verifier; the runtime never sees
//!     it.
//!
//! Production builds plug in a real quote source (SGX/Nitro adapter) and a
//! real root-of-trust verifier. The defaults are unavailable (fail-closed).

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
/// The default is unavailable (fail-closed).
pub trait TeeRuntime: Send + Sync {
    fn status(&self) -> TeeRuntimeStatus;

    /// Seal plaintext for enclave-side handling. Default: unavailable.
    fn seal_private_intent(&self, _plaintext: &[u8]) -> Result<Vec<u8>, WalletError> {
        Err(WalletError::TeeUnavailable(self.status().detail))
    }
}

/// Quote source: the enclave side. Returns a **raw hardware quote** binding
/// `report_data` to the enclave measurement. It must not return parsed
/// attestation fields: the wallet only trusts fields the verifier extracts
/// from a quote it validated against the hardware root of trust.
pub trait TeeQuoter: TeeRuntime {
    /// Produce a raw attestation quote over `report_data`.
    fn quote(&self, report_data: [u8; 32]) -> Result<Vec<u8>, WalletError>;
}

/// Quote verifier: the wallet side, owned by the wallet. Validates a raw
/// quote against the hardware root of trust (SGX EPID/DCAP or Nitro root
/// certificate chain) and only then returns the trusted fields. A runtime can
/// never influence the fields returned here, so a self-attesting software
/// runtime cannot fabricate an attestation.
pub trait TeeQuoteVerifier: Send + Sync {
    /// Verify `quote` cryptographically and extract the trusted fields.
    fn verify_quote(&self, quote: &[u8]) -> Result<TeeAttestation, WalletError>;
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

impl TeeQuoter for UnavailableTeeRuntime {
    fn quote(&self, _report_data: [u8; 32]) -> Result<Vec<u8>, WalletError> {
        // No enclave is linked, so no quote can ever be produced.
        // `sign_with_privacy` therefore stays fail-closed under
        // tee_enabled=true (security review, HIGH).
        Err(WalletError::TeeUnavailable(
            "TEE backend is not linked in this build; no quote available".into(),
        ))
    }
}

/// Default quote verifier: no hardware root is linked, so no quote can ever
/// verify. `sign_with_privacy` stays fail-closed even if a runtime somehow
/// produced bytes claiming to be a quote (Strix MEDIUM, CWE-347).
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableTeeQuoteVerifier;

impl TeeQuoteVerifier for UnavailableTeeQuoteVerifier {
    fn verify_quote(&self, _quote: &[u8]) -> Result<TeeAttestation, WalletError> {
        Err(WalletError::TeeUnavailable(
            "no hardware attestation root is linked in this build; quotes cannot be verified"
                .into(),
        ))
    }
}

// ── (2026-07-23): TEE SDK extension - quote + verifier + mock runtime ──
//
// Production: UnavailableTeeRuntime + UnavailableTeeQuoteVerifier (both
// fail-closed) remain the default. Testing: MockTeeRuntime provides
// deterministic seal/quote and MockQuoteVerifier verifies that exact format,
// so the trust boundary (runtime produces raw bytes, wallet verifies) is
// exercised in CI without real hardware.

/// Parsed, verified attestation - the wallet's view of a quote AFTER the
/// verifier has checked it against the hardware root of trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeeAttestation {
    /// Enclave measurement hash (MRENCLAVE / Nitro PCR0), read from the quote.
    pub measurement: [u8; 32],
    /// Report data the quote was bound to (the seal digest).
    pub report_data: [u8; 32],
    /// Attestation timestamp (unix seconds), read from the quote.
    pub timestamp: u64,
    /// Backend identifier, read from the quote.
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

/// Mock quote source for testing ONLY. NOT for production use.
/// Provides deterministic seal/quote with a fixed measurement.
#[cfg(test)]
pub mod mock {
    use super::*;

    /// Fixed test measurement hash (deterministic for CI).
    pub const MOCK_MEASUREMENT: [u8; 32] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAA,
        0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
        0xBA, 0x98,
    ];

    /// Mock quote format:
    ///   [0u8;4] magic "MOCKQ", measurement(32), report_data(32),
    ///   backend(1), timestamp(8)
    /// A verifier that understands this format is the ONLY thing that can
    /// turn these bytes into a [`TeeAttestation`]; arbitrary bytes fail.
    pub const MOCK_QUOTE_MAGIC: [u8; 4] = *b"MOCK";

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
            // NOT cryptographically secure - test only.
            let mut sealed = Vec::with_capacity(4 + 4 + plaintext.len());
            sealed.extend_from_slice(&[0x5E, 0xA1, 0xED, 0x00]);
            sealed.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
            sealed.extend_from_slice(plaintext);
            Ok(sealed)
        }
    }

    impl TeeQuoter for MockTeeRuntime {
        fn quote(&self, report_data: [u8; 32]) -> Result<Vec<u8>, WalletError> {
            let mut q = Vec::with_capacity(4 + 32 + 32 + 1 + 8);
            q.extend_from_slice(&MOCK_QUOTE_MAGIC);
            q.extend_from_slice(&MOCK_MEASUREMENT);
            q.extend_from_slice(&report_data);
            q.push(self.kind.as_str().as_bytes()[0]);
            q.extend_from_slice(&0u64.to_le_bytes()); // deterministic timestamp
            Ok(q)
        }
    }

    /// Verifier that understands the mock quote format above. This stands in
    /// for the hardware root-of-trust check: bytes that do not match the
    /// format, or that name a measurement the verifier does not recognize,
    /// are rejected.
    pub struct MockQuoteVerifier {
        pub recognized_measurements: Vec<[u8; 32]>,
    }

    impl Default for MockQuoteVerifier {
        fn default() -> Self {
            Self {
                recognized_measurements: vec![MOCK_MEASUREMENT],
            }
        }
    }

    impl TeeQuoteVerifier for MockQuoteVerifier {
        fn verify_quote(&self, quote: &[u8]) -> Result<TeeAttestation, WalletError> {
            if quote.len() != 4 + 32 + 32 + 1 + 8 || quote[0..4] != MOCK_QUOTE_MAGIC {
                return Err(WalletError::TeeUnavailable(
                    "quote does not verify against the hardware root of trust".into(),
                ));
            }
            let mut measurement = [0u8; 32];
            measurement.copy_from_slice(&quote[4..36]);
            if !self.recognized_measurements.contains(&measurement) {
                return Err(WalletError::TeeUnavailable(
                    "quote names an unrecognized enclave measurement".into(),
                ));
            }
            let mut report_data = [0u8; 32];
            report_data.copy_from_slice(&quote[36..68]);
            let backend_byte = quote[68];
            let backend = match backend_byte {
                b'c' => TeeBackendKind::ClientSgx,
                b's' => TeeBackendKind::ServerNitro,
                _ => TeeBackendKind::None,
            };
            let mut timestamp_bytes = [0u8; 8];
            timestamp_bytes.copy_from_slice(&quote[69..77]);
            Ok(TeeAttestation {
                measurement,
                report_data,
                timestamp: u64::from_le_bytes(timestamp_bytes),
                backend,
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
        fn mock_quote_verifies_with_recognized_measurement() {
            let rt = MockTeeRuntime::new(TeeBackendKind::ServerNitro);
            let data = [42u8; 32];
            let quote = rt.quote(data).unwrap();
            let verifier = MockQuoteVerifier::default();
            let att = verifier.verify_quote(&quote).unwrap();
            assert!(att.verify_measurement(&MOCK_MEASUREMENT));
            assert!(att.verify_report_data(&data));
            assert_eq!(att.backend, TeeBackendKind::ServerNitro);
        }

        #[test]
        fn mock_quote_rejects_arbitrary_bytes() {
            let verifier = MockQuoteVerifier::default();
            let err = verifier.verify_quote(b"not a quote at all").unwrap_err();
            assert!(matches!(err, WalletError::TeeUnavailable(_)));
        }

        #[test]
        fn mock_quote_rejects_unrecognized_measurement() {
            let verifier = MockQuoteVerifier {
                recognized_measurements: vec![[0x11; 32]],
            };
            let rt = MockTeeRuntime::new(TeeBackendKind::ClientSgx);
            let quote = rt.quote([0u8; 32]).unwrap();
            let err = verifier.verify_quote(&quote).unwrap_err();
            assert!(matches!(err, WalletError::TeeUnavailable(_)));
        }

        #[test]
        fn unavailable_runtime_rejects_quote() {
            let rt = UnavailableTeeRuntime::for_backend(TeeBackendKind::ClientSgx);
            assert!(!rt.status().available);
            assert!(rt.seal_private_intent(b"test").is_err());
            assert!(rt.quote([0u8; 32]).is_err());
        }

        #[test]
        fn unavailable_verifier_rejects_everything() {
            let v = UnavailableTeeQuoteVerifier;
            let err = v.verify_quote(b"anything").unwrap_err();
            assert!(matches!(err, WalletError::TeeUnavailable(_)));
        }
    }
}
