//! Kuantum-guvenli hesap soyutlama (KQ-* kapilari).
//!
//! # Bu dizinin gecmisi
//!
//! Bu dizin `lib.rs`'te bildirilmemisti: bes dosyanin hicbiri derlenmiyordu.
//! Olculdu, tahmin edilmedi: `threshold_mldsa.rs`'e gecersiz Rust yazildi ve
//! `cargo check --lib` yine gecti. Derlenmedigi icin ne clippy, ne kapilar,
//! ne de testler bu koda bakiyordu; icerideki uc "dogrulama" fonksiyonu
//! hicbir seyi reddedemeyecek durumdaydi ve bu fark edilmemisti.
//!
//! `no-orphan-source-files` kapisi da goremezdi: kapi `mod.rs` adli dosyalari
//! kosulsuz muaf tutuyordu, dolayisiyla ulasilamaz bir dizinin `mod.rs`'i
//! muaf sayiliyor, kardes dosyalar da o muaf dosya tarafindan "bildirilmis"
//! kabul ediliyordu. Kapi artik koklerden ulasilabilirligi izliyor.
//!
//! # Kapsam
//!
//! Buradaki tipler imza ve politika dogrulamasi yapar. Zincir durumu
//! degistirmezler ve bir kanit sisteminin yerine gecmezler; her modulun
//! basinda ne soyledigi ve ne soylemedigi ayri ayri yaziyor.

pub mod private_transfer_auth;
pub mod quantum_account;
pub mod tee_attestation;
pub mod threshold_mldsa;

pub use private_transfer_auth::{PrivateTransferAuth, PrivateTransferError, PrivateTransferGates};
pub use quantum_account::{
    BftGuardianFinality, GuardianVote, PactBinding, QuantumAccount, RecoveryProposal,
};
pub use tee_attestation::{
    TeeAttestation, TeeBackendKind, TeeError, TeeGates, TeeRuntime, TeeRuntimeStatus,
};
pub use threshold_mldsa::{
    MultisigAuthorization, MultisigPolicy, OwnerSignature, ThresholdError, ThresholdGates,
};
