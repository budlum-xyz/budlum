//! F10 EVM ChainAdapter — Universal Relayer gerçek Ethereum köprüsü.
//!
//! Bu modül grubu Budlum'a, relayer'ın ürettiği Ethereum receipt proof'larını
//! **bağımsız olarak** kriptografik doğrulama yeteneği kazandırır:
//!
//! - `rlp` — in-tree Recursive Length Prefix (Ethereum Yellow Paper Appendix B).
//! - `mpt` — in-tree Merkle-Patricia trie **verifier** (Appendix D, verify-only;
//!   Proof üretimi relayer'da).
//! - `receipt` — Ethereum receipt RLP schema + receiptsRoot proof.
//! - `sync_committee` — PoS light-client (BLS12-381, `blst` reuse).
//! - `header` — Ethereum header chain + finality kararı.
//! - `adapter` — `EvmChainAdapter` (ChainAdapter impl).
//!
//! **Güvenlik sabiti:** hiçbir fonksiyon network'e bağlanmaz. Tüm doğrulama
//! Deterministik ve on-chain (Budlum konsensüsünde). Relayer proof üretir,
//! Budlum verify eder (relayer_produces güven modeli).
//!
//! Temel katman RLP + MPT verifier + KAT vektörleridir; receipt, header ve
//! Sync-committee doğrulaması bunun üstüne kurulur.

pub mod adapter;
pub mod bud_to_eth;
pub mod header;
pub mod mpt;
pub mod receipt;
pub mod rlp;
pub mod sync_committee;
pub mod verify;
