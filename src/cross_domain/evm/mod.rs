//! F10 EVM ChainAdapter — Universal Relayer gerçek Ethereum köprüsü (H4 kapatma).
//!
//! RFC: `docs/RFC_F10_EVM_CHAIN_ADAPTER.md` (kullanıcı-onaylı 4 karar).
//!
//! Bu modül grubu Budlum'a, relayer'ın ürettiği Ethereum receipt proof'larını
//! **bağımsız olarak** kriptografik doğrulama yeteneği kazandırır:
//!
//! - `rlp` — in-tree Recursive Length Prefix (Ethereum Yellow Paper Appendix B).
//! - `mpt` — in-tree Merkle-Patricia trie **verifier** (Appendix D, verify-only;
//!   proof üretimi relayer'da).
//! - `receipt` (F10.2) — Ethereum receipt RLP schema + receiptsRoot proof.
//! - `sync_committee` (F10.3) — PoS light-client (BLS12-381, `blst` reuse).
//! - `header` (F10.2) — Ethereum header chain + finality kararı.
//! - `adapter` (F10.2) — `EvmChainAdapter` (ChainAdapter impl).
//!
//! **Güvenlik sabiti:** hiçbir fonksiyon network'e bağlanmaz. Tüm doğrulama
//! deterministik ve on-chain (Budlum konsensüsünde). Relayer proof üretir,
//! Budlum verify eder (RFC Q1 = relayer_produces).
//!
//! **F10.1 kapsamı (bu modül setinin temeli):** RLP + MPT verifier + KAT vectors.
//! Sonraki görevlar (F10.2+) bunun üstüne kurulur.

pub mod adapter;
pub mod bud_to_eth;
pub mod header;
pub mod mpt;
pub mod receipt;
pub mod rlp;
pub mod sync_committee;
pub mod verify;
