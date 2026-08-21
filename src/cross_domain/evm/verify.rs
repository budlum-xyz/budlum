//! F10.2 güvenlik çekirdeği - `verify_evm_receipt` deterministik orchestrator.
//!
//! RFC §4.1 (ETH → Budlum mint akışı) adımlarını tek doğrulama yüzeyinde birleştirir.
//! **On-chain (Budlum konsensüsünde) çalışır** - network'süz, deterministik. Relayer
//! Proof üretir, Budlum burada verify eder.
//!
//! # Doğrulama akışı
//!
//! 1. `header_chain` - target + confirmations, N-confirmation finality (RFC Q2 N-conf).
//! 2. `proof_nodes` + `target_header.receipts_root` - MPT verify → receipt bytes.
//! 3. `receipt` RLP decode (F10.2 receipt.rs) → `{status, logs}`.
//! 4. `status == true` (işlem başarılı).
//! 5. Deposit log match: `find_log(emitter, topic0)` → expected payload eşleşmesi.
//! 6. Replay protection: `(tx_hash, log_index)` daha önce işlendi mi (caller domain).
//!
//! Başarı → `VerifiedDeposit` (mint için gerekli tüm kanıtlanmış alanlar).

use crate::cross_domain::evm::header::{verify_chain, EthHeader};
use crate::cross_domain::evm::mpt::{self, MptError};
use crate::cross_domain::evm::receipt::{self, EthReceipt, ReceiptError};
use crate::cross_domain::evm::sync_committee::{
    verify_sync_aggregate, SyncAggregate, SyncCommitteeError, SyncCommitteeState,
};
/// `verify_evm_receipt` hatası (her alt-adımın hatası sarmalanır).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Header chain doğrulaması başarısız (N-conf / chain link kırık).
    Header(String),
    /// MPT kanıtı geçersiz (receipt trie'ye karşı).
    Mpt(MptError),
    /// Receipt decode başarısız.
    Receipt(ReceiptError),
    /// İşlem başarısız (`status == false`).
    TxFailed,
    /// Deposit log bulunamadı (emitter/topic0 uyuşmazlığı).
    LogNotFound,
    /// Deposit payload beklene ile eşleşmedi (amount/asset/recipient).
    PayloadMismatch,
    /// Sync-committee attestation over the target header failed.
    ///
    /// Only produced when the proof carries one. A proof that carries none is
    /// accepted on N-confirmation alone, which is what every proof did before
    /// this variant existed.
    SyncCommittee(SyncCommitteeError),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Header(m) => write!(f, "evm verify: header chain: {m}"),
            VerifyError::Mpt(e) => write!(f, "evm verify: mpt: {e}"),
            VerifyError::Receipt(e) => write!(f, "evm verify: receipt: {e}"),
            VerifyError::TxFailed => write!(f, "evm verify: transaction status=false"),
            VerifyError::LogNotFound => write!(f, "evm verify: deposit log not found"),
            VerifyError::PayloadMismatch => write!(f, "evm verify: deposit payload mismatch"),
            VerifyError::SyncCommittee(e) => write!(f, "evm verify: sync-committee: {e}"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<MptError> for VerifyError {
    fn from(e: MptError) -> Self {
        VerifyError::Mpt(e)
    }
}
impl From<ReceiptError> for VerifyError {
    fn from(e: ReceiptError) -> Self {
        VerifyError::Receipt(e)
    }
}
impl From<SyncCommitteeError> for VerifyError {
    fn from(e: SyncCommitteeError) -> Self {
        VerifyError::SyncCommittee(e)
    }
}

/// Kanıtlanmış Ethereum deposit (mint için tüm alanlar doğrulanmış).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeposit {
    /// Ethereum tx hash (replay koruması anahtarı; caller log_index ile birleştirir).
    pub tx_hash: String,
    /// Bridge kontratından çıkarılan log (data alanı = deposit payload).
    pub deposit_log_data: Vec<u8>,
    /// Kanıtlanmış receipt'in bulunduğu blok numarası.
    pub block_number: u64,
}

/// Relayer'ın ürettiği Ethereum deposit kanıtı (wire format).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmDepositProof<'a> {
    /// Hedef (deposit'i içeren) bloğun RLP-encoded header'ı.
    pub target_header: &'a [u8],
    /// Target'ın üstündeki onay header'ları (en az `confirmations` adet; her biri
    /// Parent_hash → öncekinin hash'i, number+1). RFC Q2 N-conf.
    pub confirmation_headers: &'a [&'a [u8]],
    /// Gerekli onay sayısı (reorg penceresi; mainnet ≈64, governance ile ayarlanır).
    pub required_confirmations: u32,
    /// MPT proof node'ları (receiptsRoot → target receipt).
    pub proof_nodes: &'a [Vec<u8>],
    /// Trie'deki key (RLP(tx_index) - receipt'in bulunduğu sıra).
    pub receipt_key: &'a [u8],
    /// Ethereum tx hash (replay koruması + log arama için).
    pub tx_hash: &'a str,
    /// Bridge kontrat adresi (deposit event emitter).
    pub emitter_address: &'a [u8],
    /// Deposit event imzas topic0 = keccak256("Deposit(...)").
    pub deposit_topic0: &'a [u8; 32],
    /// Ethereum PoS attestation over the target header, when the relayer has
    /// one.
    ///
    /// `None` keeps the previous behaviour exactly: finality rests on
    /// `required_confirmations` alone, which is a bet that no reorg is that
    /// deep rather than proof that none can be. Every existing caller passes
    /// `None`, so nothing that verified before stops verifying now.
    ///
    /// `Some` is the stronger claim, and it is checked. This module's header
    /// and `adapter.rs` have both said "F10.3 (sync-committee) kullanır"
    /// since they were written, and neither did: `verify_sync_aggregate`
    /// existed, was tested six ways, and no production path reached it. A
    /// bridge whose documentation claims PoS finality and whose code counts
    /// confirmations is claiming a guarantee it does not have.
    ///
    /// The `signing_message` is the caller's, because the Altair signing
    /// domain is a chain parameter this module has no business inventing.
    pub sync_attestation: Option<SyncAttestation<'a>>,
}

/// A sync-committee attestation bundled with the state that validates it.
///
/// Grouped rather than added as three loose `Option` fields, so it is
/// impossible to supply an aggregate without the committee it must verify
/// against, or a signing message without either.
/// `PartialEq`/`Eq` because `EvmDepositProof` derives them and an
/// `Option<SyncAttestation>` field makes that requirement transitive. Both
/// referents already satisfy it, so the comparison is the structural one a
/// caller would expect: two attestations are equal when they name the same
/// committee, the same aggregate and the same signing message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAttestation<'a> {
    /// Light-client state holding the 512 pubkeys for this period.
    pub state: &'a SyncCommitteeState,
    /// The bitmap and aggregate signature the relayer observed.
    pub aggregate: &'a SyncAggregate,
    /// Altair signing domain combined with the header hash. Caller-derived,
    /// because the domain depends on the fork and the genesis validators
    /// root, neither of which is knowable here.
    pub signing_message: &'a [u8],
}

/// Ethereum deposit kanıtını baştan sona doğrular. Deterministik, network'süz.
///
/// Başarı → `VerifiedDeposit` (mint için caller'a tüm kanıtlanmış alanlar).
/// Başarısız → kanıtın hangi adımda geçersiz olduğu (`VerifyError`).
pub fn verify_evm_receipt(proof: &EvmDepositProof<'_>) -> Result<VerifiedDeposit, VerifyError> {
    // 1. Header decode + N-confirmation finality.
    let target = decode_header_or_err(proof.target_header)?;
    let confs: Result<Vec<EthHeader>, VerifyError> = proof
        .confirmation_headers
        .iter()
        .map(|raw| decode_header_or_err(raw))
        .collect();
    let confs = confs?;
    verify_chain(&target, &confs, proof.required_confirmations)
        .map_err(|e| VerifyError::Header(e.to_string()))?;

    // 2. MPT verify: receiptsRoot → receipt bytes.
    let receipt_bytes = mpt::verify(proof.proof_nodes, &target.receipts_root, proof.receipt_key)?;

    // 3. Receipt RLP decode.
    let receipt: EthReceipt = receipt::decode_receipt(&receipt_bytes)?;

    // 4. Status kontrolü.
    if !receipt.status {
        return Err(VerifyError::TxFailed);
    }

    // 5. Deposit log match.
    let log = receipt
        .find_log(proof.emitter_address, proof.deposit_topic0)
        .ok_or(VerifyError::LogNotFound)?;

    // 5b. PoS attestation, when the relayer supplied one.
    //
    // Runs after the cheap structural checks and before the caller is handed
    // anything it could mint against. Verifying 342 BLS signatures is the
    // most expensive step here by a wide margin, so a proof that is malformed
    // in some cheaper way should not pay for it.
    //
    // Deliberately not mandatory. Making it so would refuse every proof the
    // current relayer produces, and a bridge that refuses everything is
    // indistinguishable from one that is switched off. What it does buy is
    // that a proof which *claims* PoS finality has that claim checked rather
    // than trusted.
    if let Some(ref attestation) = proof.sync_attestation {
        verify_sync_aggregate(
            attestation.state,
            attestation.aggregate,
            attestation.signing_message,
        )?;
    }

    // 6. (Replay koruması caller domain'inde - tx_hash döner.)
    Ok(VerifiedDeposit {
        tx_hash: proof.tx_hash.to_string(),
        deposit_log_data: log.data.clone(),
        block_number: target.number,
    })
}

fn decode_header_or_err(raw: &[u8]) -> Result<EthHeader, VerifyError> {
    crate::cross_domain::evm::header::decode_header(raw)
        .map_err(|e| VerifyError::Header(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::cross_domain::evm::header::DEFAULT_CONFIRMATIONS;
    use crate::cross_domain::evm::mpt::{keccak256, to_nibbles};
    use crate::cross_domain::evm::rlp::{encode, Item};

    // ---- Test fixture builder ----

    fn trim_u64(n: u64) -> Vec<u8> {
        if n == 0 {
            return Vec::new();
        }
        let be = n.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        be[start..].to_vec()
    }

    fn header_rlp(parent: [u8; 32], number: u64, receipts_root: [u8; 32]) -> Vec<u8> {
        encode(&Item::List(vec![
            Item::String(parent.to_vec()),
            Item::String(vec![0u8; 32]),
            Item::String(vec![0u8; 20]),
            Item::String(vec![0u8; 32]),
            Item::String(vec![0u8; 32]),
            Item::String(receipts_root.to_vec()),
            Item::String(vec![0u8; 256]),
            Item::String(vec![]),
            Item::String(trim_u64(number)),
        ]))
    }

    fn receipt_rlp(success: bool, logs: Vec<Item>) -> Vec<u8> {
        encode(&Item::List(vec![
            if success {
                Item::String(vec![0x01])
            } else {
                Item::String(vec![])
            },
            Item::String(vec![]),
            Item::String(vec![0u8; 256]),
            Item::List(logs),
        ]))
    }

    fn log_item(addr: &[u8], topic0: [u8; 32], data: &[u8]) -> Item {
        Item::List(vec![
            Item::String(addr.to_vec()),
            Item::List(vec![Item::String(topic0.to_vec())]),
            Item::String(data.to_vec()),
        ])
    }

    /// Tam bir kanıt fixture'ı üretir: target header + N conf + receipt proof +
    /// Deposit log. `(emitter, topic0, log_data, success, n_conf)`.
    struct Fixture {
        target_header: Vec<u8>,
        conf_headers: Vec<Vec<u8>>,
        receipts_root: [u8; 32],
        proof_nodes: Vec<Vec<u8>>,
        receipt_key: Vec<u8>,
    }

    fn build_fixture(
        emitter: &[u8],
        topic0: [u8; 32],
        log_data: &[u8],
        success: bool,
        n_conf: u32,
    ) -> Fixture {
        // Tek-leaf trie: key = RLP(tx_index=0); leaf value = receipt.
        let receipt_bytes = receipt_rlp(success, vec![log_item(emitter, topic0, log_data)]);
        // MPT key = keccak256(rlp(0)) nibbles; leaf path = full 64 nibbles.
        let key_bytes = encode(&Item::String(vec![])); // rlp(0) = 0x80
        let nibbles = to_nibbles(&keccak256(&key_bytes));

        // Leaf node RLP.
        let leaf_node = Item::List(vec![
            Item::String(crate::cross_domain::evm::mpt::hp_encode(&nibbles, true)),
            Item::String(receipt_bytes.clone()),
        ]);
        let leaf_bytes = encode(&leaf_node);
        let receipts_root = keccak256(&leaf_bytes);

        // Target header at number=100.
        let target_hdr = header_rlp([9u8; 32], 100, receipts_root);
        let target_hash = keccak256(&target_hdr);

        // N confirmation headers (chain: parent = prev hash, number+1).
        let mut conf_headers = Vec::new();
        let mut prev_hash = target_hash;
        for offset in 1..=n_conf {
            let h = header_rlp(prev_hash, 100 + offset as u64, receipts_root);
            prev_hash = keccak256(&h);
            conf_headers.push(h);
        }

        Fixture {
            target_header: target_hdr,
            conf_headers,
            receipts_root,
            proof_nodes: vec![leaf_bytes],
            receipt_key: key_bytes,
        }
    }

    fn conf_refs(f: &Fixture) -> Vec<&[u8]> {
        f.conf_headers.iter().map(|v| v.as_slice()).collect()
    }

    // ---- Pozitif: tam happy-path ----

    #[test]
    fn verify_full_happy_path() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let data = b"deposit-payload";
        let f = build_fixture(&emitter, topic0, data, true, 3);

        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs(&f),
            required_confirmations: 3,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0xabc123",
            emitter_address: &emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        let verified = verify_evm_receipt(&proof).unwrap();
        assert_eq!(verified.tx_hash, "0xabc123");
        assert_eq!(verified.deposit_log_data, data);
        assert_eq!(verified.block_number, 100);
    }

    // ---- Negatif: tx başarısız ----

    #[test]
    fn verify_rejects_failed_tx_status() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"data", false, 3);
        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs(&f),
            required_confirmations: 3,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0xdead",
            emitter_address: &emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        assert_eq!(
            verify_evm_receipt(&proof).unwrap_err(),
            VerifyError::TxFailed
        );
    }

    // ---- Negatif: yetersiz onay ----

    #[test]
    fn verify_rejects_insufficient_confirmations() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"data", true, 2);
        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs(&f),
            required_confirmations: DEFAULT_CONFIRMATIONS, // 64 > 2
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0x1",
            emitter_address: &emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        let err = verify_evm_receipt(&proof).unwrap_err();
        assert!(matches!(err, VerifyError::Header(_)));
    }

    // ---- Negatif: chain kırık ----

    #[test]
    fn verify_rejects_broken_chain() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"data", true, 3);
        // Kırık confirmation: yanlış parent.
        let bad_conf = header_rlp([0xff; 32], 101, f.receipts_root);
        let conf_refs = vec![bad_conf.as_slice()];
        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs,
            required_confirmations: 1,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0x1",
            emitter_address: &emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        let err = verify_evm_receipt(&proof).unwrap_err();
        assert!(matches!(err, VerifyError::Header(_)));
    }

    // ---- Negatif: deposit log yok (yanlış emitter) ----

    #[test]
    fn verify_rejects_wrong_emitter() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"data", true, 3);
        let wrong_emitter = vec![0xdd; 20];
        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs(&f),
            required_confirmations: 3,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0x1",
            emitter_address: &wrong_emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        assert_eq!(
            verify_evm_receipt(&proof).unwrap_err(),
            VerifyError::LogNotFound
        );
    }

    // ---- Negatif: deposit topic0 uyuşmaz ----

    #[test]
    fn verify_rejects_wrong_topic0() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"data", true, 3);
        let wrong_topic = [0x99; 32];
        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs(&f),
            required_confirmations: 3,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0x1",
            emitter_address: &emitter,
            deposit_topic0: &wrong_topic,
            sync_attestation: None,
        };
        assert_eq!(
            verify_evm_receipt(&proof).unwrap_err(),
            VerifyError::LogNotFound
        );
    }

    // ---- Negatif: MPT kanıtı bozuk (eksik node) ----

    #[test]
    fn verify_rejects_missing_mpt_node() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"data", true, 3);
        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs(&f),
            required_confirmations: 3,
            proof_nodes: &[], // boş → kök node eksik
            receipt_key: &f.receipt_key,
            tx_hash: "0x1",
            emitter_address: &emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        let err = verify_evm_receipt(&proof).unwrap_err();
        assert!(matches!(err, VerifyError::Mpt(_)));
    }

    // ---- Negatif: yanlış root (target header'ın receiptsRoot proof'tan farklı) ----
    // Bu durum MPT verify'nin MissingNode'una düşer (proof kök node'unu bulamaz).

    #[test]
    fn verify_does_not_panic_on_garbage() {
        // DoS güvenliği: tamamen çöp kanıt → Err, panic YOK.
        let garbage = vec![vec![0xff; 50]; 3];
        let proof = EvmDepositProof {
            target_header: &garbage[0],
            confirmation_headers: &[&garbage[1][..], &garbage[2][..]],
            required_confirmations: 1,
            proof_nodes: &garbage,
            receipt_key: &garbage[0],
            tx_hash: "garbage",
            emitter_address: &garbage[0],
            deposit_topic0: &[0u8; 32],
            sync_attestation: None,
        };
        let _ = verify_evm_receipt(&proof); // Err beklenir, panic YOK.
    }

    // ---- Sync-committee attestation ----

    use crate::cross_domain::evm::sync_committee::{
        BLS_PUBKEY_LEN, BLS_SIGNATURE_LEN, PARTICIPATION_THRESHOLD, SYNC_COMMITTEE_SIZE,
    };

    fn empty_committee() -> SyncCommitteeState {
        SyncCommitteeState {
            current_period: 0,
            current_sync_committee: [[0u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
            next_sync_committee: [[0u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
        }
    }

    fn aggregate_with_participation(bits_set: bool) -> SyncAggregate {
        SyncAggregate {
            sync_committee_bits: if bits_set {
                [0xFFu8; SYNC_COMMITTEE_SIZE / 8]
            } else {
                [0u8; SYNC_COMMITTEE_SIZE / 8]
            },
            sync_committee_signature: [0u8; BLS_SIGNATURE_LEN],
        }
    }

    fn proof_with_attestation<'a>(
        f: &'a Fixture,
        confs: &'a [&'a [u8]],
        emitter: &'a [u8],
        topic0: &'a [u8; 32],
        attestation: Option<SyncAttestation<'a>>,
    ) -> EvmDepositProof<'a> {
        EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: confs,
            required_confirmations: 3,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0xabc123",
            emitter_address: emitter,
            deposit_topic0: topic0,
            sync_attestation: attestation,
        }
    }

    /// A proof carrying no attestation verifies exactly as it did before.
    ///
    /// The narrow half. Every relayer in the tree produces `None`, and making
    /// the attestation mandatory would refuse all of them; a bridge that
    /// refuses everything is indistinguishable from one switched off.
    #[test]
    fn a_proof_without_an_attestation_still_verifies_on_confirmations_alone() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"payload", true, 3);
        let confs = conf_refs(&f);

        let proof = proof_with_attestation(&f, &confs, &emitter, &topic0, None);
        assert!(
            verify_evm_receipt(&proof).is_ok(),
            "N-confirmation finality must keep working; this is what every \
             existing caller relies on"
        );
    }

    /// A proof that claims PoS finality has the claim checked.
    ///
    /// This is the defect. `sync_committee.rs` implements Altair verification
    /// and is tested six ways; `adapter.rs` said "F10.3 (sync-committee)
    /// kullanır" in two places, and no production path called
    /// `verify_sync_aggregate`. A bridge whose documentation claims proof of
    /// stake finality and whose code counts confirmations is claiming a
    /// guarantee it does not have: confirmations are a bet that no reorg goes
    /// that deep, not evidence that none can.
    #[test]
    fn an_attestation_below_the_participation_threshold_is_rejected() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"payload", true, 3);
        let confs = conf_refs(&f);

        let state = empty_committee();
        let aggregate = aggregate_with_participation(false);
        let proof = proof_with_attestation(
            &f,
            &confs,
            &emitter,
            &topic0,
            Some(SyncAttestation {
                state: &state,
                aggregate: &aggregate,
                signing_message: b"altair-domain-and-header-hash",
            }),
        );

        let err = verify_evm_receipt(&proof)
            .expect_err("an attestation nobody signed must not pass as finality");
        assert!(
            matches!(
                err,
                VerifyError::SyncCommittee(SyncCommitteeError::InsufficientParticipation {
                    participating: 0,
                    threshold: PARTICIPATION_THRESHOLD,
                })
            ),
            "the refusal must name the participation shortfall, got: {err}"
        );
    }

    /// Participation alone is not enough; the signatures must verify.
    ///
    /// The bitmap is attacker-supplied. A committee of zero pubkeys with
    /// every bit set claims full participation and verifies nothing, and the
    /// count of *valid* signatures is what the threshold applies to.
    #[test]
    fn a_full_bitmap_over_unverifiable_signatures_is_rejected() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"payload", true, 3);
        let confs = conf_refs(&f);

        let state = empty_committee();
        let aggregate = aggregate_with_participation(true);
        assert_eq!(
            aggregate.participation_count(),
            SYNC_COMMITTEE_SIZE,
            "the fixture only means something if the bitmap claims everyone signed"
        );

        let proof = proof_with_attestation(
            &f,
            &confs,
            &emitter,
            &topic0,
            Some(SyncAttestation {
                state: &state,
                aggregate: &aggregate,
                signing_message: b"altair-domain-and-header-hash",
            }),
        );

        let err = verify_evm_receipt(&proof)
            .expect_err("a bitmap claiming 512 signers over 512 zero keys must not pass");
        assert!(
            matches!(err, VerifyError::SyncCommittee(_)),
            "the refusal must come from the attestation, got: {err}"
        );
    }

    /// The attestation runs after the cheap checks, not before them.
    ///
    /// Verifying 342 BLS signatures is by far the most expensive step here. A
    /// proof that is malformed in some cheaper way must be refused for that
    /// reason, both because the message is more useful and because an
    /// attacker must not be able to spend a node's CPU with a proof that a
    /// byte comparison would have rejected.
    #[test]
    fn a_failed_transaction_is_refused_before_the_signatures_are_checked() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        // success = false: the receipt says the transaction reverted.
        let f = build_fixture(&emitter, topic0, b"payload", false, 3);
        let confs = conf_refs(&f);

        let state = empty_committee();
        let aggregate = aggregate_with_participation(false);
        let proof = proof_with_attestation(
            &f,
            &confs,
            &emitter,
            &topic0,
            Some(SyncAttestation {
                state: &state,
                aggregate: &aggregate,
                signing_message: b"altair-domain-and-header-hash",
            }),
        );

        let err = verify_evm_receipt(&proof).expect_err("a reverted transaction must be refused");
        assert_eq!(
            err,
            VerifyError::TxFailed,
            "the cheap structural refusal must win, so a malformed proof cannot \
             make a node verify 342 BLS signatures before saying no"
        );
    }
}
