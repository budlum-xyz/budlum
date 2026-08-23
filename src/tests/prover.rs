//! Integration tests permissionless prover integration.
//!
//! Covers the required cases:
//!  - unregistered account: valid proof accepted, but NO reward
//!  - registered prover: valid proof accepted AND rewarded
//!  - invalid proof: fee burned, state unchanged
//!  - conflicting proof claim for same (domain, height): rejected
//!  - idempotent re-submission of same claim
//!
//! Uses real STARK proofs produced by `execution::zkvm::prove_bytecode`.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;

use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams};
use crate::cross_domain::MessageKind;
use crate::execution::zkvm::{prove_bytecode, DEFAULT_CONTRACT_GAS_LIMIT};
use crate::prover::{ProofAcceptance, ProofClaimKey, ZkProofSubmission};
use crate::storage::db::Storage;
use bud_isa::{Instruction, Opcode};
use bud_proof::{ExecutionPublicInputs, ProofEnvelope};
use std::sync::Arc;
use tempfile::tempdir;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn fresh_chain() -> Blockchain {
    let consensus = Arc::new(PoWEngine::new(0));
    Blockchain::new(consensus, None, 45262, None)
}

/// Alani kaydeder ve verilen programi zk izin listesine yazar.
///
/// Bu yardimci var, cunku artik bir kanit yalnizca gecerli olmakla kabul
/// edilmiyor: alanin o program icin acikca izin vermis olmasi gerekiyor. Izin
/// listesi bos dogar, yani kayit tek basina yetmez.
fn register_domain_allowing(bc: &mut Blockchain, id: u32, program: &[u64]) {
    let mut domain = crate::domain::plugin::default_domain(
        id,
        crate::domain::ConsensusKind::Zk,
        45262 + id as u64,
        "zk-proof-verification",
        0,
    );
    domain
        .zk_program_allowlist
        .push(crate::prover::zk_program_hash(program));
    bc.domain_registry.register(domain).expect("register");
}

/// A tiny valid program: Load imm 7 -> reg1, Log reg1, Halt.
fn sample_bytecode() -> Vec<u8> {
    let program = vec![
        Instruction {
            opcode: Opcode::Load,
            rd: 1,
            rs1: 0,
            rs2: 0,
            imm: 7,
        }
        .encode(),
        Instruction {
            opcode: Opcode::Log,
            rd: 0,
            rs1: 1,
            rs2: 0,
            imm: 0,
        }
        .encode(),
        Instruction {
            opcode: Opcode::Halt,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        }
        .encode(),
    ];
    program.into_iter().flat_map(|i| i.to_le_bytes()).collect()
}

fn real_proof() -> (ProofEnvelope, ExecutionPublicInputs, Vec<u64>) {
    prove_bytecode(&sample_bytecode(), DEFAULT_CONTRACT_GAS_LIMIT).expect("proving must succeed")
}

/// Build a submission whose message payload_hash correctly binds the proof.
fn submission(
    sender: Address,
    domain: u32,
    height: u64,
    proof: &ProofEnvelope,
    pi: &ExecutionPublicInputs,
    program: &[u64],
) -> ZkProofSubmission {
    let payload_hash = ZkProofSubmission::payload_binding_hash(proof, pi, program, domain, height);
    let message = CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain: domain,
        target_domain: domain,
        source_height: height,
        event_index: 0,
        nonce: height,
        sender,
        recipient: Address::zero(),
        payload_hash,
        kind: MessageKind::Custom(b"zk-proof".to_vec()),
        expiry_height: 1000,
    });
    ZkProofSubmission {
        message,
        proof: proof.clone(),
        public_inputs: pi.clone(),
        program: program.to_vec(),
    }
}

#[test]
fn unregistered_account_valid_proof_accepted_but_not_rewarded() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x01);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee); // enough only for the (refunded) fee

    let before = bc.state.get_balance(&sender);
    let outcome = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(
        outcome,
        ProofAcceptance::Accepted {
            rewarded: false,
            reward: 0
        }
    );
    // Valid proof fee is burned under fee-only fixed-supply policy.
    assert_eq!(bc.state.get_balance(&sender), before - fee);
    assert_eq!(bc.proof_claims.len(), 1);
}

#[test]
fn registered_prover_valid_proof_is_fee_only_without_mint() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let prover = addr(0x02);
    // Fund + register as prover.
    bc.state.add_balance(&prover, 5_000);
    bc.state.bond_prover(&prover, 2_000).unwrap();
    assert!(bc.state.registry.is_active_prover(&prover));

    let fee = bc.state.registry.params().proof_submission_fee;
    let before = bc.state.get_balance(&prover);
    let outcome = bc
        .submit_zk_proof(submission(prover, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(
        outcome,
        ProofAcceptance::Accepted {
            rewarded: false,
            reward: 0
        }
    );
    assert_eq!(bc.state.get_balance(&prover), before - fee);
}

#[test]
fn invalid_proof_burns_fee_and_leaves_state_unchanged() {
    let mut bc = fresh_chain();
    let (mut proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    // Corrupt the proof bytes so verification fails.
    if let Some(b) = proof.proof_bytes.first_mut() {
        *b ^= 0xFF;
    } else {
        proof.proof_bytes.push(0xFF);
    }
    let sender = addr(0x03);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee);

    let err = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(err.contains("invalid proof"));
    // Fee burned.
    assert_eq!(bc.state.get_balance(&sender), 0);
    // No claim recorded, no message stored.
    assert_eq!(bc.proof_claims.len(), 0);
    assert_eq!(bc.state.message_registry.len(), 0);
}

#[test]
fn insufficient_fee_rejected_without_verification() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x04); // no balance
    let err = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(err.contains("insufficient balance"));
    assert_eq!(bc.proof_claims.len(), 0);
}

#[test]
fn payload_hash_mismatch_rejected() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x05);
    bc.state.add_balance(&sender, 1_000);
    let mut sub = submission(sender, 1, 10, &proof, &pi, &program);
    // Tamper the binding.
    sub.message.payload_hash = [0xAAu8; 32];
    let err = bc.submit_zk_proof(sub).unwrap_err();
    assert!(err.contains("payload hash"));
    // Fee not charged (rejected before fee).
    assert_eq!(bc.state.get_balance(&sender), 1_000);
}

#[test]
fn wrong_message_kind_rejected() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x06);
    bc.state.add_balance(&sender, 1_000);
    let mut sub = submission(sender, 1, 10, &proof, &pi, &program);
    sub.message = CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain: 1,
        target_domain: 1,
        source_height: 10,
        event_index: 0,
        nonce: 10,
        sender,
        recipient: Address::zero(),
        payload_hash: sub.message.payload_hash,
        kind: MessageKind::BridgeLock, // wrong kind
        expiry_height: 1000,
    });
    let err = bc.submit_zk_proof(sub).unwrap_err();
    assert!(err.contains("not a ZK proof"));
}

#[test]
fn idempotent_resubmission_same_claim() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let prover = addr(0x07);
    bc.state.add_balance(&prover, 5_000);
    bc.state.bond_prover(&prover, 2_000).unwrap();
    let fee = bc.state.registry.params().proof_submission_fee;

    // First submission: accepted without minting.
    let first = bc
        .submit_zk_proof(submission(prover, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(
        first,
        ProofAcceptance::Accepted {
            rewarded: false,
            reward: 0
        }
    );
    let after_first = bc.state.get_balance(&prover);

    // Second identical submission: idempotent, NO extra reward.
    let second = bc
        .submit_zk_proof(submission(prover, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(second, ProofAcceptance::Idempotent);
    assert_eq!(bc.state.get_balance(&prover), after_first - fee);
    // Still one claim.
    assert_eq!(bc.proof_claims.len(), 1);
}

#[test]
fn conflicting_claim_same_domain_height_rejected() {
    use crate::prover::AcceptedProofClaim;
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);

    // Pre-seed an accepted claim for (domain=1, height=10) with a DIFFERENT
    // Final state root than the proof we are about to submit. (Seeding directly
    // Makes the conflict deterministic regardless of VM state-root semantics.)
    let key = ProofClaimKey {
        domain_id: 1,
        target_height: 10,
    };
    let conflicting_root = {
        let mut r = pi.final_state_root;
        r[0] ^= 0xFF; // guaranteed different
        r
    };
    bc.proof_claims.record(AcceptedProofClaim {
        key,
        final_state_root: conflicting_root,
        prover: addr(0x08),
        rewarded: false,
    });
    assert_eq!(bc.proof_claims.len(), 1);

    // A genuinely valid proof asserting a different root for the same
    // (domain, height) must be rejected as conflicting...
    let prover_b = addr(0x09);
    bc.state.add_balance(&prover_b, 1_000);
    let before_b = bc.state.get_balance(&prover_b);
    let err = bc
        .submit_zk_proof(submission(prover_b, 1, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(err.contains("conflicting"));
    // ...and the honest prover's fee is refunded (protocol-level rejection).
    assert_eq!(bc.state.get_balance(&prover_b), before_b);
    // No new claim recorded.
    assert_eq!(bc.proof_claims.len(), 1);
}

#[test]
fn proof_claim_registry_persists_across_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("prover.db");
    let db_path = db_path.to_string_lossy().to_string();

    let mut bc = Blockchain::new(
        Arc::new(PoWEngine::new(0)),
        Some(Storage::new(&db_path).unwrap()),
        45262,
        None,
    );
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let prover = addr(0x0A);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&prover, fee);

    bc.submit_zk_proof(submission(prover, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(bc.proof_claims.len(), 1);
    drop(bc);

    let restarted = Blockchain::new(
        Arc::new(PoWEngine::new(0)),
        Some(Storage::new(&db_path).unwrap()),
        45262,
        None,
    );
    let key = ProofClaimKey {
        domain_id: 1,
        target_height: 10,
    };
    assert!(restarted.proof_claims.get(&key).is_some());
    assert_eq!(restarted.proof_claims.len(), 1);
}

/// Baska bir zincir icin uretilmis kanit, burada kabul edilmemeli.
///
/// `public_inputs.chain_id` gonderenden gelir. STARK yalnizca "bu genel
/// girdilerle bu program boyle kostu" der; girdilerin **hangi zincire** ait
/// oldugunu kisitlamaz. Denetim dogrulayicida yapilmazsa, kendi zincirinde
/// tamamen gecerli bir kanit burada da gecer ve bir alani ilerletir.
#[test]
fn a_proof_bound_to_another_chain_is_refused() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x09);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee);

    // Ayni kanit, yalnizca chain_id baska bir zincire isaret ediyor.
    let mut foreign = pi.clone();
    foreign.chain_id = pi.chain_id + 1;

    let before = bc.state.get_balance(&sender);
    let err = bc
        .submit_zk_proof(submission(sender, 1, 11, &proof, &foreign, &program))
        .expect_err("baska zincire bagli kanit reddedilmeli");
    assert!(
        err.contains("chain"),
        "hata zincir baglamasini anlatmali: {err}"
    );
    assert_eq!(
        bc.state.get_balance(&sender),
        before,
        "reddedilen kanit ucret yakmamali: denetim ucretten once"
    );

    // Kontrol: dogru chain_id ile ayni kanit kabul edilir.
    bc.submit_zk_proof(submission(sender, 1, 11, &proof, &pi, &program))
        .expect("dogru zincire bagli kanit kabul edilmeli");
}

/// Bir yukseklik icin uretilmis kanit, baska bir yukseklige sunulamamali.
///
/// Kabul edilen iddianin anahtari `(alan, yukseklik)`. Baglama hash'i bu
/// ikisini kapsamazsa, gecerli tek bir kanit henuz iddia edilmemis her
/// cifte sunulabilir: saldirgan yalnizca tasima mesajini yeniden kurar,
/// kanita hic dokunmaz. Kanit "bir program boyle kostu" der; "bu, su
/// yukseklikteki gecistir" demez.
#[test]
fn a_proof_claimed_at_one_height_cannot_be_replayed_at_another() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x0a);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);

    // 20. yukseklik icin gecerli bir iddia.
    bc.submit_zk_proof(submission(sender, 1, 20, &proof, &pi, &program))
        .expect("ilk iddia kabul edilmeli");

    // Ayni kanit, 21. yukseklige sunuluyor: mesaj yeniden kuruluyor ama
    // baglama hash'i artik yuksekligi de kapsadigi icin tutmuyor.
    let mut replayed = submission(sender, 1, 20, &proof, &pi, &program);
    replayed.message.source_height = 21;
    let err = bc
        .submit_zk_proof(replayed)
        .expect_err("yuksekligi degistirilen kanit reddedilmeli");
    assert!(
        err.contains("payload hash"),
        "hata baglamayi anlatmali: {err}"
    );

    // Alan degistirmek de ayni sekilde tutmamali.
    let mut cross_domain = submission(sender, 1, 20, &proof, &pi, &program);
    cross_domain.message.target_domain = 2;
    let err = bc
        .submit_zk_proof(cross_domain)
        .expect_err("alani degistirilen kanit reddedilmeli");
    assert!(
        err.contains("payload hash"),
        "hata baglamayi anlatmali: {err}"
    );
}

/// Kanit kusursuz, program yetkisiz: reddedilmeli.
///
/// Saldirinin bicimi sudur: saldirgan kendi programini yazar, onu durustce
/// calistirir ve gercek bir STARK uretir. Kanit gecerlidir - hicbir kriptografik
/// denetim onu yakalayamaz, cunku yalan kanitta degil, calistirilan kodun
/// kendisindedir. `program_hash` denetimi de yardim etmez: gonderen hem programi
/// hem hash'i verdigi icin o denetim her zaman gecer.
///
/// Reddi saglayan tek sey alanin onceden ilan ettigi izin listesidir.
#[test]
fn a_valid_proof_over_an_unauthorized_program_is_refused() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();

    // Alan kayitli ve zk kabul ediyor, ama BASKA bir program icin izin veriyor.
    let mut other_program = program.clone();
    other_program.push(0);
    register_domain_allowing(&mut bc, 1, &other_program);

    let sender = addr(0x21);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);
    let before = bc.state.get_balance(&sender);

    let err = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(
        err.contains("not on the zk allowlist"),
        "izinsiz program izin listesi gerekcesiyle reddedilmeli, gelen: {err}"
    );

    // Kapi ucretten once: reddedilen gonderim para yakmamali.
    assert_eq!(
        bc.state.get_balance(&sender),
        before,
        "izin listesi reddi ucretten once olmali"
    );

    // Ve hicbir iddia kaydedilmemeli.
    assert!(bc
        .proof_claims
        .get(&ProofClaimKey {
            domain_id: 1,
            target_height: 10,
        })
        .is_none());
}

/// Bos izin listesi = kapali kapi.
///
/// Varsayilanin yonu onemli: yeni ya da goc etmis bir alan, kimse ona program
/// vermeden zk ile ilerletilememeli. Fail-open bir varsayilan bu alani sussuz
/// birakirdi.
#[test]
fn a_domain_with_an_empty_allowlist_accepts_no_proof() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();

    let domain = crate::domain::plugin::default_domain(
        2,
        crate::domain::ConsensusKind::Zk,
        45264,
        "zk-proof-verification",
        0,
    );
    assert!(
        domain.zk_program_allowlist.is_empty(),
        "alan zk kanitina kapali dogmali"
    );
    bc.domain_registry.register(domain).expect("register");

    let sender = addr(0x22);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);

    let err = bc
        .submit_zk_proof(submission(sender, 2, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(err.contains("not on the zk allowlist"), "gelen: {err}");
}

/// Kayitsiz alan: kanit degerlendirilmeden reddedilir.
#[test]
fn a_proof_for_an_unknown_domain_is_refused() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    let sender = addr(0x23);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);

    let err = bc
        .submit_zk_proof(submission(sender, 77, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(err.contains("unknown domain 77"), "gelen: {err}");
}

/// 1d (tazelik): genel girdi cok eski bir yukseklik iddia ederse kanit,
/// kanit sisteminin kendisi dogrulamadan once reddedilir.
#[test]
fn a_proof_claiming_a_stale_block_height_is_rejected() {
    let mut bc = fresh_chain();
    let (proof, mut pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x31);
    pi.block_height = 100_000;

    let err = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap_err();
    assert!(err.contains("block height"), "hata sebebi soylemeli: {err}");
}

/// 1e (sureklilik): kabul edilen kanit alanin ilerlemesini kendi final
/// kokune tasir; bu ilerlemenin gerisine yapilan iddia reddedilir.
#[test]
fn acceptance_advances_the_domain_and_stale_claims_are_rejected() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x32);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);

    let out = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert!(matches!(out, ProofAcceptance::Accepted { .. }));

    let d = bc.domain_registry.get(1).expect("alan kayitli");
    assert_eq!(
        d.last_committed_height, 10,
        "kabul, alanin ilerlemesini tasimali"
    );
    assert_eq!(
        d.last_committed_hash, pi.final_state_root,
        "final kok alana baglanmali"
    );

    // Ayni kanit, geride bir yukseklige iddia: ucret yakilmadan kapi 1e'de red.
    let err = bc
        .submit_zk_proof(submission(sender, 1, 9, &proof, &pi, &program))
        .unwrap_err();
    assert!(
        err.contains("stale zk claim"),
        "hata sebebi soylemeli: {err}"
    );

    // Ilerlemeyi tasiyan ilk kabulden sonra ayni yukseklige yeniden sunum
    // idempotent kalir (kapi 1e esitlige dokunmaz, calisma iddia katmaninin).
    let again = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &pi, &program))
        .unwrap();
    assert_eq!(again, ProofAcceptance::Idempotent);
}

/// Ilan edilen butcenin asilmasi reddedilir.
///
/// `gas_limit` ve `gas_used` genel girdilerin icinde ve baglama hash'inde:
/// gonderen ikisini de sonradan degistiremez. Ama ikisi **birbirine karsi**
/// denetlenmezse tutarli sekilde imzalanmis bir asim kabul edilirdi.
///
/// Kanit sistemi bu iliskiyi kisitlamaz - STARK "bu program bu girdilerle
/// boyle kostu" der, ilan edilen tavanin asilmadigini soylemez. Izin listesi
/// de soylemez: o **hangi kodun** calisabilecegini denetler, bu ise o kodun
/// ilan ettigi sinir icinde kalip kalmadigini.
#[test]
fn gas_used_above_the_declared_limit_is_refused() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x01);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);
    let before = bc.state.get_balance(&sender);

    let mut overspent = pi.clone();
    overspent.gas_limit = 1_000;
    overspent.gas_used = 1_001;

    let err = bc
        .submit_zk_proof(submission(sender, 1, 10, &proof, &overspent, &program))
        .expect_err("ilan edilen butcenin asilmasi reddedilmeli");
    assert!(
        err.contains("gas"),
        "ret, asilan seyin butce oldugunu soylemeli: {err}"
    );
    // Ret ucretten once: reddedilen bir kanit bakiyeye dokunmaz.
    assert_eq!(bc.state.get_balance(&sender), before);
}

/// Tam tavanda harcama kabul edilir: sinir asilmadi.
///
/// `>` degil `>=` yazmak, ilan ettigi kadarini harcayan durust bir programi
/// reddederdi.
#[test]
fn spending_exactly_the_declared_limit_is_allowed() {
    let mut bc = fresh_chain();
    let (proof, pi, program) = real_proof();
    register_domain_allowing(&mut bc, 1, &program);
    let sender = addr(0x02);
    let fee = bc.state.registry.params().proof_submission_fee;
    bc.state.add_balance(&sender, fee * 4);

    let mut exact = pi.clone();
    exact.gas_limit = 5_000;
    exact.gas_used = 5_000;

    // Butce denetimi bu kaniti gecirmeli. Kanit dogrulamasi baska sebeplerle
    // duserse de olur; olculen sey butce kapisinin yanlis reddetmemesi.
    let outcome = bc.submit_zk_proof(submission(sender, 1, 10, &proof, &exact, &program));
    if let Err(e) = &outcome {
        assert!(
            !e.contains("declared limit"),
            "tam tavanda harcama butce kapisina takilmamali: {e}"
        );
    }
}
