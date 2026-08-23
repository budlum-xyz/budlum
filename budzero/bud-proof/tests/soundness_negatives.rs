// Integration test: an unwrap here is how the test reports a broken
// invariant, so the workspace-wide panic gate does not apply.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use bud_isa::{Instruction, Opcode};
use bud_proof::adapter::{ExecutionPublicInputs, ProverAdapter};
use bud_proof::DefaultAdapter as Prover;
use bud_vm::Vm;
use tiny_keccak::{Hasher, Keccak};

fn inst(opcode: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32) -> u64 {
    Instruction {
        opcode,
        rd,
        rs1,
        rs2,
        imm,
    }
    .encode()
}

// ── Gercek soundness olcumu (2026-08-23) ─────────────────────────────────
//
// Buradaki testler bir `tampered_check_fails` harness'inin yerini aldi. O
// harness olculdu ve **hicbir zaman kisit olcmemis**: `p3_air::check_constraints`
// bu AIR icin iki sebeple daha ilk satirda panikliyor -
//
//   1. `num_public_values()` 56 dondururken harness 48 uzunlukta bir dizi
//      veriyordu -> "index out of bounds: the len is 48 but the index is 48".
//   2. O duzeltildikten sonra bile AIR permutasyon (lookup) verisi istiyor ->
//      "permutation() called on a builder created without permutation data".
//
// `catch_unwind(...).is_err()` bu panikleri bir kisit ihlalinden ayirt
// etmiyordu, dolayisiyla **tamper hic uygulanmadan da** `true` donuyordu
// (olculdu). Bes negatif testin hepsi bu yuzden yanlis sebepten yesildi ve
// AIR uzerinde hicbir guvence saglamiyordu.
//
// `bud_stark::prover` zaten ayni sonuca varmis: oradaki `check_constraints`
// cagrisi hem `#[cfg(debug_assertions)]` hem `if !has_aux_trace` ardinda
// duruyor - bu AIR icin o API yeterli degil.
//
// Bu yuzden asagidakiler AIR'i dogrudan degil **prove + verify** uzerinden
// olcuyor: gecerli bir kanit uretilir, sonra tek bir sey degistirilip
// dogrulayicinin reddetmesi beklenir. Bu, zincirin gercekten maruz kaldigi
// saldiri yuzeyidir - dogrulayiciya sunulan iddia.

/// Gecerli bir kanit ve onu dogrulamak icin gereken her sey.
type Kanit = (
    bud_proof::adapter::ProofEnvelope,
    ExecutionPublicInputs,
    Vec<u64>,
);

/// Tek bir public input alanini kurcalayan islev.
type Bozucu = fn(&mut ExecutionPublicInputs);

fn calisan_kanit() -> Kanit {
    let bytecode = vec![
        inst(Opcode::Add, 1, 2, 3, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    let mut vm = Vm::new(65536);
    vm.registers[2] = 10;
    vm.registers[3] = 20;
    let receipt = vm.run_receipt(&bytecode);

    let mut bytecode_bytes = Vec::with_capacity(bytecode.len() * 8);
    for w in &bytecode {
        bytecode_bytes.extend_from_slice(&w.to_le_bytes());
    }
    let mut program_hash = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(&bytecode_bytes);
    k.finalize(&mut program_hash);

    let initial_state_root = bud_proof::initial_state_root_of(
        bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(&vm.trace)),
        bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
            &vm.trace,
        )),
    );

    let pi = ExecutionPublicInputs {
        chain_id: 1,
        program_hash,
        initial_state_root,
        final_state_root: [0u8; 32],
        sender: vm.context.sender,
        nonce: vm.context.nonce,
        block_height: vm.context.block_height,
        gas_limit: vm.gas_limit,
        gas_used: vm.gas_used,
        exit_code: 0,
        trace_len: vm.trace.len() as u64,
        event_digest: bud_proof::event_digest_from_events(&receipt.events),
        state_writes_digest: [0u8; 32],
    };

    let envelope = Prover::prove(&vm.trace, &pi, &bytecode).expect("kanit uretilemedi");
    (envelope, pi, bytecode)
}

/// Kontrol grubu: kurcalanmamis kanit **kabul** edilmeli.
///
/// Bu test olmadan asagidaki reddetme testleri hicbir sey ifade etmez - eski
/// harness tam olarak bu kontrolun yoklugundan oturu bes testi birden yanlis
/// sebepten yesil gostermisti.
#[test]
fn kurcalanmamis_kanit_kabul_edilir() {
    let (envelope, pi, bytecode) = calisan_kanit();
    Prover::verify(&envelope, &pi, &bytecode).expect("temiz kanit reddedildi");
}

/// Kanit, yalnizca uretildigi program icin gecerli olmali.
///
/// Ayni kaniti farkli bir programin ciktisi gibi sunabilmek "hangi kodu
/// calistirdim" iddiasini tamamen degersiz kilardi.
#[test]
fn baska_program_icin_sunulan_kanit_reddedilir() {
    let (envelope, pi, _) = calisan_kanit();
    let baska = vec![
        inst(Opcode::Sub, 1, 2, 3, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    assert!(
        Prover::verify(&envelope, &pi, &baska).is_err(),
        "kanit baska bir program icin kabul edildi; program baglamasi yok"
    );
}

/// Public input alanlari tek tek kurcalanirsa kanit gecersiz olmali.
///
/// Her alan **ayri** iddia ediliyor: tek bir toplu `assert`, bir alanin
/// baglanmamis olmasini digerlerinin basarisi altinda gizlerdi. Bu tam olarak
/// SP1'in `committed_value_digest` kisitsizligi ve Aleo/snarkVM'in eksik
/// absorb bulgusunun sinifi - dogrulayici, kanit sisteminin kisitlamadigi
/// alanlari kendi kodunda denetlemek zorunda.
#[test]
fn kurcalanan_public_input_reddedilir() {
    let (envelope, temiz, bytecode) = calisan_kanit();

    let degisiklikler: Vec<(&str, Bozucu)> = vec![
        ("chain_id", |p| p.chain_id ^= 1),
        ("program_hash", |p| p.program_hash[0] ^= 1),
        ("initial_state_root", |p| p.initial_state_root[0] ^= 1),
        ("final_state_root", |p| p.final_state_root[0] ^= 1),
        ("sender", |p| p.sender ^= 1),
        ("nonce", |p| p.nonce ^= 1),
        ("block_height", |p| p.block_height ^= 1),
        ("gas_used", |p| p.gas_used ^= 1),
        ("exit_code", |p| p.exit_code ^= 1),
        ("trace_len", |p| p.trace_len ^= 1),
        ("event_digest", |p| p.event_digest[0] ^= 1),
        ("state_writes_digest", |p| p.state_writes_digest[0] ^= 1),
    ];

    for (ad, boz) in degisiklikler {
        let mut pi = temiz.clone();
        boz(&mut pi);
        assert!(
            Prover::verify(&envelope, &pi, &bytecode).is_err(),
            "`{ad}` kurcalandi ama kanit hala gecerli sayildi; bu alan kanita bagli degil"
        );
    }
}
