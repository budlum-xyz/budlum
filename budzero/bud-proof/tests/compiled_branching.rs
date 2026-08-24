// Integration test: an unwrap here is how the test reports a broken
// invariant, so the workspace-wide panic gate does not apply.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! BULGU: derleyicinin urettigi kosullu dallanma kanitlanamiyor.
//!
//! Olculdu (canli `bud-cli run`): dallanma iceren HER program
//! "Verification of generated proof failed!" veriyor, duz programlar geciyor.
//!
//!   example.bud      (Jmp/Jnz yok, 22 adim) -> VALID
//!   example2.bud     (Jmp/Jnz yok, 16 adim) -> VALID
//!   uzun.bud         (Jmp/Jnz yok, 19 adim) -> VALID
//!   sadeceif.bud     (Jnz + Jmp)            -> BASARISIZ
//!   kisadongu.bud    (Jnz + Jmp)            -> BASARISIZ
//!   control_flow.bud (Jnz + Jmp)            -> BASARISIZ
//!   example_loop.bud (Jnz + Jmp)            -> BASARISIZ
//!
//! Bytecode karsilastirmasi ayrimi kesinlestirdi: basarisiz programlarin
//! opcode kumesinde `Jnz` ve `Jmp` var, gecenlerde ikisi de yok. Yani sorun
//! not the trace length but branching itself -- a straight 19 step program
//! gecerken 2 turluk dongu dusuyor.
//!
//! Mevcut 106 prover testi bu bosluga dusmustu: hepsi ELLE kurulmus komut
//! dizileri kanitliyor (`inst(Opcode::Jnz, ...)`), derleyicinin gercek
//! ciktisini hicbiri kanitlamiyor. Elle kurulan Jnz gecerken derlenmis Jnz
//! fails, the difference is not in the instruction itself but in the
//! cevresinde (pc hedefi, cagri cercevesi, register tahsisi) demektir.
//!
//! Bu test o boslugu kapatir: kaynak koddan baslar, derleyiciyi calistirir,
//! VM ile yurutur ve URETILEN kaniti dogrular.

use bud_compiler::compile;
use bud_isa::IsaProfile;
use bud_proof::adapter::{ExecutionPublicInputs, ProverAdapter};
use bud_proof::DefaultAdapter as Prover;
use bud_vm::Vm;
use tiny_keccak::{Hasher, Keccak};

/// Compiles, executes, proves and verifies the source. `Ok(())` = the proof is valid.
///
/// Public input'lar `bud-cli`'nin `run` yolundaki ile AYNI sekilde kurulur:
/// `initial_state_root` is not the root of the state tree but the value the AIR
/// katladigi bellek+register goruntusudur; elle sabit vermek
/// `PublicInputsMismatch` uretir.
fn compile_run_prove(kaynak: &str) -> Result<(), String> {
    let bytecode =
        compile(kaynak, IsaProfile::Experimental).map_err(|e| format!("derleme hatasi: {e:?}"))?;

    let mut vm = Vm::new(bud_compiler::MIN_VM_MEMORY_BYTES);
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

    let envelope = Prover::prove(&vm.trace, &pi, &bytecode)
        .map_err(|e| format!("the proof could not be produced: {e:?}"))?;
    Prover::verify(&envelope, &pi, &bytecode)
        .map_err(|e| format!("the proof is invalid: {e:?}"))?;
    Ok(())
}

/// Control: a branchless program can be proven. This test must be GREEN;
/// if it turns red the problem is not branching but the whole pipeline
/// ve asagidaki testin teshisi yaniltici olur.
#[test]
fn a_branchless_program_is_proven() {
    let kaynak = r#"
contract Duz {
    pub fn main() {
        let a = 1;
        let b = 2;
        let c = a + b;
        emit R(c);
    }
}
"#;
    compile_run_prove(kaynak).expect("dallanmasiz program kanitlanabilmeli");
}

/// BULGU: tek bir `if` iceren program kanitlanamiyor.
#[test]
fn a_compiled_if_is_proven() {
    let kaynak = r#"
contract SadeceIf {
    pub fn main() {
        let a = 5;
        if (a > 3) {
            emit Buyuk(a);
        } else {
            emit Kucuk(a);
        }
    }
}
"#;
    compile_run_prove(kaynak).expect("derleyicinin urettigi kosullu dallanma kanitlanabilmeli");
}

/// BULGU: `while` dongusu iceren program kanitlanamiyor.
#[test]
fn a_compiled_while_loop_is_proven() {
    let kaynak = r#"
contract KisaDongu {
    pub fn main() {
        let i = 0;
        while (i < 2) {
            i = i + 1;
        }
        emit R(i);
    }
}
"#;
    compile_run_prove(kaynak).expect("derleyicinin urettigi dongu kanitlanabilmeli");
}
