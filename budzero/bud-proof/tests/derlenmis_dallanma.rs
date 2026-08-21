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
//! trace uzunlugu degil, dallanmanin kendisi -- 19 adimlik duz program
//! gecerken 2 turluk dongu dusuyor.
//!
//! Mevcut 106 prover testi bu bosluga dusmustu: hepsi ELLE kurulmus komut
//! dizileri kanitliyor (`inst(Opcode::Jnz, ...)`), derleyicinin gercek
//! ciktisini hicbiri kanitlamiyor. Elle kurulan Jnz gecerken derlenmis Jnz
//! dusuyorsa fark, komutun kendisinde degil, derleyicinin urettigi
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

/// Kaynagi derler, yurutur, kanitlar ve dogrular. `Ok(())` = kanit gecerli.
///
/// Public input'lar `bud-cli`'nin `run` yolundaki ile AYNI sekilde kurulur:
/// `initial_state_root` state agacinin koku degil, AIR'in trace'ten kendi
/// katladigi bellek+register goruntusudur; elle sabit vermek
/// `PublicInputsMismatch` uretir.
fn derle_yurut_kanitla(kaynak: &str) -> Result<(), String> {
    let bytecode = compile(kaynak, IsaProfile::Experimental)
        .map_err(|e| format!("derleme hatasi: {e:?}"))?;

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
        .map_err(|e| format!("kanit uretilemedi: {e:?}"))?;
    Prover::verify(&envelope, &pi, &bytecode).map_err(|e| format!("kanit gecersiz: {e:?}"))?;
    Ok(())
}

/// Kontrol: dallanmasiz program kanitlanabiliyor. Bu test YESIL olmali;
/// kirmizi donerse sorun dallanmada degil, boru hattinin tamaminda demektir
/// ve asagidaki testin teshisi yaniltici olur.
#[test]
fn dallanmasiz_program_kanitlanir() {
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
    derle_yurut_kanitla(kaynak).expect("dallanmasiz program kanitlanabilmeli");
}

/// BULGU: tek bir `if` iceren program kanitlanamiyor.
#[test]
fn derlenmis_if_kanitlanir() {
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
    derle_yurut_kanitla(kaynak)
        .expect("derleyicinin urettigi kosullu dallanma kanitlanabilmeli");
}

/// BULGU: `while` dongusu iceren program kanitlanamiyor.
#[test]
fn derlenmis_while_dongusu_kanitlanir() {
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
    derle_yurut_kanitla(kaynak).expect("derleyicinin urettigi dongu kanitlanabilmeli");
}
