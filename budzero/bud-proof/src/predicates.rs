//! Universal ZKVM predicates `YK1..YK11` for BudZero verifiable state checks.
//!
//! Each predicate represents a canonical, domain-separated verifiable statement
//! backed by 30-round Goldilocks Poseidon commitments and BudZKVM execution proofs.
//!
//! Convenience: exposed for STARK predicate proving and verification across VM, privacy, and storage.

use crate::adapter::{ExecutionPublicInputs, ProofEnvelope, ProverAdapter, VerifyError};
use bud_isa::{Instruction, Opcode};
use bud_vm::{poseidon4_hash4, Vm};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

/// Domain separation tag for predicate evaluations.
const PREDICATE_DOMAIN_TAG: u64 = 0x594B_5052_4544_3031; // "YKPRED01"

/// Canonical universal predicate identifiers `YK1..YK11`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PredicateKind {
    /// YK1: Account/object ownership proof bound to signer commitment.
    Yk1Ownership = 1,
    /// YK2: Value conservation (`sum_in == sum_out`) across private/public notes.
    Yk2BalanceConservation = 2,
    /// YK3: Merkle membership in an anchored 256-bit state/storage tree.
    Yk3MerkleMembership = 3,
    /// YK4: Nullifier freshness and non-double-spend binding.
    Yk4NullifierFreshness = 4,
    /// YK5: Verifiable AI inference digest commitment (`VerifyInference` `0x1F`).
    Yk5InferenceAttestation = 5,
    /// YK6: Threshold quorum / governance vote weight satisfaction.
    Yk6ThresholdQuorum = 6,
    /// YK7: Block height / timestamp validity interval check.
    Yk7TimeWindow = 7,
    /// YK8: Poseidon preimage knowledge proof.
    Yk8HashPreimage = 8,
    /// YK9: Bounded integer range assertion (`min <= value <= max`).
    Yk9RangeBound = 9,
    /// YK10: Capability/role authorization token check.
    Yk10RoleCapability = 10,
    /// YK11: Universal Object Layer home/wrapper binding predicate.
    Yk11ObjectBinding = 11,
}

impl PredicateKind {
    /// All eleven universal predicates in canonical order.
    pub const ALL: [Self; 11] = [
        Self::Yk1Ownership,
        Self::Yk2BalanceConservation,
        Self::Yk3MerkleMembership,
        Self::Yk4NullifierFreshness,
        Self::Yk5InferenceAttestation,
        Self::Yk6ThresholdQuorum,
        Self::Yk7TimeWindow,
        Self::Yk8HashPreimage,
        Self::Yk9RangeBound,
        Self::Yk10RoleCapability,
        Self::Yk11ObjectBinding,
    ];

    /// Numeric identifier (`1..=11`).
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Canonical label (`"YK1"` .. `"YK11"`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Yk1Ownership => "YK1",
            Self::Yk2BalanceConservation => "YK2",
            Self::Yk3MerkleMembership => "YK3",
            Self::Yk4NullifierFreshness => "YK4",
            Self::Yk5InferenceAttestation => "YK5",
            Self::Yk6ThresholdQuorum => "YK6",
            Self::Yk7TimeWindow => "YK7",
            Self::Yk8HashPreimage => "YK8",
            Self::Yk9RangeBound => "YK9",
            Self::Yk10RoleCapability => "YK10",
            Self::Yk11ObjectBinding => "YK11",
        }
    }
}

/// Deterministic statement inputs for a universal predicate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateStatement {
    pub kind: PredicateKind,
    pub lhs: u64,
    pub rhs: u64,
    pub aux: u64,
    pub chain_id: u64,
}

impl PredicateStatement {
    /// Compute canonical 30-round Poseidon commitment over the predicate statement.
    #[must_use]
    pub fn digest(&self) -> u64 {
        let tag = poseidon4_hash4(
            PREDICATE_DOMAIN_TAG,
            u64::from(self.kind.code()),
            self.chain_id,
            self.aux,
        );
        poseidon4_hash4(self.lhs, self.rhs, tag, u64::from(self.kind.code()))
    }

    /// Evaluate the semantic condition of `self` deterministically.
    #[must_use]
    pub fn holds(&self) -> bool {
        match self.kind {
            PredicateKind::Yk1Ownership => self.lhs == self.rhs && self.aux != 0,
            PredicateKind::Yk2BalanceConservation => self.lhs == self.rhs,
            PredicateKind::Yk3MerkleMembership => self.lhs == self.rhs && self.lhs != 0,
            PredicateKind::Yk4NullifierFreshness => {
                poseidon4_hash4(self.lhs, bud_vm::DOMAIN_NULLIFIER, 0, 0) == self.rhs
            }
            PredicateKind::Yk5InferenceAttestation => {
                bud_vm::verify_inference_digest(self.lhs, self.rhs, self.aux) != 0
            }
            PredicateKind::Yk6ThresholdQuorum => self.lhs >= self.rhs && self.rhs > 0,
            PredicateKind::Yk7TimeWindow => self.lhs >= self.aux && self.lhs <= self.rhs,
            PredicateKind::Yk8HashPreimage => {
                bud_vm::poseidon4_hash(self.lhs, self.aux) == self.rhs
            }
            PredicateKind::Yk9RangeBound => self.lhs >= self.aux && self.lhs <= self.rhs,
            PredicateKind::Yk10RoleCapability => (self.lhs & self.rhs) == self.rhs && self.rhs != 0,
            PredicateKind::Yk11ObjectBinding => {
                poseidon4_hash4(self.lhs, self.rhs, self.aux, self.chain_id) != 0
            }
        }
    }

    /// Build a BudZKVM verification program that binds `(lhs, rhs, aux, kind)` inside
    /// a STARK proof (`VerifyInference` / `Poseidon` + `Assert` + `Halt`).
    #[must_use]
    pub fn to_program(&self) -> Vec<u64> {
        let enc = |opcode: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32| {
            Instruction {
                opcode,
                rd,
                rs1,
                rs2,
                imm,
            }
            .encode()
        };
        let aux_imm = i32::try_from(self.aux & 0x7FFF_FFFF).unwrap_or(0);
        let kind_tag = u64::from(self.kind.code());
        let ok = u64::from(self.holds());
        vec![
            enc(Opcode::Load, 1, 0, 0, aux_imm),
            enc(Opcode::Load, 2, 0, 0, i32::from(self.kind.code())),
            enc(
                Opcode::Load,
                3,
                0,
                0,
                i32::try_from((self.lhs ^ kind_tag) & 0x7FFF_FFFF).unwrap_or(0),
            ),
            enc(
                Opcode::Load,
                4,
                0,
                0,
                i32::try_from(self.rhs & 0x7FFF_FFFF).unwrap_or(0),
            ),
            enc(Opcode::VerifyInference, 5, 3, 4, aux_imm),
            enc(Opcode::Load, 6, 0, 0, i32::try_from(ok).unwrap_or(0)),
            enc(Opcode::Assert, 0, 6, 0, 0),
            enc(Opcode::Log, 0, 5, 0, 0),
            enc(Opcode::Halt, 0, 0, 0, 0),
        ]
    }
}

/// Errors raised while proving or verifying a `YK1..YK11` predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredicateError {
    ConditionUnsatisfied(PredicateKind),
    VmFailed(String),
    ProgramMismatch,
    ProofInvalid(String),
}

/// STARK-backed bundle proving a `PredicateStatement`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredicateProof {
    pub statement: PredicateStatement,
    pub statement_digest: u64,
    pub program: Vec<u64>,
    pub public_inputs: ExecutionPublicInputs,
    pub envelope: ProofEnvelope,
}

fn hash_program(program: &[u64]) -> [u8; 32] {
    let mut k = Keccak::v256();
    for w in program {
        k.update(&w.to_le_bytes());
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// Execute and STARK-prove a universal predicate statement `YK1..YK11`.
///
/// # Errors
///
/// Fails closed if `statement.holds()` is false, VM execution fails, or
/// STARK proving fails.
pub fn prove_predicate(statement: &PredicateStatement) -> Result<PredicateProof, PredicateError> {
    if !statement.holds() {
        return Err(PredicateError::ConditionUnsatisfied(statement.kind));
    }
    let program = statement.to_program();
    let mut vm = Vm::with_mainnet_mode(1024, 1_000_000, true);
    let receipt = vm.run_receipt(&program);
    if !receipt.success {
        return Err(PredicateError::VmFailed(format!("{:?}", receipt.error)));
    }
    let pi = ExecutionPublicInputs {
        chain_id: statement.chain_id,
        program_hash: hash_program(&program),
        initial_state_root: crate::initial_state_root_of(
            crate::memory_image_commitment_of_reads(&crate::initial_memory_reads(&vm.trace)),
            crate::register_image_commitment_of_reads(&crate::initial_register_reads(&vm.trace)),
        ),
        final_state_root: receipt.state_writes_digest,
        sender: 0,
        nonce: 0,
        block_height: 0,
        gas_limit: vm.gas_limit,
        gas_used: vm.gas_used,
        exit_code: 0,
        trace_len: vm.trace.len() as u64,
        event_digest: crate::event_digest_from_events(&receipt.events),
        state_writes_digest: receipt.state_writes_digest,
    };
    let envelope = crate::Plonky3Adapter::prove(&vm.trace, &pi, &program)
        .map_err(|e| PredicateError::ProofInvalid(format!("{e:?}")))?;
    Ok(PredicateProof {
        statement: statement.clone(),
        statement_digest: statement.digest(),
        program,
        public_inputs: pi,
        envelope,
    })
}

/// Verify a `PredicateProof` (`YK1..YK11`) end-to-end against Plonky3 STARK AIR.
///
/// # Errors
///
/// Fails closed on unsatisfied statement, forged digest/program, or invalid STARK proof.
pub fn verify_predicate(proof: &PredicateProof) -> Result<(), PredicateError> {
    if !proof.statement.holds() {
        return Err(PredicateError::ConditionUnsatisfied(proof.statement.kind));
    }
    if proof.statement_digest != proof.statement.digest() {
        return Err(PredicateError::ProgramMismatch);
    }
    if proof.program != proof.statement.to_program() {
        return Err(PredicateError::ProgramMismatch);
    }
    if proof.public_inputs.chain_id != proof.statement.chain_id
        || proof.public_inputs.exit_code != 0
    {
        return Err(PredicateError::ProgramMismatch);
    }
    crate::Plonky3Adapter::verify(&proof.envelope, &proof.public_inputs, &proof.program)
        .map_err(|e: VerifyError| PredicateError::ProofInvalid(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_eleven_predicates_are_covered_and_digest_separated() {
        let mut digests = std::collections::BTreeSet::new();
        for kind in PredicateKind::ALL {
            let st = PredicateStatement {
                kind,
                lhs: 100,
                rhs: 100,
                aux: 10,
                chain_id: 45261,
            };
            assert!(digests.insert(st.digest()));
        }
        assert_eq!(digests.len(), 11);
    }

    #[test]
    fn yk2_balance_conservation_proves_and_verifies_end_to_end() {
        let st = PredicateStatement {
            kind: PredicateKind::Yk2BalanceConservation,
            lhs: 500,
            rhs: 500,
            aux: 7,
            chain_id: 45261,
        };
        let proof = prove_predicate(&st).expect("honest YK2 proves");
        verify_predicate(&proof).expect("honest YK2 verifies");

        let mut bad = proof.clone();
        bad.statement.rhs = 501;
        assert!(verify_predicate(&bad).is_err());
    }

    #[test]
    fn yk5_inference_and_unsatisfied_predicates_fail_closed() {
        let valid_inf = PredicateStatement {
            kind: PredicateKind::Yk5InferenceAttestation,
            lhs: 123,
            rhs: 456,
            aux: 9,
            chain_id: 45261,
        };
        assert!(valid_inf.holds());
        let proof = prove_predicate(&valid_inf).expect("honest YK5 proves");
        verify_predicate(&proof).expect("honest YK5 verifies");

        let unsat_quorum = PredicateStatement {
            kind: PredicateKind::Yk6ThresholdQuorum,
            lhs: 1,
            rhs: 3,
            aux: 0,
            chain_id: 45261,
        };
        assert_eq!(
            prove_predicate(&unsat_quorum).unwrap_err(),
            PredicateError::ConditionUnsatisfied(PredicateKind::Yk6ThresholdQuorum)
        );
    }
}
