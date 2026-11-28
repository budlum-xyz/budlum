//! Universal ZKVM predicates `YK1..YK11` for BudZero verifiable state checks.
//!
//! Only YK6 is presently provable/verifiable, as a public quorum counter
//! checked against independently authenticated shares at its escrow boundary.
//! The other predicates require private-witness or context binding not yet
//! supplied by this generic public-statement API; their doors stay closed.
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
            // YK2 only carries the caller's two public numbers and cannot bind
            // hidden note commitments, so it must never report value
            // conservation until a commitment-bound circuit exists.
            PredicateKind::Yk2BalanceConservation => false,
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

    /// Build a BudZKVM program for the public statement.
    ///
    /// The quorum predicate is backed by independently checked ML-DSA shares
    /// at the threshold-escrow boundary; its digest uses ordinary Poseidon.
    /// Other YK predicates retain the staged VerifyInference opcode and
    /// remain closed under the default schedule. In particular this must not
    /// turn a claimed Merkle root, a model digest, or an unsigned object grant
    /// into a live proof by routing them around their opening gates.
    #[must_use]
    pub fn to_program(&self) -> Vec<u64> {
        let commitment_opcode = if self.kind == PredicateKind::Yk6ThresholdQuorum {
            Opcode::Poseidon
        } else {
            Opcode::VerifyInference
        };
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
        let lo31 = |v: u64| i32::try_from(v & 0x7FFF_FFFF).unwrap_or(0);
        let hi31 = |v: u64| i32::try_from((v >> 31) & 0x7FFF_FFFF).unwrap_or(0);
        let top_bits = (((self.lhs >> 62) & 3)
            | (((self.rhs >> 62) & 3) << 2)
            | (((self.aux >> 62) & 3) << 4)
            | (((self.chain_id >> 62) & 3) << 6)) as i32;
        let aux_lo = lo31(self.aux);
        let kind_tag = u64::from(self.kind.code());
        let ok = u64::from(self.holds());
        // Bind all 64 bits of (lhs, rhs, aux, chain_id) plus kind into the
        // instruction stream and Poseidon commitment so reusing a STARK proof
        // under modified high bits is rejected by program_hash verification.
        vec![
            enc(Opcode::Load, 1, 0, 0, aux_lo),
            enc(Opcode::Load, 2, 0, 0, i32::from(self.kind.code())),
            enc(Opcode::Load, 3, 0, 0, lo31(self.lhs ^ kind_tag)),
            enc(Opcode::Load, 4, 0, 0, lo31(self.rhs)),
            enc(Opcode::Load, 7, 0, 0, hi31(self.lhs)),
            enc(Opcode::Load, 8, 0, 0, hi31(self.rhs)),
            enc(Opcode::Load, 9, 0, 0, hi31(self.aux)),
            enc(Opcode::Load, 10, 0, 0, lo31(self.chain_id)),
            enc(Opcode::Load, 11, 0, 0, hi31(self.chain_id)),
            enc(Opcode::Load, 12, 0, 0, top_bits),
            enc(Opcode::Poseidon, 13, 7, 8, 0),
            enc(Opcode::Poseidon, 14, 9, 10, 0),
            enc(Opcode::Poseidon, 15, 11, 12, 0),
            enc(Opcode::Poseidon, 16, 13, 14, 0),
            enc(Opcode::Poseidon, 17, 16, 15, 0),
            enc(commitment_opcode, 5, 3, 4, aux_lo),
            enc(Opcode::Poseidon, 5, 5, 17, 0),
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
    /// This generic API does not bind the private witness or remote context
    /// required by this predicate, independently of the VM opcode schedule.
    ActivationClosed(PredicateKind),
    VmFailed(String),
    ProgramMismatch,
    ProofInvalid(String),
}

/// STARK-backed bundle proving a `PredicateStatement`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    // A VM accepting VerifyInference would still only prove an equality of
    // caller-supplied public numbers, not ownership, Merkle membership, or an
    // actual inference. Opening the opcode must not implicitly open YK1..YK11.
    if statement.kind != PredicateKind::Yk6ThresholdQuorum {
        return Err(PredicateError::ActivationClosed(statement.kind));
    }
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
    // Independently refuse externally produced STARKs for the unbound kinds:
    // an isolated prover can run the opcode even while production decoding is
    // closed. A valid execution trace is not a proof of a missing relation.
    if proof.statement.kind != PredicateKind::Yk6ThresholdQuorum {
        return Err(PredicateError::ActivationClosed(proof.statement.kind));
    }
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
        || proof.public_inputs.program_hash != hash_program(&proof.program)
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
    fn yk2_balance_conservation_stays_closed_until_private_witness_is_bound() {
        for (lhs, rhs) in [(500, 500), (0, 0), (1_000, 999)] {
            let st = PredicateStatement {
                kind: PredicateKind::Yk2BalanceConservation,
                lhs,
                rhs,
                aux: 7,
                chain_id: 45261,
            };
            assert!(
                !st.holds(),
                "prover-chosen public sums must never report value conservation"
            );
            let mut isolated_vm = Vm::with_mainnet_mode(1024, 1_000_000, false);
            assert!(
                !isolated_vm.run_receipt(&st.to_program()).success,
                "even an isolated VM must reject a YK2 statement lacking hidden note commitments"
            );
            assert_eq!(
                prove_predicate(&st).unwrap_err(),
                PredicateError::ActivationClosed(PredicateKind::Yk2BalanceConservation)
            );
        }

        // Verifier must refuse YK2 with ActivationClosed before evaluating holds(),
        // even when handed an externally built proof shell.
        let quorum = PredicateStatement {
            kind: PredicateKind::Yk6ThresholdQuorum,
            lhs: 4,
            rhs: 4,
            aux: 7,
            chain_id: 45261,
        };
        let mut forged_yk2 = prove_predicate(&quorum).expect("quorum proof builds");
        forged_yk2.statement = PredicateStatement {
            kind: PredicateKind::Yk2BalanceConservation,
            lhs: 500,
            rhs: 500,
            aux: 7,
            chain_id: 45261,
        };
        assert_eq!(
            verify_predicate(&forged_yk2).unwrap_err(),
            PredicateError::ActivationClosed(PredicateKind::Yk2BalanceConservation)
        );
    }

    #[test]
    fn isolated_valid_yk1_execution_proof_cannot_authorize_ownership() {
        let statement = PredicateStatement {
            kind: PredicateKind::Yk1Ownership,
            lhs: 500,
            rhs: 500,
            aux: 1,
            chain_id: 45261,
        };
        let program = statement.to_program();
        assert!(program.iter().any(|word| {
            Instruction::decode(*word).is_ok_and(|ins| ins.opcode == Opcode::VerifyInference)
        }));
        // An isolated VM can produce a real STARK for a public equality.
        // That still provides no private ownership witness and must be refused
        // at the *verifier* boundary, not just at production VM admission.
        let mut vm = Vm::with_mainnet_mode(1024, 1_000_000, false);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        let pi = ExecutionPublicInputs {
            chain_id: statement.chain_id,
            program_hash: hash_program(&program),
            initial_state_root: crate::initial_state_root_of(
                crate::memory_image_commitment_of_reads(&crate::initial_memory_reads(&vm.trace)),
                crate::register_image_commitment_of_reads(&crate::initial_register_reads(
                    &vm.trace,
                )),
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
            .expect("the isolated STARK really proves VM execution");
        crate::Plonky3Adapter::verify_with_activation(
            &envelope,
            &pi,
            &program,
            bud_isa::MainnetActivation::full(),
        )
        .expect("a hypothetically activated VM accepts this public execution trace");
        let proof = PredicateProof {
            statement: statement.clone(),
            statement_digest: statement.digest(),
            program,
            public_inputs: pi,
            envelope,
        };
        assert_eq!(
            verify_predicate(&proof),
            Err(PredicateError::ActivationClosed(
                PredicateKind::Yk1Ownership
            ))
        );
    }

    #[test]
    fn yk6_quorum_uses_poseidon_without_opening_inference_or_merkle() {
        let st = PredicateStatement {
            kind: PredicateKind::Yk6ThresholdQuorum,
            lhs: 4,
            rhs: 4,
            aux: 7,
            chain_id: 45261,
        };
        assert!(!bud_isa::MainnetActivation::default().verify_inference_enabled);
        assert!(st.to_program().iter().any(|word| {
            Instruction::decode(*word).is_ok_and(|inst| inst.opcode == Opcode::Poseidon)
        }));
        let proof = prove_predicate(&st).expect("quorum predicate proves with ordinary Poseidon");
        verify_predicate(&proof).expect("quorum predicate verifies with ordinary Poseidon");
        let mut bad = proof;
        bad.statement.aux ^= 1;
        assert_eq!(verify_predicate(&bad), Err(PredicateError::ProgramMismatch));
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
        assert_eq!(
            prove_predicate(&valid_inf).unwrap_err(),
            PredicateError::ActivationClosed(PredicateKind::Yk5InferenceAttestation)
        );
        for kind in [
            PredicateKind::Yk3MerkleMembership,
            PredicateKind::Yk11ObjectBinding,
        ] {
            let gated = PredicateStatement {
                kind,
                lhs: 123,
                rhs: 123,
                aux: 1,
                chain_id: 45261,
            };
            assert_eq!(
                prove_predicate(&gated).unwrap_err(),
                PredicateError::ActivationClosed(kind)
            );
        }

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

    #[test]
    fn budprf01_predicates_refuses_upper_33bit_stark_forgery_and_program_hash_tamper() {
        // 1. Every single bit of all four 64-bit statement inputs must affect to_program().
        let base = PredicateStatement {
            kind: PredicateKind::Yk6ThresholdQuorum,
            lhs: 4,
            rhs: 4,
            aux: 7,
            chain_id: 45261,
        };
        let base_prog = base.to_program();
        for bit in [31u32, 32, 62, 63] {
            let mask = 1u64 << bit;
            let mut s_lhs = base.clone();
            s_lhs.lhs ^= mask;
            assert_ne!(
                s_lhs.to_program(),
                base_prog,
                "flipping lhs bit {bit} must change to_program()"
            );
            let mut s_rhs = base.clone();
            s_rhs.rhs ^= mask;
            assert_ne!(
                s_rhs.to_program(),
                base_prog,
                "flipping rhs bit {bit} must change to_program()"
            );
            let mut s_aux = base.clone();
            s_aux.aux ^= mask;
            assert_ne!(
                s_aux.to_program(),
                base_prog,
                "flipping aux bit {bit} must change to_program()"
            );
            let mut s_cid = base.clone();
            s_cid.chain_id ^= mask;
            assert_ne!(
                s_cid.to_program(),
                base_prog,
                "flipping chain_id bit {bit} must change to_program()"
            );
        }

        // 2. Live zero-cost STARK forgery: prove a small quorum once, then forge upper
        // 33 bits of aux or (lhs, rhs) while recomputing statement_digest only.
        let honest = prove_predicate(&base).expect("honest quorum proves");
        verify_predicate(&honest).expect("honest quorum verifies");

        let mut forged_aux = honest.clone();
        forged_aux.statement.aux |= 1u64 << 32;
        forged_aux.statement_digest = forged_aux.statement.digest();
        assert!(
            verify_predicate(&forged_aux).is_err(),
            "reusing STARK proof with forged upper-33-bit aux must be refused"
        );

        let mut forged_quorum = honest;
        forged_quorum.statement.lhs |= 1u64 << 32;
        forged_quorum.statement.rhs |= 1u64 << 32;
        forged_quorum.statement_digest = forged_quorum.statement.digest();
        assert!(
            verify_predicate(&forged_quorum).is_err(),
            "reusing STARK proof with forged upper-33-bit quorum weight must be refused"
        );

        // 3. Honest full-64-bit escrow aux value (> 2^63, >= GOLDILOCKS_P) still proves & verifies.
        let high_aux = PredicateStatement {
            kind: PredicateKind::Yk6ThresholdQuorum,
            lhs: 5,
            rhs: 4,
            aux: 0xFFFF_FFFF_FFFF_FFFE,
            chain_id: 45261,
        };
        let high_proof = prove_predicate(&high_aux).expect("high-64-bit aux proves");
        verify_predicate(&high_proof).expect("high-64-bit aux verifies");
    }
}
