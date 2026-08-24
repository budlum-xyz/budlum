// Unsafe kilidi: bu crate su an 0 unsafe. Bir `unsafe` blok girdigi an
// the build FAILs (a regression gate). The same policy as the main crate.
#![forbid(unsafe_code)]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Halt = 0x00,
    Add = 0x01,
    Sub = 0x02,
    Mul = 0x03,
    Div = 0x04,
    Inv = 0x05,
    And = 0x06,
    Not = 0x09,
    Eq = 0x0A,
    Neq = 0x0B,
    Lt = 0x0C,
    Gt = 0x0D,
    Lte = 0x0E,
    Gte = 0x0F,
    Jmp = 0x10,
    Jnz = 0x11,
    Call = 0x12,
    Ret = 0x13,
    Load = 0x14,
    Store = 0x15,
    Push = 0x16,
    Pop = 0x17,
    Assert = 0x18,
    Poseidon = 0x19,
    Log = 0x1A,
    SRead = 0x1B,
    SWrite = 0x1C,
    Syscall = 0x1D,
    VerifyMerkle = 0x1E,
    /// AI Inference verification opcode.
    /// Verifies a ZKVM execution proof for AI inference, the core
    /// Primitive for trustless AI in the Agentic Economy paradigm.
    ///
    /// Semantics: VerifyInference rd, rs1, rs2, imm
    ///   Rd = destination register (0 = fail, 1 = success)
    ///   Rs1  = pointer to AiExecutionProof struct in memory
    ///   Rs2  = pointer to model_id + input_commitment in memory
    ///   Imm = proof_type (0 = STARK, 1 = SNARK wrap)
    ///
    /// Like VerifyMerkle, this opcode is mainnet-gated: it requires
    /// Explicit activation via MainnetActivation after the genesis
    /// Ceremony completes. This ensures the AI verification layer
    /// Is thoroughly audited before mainnet deployment.
    VerifyInference = 0x1F,
    /// Privacy layer - commitment for private transfer.
    /// Binds amount + recipient + blinding into a Poseidon commitment hash.
    /// Mainnet-gated (staged rollout, like VerifyMerkle/VerifyInference).
    PrivacyCommit = 0x20,
    /// Nullifier check - marks a spent commitment without revealing which.
    /// Prevents double-spend. Mainnet-gated.
    NullifierCheck = 0x21,
    /// Sum-conservation - proves Σinputs == Σoutputs without revealing
    /// Amounts (homomorphic commitment). Mainnet-gated.
    SumConservation = 0x22,
}

impl Opcode {
    pub fn is_experimental(&self) -> bool {
        false
    }

    /// Opcodes that require a separate mainnet
    /// Activation gate. VerifyMerkle and VerifyInference are the opcodes
    /// With a staged rollout.
    pub fn requires_mainnet_activation(&self) -> bool {
        matches!(
            self,
            Opcode::VerifyMerkle
                | Opcode::VerifyInference
                | Opcode::PrivacyCommit
                | Opcode::NullifierCheck
                | Opcode::SumConservation
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsaProfile {
    Production,
    Experimental,
    Testing,
}

/// Controls which opcodes
/// Are active on mainnet. Default: VerifyMerkle and VerifyInference NOT
/// Active on mainnet (staged rollout). After ceremony completion, flip
/// The corresponding flags to true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MainnetActivation {
    /// False = OFF on mainnet (staged rollout) - the same as bool::default,
    /// clippy::derivable_impls nedeniyle derive'a indirildi.
    pub verify_merkle_enabled: bool,
    /// AI inference verification opcode gate.
    /// False = mainnet'te KAPALI - requires post-ceremony activation.
    /// When true, VerifyInference (0x1F) opcode is allowed on mainnet,
    /// Enabling ZKVM-proven AI inference verification.
    pub verify_inference_enabled: bool,
    /// Privacy-layer opcode gates (staged rollout).
    pub privacy_commit_enabled: bool,
    pub nullifier_check_enabled: bool,
    pub sum_conservation_enabled: bool,
}

impl Default for MainnetActivation {
    /// Privacy opcodes are on; Merkle and inference verification are not.
    ///
    /// The privacy three (`PrivacyCommit`, `NullifierCheck`,
    /// `SumConservation`) were held closed because they hash through a
    /// Poseidon permutation truncated to four rounds. At `alpha = 7` that
    /// leaves algebraic degree 2401 - low enough to invert by interpolation
    /// and cheap enough to collide by brute force, so the commitments
    /// neither hid nor bound.
    ///
    /// The permutation is now the full Goldilocks width-8 instance: `R_F = 8`,
    /// `R_P = 22`, 30 rounds, and the AIR constrains every one of them. The
    /// reason for the gate is gone, so the gate is gone.
    ///
    /// `VerifyMerkle` and `VerifyInference` stay closed for reasons that have
    /// nothing to do with Poseidon. `VerifyInference` has no verification
    /// circuit behind it at all and returns a hard-coded zero; see
    /// `docs/AI_VERIFICATION_STATUS.md`.
    ///
    /// `VerifyMerkle`'in gerekcesi degisti. Uzun sure "unfinished path
    /// verification" yaziyordu ve dogruydu: 64 genisleme satiri Poseidon
    /// chain correctly row by row, but **the result it reaches was bound to nothing**.
    /// baglanmiyordu**. Kok karsilastirmasi orijinal satirin
    /// `merkle_current` hucresine bakiyordu ve o hucreye 64. turun
    /// ciktisinin yazildigini zorlayan kisit yoktu; genisleme satirlarina
    /// a prover that writes the claimed root itself there without touching
    /// produced a proof that verified. Measured, and it did.
    ///
    /// O bosluk kapandi (`plonky3_air.rs`, "Son turun ciktisi ...";
    /// `rejects_verify_merkle_root_not_produced_by_the_path`). Kapi yine de
    /// closed: the remaining condition is an **external check**, not a missing constraint.
    /// iddiasinin onu yazani ikna etmesi yetmez. Bu yorumun onceki surumu
    /// yol dogrulamasini "implemented" sayiyordu ve eksik olan sey tam da
    /// a binding nobody had written down as a separate item - the internal review's
    /// neyi kacirdigini gosteren orneklerden biri. Bayragi bu yorumun
    /// gucune dayanarak acmayin.
    fn default() -> Self {
        Self {
            verify_merkle_enabled: false,
            verify_inference_enabled: false,
            privacy_commit_enabled: true,
            nullifier_check_enabled: true,
            sum_conservation_enabled: true,
        }
    }
}

impl MainnetActivation {
    /// Full activation - all mainnet-gated opcodes enabled (post-ceremony).
    pub fn full() -> Self {
        Self {
            verify_merkle_enabled: true,
            verify_inference_enabled: true,
            privacy_commit_enabled: true,
            nullifier_check_enabled: true,
            sum_conservation_enabled: true,
        }
    }

    /// Check if an opcode is allowed under this activation state.
    pub fn allows(&self, opcode: Opcode) -> bool {
        if opcode.requires_mainnet_activation() {
            match opcode {
                Opcode::VerifyMerkle => self.verify_merkle_enabled,
                Opcode::VerifyInference => self.verify_inference_enabled,
                Opcode::PrivacyCommit => self.privacy_commit_enabled,
                Opcode::NullifierCheck => self.nullifier_check_enabled,
                Opcode::SumConservation => self.sum_conservation_enabled,
                _ => false,
            }
        } else {
            true
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    InvalidOpcode(u8),
    ExperimentalOpcodeDisabled(Opcode, IsaProfile),
    MainnetActivationRequired(Opcode),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::InvalidOpcode(op) => write!(f, "Unknown opcode 0x{:02X}", op),
            DecodeError::ExperimentalOpcodeDisabled(op, p) => {
                write!(f, "Opcode {:?} disabled in {:?}", op, p)
            }
            DecodeError::MainnetActivationRequired(op) => {
                write!(f, "Opcode {:?} requires mainnet activation", op)
            }
        }
    }
}

impl std::error::Error for DecodeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instruction {
    pub opcode: Opcode,
    pub rd: u8,
    pub rs1: u8,
    pub rs2: u8,
    pub imm: i32,
}

impl Instruction {
    pub fn encode(&self) -> u64 {
        let mut res = self.opcode as u64;
        res |= (self.rd as u64) << 8;
        res |= (self.rs1 as u64) << 13;
        res |= (self.rs2 as u64) << 18;
        res |= ((self.imm as u32) as u64) << 23;
        res
    }

    pub fn decode_any(val: u64) -> Result<Self, DecodeError> {
        let op_u8 = (val & 0xFF) as u8;
        let opcode = match op_u8 {
            0x00 => Opcode::Halt,
            0x01 => Opcode::Add,
            0x02 => Opcode::Sub,
            0x03 => Opcode::Mul,
            0x04 => Opcode::Div,
            0x05 => Opcode::Inv,
            0x06 => Opcode::And,
            0x09 => Opcode::Not,
            0x0A => Opcode::Eq,
            0x0B => Opcode::Neq,
            0x0C => Opcode::Lt,
            0x0D => Opcode::Gt,
            0x0E => Opcode::Lte,
            0x0F => Opcode::Gte,
            0x10 => Opcode::Jmp,
            0x11 => Opcode::Jnz,
            0x12 => Opcode::Call,
            0x13 => Opcode::Ret,
            0x14 => Opcode::Load,
            0x15 => Opcode::Store,
            0x16 => Opcode::Push,
            0x17 => Opcode::Pop,
            0x18 => Opcode::Assert,
            0x19 => Opcode::Poseidon,
            0x1A => Opcode::Log,
            0x1B => Opcode::SRead,
            0x1C => Opcode::SWrite,
            0x1D => Opcode::Syscall,
            0x1E => Opcode::VerifyMerkle,
            0x1F => Opcode::VerifyInference,
            0x20 => Opcode::PrivacyCommit,
            0x21 => Opcode::NullifierCheck,
            0x22 => Opcode::SumConservation,
            _ => return Err(DecodeError::InvalidOpcode(op_u8)),
        };
        Ok(Self {
            opcode,
            rd: ((val >> 8) & 0x1F) as u8,
            rs1: ((val >> 13) & 0x1F) as u8,
            rs2: ((val >> 18) & 0x1F) as u8,
            imm: ((val >> 23) & 0xFFFFFFFF) as i32,
        })
    }

    pub fn decode_for_profile(val: u64, profile: IsaProfile) -> Result<Self, DecodeError> {
        let inst = Self::decode_any(val)?;
        if inst.opcode.is_experimental() && profile == IsaProfile::Production {
            return Err(DecodeError::ExperimentalOpcodeDisabled(
                inst.opcode,
                profile,
            ));
        }
        Ok(inst)
    }

    /// Decode with mainnet activation gate.
    /// Mainnet callers must pass `MainnetActivation::full` post-ceremony.
    pub fn decode_for_mainnet(
        val: u64,
        activation: MainnetActivation,
    ) -> Result<Self, DecodeError> {
        let inst = Self::decode_for_profile(val, IsaProfile::Production)?;
        if !activation.allows(inst.opcode) {
            return Err(DecodeError::MainnetActivationRequired(inst.opcode));
        }
        Ok(inst)
    }

    pub fn decode(val: u64) -> Result<Self, String> {
        let profile = if cfg!(feature = "experimental") {
            IsaProfile::Experimental
        } else {
            #[cfg(test)]
            {
                IsaProfile::Testing
            }
            #[cfg(not(test))]
            {
                IsaProfile::Production
            }
        };
        Self::decode_for_profile(val, profile).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_merkle_enabled_in_production() {
        let raw = Instruction {
            opcode: Opcode::VerifyMerkle,
            rd: 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
        }
        .encode();
        let inst = Instruction::decode_for_profile(raw, IsaProfile::Production)
            .expect("VerifyMerkle enabled in Production");
        assert_eq!(inst.opcode, Opcode::VerifyMerkle);
        assert!(!Opcode::VerifyMerkle.is_experimental());
    }

    #[test]
    fn s2_mainnet_activation_default_rejects_verify_merkle() {
        let raw = Instruction {
            opcode: Opcode::VerifyMerkle,
            rd: 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
        }
        .encode();
        let err = Instruction::decode_for_mainnet(raw, MainnetActivation::default())
            .expect_err("VerifyMerkle blocked on mainnet by default");
        assert!(matches!(
            err,
            DecodeError::MainnetActivationRequired(Opcode::VerifyMerkle)
        ));
    }

    #[test]
    fn s2_mainnet_activation_full_allows_verify_merkle() {
        let raw = Instruction {
            opcode: Opcode::VerifyMerkle,
            rd: 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
        }
        .encode();
        let inst = Instruction::decode_for_mainnet(raw, MainnetActivation::full())
            .expect("VerifyMerkle allowed with full mainnet activation");
        assert_eq!(inst.opcode, Opcode::VerifyMerkle);
    }

    #[test]
    fn s2_mainnet_activation_allows_other_opcodes() {
        let raw = Instruction {
            opcode: Opcode::Add,
            rd: 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
        }
        .encode();
        let inst = Instruction::decode_for_mainnet(raw, MainnetActivation::default())
            .expect("Add always allowed on mainnet");
        assert_eq!(inst.opcode, Opcode::Add);
    }

    #[test]
    fn plain_opcodes_still_decode_in_production() {
        let raw = Instruction {
            opcode: Opcode::Add,
            rd: 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
        }
        .encode();
        let inst = Instruction::decode_for_profile(raw, IsaProfile::Production).unwrap();
        assert_eq!(inst.opcode, Opcode::Add);
    }

    // ===================== VerifyInference Opcode =====================

    #[test]
    fn verify_inference_enabled_in_production() {
        let raw = Instruction {
            opcode: Opcode::VerifyInference,
            rd: 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
        }
        .encode();
        let inst = Instruction::decode_for_profile(raw, IsaProfile::Production)
            .expect("VerifyInference enabled in Production");
        assert_eq!(inst.opcode, Opcode::VerifyInference);
        assert!(!Opcode::VerifyInference.is_experimental());
    }

    #[test]
    fn p5_mainnet_activation_default_rejects_verify_inference() {
        let raw = Instruction {
            opcode: Opcode::VerifyInference,
            rd: 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
        }
        .encode();
        let err = Instruction::decode_for_mainnet(raw, MainnetActivation::default())
            .expect_err("VerifyInference blocked on mainnet by default");
        assert!(matches!(
            err,
            DecodeError::MainnetActivationRequired(Opcode::VerifyInference)
        ));
    }

    #[test]
    fn p5_mainnet_activation_full_allows_verify_inference() {
        let raw = Instruction {
            opcode: Opcode::VerifyInference,
            rd: 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
        }
        .encode();
        let inst = Instruction::decode_for_mainnet(raw, MainnetActivation::full())
            .expect("VerifyInference allowed with full mainnet activation");
        assert_eq!(inst.opcode, Opcode::VerifyInference);
    }

    // ===================== Privacy opcodes (0x20 to 0x22) =====================

    #[test]
    fn d2_privacy_opcodes_decode_and_decode_any_roundtrip() {
        for op in [
            Opcode::PrivacyCommit,
            Opcode::NullifierCheck,
            Opcode::SumConservation,
        ] {
            let raw = Instruction {
                opcode: op,
                rd: 1,
                rs1: 2,
                rs2: 3,
                imm: 0,
            }
            .encode();
            let inst = Instruction::decode_any(raw).expect("decodes via decode_any");
            assert_eq!(inst.opcode, op);
            let inst2 = Instruction::decode_for_profile(raw, IsaProfile::Production).unwrap();
            assert_eq!(inst2.opcode, op);
        }
    }

    /// The privacy opcodes decode under the default activation now that the
    /// permutation behind them is the full 30-round instance.
    ///
    /// Reverse-edit alarm: if the round count gate is ever weakened,
    /// four-round Poseidon at degree 2401 made the commitments neither hiding
    /// nor binding; with 8 full + 22 partial rounds that reason is gone.
    #[test]
    fn d2_mainnet_activation_default_allows_privacy_opcodes() {
        for op in [
            Opcode::PrivacyCommit,
            Opcode::NullifierCheck,
            Opcode::SumConservation,
        ] {
            let raw = Instruction {
                opcode: op,
                rd: 1,
                rs1: 2,
                rs2: 3,
                imm: 0,
            }
            .encode();
            let inst = Instruction::decode_for_mainnet(raw, MainnetActivation::default())
                .unwrap_or_else(|e| panic!("{op:?} must decode by default, got {e:?}"));
            assert_eq!(inst.opcode, op);
        }
    }

    /// The two opcodes that are still gated must keep failing closed, and for
    /// their own reasons - an unfinished Merkle path check and a
    /// VerifyInference that has no circuit behind it.
    #[test]
    fn d2_mainnet_activation_default_still_rejects_merkle_and_inference() {
        for op in [Opcode::VerifyMerkle, Opcode::VerifyInference] {
            let raw = Instruction {
                opcode: op,
                rd: 1,
                rs1: 2,
                rs2: 3,
                imm: 0,
            }
            .encode();
            let err = Instruction::decode_for_mainnet(raw, MainnetActivation::default())
                .expect_err("must stay blocked on mainnet by default");
            assert!(
                matches!(err, DecodeError::MainnetActivationRequired(_)),
                "{op:?} must require mainnet activation"
            );
        }
    }

    #[test]
    fn d2_mainnet_activation_full_allows_privacy_opcodes() {
        for op in [
            Opcode::PrivacyCommit,
            Opcode::NullifierCheck,
            Opcode::SumConservation,
        ] {
            let raw = Instruction {
                opcode: op,
                rd: 1,
                rs1: 2,
                rs2: 3,
                imm: 0,
            }
            .encode();
            let inst = Instruction::decode_for_mainnet(raw, MainnetActivation::full())
                .expect("privacy opcode allowed with full mainnet activation");
            assert_eq!(inst.opcode, op);
        }
    }

    /// The privacy opcodes are open, and the permutation behind them has to
    /// stay strong enough to justify that.
    ///
    /// They were closed while Poseidon was truncated to four rounds: at
    /// `alpha = 7` the permutation sat at algebraic degree 2401, invertible by
    /// interpolation and collidable by brute force, so `PrivacyCommit` hid
    /// nothing and `NullifierCheck` bound nothing. The permutation is now the
    /// full 30-round instance, so the gate came off.
    ///
    /// Reverse-edit alarm: if the round count is ever
    /// cut back down, the privacy layer is unsound again and the flags must
    /// close in the same change.
    #[test]
    fn privacy_opcodes_are_open_only_while_poseidon_is_strong() {
        let rounds = bud_vm_round_count();
        assert_eq!(
            rounds, 30,
            "the Poseidon round count changed to {rounds}; the privacy gate is \
             open on the assumption of 8 full + 22 partial rounds. Re-derive \
             the security argument in budzero/docs/STABILIZATION.md and close \
             the flags in the same change."
        );

        let default = MainnetActivation::default();
        for (opcode, enabled) in [
            (Opcode::PrivacyCommit, default.privacy_commit_enabled),
            (Opcode::NullifierCheck, default.nullifier_check_enabled),
            (Opcode::SumConservation, default.sum_conservation_enabled),
        ] {
            assert!(enabled, "{opcode:?} should be enabled by default");
            assert!(
                default.allows(opcode),
                "{opcode:?} must be permitted under the default activation state"
            );
        }
    }

    /// The two opcodes still gated are gated for their own reasons, not
    /// Poseidon's, so lengthening the permutation must not have opened them.
    #[test]
    fn merkle_and_inference_stay_gated_by_default() {
        let default = MainnetActivation::default();
        assert!(
            !default.verify_merkle_enabled,
            "VerifyMerkle path verification is still unfinished"
        );
        assert!(
            !default.verify_inference_enabled,
            "VerifyInference has no verification circuit; it returns a \
             hard-coded zero. See docs/AI_VERIFICATION_STATUS.md"
        );
        assert!(!default.allows(Opcode::VerifyMerkle));
        assert!(!default.allows(Opcode::VerifyInference));
    }

    /// Reads the round count from the constant `bud-vm` exposes.
    ///
    /// Kept as a helper so the assertion above names what it checks rather than
    /// hiding a magic number behind an array length.
    fn bud_vm_round_count() -> usize {
        // bud-isa must not depend on bud-vm (it sits below it in the graph), so
        // the count is read from the source rather than imported.
        let src = include_str!("../../bud-vm/src/lib.rs");
        let marker = "pub const POSEIDON_RC_FULL: [[u64; 8]; ";
        let start = src
            .find(marker)
            .expect("POSEIDON_RC_FULL declaration not found in bud-vm")
            + marker.len();
        let end = start
            + src[start..]
                .find(']')
                .expect("malformed POSEIDON_RC_FULL declaration");
        src[start..end]
            .trim()
            .parse()
            .expect("POSEIDON_RC round count is not a number")
    }
}
