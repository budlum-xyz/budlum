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
    Or = 0x07,
    Xor = 0x08,
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
    /// P5 ADIM11 Bulgu 32: AI Inference verification opcode.
    /// Verifies a ZKVM execution proof for AI inference — the core
    /// primitive for trustless AI in the Agentic Economy paradigm.
    ///
    /// Semantics: VerifyInference rd, rs1, rs2, imm
    ///   rd   = destination register (0 = fail, 1 = success)
    ///   rs1  = pointer to AiExecutionProof struct in memory
    ///   rs2  = pointer to model_id + input_commitment in memory
    ///   imm  = proof_type (0 = STARK, 1 = SNARK wrap)
    ///
    /// Like VerifyMerkle, this opcode is mainnet-gated: it requires
    /// explicit activation via MainnetActivation after the genesis
    /// ceremony completes. This ensures the AI verification layer
    /// is thoroughly audited before mainnet deployment.
    VerifyInference = 0x1F,
}

impl Opcode {
    pub fn is_experimental(&self) -> bool {
        false
    }

    /// S2 (Paket B, 2026-07-17): Opcodes that require a separate mainnet
    /// activation gate. VerifyMerkle and VerifyInference are the opcodes
    /// with a staged rollout.
    pub fn requires_mainnet_activation(&self) -> bool {
        matches!(self, Opcode::VerifyMerkle | Opcode::VerifyInference)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsaProfile {
    Production,
    Experimental,
    Testing,
}

/// S2 (Paket B, 2026-07-17) + P5 ADIM11 (Bulgu 32): Controls which opcodes
/// are active on mainnet. Default: VerifyMerkle and VerifyInference NOT
/// active on mainnet (staged rollout). After ceremony completion, flip
/// the corresponding flags to true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MainnetActivation {
    /// false = mainnet'te KAPALI (staged rollout) — bool::default() ile aynı,
    /// clippy::derivable_impls nedeniyle derive'a indirildi (ARENA2 2026-07-17).
    pub verify_merkle_enabled: bool,
    /// P5 ADIM11 Bulgu 32: AI inference verification opcode gate.
    /// false = mainnet'te KAPALI — requires post-ceremony activation.
    /// When true, VerifyInference (0x1F) opcode is allowed on mainnet,
    /// enabling ZKVM-proven AI inference verification.
    pub verify_inference_enabled: bool,
}

impl MainnetActivation {
    /// Full activation — all mainnet-gated opcodes enabled (post-ceremony).
    pub fn full() -> Self {
        Self {
            verify_merkle_enabled: true,
            verify_inference_enabled: true,
        }
    }

    /// Check if an opcode is allowed under this activation state.
    pub fn allows(&self, opcode: Opcode) -> bool {
        if opcode.requires_mainnet_activation() {
            match opcode {
                Opcode::VerifyMerkle => self.verify_merkle_enabled,
                Opcode::VerifyInference => self.verify_inference_enabled,
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
            0x07 => Opcode::Or,
            0x08 => Opcode::Xor,
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

    /// S2 (Paket B): decode with mainnet activation gate.
    /// Mainnet callers must pass `MainnetActivation::full()` post-ceremony.
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
    fn tur119_plain_opcodes_still_decode_in_production() {
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

    // ===================== P5 ADIM11 — VerifyInference Opcode =====================

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
}
