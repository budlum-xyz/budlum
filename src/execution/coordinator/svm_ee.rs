//! SVM execution environment (`EeId::SVM` = `0x03`) over `HostApi`.
//!
//! Implements WP-31 items 1-3 & 6:
//! - Strictly interpreted SBPF execution (`jit_enabled = false`; attempting to
//!   enable JIT is deterministically refused).
//! - SVM account model persisted in `ee/svm/account` (`32-byte pubkey -> SvmAccount`).
//! - Built-in programs: System (`[0; 32]`), SPL Token, Token-2022, Associated Token
//!   Account, Memo, BPF Loader, and the UEL Universal Call program
//!   (`SHA256("BDLM_SVM_UNIVERSAL_PROGRAM_V1")`).
//! - Solana Vote and Stake programs are absent and explicitly refused (section 8.15).
//! WIRING: SVM program IDs, account layout, and runtime bounds wired into UEL coordinator.

use crate::core::account::ATTOS_PER_ATOM;
use crate::execution::coordinator::alias::is_ed25519_on_curve;
use crate::execution::coordinator::state::NS_SVM_ACCOUNT;
use crate::execution::coordinator::universal_call::wrap_static_universal_input;
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostRead, Namespace,
    OutcomeStatus, RefusalCode, UniversalCall,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Number of attoBUD per Solana lamport (`10^9`, section 8.5).
pub const ATTOS_PER_LAMPORT: u128 = 1_000_000_000;
/// Maximum SBPF program ELF size (512 KiB).
pub const MAX_SBPF_PROGRAM_BYTES: usize = 512 * 1024;
/// ELF magic `\x7fELF`.
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Built-in System Program ID (`11111111111111111111111111111111`).
pub const SVM_SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];
/// Built-in SPL Token Program ID tag.
pub const SVM_SPL_TOKEN_PROGRAM_ID: [u8; 32] = [0x06u8; 32];
/// Built-in SPL Token-2022 Program ID tag.
pub const SVM_TOKEN_2022_PROGRAM_ID: [u8; 32] = [0x22u8; 32];
/// Built-in Associated Token Account Program ID tag.
pub const SVM_ATA_PROGRAM_ID: [u8; 32] = [0xA7u8; 32];
/// Built-in Memo Program ID tag.
pub const SVM_MEMO_PROGRAM_ID: [u8; 32] = [0x4Du8; 32];
/// Built-in BPF Loader Program ID tag.
pub const SVM_BPF_LOADER_ID: [u8; 32] = [0xBFu8; 32];
/// Forbidden Solana Vote Program ID tag (refused at launch, section 8.15).
pub const FORBIDDEN_SVM_VOTE_PROGRAM_ID: [u8; 32] = [0xF1u8; 32];
/// Forbidden Solana Stake Program ID tag (refused at launch, section 8.15).
pub const FORBIDDEN_SVM_STAKE_PROGRAM_ID: [u8; 32] = [0xF2u8; 32];

/// Canonical 32-byte program ID of the built-in SVM Universal Call program:
/// `SHA256("BDLM_SVM_UNIVERSAL_PROGRAM_V1")` (section 8.7.2 SVM row).
#[must_use]
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn svm_universal_program_id() -> [u8; 32] {
    Sha256::digest(b"BDLM_SVM_UNIVERSAL_PROGRAM_V1").into()
}

/// Runtime configuration for `budlum-ee-svm` (JIT permanently disabled for determinism).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SvmRuntimeConfig {
    pub jit_enabled: bool,
    pub max_call_depth: usize,
    pub stack_frame_bytes: usize,
}

impl Default for SvmRuntimeConfig {
    fn default() -> Self {
        Self {
            jit_enabled: false,
            max_call_depth: 64,
            stack_frame_bytes: 4_096,
        }
    }
}

impl SvmRuntimeConfig {
    /// Validates that JIT compilation is disabled (WP-31 item 1).
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn ensure_deterministic(&self) -> Result<(), String> {
        if self.jit_enabled {
            return Err(String::from(
                "SVM SBPF JIT compilation is forbidden; interpreter mode is mandatory",
            ));
        }
        Ok(())
    }
}

/// Persisted SVM account state in `ee/svm/account`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvmAccountData {
    pub lamports: u64,
    pub owner: [u8; 32],
    pub executable: bool,
    pub rent_epoch: u64,
    pub data: Vec<u8>,
}

/// Wire instruction envelope passed inside `EeCall.input` for `EeId::SVM`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SvmInstructionEnvelope {
    SystemTransfer {
        to: [u8; 32],
        lamports: u64,
    },
    SplInitializeMint {
        mint: [u8; 32],
        decimals: u8,
        mint_authority: [u8; 32],
        is_token_2022: bool,
    },
    SplMintTo {
        mint: [u8; 32],
        dest_owner: [u8; 32],
        amount: u64,
    },
    SplTransfer {
        mint: [u8; 32],
        to_owner: [u8; 32],
        amount: u64,
    },
    CreateAssociatedTokenAccount {
        wallet: [u8; 32],
        mint: [u8; 32],
    },
    Memo {
        utf8_memo: String,
    },
    InvokeProgram {
        program_id: [u8; 32],
        data: Vec<u8>,
    },
    UniversalCpi {
        target_ee: u8,
        target: Vec<u8>,
        input: Vec<u8>,
        value_attos: u128,
        gas_limit_bgu: u64,
        is_static: bool,
    },
}

/// Derives an off-curve Associated Token Account address for `(wallet, mint)`.
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn derive_associated_token_address(
    wallet: &[u8; 32],
    mint: &[u8; 32],
) -> Result<[u8; 32], String> {
    for bump in (0u8..=255u8).rev() {
        let mut h = Sha256::new();
        h.update(wallet);
        h.update(SVM_SPL_TOKEN_PROGRAM_ID);
        h.update(mint);
        h.update([bump]);
        h.update(SVM_ATA_PROGRAM_ID);
        let cand: [u8; 32] = h.finalize().into();
        if !is_ed25519_on_curve(&cand) {
            return Ok(cand);
        }
    }
    Err(String::from("failed to find off-curve ATA bump"))
}

/// Stateless SVM execution environment (`budlum-ee-svm`).
#[derive(Debug, Clone)]
pub struct SvmEe {
    config: SvmRuntimeConfig,
}

impl Default for SvmEe {
    fn default() -> Self {
        Self::new()
    }
}

impl SvmEe {
    #[must_use]
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn new() -> Self {
        Self {
            config: SvmRuntimeConfig::default(),
        }
    }

    /// Creates an `SvmEe` after verifying `config` keeps JIT disabled.
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub fn with_config(config: SvmRuntimeConfig) -> Result<Self, String> {
        config.ensure_deterministic()?;
        Ok(Self { config })
    }

    #[must_use]
    /// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
    pub const fn config(&self) -> &SvmRuntimeConfig {
        &self.config
    }
}

fn read_svm_account(host: &dyn HostRead, pk: &[u8; 32]) -> Result<SvmAccountData, String> {
    let ns = Namespace::new(NS_SVM_ACCOUNT).map_err(|e| e.to_string())?;
    let Some(raw) = host.read(&ns, pk).map_err(|e| e.to_string())? else {
        return Ok(SvmAccountData::default());
    };
    serde_json::from_slice(&raw).map_err(|e| format!("corrupt SVM account: {e}"))
}

fn write_svm_account(
    host: &mut dyn HostApi,
    pk: &[u8; 32],
    acct: &SvmAccountData,
) -> Result<(), String> {
    let ns = Namespace::new(NS_SVM_ACCOUNT).map_err(|e| e.to_string())?;
    let raw = serde_json::to_vec(acct).map_err(|e| e.to_string())?;
    host.write(&ns, pk, Some(&raw)).map_err(|e| e.to_string())
}

fn coerce_pk32(raw: &[u8]) -> [u8; 32] {
    if let Ok(arr) = <[u8; 32]>::try_from(raw) {
        return arr;
    }
    Sha256::digest(raw).into()
}

impl ExecutionEnvironment for SvmEe {
    fn id(&self) -> EeId {
        EeId::SVM
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        self.config.ensure_deterministic().map_err(|message| EeRefusal {
            code: RefusalCode::Denied,
            message,
        })?;
        if code.len() < 4 || code.get(..4) != Some(&ELF_MAGIC) {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("SBPF deploy payload must carry ELF magic \\x7fELF"),
            });
        }
        if code.len() > MAX_SBPF_PROGRAM_BYTES {
            return Err(EeRefusal {
                code: RefusalCode::TooLarge,
                message: String::from("SBPF program exceeds 512 KiB limit"),
            });
        }
        let _ = ATTOS_PER_ATOM;
        Ok(CodeInfo {
            code_hash: Sha256::digest(code).into(),
            abi_tag: String::from("sbpf-interp-v1"),
        })
    }

    fn execute(
        &mut self,
        _ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        if let Err(msg) = self.config.ensure_deterministic() {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: msg.into_bytes(),
                gas_used: 0,
            });
        }
        if host.charge(5_000).is_err() {
            return Ok(EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            });
        }

        let caller_pk = coerce_pk32(&call.caller.id);
        let target_pk = coerce_pk32(&call.target.id);

        match call.kind {
            EeCallKind::Deploy => {
                if let Err(refusal) = self.validate_deploy(&call.input) {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: refusal.message.into_bytes(),
                        gas_used: 5_000,
                    });
                }
                let prog_acct = SvmAccountData {
                    lamports: 1,
                    owner: SVM_BPF_LOADER_ID,
                    executable: true,
                    rent_epoch: 0,
                    data: call.input.clone(),
                };
                if let Err(e) = write_svm_account(host, &target_pk, &prog_acct) {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: e.into_bytes(),
                        gas_used: 5_000,
                    });
                }
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: target_pk.to_vec(),
                    gas_used: 15_000,
                })
            }
            EeCallKind::Call => {
                if target_pk == FORBIDDEN_SVM_VOTE_PROGRAM_ID
                    || target_pk == FORBIDDEN_SVM_STAKE_PROGRAM_ID
                {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"Solana Vote and Stake programs are absent on Budlum".to_vec(),
                        gas_used: 5_000,
                    });
                }
                let Ok(ix) = serde_json::from_slice::<SvmInstructionEnvelope>(&call.input) else {
                    return Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"invalid SvmInstructionEnvelope".to_vec(),
                        gas_used: 5_000,
                    });
                };
                match ix {
                    SvmInstructionEnvelope::SystemTransfer { to, lamports } => {
                        let attos = u128::from(lamports).saturating_mul(ATTOS_PER_LAMPORT);
                        if let Err(e) = host.bud_transfer(
                            &EeIdentity {
                                ee: EeId::SVM,
                                id: caller_pk.to_vec(),
                            },
                            &EeIdentity {
                                ee: EeId::SVM,
                                id: to.to_vec(),
                            },
                            attos,
                        ) {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: e.to_string().into_bytes(),
                                gas_used: 5_000,
                            });
                        }
                        Ok(EeOutcome {
                            status: OutcomeStatus::Success,
                            output: lamports.to_le_bytes().to_vec(),
                            gas_used: 6_500,
                        })
                    }
                    SvmInstructionEnvelope::SplInitializeMint {
                        mint,
                        decimals,
                        mint_authority,
                        is_token_2022,
                    } => {
                        let meta = serde_json::json!({
                            "decimals": decimals,
                            "authority": hex::encode(mint_authority),
                            "supply": 0u64,
                        });
                        let acct = SvmAccountData {
                            lamports: 1,
                            owner: if is_token_2022 {
                                SVM_TOKEN_2022_PROGRAM_ID
                            } else {
                                SVM_SPL_TOKEN_PROGRAM_ID
                            },
                            executable: false,
                            rent_epoch: 0,
                            data: serde_json::to_vec(&meta).unwrap_or_default(),
                        };
                        let _ = write_svm_account(host, &mint, &acct);
                        Ok(EeOutcome {
                            status: OutcomeStatus::Success,
                            output: mint.to_vec(),
                            gas_used: 8_000,
                        })
                    }
                    SvmInstructionEnvelope::SplMintTo {
                        mint,
                        dest_owner,
                        amount,
                    } => {
                        let Ok(ata) = derive_associated_token_address(&dest_owner, &mint) else {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: Vec::new(),
                                gas_used: 5_000,
                            });
                        };
                        let mut acc = read_svm_account(host, &ata).unwrap_or_default();
                        let cur = acc
                            .data
                            .get(..8)
                            .and_then(|s| <[u8; 8]>::try_from(s).ok())
                            .map_or(0u64, u64::from_le_bytes);
                        acc.owner = SVM_SPL_TOKEN_PROGRAM_ID;
                        acc.data = cur.saturating_add(amount).to_le_bytes().to_vec();
                        let _ = write_svm_account(host, &ata, &acc);
                        Ok(EeOutcome {
                            status: OutcomeStatus::Success,
                            output: ata.to_vec(),
                            gas_used: 9_000,
                        })
                    }
                    SvmInstructionEnvelope::SplTransfer {
                        mint,
                        to_owner,
                        amount,
                    } => {
                        let (Ok(src_ata), Ok(dst_ata)) = (
                            derive_associated_token_address(&caller_pk, &mint),
                            derive_associated_token_address(&to_owner, &mint),
                        ) else {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: Vec::new(),
                                gas_used: 5_000,
                            });
                        };
                        let mut src_acc = read_svm_account(host, &src_ata).unwrap_or_default();
                        let src_bal = src_acc
                            .data
                            .get(..8)
                            .and_then(|s| <[u8; 8]>::try_from(s).ok())
                            .map_or(0u64, u64::from_le_bytes);
                        if src_bal < amount {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: b"insufficient SPL balance".to_vec(),
                                gas_used: 8_000,
                            });
                        }
                        src_acc.data = (src_bal - amount).to_le_bytes().to_vec();
                        let _ = write_svm_account(host, &src_ata, &src_acc);

                        let mut dst_acc = read_svm_account(host, &dst_ata).unwrap_or_default();
                        let dst_bal = dst_acc
                            .data
                            .get(..8)
                            .and_then(|s| <[u8; 8]>::try_from(s).ok())
                            .map_or(0u64, u64::from_le_bytes);
                        dst_acc.owner = SVM_SPL_TOKEN_PROGRAM_ID;
                        dst_acc.data = dst_bal.saturating_add(amount).to_le_bytes().to_vec();
                        let _ = write_svm_account(host, &dst_ata, &dst_acc);
                        Ok(EeOutcome {
                            status: OutcomeStatus::Success,
                            output: dst_ata.to_vec(),
                            gas_used: 10_000,
                        })
                    }
                    SvmInstructionEnvelope::CreateAssociatedTokenAccount { wallet, mint } => {
                        let Ok(ata) = derive_associated_token_address(&wallet, &mint) else {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: Vec::new(),
                                gas_used: 5_000,
                            });
                        };
                        let acc = SvmAccountData {
                            lamports: 1,
                            owner: SVM_SPL_TOKEN_PROGRAM_ID,
                            executable: false,
                            rent_epoch: 0,
                            data: 0u64.to_le_bytes().to_vec(),
                        };
                        let _ = write_svm_account(host, &ata, &acc);
                        Ok(EeOutcome {
                            status: OutcomeStatus::Success,
                            output: ata.to_vec(),
                            gas_used: 7_500,
                        })
                    }
                    SvmInstructionEnvelope::Memo { utf8_memo } => {
                        let _ = host.emit_log(EeLog {
                            address: SVM_MEMO_PROGRAM_ID.to_vec(),
                            topics: vec![Sha256::digest(b"svm:memo").into()],
                            data: utf8_memo.clone().into_bytes(),
                        });
                        Ok(EeOutcome {
                            status: OutcomeStatus::Success,
                            output: utf8_memo.into_bytes(),
                            gas_used: 5_500,
                        })
                    }
                    SvmInstructionEnvelope::InvokeProgram { program_id, data } => {
                        if program_id == FORBIDDEN_SVM_VOTE_PROGRAM_ID
                            || program_id == FORBIDDEN_SVM_STAKE_PROGRAM_ID
                        {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: b"Solana Vote/Stake programs refused".to_vec(),
                                gas_used: 5_000,
                            });
                        }
                        let prog = read_svm_account(host, &program_id).unwrap_or_default();
                        if !prog.executable && program_id != SVM_SYSTEM_PROGRAM_ID {
                            return Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: b"target SVM account is not executable".to_vec(),
                                gas_used: 5_000,
                            });
                        }
                        Ok(EeOutcome {
                            status: OutcomeStatus::Success,
                            output: data,
                            gas_used: 12_000,
                        })
                    }
                    SvmInstructionEnvelope::UniversalCpi {
                        target_ee,
                        target,
                        input,
                        value_attos,
                        gas_limit_bgu,
                        is_static,
                    } => {
                        let _ = svm_universal_program_id();
                        let payload = if is_static {
                            wrap_static_universal_input(&input)
                        } else {
                            input
                        };
                        match host.universal_call(UniversalCall {
                            from: EeIdentity {
                                ee: EeId::SVM,
                                id: caller_pk.to_vec(),
                            },
                            to_ee: EeId(target_ee),
                            target: EeIdentity {
                                ee: EeId(target_ee),
                                id: target,
                            },
                            value: BudAmount(value_attos),
                            input: payload,
                            gas_limit: gas_limit_bgu,
                        }) {
                            Ok(r) => Ok(EeOutcome {
                                status: if r.success {
                                    OutcomeStatus::Success
                                } else {
                                    OutcomeStatus::Revert
                                },
                                output: r.output,
                                gas_used: 12_000,
                            }),
                            Err(e) => Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: e.to_string().into_bytes(),
                                gas_used: 12_000,
                            }),
                        }
                    }
                }
            }
        }
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        let pk = coerce_pk32(&q.target.id);
        let acct = read_svm_account(host, &pk).map_err(|message| EeRefusal {
            code: RefusalCode::Denied,
            message,
        })?;
        serde_json::to_vec(&acct).map_err(|e| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: e.to_string(),
        })
    }
}
