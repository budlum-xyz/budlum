//! Out-of-process SVM Execution Environment (`EeId::SVM = 0x03`).
//!
//! Executes verified sBPF programs via `solana-sbpf = "=0.10.0"` with JIT
//! disabled at compile time (`default-features = false`, `interpreted = true`),
//! `1 CU = 1 BGU`, accounts persisted under `ee/svm/account`, native built-ins
//! (`System`, `SPL Token`, `Token-2022`, `ATA`, `Memo`, `BPF Upgradeable Loader`,
//! and `UniversalCall` at `SHA256("BDLM_SVM_UNIVERSAL_PROGRAM_V1")`), and
//! deterministic refusal of Solana `Vote` and `Stake` programs (`Section 8.15`).

#![forbid(unsafe_code)]

pub mod pointer;
pub mod programs;

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use budlum_uel_abi::transport::panic_digest;
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostError, HostRead, Namespace,
    OutcomeStatus, RefusalCode, UniversalCall,
};
use sha2::{Digest as _, Sha256};
use solana_sbpf::aligned_memory::AlignedMemory;
use solana_sbpf::ebpf;
use solana_sbpf::elf::Executable;
use solana_sbpf::error::{EbpfError, ProgramResult};
use solana_sbpf::memory_region::{MemoryMapping, MemoryRegion};
use solana_sbpf::program::{BuiltinProgram, FunctionRegistry, SBPFVersion};
use solana_sbpf::verifier::RequisiteVerifier;
use solana_sbpf::vm::{Config, ContextObject, EbpfVm};

use crate::programs::{
    decode_borsh_universal_call, derive_associated_token_address, derive_spl_mint_address,
    SplMintState, SplTokenAccountState, SvmAccountRecord, SvmInstructionEnvelope,
    ASSOCIATED_TOKEN_PROGRAM_ID, ATTOS_PER_LAMPORT, BPF_LOADER_UPGRADEABLE_ID, MEMO_PROGRAM_ID,
    NS_SVM_ACCOUNT, SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID, STAKE_PROGRAM_ID,
    SYSTEM_PROGRAM_ID, UNIVERSAL_CALL_PROGRAM_ID, VOTE_PROGRAM_ID,
};

/// Maximum deployed sBPF binary size (`2 MiB`).
pub const MAX_SBPF_CODE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum sBPF heap per invocation (`32 KiB`).
pub const SBPF_HEAP_BYTES: usize = 32 * 1024;
/// Read-only `query` CU ceiling (`1_400_000 CU`).
pub const QUERY_CU_LIMIT: u64 = 1_400_000;

/// Instruction meter mapping `1 sBPF instruction = 1 CU = 1 BGU`.
#[derive(Debug, Clone)]
pub struct SvmMeter {
    remaining: u64,
}

impl SvmMeter {
    #[must_use]
    pub const fn new(limit: u64) -> Self {
        Self { remaining: limit }
    }
}

impl ContextObject for SvmMeter {
    fn trace(&mut self, _state: [u64; 12]) {}

    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }
}

/// Deterministic `solana-sbpf` configuration with instruction metering on and tracing off.
#[must_use]
pub fn deterministic_sbpf_config() -> Config {
    Config {
        max_call_depth: 64,
        stack_frame_size: 4_096,
        enable_address_translation: true,
        enable_stack_frame_gaps: true,
        instruction_meter_checkpoint_distance: 10_000,
        enable_instruction_meter: true,
        enable_instruction_tracing: false,
        enable_symbol_and_section_labels: false,
        reject_broken_elfs: true,
        noop_instruction_rate: 0,
        sanitize_user_provided_values: true,
        optimize_rodata: true,
        aligned_memory_mapping: true,
        enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V3,
    }
}

fn load_and_verify_sbpf(
    code: &[u8],
    loader: Arc<BuiltinProgram<SvmMeter>>,
) -> Result<Executable<SvmMeter>, String> {
    if code.is_empty() {
        return Err(String::from("empty sBPF program"));
    }
    if code.len() > MAX_SBPF_CODE_BYTES {
        return Err(format!(
            "sBPF program size {} exceeds limit {MAX_SBPF_CODE_BYTES}",
            code.len()
        ));
    }
    if code.starts_with(b"\x7fELF") {
        let exe =
            Executable::from_elf(code, loader).map_err(|e| format!("ELF load failed: {e}"))?;
        exe.verify::<RequisiteVerifier>()
            .map_err(|e| format!("sBPF verify failed: {e}"))?;
        return Ok(exe);
    }
    for ver in [SBPFVersion::V3, SBPFVersion::V0] {
        if let Ok(exe) =
            Executable::from_text_bytes(code, loader.clone(), ver, FunctionRegistry::default())
        {
            if exe.verify::<RequisiteVerifier>().is_ok() {
                return Ok(exe);
            }
        }
    }
    Err(String::from("sBPF bytecode failed RequisiteVerifier"))
}

fn parse_pubkey32(raw: &[u8]) -> Option<[u8; 32]> {
    raw.try_into().ok()
}

#[cfg(test)]
fn read_svm_account(host: &dyn HostRead, pubkey: &[u8; 32]) -> SvmAccountRecord {
    read_svm_account_checked(host, pubkey)
        .ok()
        .flatten()
        .unwrap_or_default()
}

fn read_svm_account_checked(
    host: &dyn HostRead,
    pubkey: &[u8; 32],
) -> Result<Option<SvmAccountRecord>, HostError> {
    let ns = Namespace::new(NS_SVM_ACCOUNT).map_err(|e| HostError::Invalid(e.to_string()))?;
    match host.read(&ns, pubkey)? {
        None => Ok(None),
        Some(raw) => serde_json::from_slice(&raw)
            .map(Some)
            .map_err(|e| HostError::Invalid(format!("corrupt SVM account record: {e}"))),
    }
}

fn map_svm_read_err(err: HostError) -> (OutcomeStatus, String) {
    match err {
        HostError::OutOfGas => (OutcomeStatus::OutOfGas, String::new()),
        other => (OutcomeStatus::Revert, other.to_string()),
    }
}

fn svm_account_exists(host: &dyn HostRead, pubkey: &[u8; 32]) -> Result<bool, HostError> {
    let ns = Namespace::new(NS_SVM_ACCOUNT).map_err(|e| HostError::Invalid(e.to_string()))?;
    Ok(host.read(&ns, pubkey)?.is_some())
}

fn write_svm_account(
    host: &mut dyn HostApi,
    pubkey: &[u8; 32],
    rec: &SvmAccountRecord,
) -> Result<(), HostError> {
    let ns = Namespace::new(NS_SVM_ACCOUNT).map_err(|e| HostError::Invalid(e.to_string()))?;
    let bytes = serde_json::to_vec(rec).map_err(|e| HostError::Invalid(e.to_string()))?;
    host.write(&ns, pubkey, Some(&bytes))
}

type SbpfExecResult = Result<(u64, u64, Vec<u8>), (OutcomeStatus, String, u64)>;

fn execute_sbpf_bytecode(code: &[u8], input: &[u8], cu_limit: u64) -> SbpfExecResult {
    let loader = Arc::new(BuiltinProgram::new_loader(deterministic_sbpf_config()));
    let exe = load_and_verify_sbpf(code, loader.clone())
        .map_err(|m| (OutcomeStatus::InvalidCode, m, 0))?;
    let sbpf_version = exe.get_sbpf_version();
    let stack_size = exe.get_config().stack_size();
    let mut stack = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(stack_size);
    let mut heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(SBPF_HEAP_BYTES);
    let mut input_buf = input.to_vec();
    if input_buf.is_empty() {
        input_buf.resize(8, 0);
    }

    let regions = vec![
        exe.get_ro_region(),
        MemoryRegion::new_writable(stack.as_slice_mut(), ebpf::MM_STACK_START),
        MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
        MemoryRegion::new_writable(input_buf.as_mut_slice(), ebpf::MM_INPUT_START),
    ];
    let mapping = MemoryMapping::new(regions, exe.get_config(), sbpf_version)
        .map_err(|e| (OutcomeStatus::Revert, format!("memory map: {e}"), 0))?;
    let mut meter = SvmMeter::new(cu_limit);
    let mut vm = EbpfVm::new(loader, sbpf_version, &mut meter, mapping, stack_size);
    let (insns, result) = vm.execute_program(&exe, true);
    let cu_used = insns.max(1).min(cu_limit);
    match result {
        ProgramResult::Ok(exit_code) => {
            if exit_code == 0 {
                Ok((exit_code, cu_used, input_buf))
            } else {
                Err((
                    OutcomeStatus::Revert,
                    format!("sBPF program exited with code {exit_code}"),
                    cu_used,
                ))
            }
        }
        ProgramResult::Err(EbpfError::ExceededMaxInstructions) => Err((
            OutcomeStatus::OutOfGas,
            String::from("compute budget exceeded"),
            cu_limit,
        )),
        ProgramResult::Err(err) => Err((OutcomeStatus::Revert, err.to_string(), cu_used)),
    }
}

fn map_svm_host_err(err: HostError) -> (OutcomeStatus, String) {
    match err {
        HostError::OutOfGas => (OutcomeStatus::OutOfGas, String::from("out of gas")),
        other => (OutcomeStatus::Revert, other.to_string()),
    }
}

fn charge_svm_cu(
    host: &mut dyn HostApi,
    cu: u64,
    gas_limit: u64,
) -> Result<(), (OutcomeStatus, String)> {
    if cu > gas_limit || host.charge(cu).is_err() {
        return Err((OutcomeStatus::OutOfGas, String::from("out of gas")));
    }
    Ok(())
}

fn handle_system_program(
    caller: &[u8; 32],
    ix: &SvmInstructionEnvelope,
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<(Vec<u8>, u64), (OutcomeStatus, String)> {
    if ix.data.len() < 4 {
        return Err((OutcomeStatus::Revert, String::from("short system ix")));
    }
    let tag_bytes: [u8; 4] = ix
        .data
        .get(..4)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0xff; 4]);
    let tag = u32::from_le_bytes(tag_bytes);
    match tag {
        // 0 = CreateAccount { lamports: u64, space: u64, owner: [u8; 32] }
        0 => {
            if ix.data.len() < 52 || ix.accounts.len() < 2 {
                return Err((OutcomeStatus::Revert, String::from("bad CreateAccount")));
            }
            let lamports = u64::from_le_bytes(
                ix.data
                    .get(4..12)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0; 8]),
            );
            let space_u64 = u64::from_le_bytes(
                ix.data
                    .get(12..20)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0; 8]),
            );
            let Ok(space) = usize::try_from(space_u64) else {
                return Err((OutcomeStatus::Revert, String::from("space > 1 MiB")));
            };
            let owner: [u8; 32] = ix
                .data
                .get(20..52)
                .and_then(|s| s.try_into().ok())
                .unwrap_or(SYSTEM_PROGRAM_ID);
            if space > 1024 * 1024 {
                return Err((OutcomeStatus::Revert, String::from("space > 1 MiB")));
            }
            let payer = ix.accounts.first().ok_or_else(|| {
                (
                    OutcomeStatus::Revert,
                    String::from("missing CreateAccount payer"),
                )
            })?;
            let new_account = ix.accounts.get(1).ok_or_else(|| {
                (
                    OutcomeStatus::Revert,
                    String::from("missing CreateAccount target"),
                )
            })?;
            if payer.pubkey != *caller || !payer.is_signer || !payer.is_writable {
                return Err((
                    OutcomeStatus::Revert,
                    String::from("CreateAccount payer must be the authenticated writable signer"),
                ));
            }
            // The worker receives only the authenticated outer caller, not a
            // transaction-level signer set. AccountMeta.is_signer is caller
            // supplied and cannot authorize another key; restrict creation to
            // the caller's own absent account until co-signers are authenticated
            // by the coordinator.
            if new_account.pubkey != *caller || !new_account.is_signer || !new_account.is_writable {
                return Err((
                    OutcomeStatus::Revert,
                    String::from("CreateAccount target is not an authenticated signer"),
                ));
            }
            let cu = 150u64.saturating_add(space_u64.saturating_mul(25));
            charge_svm_cu(host, cu, gas_limit)?;
            let to_pk = new_account.pubkey;
            if svm_account_exists(host, &to_pk).map_err(map_svm_host_err)? {
                return Err((
                    OutcomeStatus::Revert,
                    String::from("CreateAccount target already exists"),
                ));
            }
            if lamports > 0 && to_pk != *caller {
                let attos = u128::from(lamports).saturating_mul(ATTOS_PER_LAMPORT);
                host.bud_transfer(
                    &EeIdentity {
                        ee: EeId::SVM,
                        id: caller.to_vec(),
                    },
                    &EeIdentity {
                        ee: EeId::SVM,
                        id: to_pk.to_vec(),
                    },
                    attos,
                )
                .map_err(map_svm_host_err)?;
            }
            let rec = SvmAccountRecord {
                owner,
                executable: false,
                rent_epoch: u64::MAX,
                data: vec![0u8; space],
            };
            write_svm_account(host, &to_pk, &rec).map_err(map_svm_host_err)?;
            Ok((Vec::new(), cu))
        }
        // 2 = Transfer { lamports: u64 }
        2 => {
            if ix.data.len() < 12 || ix.accounts.len() < 2 {
                return Err((OutcomeStatus::Revert, String::from("bad Transfer")));
            }
            let from = ix.accounts.first().ok_or_else(|| {
                (
                    OutcomeStatus::Revert,
                    String::from("missing Transfer source"),
                )
            })?;
            let to = ix.accounts.get(1).ok_or_else(|| {
                (
                    OutcomeStatus::Revert,
                    String::from("missing Transfer destination"),
                )
            })?;
            if from.pubkey != *caller || !from.is_signer || !from.is_writable {
                return Err((
                    OutcomeStatus::Revert,
                    String::from("Transfer source must be the authenticated writable signer"),
                ));
            }
            if !to.is_writable || to.pubkey == [0u8; 32] {
                return Err((
                    OutcomeStatus::Revert,
                    String::from("Transfer destination must be writable and non-zero"),
                ));
            }
            let cu = 150u64;
            charge_svm_cu(host, cu, gas_limit)?;
            let lamports = u64::from_le_bytes(
                ix.data
                    .get(4..12)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0; 8]),
            );
            let to_pk = to.pubkey;
            if lamports > 0 {
                let attos = u128::from(lamports).saturating_mul(ATTOS_PER_LAMPORT);
                host.bud_transfer(
                    &EeIdentity {
                        ee: EeId::SVM,
                        id: caller.to_vec(),
                    },
                    &EeIdentity {
                        ee: EeId::SVM,
                        id: to_pk.to_vec(),
                    },
                    attos,
                )
                .map_err(map_svm_host_err)?;
            }
            Ok((Vec::new(), cu))
        }
        _ => Err((
            OutcomeStatus::Revert,
            format!("unsupported System tag {tag}"),
        )),
    }
}

fn handle_spl_token(
    program_id: &[u8; 32],
    caller: &[u8; 32],
    ix: &SvmInstructionEnvelope,
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<(Vec<u8>, u64), (OutcomeStatus, String)> {
    let Some(&op) = ix.data.first() else {
        return Err((OutcomeStatus::Revert, String::from("empty SPL Token ix")));
    };
    let required_cu = match op {
        0 | 1 => 1_500u64,
        3 | 7 => 2_500u64,
        _ => return Err((OutcomeStatus::Revert, format!("unsupported SPL op {op}"))),
    };
    charge_svm_cu(host, required_cu, gas_limit)?;
    match op {
        // 0 = InitializeMint { decimals: u8, mint_authority: [u8; 32] } (accounts: [mint_seed]).
        // The seed is not the address: the mint lives at `derive_spl_mint_address(caller,
        // seed)` and that address is the output.
        0 => {
            let Some(seed_meta) = ix.accounts.first() else {
                return Err((OutcomeStatus::Revert, String::from("missing mint seed")));
            };
            let decimals = ix.data.get(1).copied().unwrap_or(9);
            let auth: [u8; 32] = ix
                .data
                .get(2..34)
                .and_then(|s| s.try_into().ok())
                .unwrap_or(*caller);
            // The worker receives only the authenticated outer caller, so the mint address
            // is derived from it rather than taken as named, and the caller is the
            // authority. Otherwise any account could take a mint address before its issuer
            // and record a third party as the issuer of a mint that party never asked for.
            if auth != *caller {
                return Err((
                    OutcomeStatus::Revert,
                    String::from("the mint authority must be the caller"),
                ));
            }
            let Some(mint_address) = derive_spl_mint_address(caller, &seed_meta.pubkey) else {
                return Err((
                    OutcomeStatus::Revert,
                    String::from("no mint address for this seed"),
                ));
            };
            if svm_account_exists(host, &mint_address)
                .map_err(|e| (OutcomeStatus::Revert, e.to_string()))?
            {
                return Err((
                    OutcomeStatus::Revert,
                    String::from("mint already initialized"),
                ));
            }
            let mint = SplMintState {
                mint_authority: Some(auth),
                supply: 0,
                decimals,
                is_initialized: true,
            };
            let rec = SvmAccountRecord {
                owner: *program_id,
                executable: false,
                rent_epoch: u64::MAX,
                data: serde_json::to_vec(&mint).unwrap_or_default(),
            };
            write_svm_account(host, &mint_address, &rec)
                .map_err(|e| (OutcomeStatus::Revert, e.to_string()))?;
            Ok((mint_address.to_vec(), 1_500))
        }
        // 1 = InitializeAccount (accounts: [token_acc, mint, owner])
        1 => {
            if ix.accounts.len() < 3 {
                return Err((OutcomeStatus::Revert, String::from("missing SPL accounts")));
            }
            let acc_pk = ix.accounts.first().map(|m| m.pubkey).unwrap_or([0; 32]);
            let mint_pk = ix.accounts.get(1).map(|m| m.pubkey).unwrap_or([0; 32]);
            let own_pk = ix.accounts.get(2).map(|m| m.pubkey).unwrap_or([0; 32]);
            // The worker receives only the authenticated outer caller, not a
            // transaction-level signer set, so no account meta can authorize a key the
            // caller does not own. Only the caller's own associated token account may be
            // initialized here. Accepting any absent address with any owner lets a third
            // party occupy another wallet's derived account and receive its payments. The
            // associated token account program still opens an account for any wallet.
            if own_pk != *caller
                || acc_pk != derive_associated_token_address(&own_pk, program_id, &mint_pk)
            {
                return Err((
                    OutcomeStatus::Revert,
                    String::from(
                        "InitializeAccount must target the caller's own associated token account",
                    ),
                ));
            }
            if svm_account_exists(host, &acc_pk)
                .map_err(|e| (OutcomeStatus::Revert, e.to_string()))?
            {
                return Err((
                    OutcomeStatus::Revert,
                    String::from("token account already initialized"),
                ));
            }
            let mint_rec = read_svm_account_checked(host, &mint_pk)
                .map_err(map_svm_read_err)?
                .unwrap_or_default();
            if mint_rec.owner != *program_id
                || !serde_json::from_slice::<SplMintState>(&mint_rec.data)
                    .is_ok_and(|mint| mint.is_initialized)
            {
                return Err((OutcomeStatus::Revert, String::from("invalid token mint")));
            }
            let st = SplTokenAccountState {
                mint: mint_pk,
                owner: own_pk,
                amount: 0,
                delegate: None,
                delegated_amount: 0,
                is_initialized: true,
            };
            let rec = SvmAccountRecord {
                owner: *program_id,
                executable: false,
                rent_epoch: u64::MAX,
                data: serde_json::to_vec(&st).unwrap_or_default(),
            };
            write_svm_account(host, &acc_pk, &rec)
                .map_err(|e| (OutcomeStatus::Revert, e.to_string()))?;
            Ok((Vec::new(), 1_500))
        }
        // 7 = MintTo { amount: u64 } (accounts: [mint, dst_token_acc])
        7 => {
            if ix.data.len() < 9 || ix.accounts.len() < 2 {
                return Err((OutcomeStatus::Revert, String::from("bad MintTo")));
            }
            let amount = u64::from_le_bytes(
                ix.data
                    .get(1..9)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0; 8]),
            );
            let mint_pk = ix.accounts.first().map(|m| m.pubkey).unwrap_or([0; 32]);
            let dst_pk = ix.accounts.get(1).map(|m| m.pubkey).unwrap_or([0; 32]);
            let mut mint_rec = read_svm_account_checked(host, &mint_pk)
                .map_err(map_svm_read_err)?
                .unwrap_or_default();
            let mut mint: SplMintState = serde_json::from_slice(&mint_rec.data)
                .map_err(|_| (OutcomeStatus::Revert, String::from("uninitialized mint")))?;
            if mint_rec.owner != *program_id
                || !mint.is_initialized
                || mint.mint_authority != Some(*caller)
            {
                return Err((
                    OutcomeStatus::Revert,
                    String::from("mint authority mismatch"),
                ));
            }
            let mut dst_rec = read_svm_account_checked(host, &dst_pk)
                .map_err(map_svm_read_err)?
                .unwrap_or_default();
            let mut dst: SplTokenAccountState =
                serde_json::from_slice(&dst_rec.data).map_err(|_| {
                    (
                        OutcomeStatus::Revert,
                        String::from("uninitialized token acc"),
                    )
                })?;
            if dst_rec.owner != *program_id || !dst.is_initialized || dst.mint != mint_pk {
                return Err((
                    OutcomeStatus::Revert,
                    String::from("destination mint mismatch"),
                ));
            }
            mint.supply = mint
                .supply
                .checked_add(amount)
                .ok_or_else(|| (OutcomeStatus::Revert, String::from("mint supply overflow")))?;
            dst.amount = dst
                .amount
                .checked_add(amount)
                .ok_or_else(|| (OutcomeStatus::Revert, String::from("token overflow")))?;
            mint_rec.data = serde_json::to_vec(&mint).unwrap_or_default();
            dst_rec.data = serde_json::to_vec(&dst).unwrap_or_default();
            write_svm_account(host, &mint_pk, &mint_rec)
                .map_err(|e| (OutcomeStatus::Revert, e.to_string()))?;
            write_svm_account(host, &dst_pk, &dst_rec)
                .map_err(|e| (OutcomeStatus::Revert, e.to_string()))?;
            Ok((Vec::new(), 2_500))
        }
        // 3 = Transfer { amount: u64 } (accounts: [src_token_acc, dst_token_acc])
        3 => {
            if ix.data.len() < 9 || ix.accounts.len() < 2 {
                return Err((OutcomeStatus::Revert, String::from("bad SPL Transfer")));
            }
            let amount = u64::from_le_bytes(
                ix.data
                    .get(1..9)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0; 8]),
            );
            let src_pk = ix.accounts.first().map(|m| m.pubkey).unwrap_or([0; 32]);
            let dst_pk = ix.accounts.get(1).map(|m| m.pubkey).unwrap_or([0; 32]);
            let mut src_rec = read_svm_account_checked(host, &src_pk)
                .map_err(map_svm_read_err)?
                .unwrap_or_default();
            let mut dst_rec = read_svm_account_checked(host, &dst_pk)
                .map_err(map_svm_read_err)?
                .unwrap_or_default();
            let mut src: SplTokenAccountState = serde_json::from_slice(&src_rec.data)
                .map_err(|_| (OutcomeStatus::Revert, String::from("bad src token acc")))?;
            let mut dst: SplTokenAccountState = serde_json::from_slice(&dst_rec.data)
                .map_err(|_| (OutcomeStatus::Revert, String::from("bad dst token acc")))?;
            if src_rec.owner != *program_id
                || dst_rec.owner != *program_id
                || !src.is_initialized
                || !dst.is_initialized
                || src.owner != *caller
                || src.mint != dst.mint
            {
                return Err((
                    OutcomeStatus::Revert,
                    String::from("SPL owner/mint mismatch"),
                ));
            }
            if src_pk == dst_pk {
                if src.amount < amount {
                    return Err((OutcomeStatus::Revert, String::from("insufficient SPL")));
                }
                return Ok((Vec::new(), 2_500));
            }
            src.amount = src
                .amount
                .checked_sub(amount)
                .ok_or_else(|| (OutcomeStatus::Revert, String::from("insufficient SPL")))?;
            dst.amount = dst
                .amount
                .checked_add(amount)
                .ok_or_else(|| (OutcomeStatus::Revert, String::from("SPL dst overflow")))?;
            src_rec.data = serde_json::to_vec(&src).unwrap_or_default();
            dst_rec.data = serde_json::to_vec(&dst).unwrap_or_default();
            write_svm_account(host, &src_pk, &src_rec)
                .map_err(|e| (OutcomeStatus::Revert, e.to_string()))?;
            write_svm_account(host, &dst_pk, &dst_rec)
                .map_err(|e| (OutcomeStatus::Revert, e.to_string()))?;
            Ok((Vec::new(), 2_500))
        }
        _ => Err((OutcomeStatus::Revert, format!("unsupported SPL op {op}"))),
    }
}

/// Out-of-process `budlum-ee-svm` worker (`EeId::SVM = 0x03`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SvmWorker;

fn panic_payload_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        String::from("non-string SVM engine panic")
    }
}

impl SvmWorker {
    fn execute_inner(_ctx: &BlockContext, call: &EeCall, host: &mut dyn HostApi) -> EeOutcome {
        let Some(caller_pk) = parse_pubkey32(&call.caller.id) else {
            return EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"SVM caller must be 32 bytes".to_vec(),
                gas_used: 0,
            };
        };
        let Some(target_pk) = parse_pubkey32(&call.target.id) else {
            return EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"SVM target must be 32 bytes".to_vec(),
                gas_used: 0,
            };
        };

        if target_pk == VOTE_PROGRAM_ID || target_pk == STAKE_PROGRAM_ID {
            return EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"Solana Vote and Stake programs are disabled on Budlum".to_vec(),
                gas_used: 0,
            };
        }

        if call.value.0 > 0 {
            if let Err(e) = host.bud_transfer(&call.caller, &call.target, call.value.0) {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: e.to_string().into_bytes(),
                    gas_used: 0,
                };
            }
        }

        if call.kind == EeCallKind::Deploy {
            if call.input.len() > MAX_SBPF_CODE_BYTES {
                return EeOutcome {
                    status: OutcomeStatus::InvalidCode,
                    output: format!(
                        "sBPF size {} exceeds {MAX_SBPF_CODE_BYTES}",
                        call.input.len()
                    )
                    .into_bytes(),
                    gas_used: 0,
                };
            }
            let loader = Arc::new(BuiltinProgram::new_loader(deterministic_sbpf_config()));
            if let Err(msg) = load_and_verify_sbpf(&call.input, loader) {
                return EeOutcome {
                    status: OutcomeStatus::InvalidCode,
                    output: msg.into_bytes(),
                    gas_used: 0,
                };
            }
            match svm_account_exists(host, &target_pk) {
                Ok(true) => {
                    return EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"SVM program account already exists".to_vec(),
                        gas_used: 0,
                    }
                }
                Err(e) => {
                    return EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: e.to_string().into_bytes(),
                        gas_used: 0,
                    }
                }
                Ok(false) => {}
            }
            // Published code is permanent state every validator keeps:
            // the deploy pays the shared per-byte publication rate on top
            // of the flat entry fee.
            let deploy_gas = 2_000u64.saturating_add(
                u64::try_from(call.input.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(25),
            );
            if call.gas_limit < deploy_gas || host.charge(deploy_gas).is_err() {
                return EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                };
            }
            let rec = SvmAccountRecord {
                owner: BPF_LOADER_UPGRADEABLE_ID,
                executable: true,
                rent_epoch: u64::MAX,
                data: call.input.clone(),
            };
            if let Err(e) = write_svm_account(host, &target_pk, &rec) {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: e.to_string().into_bytes(),
                    gas_used: 0,
                };
            }
            return EeOutcome {
                status: OutcomeStatus::Success,
                output: target_pk.to_vec(),
                gas_used: deploy_gas,
            };
        }

        if target_pk == UNIVERSAL_CALL_PROGRAM_ID {
            let raw_borsh = serde_json::from_slice::<SvmInstructionEnvelope>(&call.input)
                .map_or_else(|_| call.input.clone(), |env| env.data);
            let Some(parsed) = decode_borsh_universal_call(&raw_borsh) else {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"malformed Borsh UniversalCall".to_vec(),
                    gas_used: 0,
                };
            };
            let ucall = UniversalCall {
                from: call.caller.clone(),
                to_ee: EeId(parsed.target_ee),
                target: EeIdentity {
                    ee: EeId(parsed.target_ee),
                    id: parsed.target,
                },
                value: BudAmount(parsed.value_attos),
                input: parsed.input,
                gas_limit: parsed.gas_limit_bgu.min(call.gas_limit),
                is_static: parsed.is_static,
            };
            return match host.universal_call(ucall) {
                Ok(ures) => {
                    if host.charge(ures.gas_used).is_err() {
                        return EeOutcome {
                            status: OutcomeStatus::OutOfGas,
                            output: Vec::new(),
                            gas_used: call.gas_limit,
                        };
                    }
                    EeOutcome {
                        status: if ures.success {
                            OutcomeStatus::Success
                        } else {
                            OutcomeStatus::Revert
                        },
                        output: ures.output,
                        gas_used: ures.gas_used,
                    }
                }
                Err(HostError::OutOfGas) => EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                },
                Err(e) => EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: e.to_string().into_bytes(),
                    gas_used: 0,
                },
            };
        }

        if target_pk == MEMO_PROGRAM_ID {
            let raw_memo = serde_json::from_slice::<SvmInstructionEnvelope>(&call.input)
                .map_or_else(|_| call.input.clone(), |env| env.data);
            if std::str::from_utf8(&raw_memo).is_err() {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"invalid UTF-8 memo".to_vec(),
                    gas_used: 0,
                };
            }
            if host.charge(500).is_err() {
                return EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                };
            }
            let _ = host.emit_log(EeLog {
                emitter: call.target.clone(),
                topics: vec![b"spl-memo".to_vec()],
                data: raw_memo.clone(),
            });
            return EeOutcome {
                status: OutcomeStatus::Success,
                output: raw_memo,
                gas_used: 500,
            };
        }

        if target_pk == SYSTEM_PROGRAM_ID {
            let Ok(ix) = serde_json::from_slice::<SvmInstructionEnvelope>(&call.input) else {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"malformed System envelope".to_vec(),
                    gas_used: 0,
                };
            };
            return match handle_system_program(&caller_pk, &ix, call.gas_limit, host) {
                Ok((out, cu)) => EeOutcome {
                    status: OutcomeStatus::Success,
                    output: out,
                    gas_used: cu,
                },
                Err((OutcomeStatus::OutOfGas, _)) => EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                },
                Err((st, msg)) => EeOutcome {
                    status: st,
                    output: msg.into_bytes(),
                    gas_used: 0,
                },
            };
        }

        if target_pk == SPL_TOKEN_PROGRAM_ID || target_pk == SPL_TOKEN_2022_PROGRAM_ID {
            let Ok(ix) = serde_json::from_slice::<SvmInstructionEnvelope>(&call.input) else {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"malformed SPL Token envelope".to_vec(),
                    gas_used: 0,
                };
            };
            return match handle_spl_token(&target_pk, &caller_pk, &ix, call.gas_limit, host) {
                Ok((out, cu)) => EeOutcome {
                    status: OutcomeStatus::Success,
                    output: out,
                    gas_used: cu,
                },
                Err((OutcomeStatus::OutOfGas, _)) => EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                },
                Err((st, msg)) => EeOutcome {
                    status: st,
                    output: msg.into_bytes(),
                    gas_used: 0,
                },
            };
        }

        if target_pk == ASSOCIATED_TOKEN_PROGRAM_ID {
            let Ok(ix) = serde_json::from_slice::<SvmInstructionEnvelope>(&call.input) else {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"malformed ATA envelope".to_vec(),
                    gas_used: 0,
                };
            };
            if ix.accounts.len() < 3 {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"missing ATA accounts".to_vec(),
                    gas_used: 0,
                };
            }
            let wallet = ix.accounts.first().map(|m| m.pubkey).unwrap_or([0; 32]);
            let mint = ix.accounts.get(1).map(|m| m.pubkey).unwrap_or([0; 32]);
            let tok_prog = ix
                .accounts
                .get(2)
                .map(|m| m.pubkey)
                .unwrap_or(SPL_TOKEN_PROGRAM_ID);
            if tok_prog != SPL_TOKEN_PROGRAM_ID && tok_prog != SPL_TOKEN_2022_PROGRAM_ID {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"unsupported ATA token program".to_vec(),
                    gas_used: 0,
                };
            }
            let mint_rec = match read_svm_account_checked(host, &mint) {
                Ok(rec) => rec.unwrap_or_default(),
                Err(HostError::OutOfGas) => {
                    return EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    };
                }
                Err(e) => {
                    return EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: e.to_string().into_bytes(),
                        gas_used: 0,
                    };
                }
            };
            if mint_rec.owner != tok_prog
                || !serde_json::from_slice::<SplMintState>(&mint_rec.data)
                    .is_ok_and(|mint| mint.is_initialized)
            {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"invalid ATA mint".to_vec(),
                    gas_used: 0,
                };
            }
            let ata = derive_associated_token_address(&wallet, &tok_prog, &mint);
            match svm_account_exists(host, &ata) {
                Ok(true) => {
                    return EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"associated token account already exists".to_vec(),
                        gas_used: 0,
                    }
                }
                Err(e) => {
                    return EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: e.to_string().into_bytes(),
                        gas_used: 0,
                    }
                }
                Ok(false) => {}
            }
            if call.gas_limit < 2_000 || host.charge(2_000).is_err() {
                return EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                };
            }
            let st = SplTokenAccountState {
                mint,
                owner: wallet,
                amount: 0,
                delegate: None,
                delegated_amount: 0,
                is_initialized: true,
            };
            let rec = SvmAccountRecord {
                owner: tok_prog,
                executable: false,
                rent_epoch: u64::MAX,
                data: serde_json::to_vec(&st).unwrap_or_default(),
            };
            if let Err(e) = write_svm_account(host, &ata, &rec) {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: e.to_string().into_bytes(),
                    gas_used: 0,
                };
            }
            return EeOutcome {
                status: OutcomeStatus::Success,
                output: ata.to_vec(),
                gas_used: 2_000,
            };
        }

        // Deployed sBPF program execution
        let prog_rec = match read_svm_account_checked(host, &target_pk) {
            Ok(rec) => rec.unwrap_or_default(),
            Err(HostError::OutOfGas) => {
                return EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                };
            }
            Err(e) => {
                return EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: e.to_string().into_bytes(),
                    gas_used: 0,
                };
            }
        };
        if !prog_rec.executable || prog_rec.data.is_empty() {
            return EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"SVM program account not executable".to_vec(),
                gas_used: 0,
            };
        }
        match execute_sbpf_bytecode(&prog_rec.data, &call.input, call.gas_limit) {
            Ok((_, cu_used, out_buf)) => {
                if host.charge(cu_used).is_err() {
                    return EeOutcome {
                        status: OutcomeStatus::OutOfGas,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    };
                }
                EeOutcome {
                    status: OutcomeStatus::Success,
                    output: out_buf,
                    gas_used: cu_used,
                }
            }
            Err((st, msg, cu_used)) => {
                let _ = host.charge(cu_used);
                EeOutcome {
                    status: st,
                    output: msg.into_bytes(),
                    gas_used: cu_used,
                }
            }
        }
    }
}

impl ExecutionEnvironment for SvmWorker {
    fn id(&self) -> EeId {
        EeId::SVM
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        if code.len() > MAX_SBPF_CODE_BYTES {
            return Err(EeRefusal {
                code: RefusalCode::TooLarge,
                message: format!("sBPF size {} exceeds {MAX_SBPF_CODE_BYTES}", code.len()),
            });
        }
        let loader = Arc::new(BuiltinProgram::new_loader(deterministic_sbpf_config()));
        load_and_verify_sbpf(code, loader).map_err(|message| EeRefusal {
            code: RefusalCode::InvalidCode,
            message,
        })?;
        let code_hash: [u8; 32] = Sha256::digest(code).into();
        Ok(CodeInfo {
            code_hash,
            abi_tag: String::from("svm-sbpf"),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let Ok(cp) = host.checkpoint_begin() else {
            return Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"SVM checkpoint begin failed".to_vec(),
                gas_used: 0,
            });
        };
        let res = catch_unwind(AssertUnwindSafe(|| Self::execute_inner(ctx, call, host)));
        match res {
            Ok(outcome) => {
                if outcome.status == OutcomeStatus::Success {
                    if host.checkpoint_commit(cp).is_err() {
                        let _ = host.checkpoint_rollback(cp);
                        return Ok(EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: b"SVM checkpoint commit failed".to_vec(),
                            gas_used: outcome.gas_used,
                        });
                    }
                } else {
                    let _ = host.checkpoint_rollback(cp);
                }
                Ok(outcome)
            }
            Err(payload) => {
                let _ = host.checkpoint_rollback(cp);
                let msg = panic_payload_message(&*payload);
                Err(EeFault {
                    ee: EeId::SVM,
                    panic_digest: panic_digest(EeId::SVM, &msg),
                })
            }
        }
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        let Some(pk) = parse_pubkey32(&q.target.id) else {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("SVM query target must be 32 bytes"),
            });
        };
        let rec = read_svm_account_checked(host, &pk)
            .map_err(|e| EeRefusal {
                code: RefusalCode::Denied,
                message: e.to_string(),
            })?
            .unwrap_or_default();
        if rec.executable && !q.input.is_empty() {
            let (_, _, out) = execute_sbpf_bytecode(&rec.data, &q.input, QUERY_CU_LIMIT).map_err(
                |(_, message, _)| EeRefusal {
                    code: RefusalCode::Denied,
                    message,
                },
            )?;
            return Ok(out);
        }
        serde_json::to_vec(&rec).map_err(|e| EeRefusal {
            code: RefusalCode::InvalidCode,
            message: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::thread;

    use budlum_uel_abi::mock::MemoryHost;
    use budlum_uel_abi::transport::{serve_connection, EeClient};
    use budlum_uel_abi::{
        BlockContext, BudAmount, EeCall, EeCallKind, EeId, EeIdentity, ExecutionEnvironment,
        OutcomeStatus, UniversalResult,
    };

    use super::*;
    use crate::programs::{encode_borsh_universal_call, BorshUniversalCall, SvmAccountMeta};

    fn minimal_sbpf_ok_program() -> Vec<u8> {
        // r0 = 0; return (SBPFVersion::V3)
        let mut code = Vec::with_capacity(16);
        code.extend_from_slice(&[ebpf::MOV64_IMM, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        code.extend_from_slice(&[ebpf::RETURN, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        code
    }

    fn test_call(target: [u8; 32], kind: EeCallKind, input: Vec<u8>, gas_limit: u64) -> EeCall {
        EeCall {
            kind,
            caller: EeIdentity {
                ee: EeId::SVM,
                id: vec![0x11; 32],
            },
            target: EeIdentity {
                ee: EeId::SVM,
                id: target.to_vec(),
            },
            value: BudAmount(0),
            input,
            gas_limit,
            depth: 0,
            tx_hash: [0; 32],
        }
    }

    fn test_ctx() -> BlockContext {
        BlockContext {
            chain_id: 205,
            height: 10,
            timestamp_ms: 1_762_000_000_000,
        }
    }

    #[test]
    fn system_create_account_cannot_overwrite_another_accounts_record() {
        let caller = [0x11; 32];
        let victim = [0x55; 32];
        let mut host = MemoryHost::new(1_000_000);
        let existing = SvmAccountRecord {
            owner: [0x33; 32],
            executable: true,
            rent_epoch: 17,
            data: b"victim program bytes".to_vec(),
        };
        write_svm_account(&mut host, &victim, &existing).expect("fixture write");
        let mut data = 0u32.to_le_bytes().to_vec();
        data.extend_from_slice(&10u64.to_le_bytes());
        data.extend_from_slice(&128u64.to_le_bytes());
        data.extend_from_slice(&[0x99; 32]);
        let ix = SvmInstructionEnvelope {
            accounts: vec![
                SvmAccountMeta {
                    pubkey: caller,
                    is_signer: true,
                    is_writable: true,
                },
                SvmAccountMeta {
                    pubkey: victim,
                    is_signer: true,
                    is_writable: true,
                },
            ],
            data,
        };
        assert!(handle_system_program(&caller, &ix, u64::MAX, &mut host).is_err());
        assert_eq!(read_svm_account(&host, &victim), existing);
    }

    #[test]
    fn svm_deploy_requires_gas_and_cannot_overwrite_existing_program() {
        let target = [0x77; 32];
        let code = minimal_sbpf_ok_program();
        let mut worker = SvmWorker;
        let mut host = MemoryHost::new(10_000);
        let deploy_gas = 2_000u64 + (code.len() as u64) * 25;
        let low_gas = test_call(target, EeCallKind::Deploy, code.clone(), 1_999);
        let outcome = worker
            .execute(&test_ctx(), &low_gas, &mut host)
            .expect("worker must not fault");
        assert_eq!(outcome.status, OutcomeStatus::OutOfGas);
        assert!(host.state.is_empty());
        assert_eq!(host.gas_charged, 0);

        // The old flat fee no longer covers the published bytes.
        let flat_only = test_call(target, EeCallKind::Deploy, code.clone(), 2_000);
        let outcome = worker
            .execute(&test_ctx(), &flat_only, &mut host)
            .expect("worker must not fault");
        assert_eq!(outcome.status, OutcomeStatus::OutOfGas);
        assert!(host.state.is_empty());
        assert_eq!(host.gas_charged, 0);

        let call = test_call(target, EeCallKind::Deploy, code, deploy_gas);
        let outcome = worker
            .execute(&test_ctx(), &call, &mut host)
            .expect("worker must not fault");
        assert_eq!(outcome.status, OutcomeStatus::Success);
        assert_eq!(outcome.gas_used, deploy_gas);
        assert_eq!(host.gas_charged, deploy_gas);
        let saved_state = host.state.clone();

        let outcome = worker
            .execute(&test_ctx(), &call, &mut host)
            .expect("worker must not fault");
        assert_eq!(outcome.status, OutcomeStatus::Revert);
        assert_eq!(host.state, saved_state);
        assert_eq!(host.gas_charged, deploy_gas);
    }

    #[test]
    fn svm_ata_creation_preserves_existing_accounts_and_checks_gas() {
        let wallet = [0x22; 32];
        let mint = [0x33; 32];
        let ata = derive_associated_token_address(&wallet, &SPL_TOKEN_PROGRAM_ID, &mint);
        let instruction = SvmInstructionEnvelope {
            accounts: vec![
                SvmAccountMeta {
                    pubkey: wallet,
                    is_signer: false,
                    is_writable: false,
                },
                SvmAccountMeta {
                    pubkey: mint,
                    is_signer: false,
                    is_writable: false,
                },
                SvmAccountMeta {
                    pubkey: SPL_TOKEN_PROGRAM_ID,
                    is_signer: false,
                    is_writable: false,
                },
            ],
            data: Vec::new(),
        };
        let input = serde_json::to_vec(&instruction).expect("serializable instruction");
        let mut worker = SvmWorker;
        let mut host = MemoryHost::new(10_000);
        let mint_record = SvmAccountRecord {
            owner: SPL_TOKEN_PROGRAM_ID,
            executable: false,
            rent_epoch: u64::MAX,
            data: serde_json::to_vec(&SplMintState {
                mint_authority: Some(wallet),
                supply: 0,
                decimals: 6,
                is_initialized: true,
            })
            .expect("serialize mint"),
        };
        write_svm_account(&mut host, &mint, &mint_record).expect("save mint");
        let initial_state = host.state.clone();
        let low_gas = test_call(
            ASSOCIATED_TOKEN_PROGRAM_ID,
            EeCallKind::Call,
            input.clone(),
            1_999,
        );
        let outcome = worker
            .execute(&test_ctx(), &low_gas, &mut host)
            .expect("worker must not fault");
        assert_eq!(outcome.status, OutcomeStatus::OutOfGas);
        assert_eq!(host.state, initial_state);

        let call = test_call(ASSOCIATED_TOKEN_PROGRAM_ID, EeCallKind::Call, input, 2_000);
        let outcome = worker
            .execute(&test_ctx(), &call, &mut host)
            .expect("worker must not fault");
        assert_eq!(outcome.status, OutcomeStatus::Success);
        assert_eq!(outcome.output, ata);
        assert_eq!(host.gas_charged, 2_000);
        let mut saved = read_svm_account(&host, &ata);
        saved.data = b"existing funded account data".to_vec();
        write_svm_account(&mut host, &ata, &saved).expect("store funded account");
        let saved_state = host.state.clone();

        let outcome = worker
            .execute(&test_ctx(), &call, &mut host)
            .expect("worker must not fault");
        assert_eq!(outcome.status, OutcomeStatus::Revert);
        assert_eq!(
            host.state, saved_state,
            "ATA creation must not zero an existing account"
        );
        assert_eq!(host.gas_charged, 2_000);
    }

    #[test]
    fn spl_token_mint_to_rejects_wrong_mint_and_self_transfer_cannot_inflate_balance() {
        let caller = [0x11; 32];
        let mint = [0x22; 32];
        let other_mint = [0x33; 32];
        let token = [0x44; 32];
        let mut host = MemoryHost::new(10_000);
        let mint_record = SvmAccountRecord {
            owner: SPL_TOKEN_PROGRAM_ID,
            executable: false,
            rent_epoch: u64::MAX,
            data: serde_json::to_vec(&SplMintState {
                mint_authority: Some(caller),
                supply: 10,
                decimals: 6,
                is_initialized: true,
            })
            .expect("serialize mint"),
        };
        let token_record = SvmAccountRecord {
            owner: SPL_TOKEN_PROGRAM_ID,
            executable: false,
            rent_epoch: u64::MAX,
            data: serde_json::to_vec(&SplTokenAccountState {
                mint: other_mint,
                owner: caller,
                amount: 10,
                delegate: None,
                delegated_amount: 0,
                is_initialized: true,
            })
            .expect("serialize account"),
        };
        write_svm_account(&mut host, &mint, &mint_record).expect("save mint");
        write_svm_account(&mut host, &token, &token_record).expect("save account");
        let before = host.state.clone();
        let mut mint_to = vec![7];
        mint_to.extend_from_slice(&5u64.to_le_bytes());
        let mint_ix = SvmInstructionEnvelope {
            accounts: vec![
                SvmAccountMeta {
                    pubkey: mint,
                    is_signer: false,
                    is_writable: true,
                },
                SvmAccountMeta {
                    pubkey: token,
                    is_signer: false,
                    is_writable: true,
                },
            ],
            data: mint_to,
        };
        assert!(handle_spl_token(
            &SPL_TOKEN_PROGRAM_ID,
            &caller,
            &mint_ix,
            u64::MAX,
            &mut host
        )
        .is_err());
        assert_eq!(
            host.state, before,
            "mint mismatch must not alter supply or account"
        );

        let mut token_record = token_record;
        token_record.data = serde_json::to_vec(&SplTokenAccountState {
            mint,
            owner: caller,
            amount: 10,
            delegate: None,
            delegated_amount: 0,
            is_initialized: true,
        })
        .expect("serialize account");
        write_svm_account(&mut host, &token, &token_record).expect("save matching token");
        let before = host.state.clone();
        let mut transfer = vec![3];
        transfer.extend_from_slice(&5u64.to_le_bytes());
        let transfer_ix = SvmInstructionEnvelope {
            accounts: vec![
                SvmAccountMeta {
                    pubkey: token,
                    is_signer: false,
                    is_writable: true,
                },
                SvmAccountMeta {
                    pubkey: token,
                    is_signer: false,
                    is_writable: true,
                },
            ],
            data: transfer,
        };
        assert!(handle_spl_token(
            &SPL_TOKEN_PROGRAM_ID,
            &caller,
            &transfer_ix,
            u64::MAX,
            &mut host
        )
        .is_ok());
        assert_eq!(host.state, before, "self-transfer cannot mint tokens");
    }

    #[test]
    fn svm_jit_is_disabled() {
        let code = minimal_sbpf_ok_program();
        let loader = Arc::new(BuiltinProgram::new_loader(deterministic_sbpf_config()));
        let Ok(exe) = load_and_verify_sbpf(&code, loader.clone()) else {
            panic!("verify failed");
        };
        let sbpf_version = exe.get_sbpf_version();
        let stack_size = exe.get_config().stack_size();
        let mut stack = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(stack_size);
        let mut heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(SBPF_HEAP_BYTES);
        let mut input = vec![0u8; 8];
        let regions = vec![
            exe.get_ro_region(),
            MemoryRegion::new_writable(stack.as_slice_mut(), ebpf::MM_STACK_START),
            MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
            MemoryRegion::new_writable(input.as_mut_slice(), ebpf::MM_INPUT_START),
        ];
        let Ok(mapping) = MemoryMapping::new(regions, exe.get_config(), sbpf_version) else {
            panic!("mapping failed");
        };
        let mut meter = SvmMeter::new(10_000);
        let mut vm = EbpfVm::new(loader, sbpf_version, &mut meter, mapping, stack_size);

        // Calling with `interpreted = false` MUST fail with `JitNotCompiled`!
        let (_, jit_res) = vm.execute_program(&exe, false);
        assert!(matches!(
            jit_res,
            ProgramResult::Err(EbpfError::JitNotCompiled)
        ));

        // Calling with `interpreted = true` succeeds cleanly!
        let (insns, interp_res) = vm.execute_program(&exe, true);
        assert!(matches!(interp_res, ProgramResult::Ok(0)));
        assert_eq!(insns, 2);
    }

    #[test]
    fn uel_svm_alias_is_off_curve() {
        for i in 0..64u8 {
            let local = [i; 32];
            let mut found = None;
            for seed in (0..=255u8).rev() {
                let mut h = Sha256::new();
                h.update(b"BDLM_SVM_ALIAS_V1");
                h.update(local);
                h.update([seed]);
                let cand: [u8; 32] = h.finalize().into();
                if curve25519_dalek::edwards::CompressedEdwardsY(cand)
                    .decompress()
                    .is_none()
                {
                    found = Some(cand);
                    break;
                }
            }
            let Some(alias) = found else {
                panic!("off-curve alias not found");
            };
            assert!(curve25519_dalek::edwards::CompressedEdwardsY(alias)
                .decompress()
                .is_none());
        }
    }

    fn hex32(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn meta(pubkey: [u8; 32]) -> SvmAccountMeta {
        SvmAccountMeta {
            pubkey,
            is_signer: false,
            is_writable: true,
        }
    }

    fn initialize_mint_ix(
        seed: [u8; 32],
        decimals: u8,
        authority: [u8; 32],
    ) -> SvmInstructionEnvelope {
        let mut data = vec![0, decimals];
        data.extend_from_slice(&authority);
        SvmInstructionEnvelope {
            accounts: vec![meta(seed)],
            data,
        }
    }

    fn initialize_account_ix(
        account: [u8; 32],
        mint: [u8; 32],
        owner: [u8; 32],
    ) -> SvmInstructionEnvelope {
        SvmInstructionEnvelope {
            accounts: vec![meta(account), meta(mint), meta(owner)],
            data: vec![1],
        }
    }

    /// The same two vectors are pinned in the root crate: the SVM environment and this
    /// worker must derive one mint address for one `(caller, seed)` pair.
    #[test]
    fn the_spl_mint_address_matches_the_known_answers() {
        let caller = [0x11u8; 32];
        assert_eq!(
            derive_spl_mint_address(&caller, &[0x22; 32]).map(|a| hex32(&a)),
            Some(String::from(
                "1ae021a316289bcb841cd784d3ca1c8a7085beb18c93bca77ef7b3f79979d816"
            ))
        );
        // The first candidate for this seed is a curve point, so the search takes its retry path.
        assert_eq!(
            derive_spl_mint_address(&caller, &[0x25; 32]).map(|a| hex32(&a)),
            Some(String::from(
                "d316db7a76988d0f340d9014b3d0c9448e2240b9dcb7446ffc231081f7029217"
            ))
        );
        // The address belongs to the caller: the same seed names another mint for another caller.
        assert_ne!(
            derive_spl_mint_address(&[0x33; 32], &[0x22; 32]),
            derive_spl_mint_address(&caller, &[0x22; 32])
        );
    }

    /// A mint address is a global identity. An account used to be able to take any
    /// unclaimed address first, block the real issuer for good and record a third party as
    /// an issuer.
    #[test]
    fn a_mint_belongs_to_the_account_that_initializes_it() {
        let alice = [0x11u8; 32];
        let mallory = [0x66u8; 32];
        let seed = [0x22u8; 32];
        let mut host = MemoryHost::new(1_000_000);

        // Mallory goes first, with the seed Alice is about to use.
        let Ok((mallory_mint, _)) = handle_spl_token(
            &SPL_TOKEN_PROGRAM_ID,
            &mallory,
            &initialize_mint_ix(seed, 6, mallory),
            u64::MAX,
            &mut host,
        ) else {
            panic!("mallory initializes her own mint");
        };
        // Alice is not blocked: her mint is a different address, derived from her.
        let Ok((alice_mint, _)) = handle_spl_token(
            &SPL_TOKEN_PROGRAM_ID,
            &alice,
            &initialize_mint_ix(seed, 6, alice),
            u64::MAX,
            &mut host,
        ) else {
            panic!("alice is not blocked by mallory");
        };
        assert_ne!(mallory_mint, alice_mint);
        let Ok(alice_address): Result<[u8; 32], _> = alice_mint.as_slice().try_into() else {
            panic!("mint address length");
        };
        assert_eq!(Some(alice_address), derive_spl_mint_address(&alice, &seed));
        let Ok(on_record) =
            serde_json::from_slice::<SplMintState>(&read_svm_account(&host, &alice_address).data)
        else {
            panic!("mint record");
        };
        assert_eq!(on_record.mint_authority, Some(alice));

        // Mallory cannot record Alice as the issuer of a mint Alice never asked for.
        let refused = handle_spl_token(
            &SPL_TOKEN_PROGRAM_ID,
            &mallory,
            &initialize_mint_ix([0x23; 32], 6, alice),
            u64::MAX,
            &mut host,
        );
        assert!(matches!(refused, Err((OutcomeStatus::Revert, _))));

        // The same caller and seed name the same mint, so a second initialization is refused.
        let again = handle_spl_token(
            &SPL_TOKEN_PROGRAM_ID,
            &alice,
            &initialize_mint_ix(seed, 6, alice),
            u64::MAX,
            &mut host,
        );
        assert!(matches!(again, Err((OutcomeStatus::Revert, _))));
    }

    /// The worker sees the outer caller and no signer set, so an account meta authorizes
    /// nothing. Only the caller's own associated token account can be initialized here. Any
    /// other absent address used to be open to anyone, with any owner.
    #[test]
    fn an_account_can_only_initialize_its_own_associated_token_account() {
        let alice = [0x11u8; 32];
        let bob = [0x22u8; 32];
        let mallory = [0x66u8; 32];
        let mut host = MemoryHost::new(1_000_000);
        let Ok((mint_vec, _)) = handle_spl_token(
            &SPL_TOKEN_PROGRAM_ID,
            &alice,
            &initialize_mint_ix([0x01; 32], 6, alice),
            u64::MAX,
            &mut host,
        ) else {
            panic!("mint");
        };
        let Ok(mint): Result<[u8; 32], _> = mint_vec.as_slice().try_into() else {
            panic!("mint address length");
        };
        let bob_ata = derive_associated_token_address(&bob, &SPL_TOKEN_PROGRAM_ID, &mint);

        // Mallory cannot occupy Bob's associated token account, as owner herself or as Bob.
        for owner in [mallory, bob] {
            let refused = handle_spl_token(
                &SPL_TOKEN_PROGRAM_ID,
                &mallory,
                &initialize_account_ix(bob_ata, mint, owner),
                u64::MAX,
                &mut host,
            );
            assert!(
                matches!(refused, Err((OutcomeStatus::Revert, _))),
                "mallory initializing bob's account with owner {} must be refused",
                hex32(&owner)
            );
        }
        assert!(!svm_account_exists(&host, &bob_ata).unwrap());

        // An arbitrary address is not an associated token account, not even for its owner.
        let refused = handle_spl_token(
            &SPL_TOKEN_PROGRAM_ID,
            &bob,
            &initialize_account_ix([0x99; 32], mint, bob),
            u64::MAX,
            &mut host,
        );
        assert!(matches!(refused, Err((OutcomeStatus::Revert, _))));

        // Bob can initialize his own.
        let own = handle_spl_token(
            &SPL_TOKEN_PROGRAM_ID,
            &bob,
            &initialize_account_ix(bob_ata, mint, bob),
            u64::MAX,
            &mut host,
        );
        assert!(own.is_ok());
        assert!(svm_account_exists(&host, &bob_ata).unwrap());
    }

    #[test]
    fn spl_token_and_sbpf_deploy_and_vote_stake_refused() {
        let mut host = MemoryHost::new(10_000_000);
        let mut worker = SvmWorker;
        let ctx = BlockContext {
            chain_id: 205,
            height: 10,
            timestamp_ms: 1_762_000_000_000,
        };
        let alice = [0x11u8; 32];
        let bob = [0x22u8; 32];
        let mint_seed = [0x33u8; 32];
        let alice_id = EeIdentity {
            ee: EeId::SVM,
            id: alice.to_vec(),
        };

        // 1. Vote & Stake programs are deterministically refused
        for forbidden in [VOTE_PROGRAM_ID, STAKE_PROGRAM_ID] {
            let Ok(out) = worker.execute(
                &ctx,
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: alice_id.clone(),
                    target: EeIdentity {
                        ee: EeId::SVM,
                        id: forbidden.to_vec(),
                    },
                    value: BudAmount(0),
                    input: Vec::new(),
                    gas_limit: 50_000,
                    depth: 0,
                    tx_hash: [0x01; 32],
                },
                &mut host,
            ) else {
                panic!("fault");
            };
            assert_eq!(out.status, OutcomeStatus::Revert);
        }

        // 2. Initialize SPL Mint + create ATAs + MintTo + Transfer
        let mut init_mint_data = vec![0u8, 6u8];
        init_mint_data.extend_from_slice(&alice);
        let init_mint_env = SvmInstructionEnvelope {
            accounts: vec![SvmAccountMeta {
                pubkey: mint_seed,
                is_signer: true,
                is_writable: true,
            }],
            data: init_mint_data,
        };
        let Ok(m_out) = worker.execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: alice_id.clone(),
                target: EeIdentity {
                    ee: EeId::SVM,
                    id: SPL_TOKEN_PROGRAM_ID.to_vec(),
                },
                value: BudAmount(0),
                input: serde_json::to_vec(&init_mint_env).unwrap_or_default(),
                gas_limit: 100_000,
                depth: 0,
                tx_hash: [0x02; 32],
            },
            &mut host,
        ) else {
            panic!("mint init fault");
        };
        assert_eq!(m_out.status, OutcomeStatus::Success);
        // The seed is not the address. The mint lives where the worker derived it, and
        // the output says where.
        let Ok(mint): Result<[u8; 32], _> = m_out.output.as_slice().try_into() else {
            panic!("bad mint address length");
        };
        assert_eq!(Some(mint), derive_spl_mint_address(&alice, &mint_seed));

        let create_ata = |w: [u8; 32], h: &mut MemoryHost, worker: &mut SvmWorker| -> [u8; 32] {
            let env = SvmInstructionEnvelope {
                accounts: vec![
                    SvmAccountMeta {
                        pubkey: w,
                        is_signer: false,
                        is_writable: false,
                    },
                    SvmAccountMeta {
                        pubkey: mint,
                        is_signer: false,
                        is_writable: false,
                    },
                    SvmAccountMeta {
                        pubkey: SPL_TOKEN_PROGRAM_ID,
                        is_signer: false,
                        is_writable: false,
                    },
                ],
                data: Vec::new(),
            };
            let Ok(res) = worker.execute(
                &ctx,
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: alice_id.clone(),
                    target: EeIdentity {
                        ee: EeId::SVM,
                        id: ASSOCIATED_TOKEN_PROGRAM_ID.to_vec(),
                    },
                    value: BudAmount(0),
                    input: serde_json::to_vec(&env).unwrap_or_default(),
                    gas_limit: 100_000,
                    depth: 0,
                    tx_hash: [0x03; 32],
                },
                h,
            ) else {
                panic!("ata fault");
            };
            assert_eq!(res.status, OutcomeStatus::Success);
            let Ok(arr) = res.output.as_slice().try_into() else {
                panic!("bad ata len");
            };
            arr
        };
        let alice_ata = create_ata(alice, &mut host, &mut worker);
        let bob_ata = create_ata(bob, &mut host, &mut worker);

        let mut mint_to_data = vec![7u8];
        mint_to_data.extend_from_slice(&1_000u64.to_le_bytes());
        let Ok(mt) = worker.execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: alice_id.clone(),
                target: EeIdentity {
                    ee: EeId::SVM,
                    id: SPL_TOKEN_PROGRAM_ID.to_vec(),
                },
                value: BudAmount(0),
                input: serde_json::to_vec(&SvmInstructionEnvelope {
                    accounts: vec![
                        SvmAccountMeta {
                            pubkey: mint,
                            is_signer: false,
                            is_writable: true,
                        },
                        SvmAccountMeta {
                            pubkey: alice_ata,
                            is_signer: false,
                            is_writable: true,
                        },
                    ],
                    data: mint_to_data,
                })
                .unwrap_or_default(),
                gas_limit: 100_000,
                depth: 0,
                tx_hash: [0x04; 32],
            },
            &mut host,
        ) else {
            panic!("mint_to fault");
        };
        assert_eq!(mt.status, OutcomeStatus::Success);

        let mut xfer_data = vec![3u8];
        xfer_data.extend_from_slice(&350u64.to_le_bytes());
        let Ok(xf) = worker.execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: alice_id.clone(),
                target: EeIdentity {
                    ee: EeId::SVM,
                    id: SPL_TOKEN_PROGRAM_ID.to_vec(),
                },
                value: BudAmount(0),
                input: serde_json::to_vec(&SvmInstructionEnvelope {
                    accounts: vec![
                        SvmAccountMeta {
                            pubkey: alice_ata,
                            is_signer: true,
                            is_writable: true,
                        },
                        SvmAccountMeta {
                            pubkey: bob_ata,
                            is_signer: false,
                            is_writable: true,
                        },
                    ],
                    data: xfer_data,
                })
                .unwrap_or_default(),
                gas_limit: 100_000,
                depth: 0,
                tx_hash: [0x05; 32],
            },
            &mut host,
        ) else {
            panic!("transfer fault");
        };
        assert_eq!(xf.status, OutcomeStatus::Success);

        let bob_rec = read_svm_account(&host, &bob_ata);
        let Ok(bob_tok) = serde_json::from_slice::<SplTokenAccountState>(&bob_rec.data) else {
            panic!("decode bob ata");
        };
        assert_eq!(bob_tok.amount, 350);

        // 3. Deploy and invoke real sBPF program
        let prog_pk = [0x77u8; 32];
        let Ok(dep) = worker.execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: alice_id.clone(),
                target: EeIdentity {
                    ee: EeId::SVM,
                    id: prog_pk.to_vec(),
                },
                value: BudAmount(0),
                input: minimal_sbpf_ok_program(),
                gas_limit: 100_000,
                depth: 0,
                tx_hash: [0x06; 32],
            },
            &mut host,
        ) else {
            panic!("deploy fault");
        };
        assert_eq!(dep.status, OutcomeStatus::Success);

        let Ok(run_out) = worker.execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: alice_id,
                target: EeIdentity {
                    ee: EeId::SVM,
                    id: prog_pk.to_vec(),
                },
                value: BudAmount(0),
                input: b"hello-svm".to_vec(),
                gas_limit: 100_000,
                depth: 0,
                tx_hash: [0x07; 32],
            },
            &mut host,
        ) else {
            panic!("call fault");
        };
        assert_eq!(run_out.status, OutcomeStatus::Success);
    }

    #[test]
    fn svm_universal_call_program_borsh_cpi_dispatches() {
        let mut host = MemoryHost::new(2_000_000).with_universal_handler(Box::new(|uc| {
            assert_eq!(uc.to_ee, EeId::EVM);
            assert_eq!(uc.input, b"cpi-from-svm");
            Ok(UniversalResult {
                success: true,
                output: b"ack-from-evm".to_vec(),
                gas_used: 900,
            })
        }));
        let mut worker = SvmWorker;
        let ctx = BlockContext {
            chain_id: 205,
            height: 11,
            timestamp_ms: 1_762_000_000_000,
        };
        let borsh = encode_borsh_universal_call(&BorshUniversalCall {
            target_ee: EeId::EVM.0,
            target: vec![0xAA; 20],
            input: b"cpi-from-svm".to_vec(),
            value_attos: 0,
            gas_limit_bgu: 50_000,
            is_static: false,
        });
        let Ok(out) = worker.execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: EeIdentity {
                    ee: EeId::SVM,
                    id: vec![0x11; 32],
                },
                target: EeIdentity {
                    ee: EeId::SVM,
                    id: UNIVERSAL_CALL_PROGRAM_ID.to_vec(),
                },
                value: BudAmount(0),
                input: borsh,
                gas_limit: 100_000,
                depth: 0,
                tx_hash: [0x08; 32],
            },
            &mut host,
        ) else {
            panic!("universal cpi fault");
        };
        assert_eq!(out.status, OutcomeStatus::Success);
        assert_eq!(out.output, b"ack-from-evm");
    }

    #[test]
    fn unix_socket_worker_roundtrip() {
        let sock_path = std::env::temp_dir().join(format!(
            "budlum-ee-svm-test-{}-{:?}.sock",
            std::process::id(),
            thread::current().id()
        ));
        let _ = std::fs::remove_file(&sock_path);
        let Ok(listener) = UnixListener::bind(&sock_path) else {
            panic!("bind failed");
        };
        let srv = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut worker = SvmWorker;
                let _ = serve_connection(stream, &mut worker);
            }
        });

        let mut client = EeClient::new(&sock_path, EeId::SVM);
        let Ok(Ok(info)) = client.validate_deploy(&minimal_sbpf_ok_program()) else {
            panic!("ipc validate_deploy failed");
        };
        assert_eq!(info.abi_tag, "svm-sbpf");
        drop(client);
        let _ = srv.join();
        let _ = std::fs::remove_file(&sock_path);
    }

    struct FailingReadHost {
        inner: MemoryHost,
        fail_with_oog: bool,
    }

    impl HostRead for FailingReadHost {
        fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
            if ns.as_str() == NS_SVM_ACCOUNT {
                return Err(if self.fail_with_oog {
                    HostError::OutOfGas
                } else {
                    HostError::Invalid(String::from("injected SVM storage read fault"))
                });
            }
            self.inner.read(ns, key)
        }
        fn bud_balance(&self, id: &EeIdentity) -> Result<BudAmount, HostError> {
            self.inner.bud_balance(id)
        }
    }

    impl HostApi for FailingReadHost {
        fn write(
            &mut self,
            ns: &Namespace,
            key: &[u8],
            value: Option<&[u8]>,
        ) -> Result<(), HostError> {
            self.inner.write(ns, key, value)
        }
        fn charge(&mut self, gas: u64) -> Result<(), budlum_uel_abi::OutOfGas> {
            self.inner.charge(gas)
        }
        fn emit_log(&mut self, log: budlum_uel_abi::EeLog) -> Result<(), HostError> {
            self.inner.emit_log(log)
        }
        fn bud_transfer(
            &mut self,
            from: &EeIdentity,
            to: &EeIdentity,
            amount: u128,
        ) -> Result<(), HostError> {
            self.inner.bud_transfer(from, to, amount)
        }
        fn universal_call(
            &mut self,
            call: budlum_uel_abi::UniversalCall,
        ) -> Result<budlum_uel_abi::UniversalResult, HostError> {
            self.inner.universal_call(call)
        }
        fn checkpoint_begin(&mut self) -> Result<u64, HostError> {
            self.inner.checkpoint_begin()
        }
        fn checkpoint_commit(&mut self, id: u64) -> Result<(), HostError> {
            self.inner.checkpoint_commit(id)
        }
        fn checkpoint_rollback(&mut self, id: u64) -> Result<(), HostError> {
            self.inner.checkpoint_rollback(id)
        }
    }

    #[test]
    fn query_and_execute_fail_closed_on_host_read_error_instead_of_default_account() {
        let mut worker = SvmWorker;
        let ctx = test_ctx();
        let target = [0x44u8; 32];

        // 1. Query MUST refuse a host read error instead of fabricating a default empty account.
        let bad_host = FailingReadHost {
            inner: MemoryHost::new(100_000),
            fail_with_oog: false,
        };
        let q = budlum_uel_abi::EeQuery {
            target: EeIdentity {
                ee: EeId::SVM,
                id: target.to_vec(),
            },
            input: Vec::new(),
        };
        assert!(
            worker.query(&ctx, &q, &bad_host).is_err(),
            "SVM query must fail closed on host.read error rather than returning a default account"
        );

        // 2. Execute MUST propagate HostError::OutOfGas as OutcomeStatus::OutOfGas (not Revert).
        let mut oog_host = FailingReadHost {
            inner: MemoryHost::new(100_000),
            fail_with_oog: true,
        };
        let out = worker
            .execute(
                &ctx,
                &test_call(target, EeCallKind::Call, vec![1, 2, 3], 100_000),
                &mut oog_host,
            )
            .expect("worker must not fault");
        assert_eq!(
            out.status,
            OutcomeStatus::OutOfGas,
            "HostError::OutOfGas while reading SVM program account must return OutOfGas"
        );
    }
}
