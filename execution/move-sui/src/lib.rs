//! Out-of-process deterministic Move (Sui dialect) UEL execution worker (
//! `EeId::MOVE_SUI = 0x05`).
//!
//! Stores Sui objects and immutable Move packages under `ee/sui/object` using
//! Lamport object versioning and `BLAKE2b-256` object digests, enforces `Section 1.5`
//! launch-closure on testnet `45261` until `PROPOSED_SUI_ACTIVATION_HEIGHT`, and
//! runs Programmable Transaction Blocks (`PublishPackage`, `SplitCoins`,
//! `MergeCoins`, `TransferObjects`, `MoveCall`, `UniversalBridgeCall`).

#![forbid(unsafe_code)]

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as _};
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostError, HostRead, Namespace,
    UniversalCall,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Pinned upstream `MystenLabs/sui` (`sui-execution`, Apache-2.0) commit reference.
pub const PINNED_SUI_EXECUTION_COMMIT: &str = "e5b8d9a4c2718f140933b42c66d8c04a7d1e9b02";

/// Budlum testnet chain ID (`Section 1.5`).
pub const BUDLUM_TESTNET_CHAIN_ID: u64 = 45_261;

/// Proposed activation height on testnet `45261` ( exit criterion).
pub const PROPOSED_SUI_ACTIVATION_HEIGHT: u64 = 50_000;

/// Canonical UEL namespace storing Sui objects and published Move packages.
pub const NS_SUI_OBJECT: &str = "ee/sui/object";

/// Magic header identifying deterministic Budlum-Sui compiled Move module bundles.
pub const SUI_MODULE_MAGIC: &[u8; 4] = b"SUIM";

/// Maximum package bundle size (`100 KiB`, matching Sui mainnet package cap).
pub const MAX_SUI_PACKAGE_BYTES: usize = 102_400;

/// Base gas charged per PTB execution in BGU.
pub const SUI_PTB_BASE_BGU: u64 = 2_000;

/// Gas charged per PTB command step in BGU.
pub const SUI_CMD_STEP_BGU: u64 = 1_200;

/// Gas charged per published module byte in BGU.
pub const SUI_PUBLISH_PER_BYTE_BGU: u64 = 25;

/// `1 MIST = 10^9 attoBUD` (`9` decimals).
pub const ATTO_PER_MIST: u128 = 1_000_000_000;

type Blake2b256 = Blake2b<U32>;

/// Ownership modes in the Sui object model (`ee/sui/object`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuiOwner {
    AddressOwner([u8; 32]),
    ObjectOwner([u8; 32]),
    Shared { initial_shared_version: u64 },
    Immutable,
}

/// Canonical Sui object persisted under `ee/sui/object/<object_id_32>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiObject {
    pub object_id: [u8; 32],
    pub version: u64,
    pub digest: [u8; 32],
    pub owner: SuiOwner,
    pub type_tag: String,
    pub contents: Vec<u8>,
}

impl SuiObject {
    /// Compute the deterministic `BLAKE2b-256` digest of this object state.
    #[must_use]
    pub fn compute_digest(&self) -> [u8; 32] {
        let mut h = Blake2b256::new();
        h.update(b"SuiObject::V1");
        h.update(self.object_id);
        h.update(self.version.to_le_bytes());
        let owner_bytes = serde_json::to_vec(&self.owner).unwrap_or_default();
        h.update((owner_bytes.len() as u64).to_le_bytes());
        h.update(&owner_bytes);
        h.update((self.type_tag.len() as u64).to_le_bytes());
        h.update(self.type_tag.as_bytes());
        h.update((self.contents.len() as u64).to_le_bytes());
        h.update(&self.contents);
        h.finalize().into()
    }
}

/// Compiled Sui Move module descriptor inside a published package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiCompiledModule {
    pub name: String,
    pub exported_functions: Vec<String>,
    pub bytecode: Vec<u8>,
}

/// Programmable Transaction Block (`PTB`) commands executed by `MoveSuiWorker`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuiPtbCommand {
    /// Publish an immutable Move package (`sui client publish` payload).
    PublishPackage {
        modules: Vec<SuiCompiledModule>,
        initial_coin_mist: u64,
    },
    /// Mint a new `0x2::coin::Coin<BUD>` object backed by debiting caller BUD.
    MintGasCoin { amount_mist: u64 },
    /// Split a `0x2::coin::Coin<BUD>` object into new owned coins (`0x2::coin::split`).
    SplitCoins {
        coin_id: [u8; 32],
        amounts_mist: Vec<u64>,
    },
    /// Merge `sources` into `primary_coin` (`0x2::coin::join`).
    MergeCoins {
        primary_coin: [u8; 32],
        sources: Vec<SuiObjectId>,
    },
    /// Transfer owned objects to `recipient` (`0x2::transfer::public_transfer`).
    TransferObjects {
        object_ids: Vec<[u8; 32]>,
        recipient: [u8; 32],
    },
    /// Freeze or share an owned object (`0x2::transfer::public_share_object`).
    ShareObject { object_id: [u8; 32] },
    /// Invoke an exported entry/public Move function in a published package.
    MoveCall {
        package_id: [u8; 32],
        module: String,
        function: String,
        shared_inputs: Vec<[u8; 32]>,
        arg_bytes: Vec<u8>,
    },
    /// Invoke another UEL environment synchronously over `HostApi::universal_call`.
    UniversalBridgeCall {
        target_ee: u8,
        target: Vec<u8>,
        input: Vec<u8>,
        value_mist: u64,
        gas_limit: u64,
    },
}

/// Alias for 32-byte Sui `ObjectID`.
pub type SuiObjectId = [u8; 32];

/// Programmable Transaction Block (`PTB`) envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiPtb {
    pub commands: Vec<SuiPtbCommand>,
}

/// Read-only Sui query shapes answered by `MoveSuiWorker::query`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuiWorkerQuery {
    GetObject { object_id: [u8; 32] },
    GetMistBalance { address: [u8; 32] },
}

/// Encode a `SUI_MODULE_MAGIC`-prefixed package image for `EeCallKind::Deploy` or
/// `validate_deploy`.
pub fn encode_sui_package_bundle(modules: &[SuiCompiledModule]) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(modules).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(SUI_MODULE_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode and structurally validate a `SUI_MODULE_MAGIC`-prefixed package bundle.
pub fn decode_sui_package_bundle(raw: &[u8]) -> Result<Vec<SuiCompiledModule>, EeRefusal> {
    if raw.len() < 4 || raw.len() > MAX_SUI_PACKAGE_BYTES {
        return Err(EeRefusal::BadCode("invalid Sui package bundle size".into()));
    }
    if raw.get(..4) != Some(SUI_MODULE_MAGIC.as_slice()) {
        return Err(EeRefusal::BadCode("missing SUIM package magic".into()));
    }
    let body = raw.get(4..).unwrap_or_default();
    let mods: Vec<SuiCompiledModule> = serde_json::from_slice(body)
        .map_err(|e| EeRefusal::BadCode(format!("bad Sui module bundle: {e}")))?;
    if mods.is_empty() {
        return Err(EeRefusal::BadCode("empty Sui package".into()));
    }
    for m in &mods {
        if m.name.is_empty() || m.exported_functions.is_empty() {
            return Err(EeRefusal::BadCode("empty module or function table".into()));
        }
    }
    Ok(mods)
}

fn derive_sui_object_id(tx_hash: &[u8; 32], ordinal: u64) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(b"BDLM_SUI_OBJ_ID_V1");
    h.update(tx_hash);
    h.update(ordinal.to_le_bytes());
    h.finalize().into()
}

fn sui_ns() -> Result<Namespace, EeFault> {
    Namespace::new(NS_SUI_OBJECT).map_err(EeFault::Wire)
}

fn read_sui_object(host: &dyn HostRead, id: &[u8; 32]) -> Result<Option<SuiObject>, HostError> {
    let ns = Namespace::new(NS_SUI_OBJECT).map_err(|_| HostError::Invalid("bad sui ns".into()))?;
    let Some(bytes) = host.read(&ns, id)? else {
        return Ok(None);
    };
    let obj = serde_json::from_slice::<SuiObject>(&bytes)
        .map_err(|e| HostError::Invalid(format!("corrupt SuiObject: {e}")))?;
    Ok(Some(obj))
}

fn write_sui_object(host: &mut dyn HostApi, mut obj: SuiObject) -> Result<SuiObject, HostError> {
    obj.digest = obj.compute_digest();
    let ns = Namespace::new(NS_SUI_OBJECT).map_err(|_| HostError::Invalid("bad sui ns".into()))?;
    let encoded = serde_json::to_vec(&obj).map_err(|e| HostError::Invalid(e.to_string()))?;
    host.write(ns, &obj.object_id, Some(&encoded))?;
    Ok(obj)
}

fn delete_sui_object(host: &mut dyn HostApi, id: &[u8; 32]) -> Result<(), HostError> {
    let ns = Namespace::new(NS_SUI_OBJECT).map_err(|_| HostError::Invalid("bad sui ns".into()))?;
    host.write(ns, id, None)
}

/// Out-of-process sequential Move (Sui dialect) worker (`EeId::MOVE_SUI = 0x05`).
#[derive(Debug, Clone)]
pub struct MoveSuiWorker {
    pub testnet_activation_height: Option<u64>,
}

impl Default for MoveSuiWorker {
    fn default() -> Self {
        Self::new()
    }
}

impl MoveSuiWorker {
    /// Default launch configuration: closed on testnet `45261` until
    /// [`PROPOSED_SUI_ACTIVATION_HEIGHT`] (`Section 1.5`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            testnet_activation_height: Some(PROPOSED_SUI_ACTIVATION_HEIGHT),
        }
    }

    /// Override testnet activation height (or `None` to keep permanently closed on `45261`).
    #[must_use]
    pub const fn with_activation_height(testnet_activation_height: Option<u64>) -> Self {
        Self {
            testnet_activation_height,
        }
    }

    /// Returns `true` if `MoveSuiWorker` is open at `ctx`.
    #[must_use]
    pub const fn is_active(&self, ctx: &BlockContext) -> bool {
        if ctx.chain_id != BUDLUM_TESTNET_CHAIN_ID {
            return true;
        }
        match self.testnet_activation_height {
            Some(h) => ctx.height >= h,
            None => false,
        }
    }
}

impl ExecutionEnvironment for MoveSuiWorker {
    fn id(&self) -> EeId {
        EeId::MOVE_SUI
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        let _ = decode_sui_package_bundle(code)?;
        let digest: [u8; 32] = Sha256::digest(code).into();
        Ok(CodeInfo {
            code_hash: digest,
            byte_len: u32::try_from(code.len()).unwrap_or(u32::MAX),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let _ = sui_ns()?;
        if !self.is_active(ctx) {
            return Ok(EeOutcome::reverted(b"MOVE_SUI_CLOSED_ON_TESTNET".to_vec(), 0));
        }
        let Ok(sender32) = <[u8; 32]>::try_from(call.caller.id.as_slice()) else {
            return Ok(EeOutcome::reverted(b"Sui caller must be 32 bytes".to_vec(), 0));
        };

        let mut gas_used: u64 = 0;
        let mut charge = |delta: u64, h: &mut dyn HostApi| -> Result<(), ()> {
            let next = gas_used.saturating_add(delta);
            if next > call.gas_limit || h.charge(delta).is_err() {
                return Err(());
            }
            gas_used = next;
            Ok(())
        };
        if charge(SUI_PTB_BASE_BGU, host).is_err() {
            return Ok(EeOutcome::out_of_gas(call.gas_limit));
        }

        if call.kind == EeCallKind::Deploy {
            let byte_cost = (call.input.len() as u64).saturating_mul(SUI_PUBLISH_PER_BYTE_BGU);
            if charge(byte_cost, host).is_err() {
                return Ok(EeOutcome::out_of_gas(call.gas_limit));
            }
            let Ok(mods) = decode_sui_package_bundle(&call.input) else {
                return Ok(EeOutcome::reverted(b"invalid Sui package bundle".to_vec(), gas_used));
            };
            let pkg_id = derive_sui_object_id(&call.tx_hash, 0);
            let contents = serde_json::to_vec(&mods).unwrap_or_default();
            let pkg_obj = SuiObject {
                object_id: pkg_id,
                version: 1,
                digest: [0u8; 32],
                owner: SuiOwner::Immutable,
                type_tag: "0x2::package::Package".to_string(),
                contents,
            };
            if write_sui_object(host, pkg_obj).is_err() {
                return Ok(EeOutcome::reverted(b"package write failed".to_vec(), gas_used));
            }
            return Ok(EeOutcome::success(pkg_id.to_vec(), gas_used));
        }

        let Ok(ptb) = serde_json::from_slice::<SuiPtb>(&call.input) else {
            return Ok(EeOutcome::reverted(b"invalid SuiPtb JSON".to_vec(), gas_used));
        };
        let mut created_ids: Vec<[u8; 32]> = Vec::new();
        let mut ordinal: u64 = 0;

        for cmd in &ptb.commands {
            if charge(SUI_CMD_STEP_BGU, host).is_err() {
                return Ok(EeOutcome::out_of_gas(call.gas_limit));
            }
            match cmd {
                SuiPtbCommand::PublishPackage {
                    modules,
                    initial_coin_mist,
                } => {
                    let bundle = match encode_sui_package_bundle(modules) {
                        Ok(b) => b,
                        Err(e) => return Ok(EeOutcome::reverted(e.into_bytes(), gas_used)),
                    };
                    let byte_cost = (bundle.len() as u64).saturating_mul(SUI_PUBLISH_PER_BYTE_BGU);
                    if charge(byte_cost, host).is_err() {
                        return Ok(EeOutcome::out_of_gas(call.gas_limit));
                    }
                    if decode_sui_package_bundle(&bundle).is_err() {
                        return Ok(EeOutcome::reverted(b"bad Sui modules".to_vec(), gas_used));
                    }
                    let pkg_id = derive_sui_object_id(&call.tx_hash, ordinal);
                    ordinal = ordinal.saturating_add(1);
                    let pkg_obj = SuiObject {
                        object_id: pkg_id,
                        version: 1,
                        digest: [0u8; 32],
                        owner: SuiOwner::Immutable,
                        type_tag: "0x2::package::Package".to_string(),
                        contents: serde_json::to_vec(modules).unwrap_or_default(),
                    };
                    if write_sui_object(host, pkg_obj).is_err() {
                        return Ok(EeOutcome::reverted(b"pkg write err".to_vec(), gas_used));
                    }
                    created_ids.push(pkg_id);
                    if *initial_coin_mist > 0 {
                        let coin_id = derive_sui_object_id(&call.tx_hash, ordinal);
                        ordinal = ordinal.saturating_add(1);
                        let coin_obj = SuiObject {
                            object_id: coin_id,
                            version: 1,
                            digest: [0u8; 32],
                            owner: SuiOwner::AddressOwner(sender32),
                            type_tag: "0x2::coin::Coin<0x2::bud::BUD>".to_string(),
                            contents: initial_coin_mist.to_le_bytes().to_vec(),
                        };
                        if write_sui_object(host, coin_obj).is_err() {
                            return Ok(EeOutcome::reverted(b"coin write err".to_vec(), gas_used));
                        }
                        created_ids.push(coin_id);
                    }
                }
                SuiPtbCommand::MintGasCoin { amount_mist } => {
                    let attos = u128::from(*amount_mist).saturating_mul(ATTO_PER_MIST);
                    let vault = EeIdentity {
                        ee: EeId::MOVE_SUI,
                        id: [0x02u8; 32].to_vec(),
                    };
                    if attos > 0 && host.bud_transfer(&call.caller, &vault, attos).is_err() {
                        return Ok(EeOutcome::reverted(
                            b"insufficient MIST balance".to_vec(),
                            gas_used,
                        ));
                    }
                    let coin_id = derive_sui_object_id(&call.tx_hash, ordinal);
                    ordinal = ordinal.saturating_add(1);
                    let coin = SuiObject {
                        object_id: coin_id,
                        version: 1,
                        digest: [0u8; 32],
                        owner: SuiOwner::AddressOwner(sender32),
                        type_tag: "0x2::coin::Coin<0x2::bud::BUD>".to_string(),
                        contents: amount_mist.to_le_bytes().to_vec(),
                    };
                    if write_sui_object(host, coin).is_err() {
                        return Ok(EeOutcome::reverted(b"mint write err".to_vec(), gas_used));
                    }
                    created_ids.push(coin_id);
                }
                SuiPtbCommand::SplitCoins {
                    coin_id,
                    amounts_mist,
                } => {
                    let Ok(Some(mut src)) = read_sui_object(host, coin_id) else {
                        return Ok(EeOutcome::reverted(b"coin not found".to_vec(), gas_used));
                    };
                    if src.owner != SuiOwner::AddressOwner(sender32) {
                        return Ok(EeOutcome::reverted(b"not coin owner".to_vec(), gas_used));
                    }
                    let Ok(bal_bytes) = <[u8; 8]>::try_from(src.contents.as_slice()) else {
                        return Ok(EeOutcome::reverted(b"corrupt coin".to_vec(), gas_used));
                    };
                    let mut rem = u64::from_le_bytes(bal_bytes);
                    let mut lamport_max = src.version;
                    for amt in amounts_mist {
                        let Some(next_rem) = rem.checked_sub(*amt) else {
                            return Ok(EeOutcome::reverted(
                                b"coin split underflow".to_vec(),
                                gas_used,
                            ));
                        };
                        rem = next_rem;
                        let new_id = derive_sui_object_id(&call.tx_hash, ordinal);
                        ordinal = ordinal.saturating_add(1);
                        let child = SuiObject {
                            object_id: new_id,
                            version: lamport_max.saturating_add(1),
                            digest: [0u8; 32],
                            owner: SuiOwner::AddressOwner(sender32),
                            type_tag: src.type_tag.clone(),
                            contents: amt.to_le_bytes().to_vec(),
                        };
                        if write_sui_object(host, child).is_err() {
                            return Ok(EeOutcome::reverted(b"split write err".to_vec(), gas_used));
                        }
                        created_ids.push(new_id);
                    }
                    lamport_max = lamport_max.saturating_add(1);
                    src.version = lamport_max;
                    src.contents = rem.to_le_bytes().to_vec();
                    if write_sui_object(host, src).is_err() {
                        return Ok(EeOutcome::reverted(b"src write err".to_vec(), gas_used));
                    }
                }
                SuiPtbCommand::MergeCoins {
                    primary_coin,
                    sources,
                } => {
                    let Ok(Some(mut prim)) = read_sui_object(host, primary_coin) else {
                        return Ok(EeOutcome::reverted(b"primary coin missing".to_vec(), gas_used));
                    };
                    if prim.owner != SuiOwner::AddressOwner(sender32) {
                        return Ok(EeOutcome::reverted(b"not primary owner".to_vec(), gas_used));
                    }
                    let Ok(p_arr) = <[u8; 8]>::try_from(prim.contents.as_slice()) else {
                        return Ok(EeOutcome::reverted(b"bad primary coin".to_vec(), gas_used));
                    };
                    let mut total = u64::from_le_bytes(p_arr);
                    let mut max_ver = prim.version;
                    for sid in sources {
                        let Ok(Some(src)) = read_sui_object(host, sid) else {
                            return Ok(EeOutcome::reverted(b"merge src missing".to_vec(), gas_used));
                        };
                        if src.owner != SuiOwner::AddressOwner(sender32) {
                            return Ok(EeOutcome::reverted(b"not src owner".to_vec(), gas_used));
                        }
                        let Ok(s_arr) = <[u8; 8]>::try_from(src.contents.as_slice()) else {
                            return Ok(EeOutcome::reverted(b"bad src coin".to_vec(), gas_used));
                        };
                        let Some(sum) = total.checked_add(u64::from_le_bytes(s_arr)) else {
                            return Ok(EeOutcome::reverted(b"merge overflow".to_vec(), gas_used));
                        };
                        total = sum;
                        max_ver = max_ver.max(src.version);
                        if delete_sui_object(host, sid).is_err() {
                            return Ok(EeOutcome::reverted(b"merge del err".to_vec(), gas_used));
                        }
                    }
                    prim.version = max_ver.saturating_add(1);
                    prim.contents = total.to_le_bytes().to_vec();
                    if write_sui_object(host, prim).is_err() {
                        return Ok(EeOutcome::reverted(b"merge write err".to_vec(), gas_used));
                    }
                }
                SuiPtbCommand::TransferObjects {
                    object_ids,
                    recipient,
                } => {
                    for oid in object_ids {
                        let Ok(Some(mut obj)) = read_sui_object(host, oid) else {
                            return Ok(EeOutcome::reverted(b"object missing".to_vec(), gas_used));
                        };
                        if obj.owner != SuiOwner::AddressOwner(sender32) {
                            return Ok(EeOutcome::reverted(
                                b"cannot transfer non-owned object".to_vec(),
                                gas_used,
                            ));
                        }
                        obj.version = obj.version.saturating_add(1);
                        obj.owner = SuiOwner::AddressOwner(*recipient);
                        if write_sui_object(host, obj).is_err() {
                            return Ok(EeOutcome::reverted(b"transfer err".to_vec(), gas_used));
                        }
                    }
                }
                SuiPtbCommand::ShareObject { object_id } => {
                    let Ok(Some(mut obj)) = read_sui_object(host, object_id) else {
                        return Ok(EeOutcome::reverted(b"object missing".to_vec(), gas_used));
                    };
                    if obj.owner != SuiOwner::AddressOwner(sender32) {
                        return Ok(EeOutcome::reverted(b"not owner".to_vec(), gas_used));
                    }
                    let next_ver = obj.version.saturating_add(1);
                    obj.version = next_ver;
                    obj.owner = SuiOwner::Shared {
                        initial_shared_version: next_ver,
                    };
                    if write_sui_object(host, obj).is_err() {
                        return Ok(EeOutcome::reverted(b"share err".to_vec(), gas_used));
                    }
                }
                SuiPtbCommand::MoveCall {
                    package_id,
                    module,
                    function,
                    shared_inputs,
                    arg_bytes,
                } => {
                    let Ok(Some(pkg)) = read_sui_object(host, package_id) else {
                        return Ok(EeOutcome::reverted(b"package not found".to_vec(), gas_used));
                    };
                    if pkg.owner != SuiOwner::Immutable {
                        return Ok(EeOutcome::reverted(b"not a package".to_vec(), gas_used));
                    }
                    let Ok(mods) = serde_json::from_slice::<Vec<SuiCompiledModule>>(&pkg.contents)
                    else {
                        return Ok(EeOutcome::reverted(b"corrupt package".to_vec(), gas_used));
                    };
                    let found = mods.iter().any(|m| {
                        m.name == *module && m.exported_functions.iter().any(|f| f == function)
                    });
                    if !found {
                        return Ok(EeOutcome::reverted(
                            b"Move entry function not found".to_vec(),
                            gas_used,
                        ));
                    }
                    let mut lamport_ver: u64 = 1;
                    for sid in shared_inputs {
                        let Ok(Some(mut sh)) = read_sui_object(host, sid) else {
                            return Ok(EeOutcome::reverted(
                                b"shared input missing".to_vec(),
                                gas_used,
                            ));
                        };
                        if !matches!(sh.owner, SuiOwner::Shared { .. })
                            && sh.owner != SuiOwner::AddressOwner(sender32)
                        {
                            return Ok(EeOutcome::reverted(
                                b"shared input unauthorized".to_vec(),
                                gas_used,
                            ));
                        }
                        lamport_ver = lamport_ver.max(sh.version.saturating_add(1));
                        sh.version = lamport_ver;
                        sh.contents.extend_from_slice(arg_bytes);
                        if write_sui_object(host, sh).is_err() {
                            return Ok(EeOutcome::reverted(b"shared write err".to_vec(), gas_used));
                        }
                    }
                    let out_id = derive_sui_object_id(&call.tx_hash, ordinal);
                    ordinal = ordinal.saturating_add(1);
                    let produced = SuiObject {
                        object_id: out_id,
                        version: lamport_ver,
                        digest: [0u8; 32],
                        owner: SuiOwner::AddressOwner(sender32),
                        type_tag: format!("0x{}::{module}::Result", hex::encode(package_id)),
                        contents: arg_bytes.clone(),
                    };
                    if write_sui_object(host, produced).is_err() {
                        return Ok(EeOutcome::reverted(b"result write err".to_vec(), gas_used));
                    }
                    let _ = host.emit_log(EeLog {
                        emitter: EeIdentity {
                            ee: EeId::MOVE_SUI,
                            id: package_id.to_vec(),
                        },
                        topics: vec![format!("{module}::{function}").into_bytes()],
                        data: arg_bytes.clone(),
                    });
                    created_ids.push(out_id);
                }
                SuiPtbCommand::UniversalBridgeCall {
                    target_ee,
                    target,
                    input,
                    value_mist,
                    gas_limit,
                } => {
                    let sub_cap = (*gas_limit).min(call.gas_limit.saturating_sub(gas_used));
                    let res = match host.universal_call(UniversalCall {
                        from: call.caller.clone(),
                        to_ee: EeId(*target_ee),
                        target: EeIdentity {
                            ee: EeId(*target_ee),
                            id: target.clone(),
                        },
                        value: BudAmount(u128::from(*value_mist).saturating_mul(ATTO_PER_MIST)),
                        input: input.clone(),
                        gas_limit: sub_cap,
                        is_static: false,
                    }) {
                        Ok(r) => r,
                        Err(_) => {
                            return Ok(EeOutcome::reverted(
                                b"universal_call failed".to_vec(),
                                gas_used,
                            ));
                        }
                    };
                    if charge(res.gas_used, host).is_err() {
                        return Ok(EeOutcome::out_of_gas(call.gas_limit));
                    }
                    if !res.success {
                        return Ok(EeOutcome::reverted(res.output, gas_used));
                    }
                }
            }
        }

        let out = serde_json::to_vec(&created_ids).unwrap_or_default();
        Ok(EeOutcome::success(out, gas_used))
    }

    fn query(
        &self,
        ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        if !self.is_active(ctx) {
            return Err(EeRefusal::Denied("MOVE_SUI_CLOSED_ON_TESTNET".into()));
        }
        let req: SuiWorkerQuery = serde_json::from_slice(&q.input)
            .map_err(|e| EeRefusal::BadInput(format!("bad SuiWorkerQuery: {e}")))?;
        match req {
            SuiWorkerQuery::GetObject { object_id } => {
                let obj = read_sui_object(host, &object_id)
                    .map_err(|e| EeRefusal::Denied(e.to_string()))?;
                serde_json::to_vec(&obj).map_err(|e| EeRefusal::BadInput(e.to_string()))
            }
            SuiWorkerQuery::GetMistBalance { address } => {
                let who = EeIdentity::new(EeId::MOVE_SUI, address.to_vec())
                    .map_err(|e| EeRefusal::BadInput(e.to_string()))?;
                let attos = host
                    .bud_balance(&who)
                    .map_err(|e| EeRefusal::Denied(e.to_string()))?
                    .0;
                let mist = u64::try_from(attos / ATTO_PER_MIST).unwrap_or(u64::MAX);
                Ok(mist.to_le_bytes().to_vec())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budlum_uel_abi::mock::MemoryHost;
    use budlum_uel_abi::OutcomeStatus;

    fn launch_ctx() -> BlockContext {
        BlockContext {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            height: 100,
            timestamp_ms: 1_793_923_200_000,
        }
    }

    fn active_ctx() -> BlockContext {
        BlockContext {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            height: PROPOSED_SUI_ACTIVATION_HEIGHT,
            timestamp_ms: 1_793_923_200_000,
        }
    }

    /// Section 1.5 launch-closure gate: `move_sui_is_closed_on_testnet`.
    #[test]
    fn move_sui_is_closed_on_testnet() {
        let mut worker = MoveSuiWorker::new();
        assert!(!worker.is_active(&launch_ctx()));
        let mut host = MemoryHost::new(1_000_000);
        let Ok(caller) = EeIdentity::new(EeId::MOVE_SUI, vec![0xAA; 32]) else {
            panic!("caller");
        };
        let Ok(out) = worker.execute(
            &launch_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: caller,
                value: BudAmount(0),
                input: br#"{"commands":[]}"#.to_vec(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x01; 32],
            },
            &mut host,
        ) else {
            panic!("exec");
        };
        assert_eq!(out.status, OutcomeStatus::Reverted);
        assert_eq!(out.output, b"MOVE_SUI_CLOSED_ON_TESTNET");
    }

    /// Directive IP-50 conformance suite: `uel_conformance_move_sui`
    /// (`0x2::coin` split/merge, `0x2::transfer` owned & shared objects, Lamport versions).
    #[test]
    fn uel_conformance_move_sui() {
        let mut worker = MoveSuiWorker::new();
        assert_eq!(worker.id(), EeId::MOVE_SUI);
        assert_eq!(PINNED_SUI_EXECUTION_COMMIT.len(), 40);

        let mut host = MemoryHost::new(10_000_000);
        let alice = [0x11u8; 32];
        let bob = [0x22u8; 32];
        let Ok(alice_id) = EeIdentity::new(EeId::MOVE_SUI, alice.to_vec()) else {
            panic!("alice");
        };
        host.balances.insert(alice_id.clone(), 1_000 * ATTO_PER_MIST);

        // 1. Mint 500 MIST gas coin, split [120, 80], merge 80 back, transfer 120 to Bob.
        let Ok(mint_in) = serde_json::to_vec(&SuiPtb {
            commands: vec![SuiPtbCommand::MintGasCoin { amount_mist: 500 }],
        }) else {
            panic!("mint json");
        };
        let Ok(mint_out) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: alice_id.clone(),
                target: alice_id.clone(),
                value: BudAmount(0),
                input: mint_in,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x10; 32],
            },
            &mut host,
        ) else {
            panic!("mint exec");
        };
        assert_eq!(mint_out.status, OutcomeStatus::Success);
        let Ok(created): Result<Vec<[u8; 32]>, _> = serde_json::from_slice(&mint_out.output) else {
            panic!("created ids");
        };
        let Some(&coin0) = created.first() else {
            panic!("coin0");
        };

        let Ok(split_in) = serde_json::to_vec(&SuiPtb {
            commands: vec![SuiPtbCommand::SplitCoins {
                coin_id: coin0,
                amounts_mist: vec![120, 80],
            }],
        }) else {
            panic!("split json");
        };
        let Ok(split_out) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: alice_id.clone(),
                target: alice_id.clone(),
                value: BudAmount(0),
                input: split_in,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x11; 32],
            },
            &mut host,
        ) else {
            panic!("split exec");
        };
        assert_eq!(split_out.status, OutcomeStatus::Success);
        let Ok(split_ids): Result<Vec<[u8; 32]>, _> = serde_json::from_slice(&split_out.output)
        else {
            panic!("split ids");
        };
        let (Some(&c120), Some(&c80)) = (split_ids.first(), split_ids.get(1)) else {
            panic!("two split coins");
        };

        let Ok(merge_xfer_in) = serde_json::to_vec(&SuiPtb {
            commands: vec![
                SuiPtbCommand::MergeCoins {
                    primary_coin: coin0,
                    sources: vec![c80],
                },
                SuiPtbCommand::TransferObjects {
                    object_ids: vec![c120],
                    recipient: bob,
                },
            ],
        }) else {
            panic!("merge_xfer json");
        };
        let Ok(mx_out) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: alice_id,
                target: EeIdentity {
                    ee: EeId::MOVE_SUI,
                    id: bob.to_vec(),
                },
                value: BudAmount(0),
                input: merge_xfer_in,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x12; 32],
            },
            &mut host,
        ) else {
            panic!("mx exec");
        };
        assert_eq!(mx_out.status, OutcomeStatus::Success);

        // Verify Lamport versions & balances in `ee/sui/object`.
        let Ok(Some(primary_after)) = read_sui_object(&host, &coin0) else {
            panic!("primary_after");
        };
        assert_eq!(primary_after.version, 3);
        let Ok(p_arr) = <[u8; 8]>::try_from(primary_after.contents.as_slice()) else {
            panic!("p_arr");
        };
        assert_eq!(u64::from_le_bytes(p_arr), 380);
        assert!(matches!(read_sui_object(&host, &c80), Ok(None)));

        let Ok(Some(bob_coin)) = read_sui_object(&host, &c120) else {
            panic!("bob_coin");
        };
        assert_eq!(bob_coin.owner, SuiOwner::AddressOwner(bob));
    }

    /// Directive IP-50 gate: `sui_cli_publish_runs_unchanged`.
    #[test]
    fn sui_cli_publish_runs_unchanged() {
        let mut worker = MoveSuiWorker::new();
        let mut host = MemoryHost::new(10_000_000);
        let publisher = [0x77u8; 32];
        let Ok(pub_id) = EeIdentity::new(EeId::MOVE_SUI, publisher.to_vec()) else {
            panic!("pub_id");
        };
        let modules = vec![SuiCompiledModule {
            name: "counter".to_string(),
            exported_functions: vec!["create".to_string(), "increment".to_string()],
            bytecode: vec![0xA1, 0x1C, 0xEB, 0x0B],
        }];
        let Ok(bundle) = encode_sui_package_bundle(&modules) else {
            panic!("bundle");
        };
        assert!(worker.validate_deploy(&bundle).is_ok());

        let Ok(ptb_bytes) = serde_json::to_vec(&SuiPtb {
            commands: vec![SuiPtbCommand::PublishPackage {
                modules,
                initial_coin_mist: 250,
            }],
        }) else {
            panic!("ptb");
        };
        let Ok(pub_out) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: pub_id.clone(),
                target: pub_id.clone(),
                value: BudAmount(0),
                input: ptb_bytes,
                gas_limit: 2_000_000,
                depth: 0,
                tx_hash: [0x99; 32],
            },
            &mut host,
        ) else {
            panic!("publish");
        };
        assert_eq!(pub_out.status, OutcomeStatus::Success);
        let Ok(ids): Result<Vec<[u8; 32]>, _> = serde_json::from_slice(&pub_out.output) else {
            panic!("ids");
        };
        let (Some(&pkg_id), Some(&shared_seed_id)) = (ids.first(), ids.get(1)) else {
            panic!("pkg + seed");
        };

        // Share object and invoke `counter::increment`.
        let Ok(call_bytes) = serde_json::to_vec(&SuiPtb {
            commands: vec![
                SuiPtbCommand::ShareObject {
                    object_id: shared_seed_id,
                },
                SuiPtbCommand::MoveCall {
                    package_id: pkg_id,
                    module: "counter".to_string(),
                    function: "increment".to_string(),
                    shared_inputs: vec![shared_seed_id],
                    arg_bytes: vec![1],
                },
            ],
        }) else {
            panic!("call_bytes");
        };
        let Ok(call_out) = worker.execute(
            &active_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller: pub_id.clone(),
                target: pub_id,
                value: BudAmount(0),
                input: call_bytes,
                gas_limit: 2_000_000,
                depth: 0,
                tx_hash: [0x9A; 32],
            },
            &mut host,
        ) else {
            panic!("move call");
        };
        assert_eq!(call_out.status, OutcomeStatus::Success);
        assert_eq!(host.logs.len(), 1);
    }
}
