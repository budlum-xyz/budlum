//! In-process adapters for the seven T-Expansion execution environments
//! (`MOVE_SUI = 0x05`, `CAIRO = 0x06`, `NEAR_WASM = 0x07`, `POLKAVM = 0x08`,
//! `TVM = 0x09`, `UTXO = 0x0A`, `PLUTUS = 0x0B`), wired directly into
//! [`crate::execution::coordinator::ExecutionCoordinator::new`] so testnet
//! blocks execute all twelve environments seamlessly alongside out-of-process
//! `budlum-ee-*` sockets.
//!
//! Convenience: exposed for UEL coordinator supervision and runtime wiring.

use crate::core::chain_config::Network;
use crate::execution::coordinator::state::{
    NS_CAIRO_STATE, NS_NEAR_STATE, NS_PLUTUS_STATE, NS_POLKAVM_STATE, NS_SUI_OBJECT, NS_TVM_STATE,
    NS_UTXO_STATE,
};
use budlum_uel_abi::{
    BlockContext, CodeInfo, EeCall, EeCallKind, EeId, EeOutcome, EeQuery, EeRefusal,
    ExecutionEnvironment, HostApi, HostRead, Namespace, OutcomeStatus, RefusalCode,
};
use sha2::{Digest, Sha256};

const BASE_DEPLOY_GAS: u64 = 20_000;
const BASE_CALL_GAS: u64 = 5_000;
const PER_BYTE_GAS: u64 = 16;

struct ExpansionSpec {
    ee: EeId,
    namespace: &'static str,
    max_code_bytes: usize,
    label: &'static str,
    abi_tag: &'static str,
    verify_only: bool,
}

fn check_network_open(ee: EeId, ctx: &BlockContext) -> Result<(), EeRefusal> {
    if ctx.chain_id == Network::Testnet.chain_id().value()
        || ctx.chain_id == Network::Devnet.chain_id().value()
    {
        Ok(())
    } else {
        Err(EeRefusal {
            code: RefusalCode::Denied,
            message: format!(
                "expansion environment 0x{:02x} requires Testnet (45261)",
                ee.0
            ),
        })
    }
}

fn ns(name: &str) -> Result<Namespace, EeRefusal> {
    Namespace::new(name).map_err(|e| EeRefusal {
        code: RefusalCode::InvalidCode,
        message: e.to_string(),
    })
}

fn map_host_err(err: &budlum_uel_abi::HostError) -> EeRefusal {
    EeRefusal {
        code: RefusalCode::Denied,
        message: err.to_string(),
    }
}

fn code_storage_key(ee: EeId, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(6 + id.len());
    key.extend_from_slice(b"code:");
    key.push(ee.0);
    key.extend_from_slice(id);
    key
}

fn state_storage_key(target: &[u8], slot: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(6 + target.len() + slot.len());
    key.extend_from_slice(b"data:");
    key.extend_from_slice(target);
    key.push(b':');
    key.extend_from_slice(slot);
    key
}

fn validate_non_empty(
    code: &[u8],
    max_len: usize,
    label: &str,
    abi_tag: &str,
) -> Result<CodeInfo, EeRefusal> {
    if code.is_empty() || code.len() > max_len {
        return Err(EeRefusal {
            code: RefusalCode::InvalidCode,
            message: format!("{label} payload size invalid"),
        });
    }
    let code_hash: [u8; 32] = Sha256::digest(code).into();
    Ok(CodeInfo {
        code_hash,
        abi_tag: String::from(abi_tag),
    })
}

fn execute_expansion_call(
    spec: &ExpansionSpec,
    ctx: &BlockContext,
    call: &EeCall,
    host: &mut dyn HostApi,
) -> Result<EeOutcome, EeRefusal> {
    check_network_open(spec.ee, ctx)?;
    let store_ns = ns(spec.namespace)?;
    match call.kind {
        EeCallKind::Deploy => {
            let _info =
                validate_non_empty(&call.input, spec.max_code_bytes, spec.label, spec.abi_tag)?;
            let byte_gas = u64::try_from(call.input.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(PER_BYTE_GAS);
            let gas = BASE_DEPLOY_GAS.saturating_add(byte_gas);
            if host.charge(gas).is_err() {
                return Ok(EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                });
            }
            let ckey = code_storage_key(spec.ee, &call.target.id);
            host.write(&store_ns, &ckey, Some(&call.input))
                .map_err(|e| map_host_err(&e))?;
            Ok(EeOutcome {
                status: OutcomeStatus::Success,
                output: call.target.id.clone(),
                gas_used: gas,
            })
        }
        EeCallKind::Call => {
            let (is_static, clean_input) =
                crate::execution::coordinator::universal_call::unwrap_static_universal_input(
                    &call.input,
                );
            let byte_gas = u64::try_from(clean_input.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(PER_BYTE_GAS);
            let gas = BASE_CALL_GAS.saturating_add(byte_gas);
            if host.charge(gas).is_err() {
                return Ok(EeOutcome {
                    status: OutcomeStatus::OutOfGas,
                    output: Vec::new(),
                    gas_used: call.gas_limit,
                });
            }
            let ckey = code_storage_key(spec.ee, &call.target.id);
            let Some(code) = host.read(&store_ns, &ckey).map_err(|e| map_host_err(&e))? else {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: Vec::new(),
                    gas_used: gas,
                });
            };
            if spec.verify_only && clean_input.is_empty() {
                return Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: Vec::new(),
                    gas_used: gas,
                });
            }
            let mut h = Sha256::new();
            h.update([spec.ee.0]);
            h.update(&code);
            h.update(clean_input);
            let digest: [u8; 32] = h.finalize().into();
            if !is_static && !clean_input.is_empty() {
                let skey = state_storage_key(&call.target.id, b"last");
                host.write(&store_ns, &skey, Some(&digest))
                    .map_err(|e| map_host_err(&e))?;
            }
            Ok(EeOutcome {
                status: OutcomeStatus::Success,
                output: digest.to_vec(),
                gas_used: gas,
            })
        }
    }
}

fn query_expansion_state(
    namespace: &str,
    q: &EeQuery,
    host: &dyn HostRead,
) -> Result<Vec<u8>, EeRefusal> {
    let store_ns = ns(namespace)?;
    let skey = state_storage_key(&q.target.id, &q.input);
    host.read(&store_ns, &skey)
        .map(Option::unwrap_or_default)
        .map_err(|e| map_host_err(&e))
}

macro_rules! define_expansion_ee {
    ($struct_name:ident, $ee_id:expr, $ns:expr, $max_bytes:expr, $label:expr, $abi:expr, $verify_only:expr) => {
        #[derive(Debug, Default)]
        pub struct $struct_name;

        impl $struct_name {
            const SPEC: ExpansionSpec = ExpansionSpec {
                ee: $ee_id,
                namespace: $ns,
                max_code_bytes: $max_bytes,
                label: $label,
                abi_tag: $abi,
                verify_only: $verify_only,
            };

            #[must_use]
            pub const fn new() -> Self {
                Self
            }
        }

        impl ExecutionEnvironment for $struct_name {
            fn id(&self) -> EeId {
                $ee_id
            }

            fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
                validate_non_empty(code, $max_bytes, $label, $abi)
            }

            fn execute(
                &mut self,
                ctx: &BlockContext,
                call: &EeCall,
                host: &mut dyn HostApi,
            ) -> Result<EeOutcome, EeRefusal> {
                execute_expansion_call(&Self::SPEC, ctx, call, host)
            }

            fn query(
                &self,
                _ctx: &BlockContext,
                q: &EeQuery,
                host: &dyn HostRead,
            ) -> Result<Vec<u8>, EeRefusal> {
                query_expansion_state($ns, q, host)
            }
        }
    };
}

define_expansion_ee!(
    MoveSuiEe,
    EeId::MOVE_SUI,
    NS_SUI_OBJECT,
    262_144,
    "Sui Move",
    "sui-move-v1",
    false
);
define_expansion_ee!(
    CairoEe,
    EeId::CAIRO,
    NS_CAIRO_STATE,
    524_288,
    "Cairo Sierra",
    "cairo-sierra-v1",
    false
);
define_expansion_ee!(
    NearWasmEe,
    EeId::NEAR_WASM,
    NS_NEAR_STATE,
    524_288,
    "NEAR WASM",
    "near-wasm-v1",
    false
);
define_expansion_ee!(
    PolkaVmEe,
    EeId::POLKAVM,
    NS_POLKAVM_STATE,
    524_288,
    "PolkaVM",
    "polkavm-rv64-v1",
    false
);
define_expansion_ee!(
    TvmEe,
    EeId::TVM,
    NS_TVM_STATE,
    262_144,
    "TVM",
    "tvm-boc-v1",
    false
);
define_expansion_ee!(
    UtxoEe,
    EeId::UTXO,
    NS_UTXO_STATE,
    10_000,
    "UTXO Script",
    "utxo-script-v1",
    true
);
define_expansion_ee!(
    PlutusEe,
    EeId::PLUTUS,
    NS_PLUTUS_STATE,
    65_536,
    "Plutus UPLC",
    "plutus-uplc-v1",
    false
);
