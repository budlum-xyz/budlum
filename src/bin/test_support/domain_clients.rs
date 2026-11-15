//! Fixtures for exercising the domain client signing boundary over HTTP.
//!
//! Convenience: shared `#[cfg(test)]` fixture included by `budlum-domain-producer`
//! and `budlum-domain-reporter` binary test suites.

use budlum_core::core::transaction::Transaction;
use budlum_core::domain::{
    hash_finality_proof, ConsensusKind, DomainCommitment, FinalityProof, VerifiedDomainCommitment,
};
use jsonrpsee::{server::ServerHandle, RpcModule};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct Files {
    _dir: tempfile::TempDir,
    pub payload: PathBuf,
    pub key: PathBuf,
    pub password: PathBuf,
}

impl Files {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let payload_path = dir.path().join("payload.json");
        let key_path = dir.path().join("wallet.json");
        let password_path = dir.path().join("password.txt");
        let proof = FinalityProof::PoWHeaderChain { headers: vec![] };
        let payload = VerifiedDomainCommitment {
            commitment: DomainCommitment {
                domain_id: 1,
                domain_height: 1,
                domain_block_hash: [1; 32],
                parent_domain_block_hash: [2; 32],
                state_root: [3; 32],
                tx_root: [4; 32],
                event_root: [5; 32],
                finality_proof_hash: hash_finality_proof(&proof).unwrap(),
                consensus_kind: ConsensusKind::PoW,
                validator_set_hash: [7; 32],
                timestamp_ms: 123,
                sequence: 0,
                producer: None,
                state_updates: Default::default(),
            },
            proof,
        };
        std::fs::write(&payload_path, serde_json::to_vec(&payload).unwrap()).unwrap();
        // A single iteration is for this ephemeral test key only.
        let wallet = budlum_core::wallet::KeyFile::seal(&[9; 32], "test-password", 1).unwrap();
        std::fs::write(&key_path, serde_json::to_vec(&wallet).unwrap()).unwrap();
        std::fs::write(&password_path, "test-password\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&password_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        Self {
            _dir: dir,
            payload: payload_path,
            key: key_path,
            password: password_path,
        }
    }
}

#[derive(Default)]
pub struct Calls {
    pub methods: Mutex<Vec<&'static str>>,
    pub transactions: Mutex<Vec<Transaction>>,
}

pub async fn rpc(chain_id: u64) -> (String, Arc<Calls>, ServerHandle) {
    let server = jsonrpsee::server::ServerBuilder::default()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let url = format!("http://{}", server.local_addr().unwrap());
    let calls = Arc::new(Calls::default());
    let mut module = RpcModule::new(calls.clone());
    module
        .register_method("bud_chainId", move |_, state, _| {
            state.methods.lock().unwrap().push("bud_chainId");
            format!("0x{chain_id:x}")
        })
        .unwrap();
    module
        .register_method("bud_getNonce", |_, state, _| {
            state.methods.lock().unwrap().push("bud_getNonce");
            "0x0"
        })
        .unwrap();
    module
        .register_method("bud_sendRawTransaction", |params, state, _| {
            state.methods.lock().unwrap().push("bud_sendRawTransaction");
            let tx: Transaction = params.one().unwrap();
            state.transactions.lock().unwrap().push(tx);
            "0xaccepted"
        })
        .unwrap();
    (url, calls, server.start(module))
}
