//! Build and submit a signed domain-commitment transaction.
//!
//! A domain producer supplies a `VerifiedDomainCommitment` produced by the
//! domain adapter, signs the settlement transaction with a V5 wallet key, and
//! sends it through the public transaction RPC. The node verifies the finality
//! proof again in the block; this tool never writes consensus state locally.
//!
//! The payload file is JSON so an adapter can be implemented in another
//! process without linking node internals. For a `PoW` domain the tool can
//! build the payload itself: `--pow-spec` takes the domain, the parent and
//! the block contents, mines the header chain and binds the commitment to it
//! (`domain::producer`). For a BFT domain `--bft-spec` signs the checkpoint
//! with the validators' BLS keys (and their ML-DSA-65 keys for the QC half),
//! and for a `PoA` domain `--poa-spec` signs with the authorities' composite
//! keys; the keys come from a separate mode-0600 file (`--quorum-keys`).
//! `--write-payload` stores the result without submitting it. The signer is a V5 wallet key
//! file sealed with a password (`bud wallet create`); neither the key nor the
//! password is ever taken on the command line.

use budlum_core::core::address::Address;
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::settlement::domains::SettlementTx;
use budlum_core::wallet::bind_signing_chain_id;
use clap::Parser;
use serde_json::Value;
use std::path::PathBuf;

#[cfg(test)]
#[path = "test_support/domain_clients.rs"]
mod domain_client_test_support;

#[derive(Debug, Parser)]
#[command(
    name = "budlum-domain-producer",
    about = "Submit a verified domain commitment"
)]
struct Cli {
    /// Public node JSON-RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,
    /// JSON file containing a `VerifiedDomainCommitment`.
    #[arg(
        long,
        required_unless_present_any = [
            "pow_spec",
            "bitcoin_spec",
            "bft_spec",
            "poa_spec",
            "dag_spec",
            "poh_spec",
            "pospace_spec"
        ],
        conflicts_with_all = [
            "pow_spec",
            "bitcoin_spec",
            "bft_spec",
            "poa_spec",
            "dag_spec",
            "poh_spec",
            "pospace_spec"
        ]
    )]
    payload: Option<PathBuf>,
    /// JSON `PowChainSpec`: mine the header chain and build the payload.
    #[arg(
        long,
        conflicts_with_all = ["bitcoin_spec", "bft_spec", "poa_spec", "dag_spec", "poh_spec", "pospace_spec"]
    )]
    pow_spec: Option<PathBuf>,
    /// JSON `BitcoinSpvChainSpec`: mine the Bitcoin header window and build the payload.
    #[arg(
        long,
        conflicts_with_all = ["bft_spec", "poa_spec", "dag_spec", "poh_spec", "pospace_spec"]
    )]
    bitcoin_spec: Option<PathBuf>,
    /// JSON `BftJob`: sign the checkpoint with the BFT validators' keys.
    #[arg(
        long,
        requires = "quorum_keys",
        conflicts_with_all = ["poa_spec", "dag_spec", "poh_spec", "pospace_spec"]
    )]
    bft_spec: Option<PathBuf>,
    /// JSON `PoaJob`: sign the block with the `PoA` authorities' keys.
    #[arg(
        long,
        requires = "quorum_keys",
        conflicts_with_all = ["dag_spec", "poh_spec", "pospace_spec"]
    )]
    poa_spec: Option<PathBuf>,
    /// JSON `DagJob`: derive the causal anchor and sign with DAG authorities' composite keys.
    #[arg(
        long,
        requires = "quorum_keys",
        conflicts_with_all = ["poh_spec", "pospace_spec"]
    )]
    dag_spec: Option<PathBuf>,
    /// JSON `PohJob`: compute the sequential PoH hash ladder and sign with authorities' composite keys.
    #[arg(long, requires = "quorum_keys", conflicts_with = "pospace_spec")]
    poh_spec: Option<PathBuf>,
    /// JSON `PospaceJob`: prove plot quality and sign with prover and authorities' composite keys.
    #[arg(long, requires = "quorum_keys")]
    pospace_spec: Option<PathBuf>,
    /// A mode-0600 JSON file with the signing seeds (`QuorumKeys`).
    #[arg(long)]
    quorum_keys: Option<PathBuf>,
    /// Write the payload to this file and exit without submitting it.
    #[arg(long)]
    write_payload: Option<PathBuf>,
    /// The V5 wallet key file (`bud wallet create`), sealed with a password.
    #[arg(long, required_unless_present = "write_payload")]
    key_file: Option<PathBuf>,
    /// A mode-0600 file holding the wallet password; else
    /// `BUD_WALLET_PASSWORD`.
    #[arg(long)]
    password_file: Option<PathBuf>,
    /// The Budlum chain this invocation signs for: `45260` mainnet, `45261`
    /// testnet, `45262` devnet.
    ///
    /// Required for submission and never defaulted. The RPC node's answer is
    /// checked against this operator-named replay domain before signing.
    #[arg(long, required_unless_present = "write_payload")]
    signing_chain_id: Option<u64>,
    /// Transaction fee in atoms.
    #[arg(long, default_value_t = 1_000)]
    fee: u64,
}

fn quantity(value: &Value, field: &str) -> Result<u64, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{field} did not return a quantity string"))?;
    text.strip_prefix("0x").map_or_else(
        || text.parse::<u64>().map_err(|e| format!("{field}: {e}")),
        |hex| u64::from_str_radix(hex, 16).map_err(|e| format!("{field}: {e}")),
    )
}

const MAX_RPC_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

async fn read_json_bounded(mut response: reqwest::Response, method: &str) -> Result<Value, String> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RPC_RESPONSE_BYTES as u64)
    {
        return Err(format!(
            "{method}: response exceeds {MAX_RPC_RESPONSE_BYTES}-byte limit"
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("{method}: failed reading response body: {e}"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RPC_RESPONSE_BYTES {
            return Err(format!(
                "{method}: response exceeds {MAX_RPC_RESPONSE_BYTES}-byte limit"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|e| format!("{method}: response was not JSON: {e}"))
}

async fn rpc_call(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let response = client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("{method}: request failed: {e}"))?;
    let answer = read_json_bounded(response, method).await?;
    if let Some(error) = answer.get("error") {
        return Err(format!("{method}: {error}"));
    }
    answer
        .get("result")
        .cloned()
        .ok_or_else(|| format!("{method}: response has no result"))
}

/// A BFT checkpoint to sign.
#[derive(Debug, serde::Deserialize)]
struct BftJob {
    block: budlum_core::domain::producer::QuorumBlockSpec,
    chain_id: u64,
    epoch: u64,
    round: u64,
    members: Vec<budlum_core::chain::finality::ValidatorEntry>,
    signers: Vec<usize>,
}

/// A `PoA` block to sign.
#[derive(Debug, serde::Deserialize)]
struct PoaJob {
    block: budlum_core::domain::producer::QuorumBlockSpec,
    authorities: Vec<budlum_core::domain::finality_adapter::PoAAuthorityKey>,
}

/// A DAG commitment job: causal round plus the composite authority set.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct DagJob {
    block: budlum_core::domain::producer::QuorumBlockSpec,
    round: u64,
    authorities: Vec<budlum_core::domain::finality_adapter::PoAAuthorityKey>,
}

/// A `PoH` commitment job: seed tick (used for heights 0/1), ladder tick count,
/// and the composite authority set.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PohJob {
    block: budlum_core::domain::producer::QuorumBlockSpec,
    #[serde(default)]
    seed_tick: budlum_core::domain::Hash32,
    tick_count: usize,
    authorities: Vec<budlum_core::domain::finality_adapter::PoAAuthorityKey>,
}

/// A `PoSpace` commitment job: index into `QuorumKeys::composite` identifying
/// the plot prover, optional deterministic challenge mining, and the composite
/// authority set.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PospaceJob {
    block: budlum_core::domain::producer::QuorumBlockSpec,
    #[serde(default)]
    prover_index: usize,
    #[serde(default)]
    mine_block_hash: bool,
    authorities: Vec<budlum_core::domain::finality_adapter::PoAAuthorityKey>,
}

/// The signing seeds, hex. For BFT, `bls_seeds` (64 bytes) and optional
/// `pq_seeds` (32 bytes) align with the job's members. For `PoA`, `composite`
/// holds one `[ml_dsa_65_seed, ed25519_seed]` pair (32 bytes each) per
/// signing authority.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct QuorumKeys {
    #[serde(default)]
    bls_seeds: Vec<String>,
    #[serde(default)]
    pq_seeds: Vec<String>,
    #[serde(default)]
    composite: Vec<[String; 2]>,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf, what: &str) -> Result<T, String> {
    serde_json::from_slice(
        &std::fs::read(path).map_err(|e| format!("cannot read {what} {}: {e}", path.display()))?,
    )
    .map_err(|e| format!("{} is not a {what}: {e}", path.display()))
}

fn seed<const N: usize>(text: &str, what: &str) -> Result<[u8; N], String> {
    hex::decode(text.strip_prefix("0x").unwrap_or(text))
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{what} is not {N} bytes of hex"))
}

fn read_keys(cli: &Cli) -> Result<QuorumKeys, String> {
    use std::io::Read;
    const MAX_QUORUM_KEYS_BYTES: u64 = 1_048_576;
    let path = cli
        .quorum_keys
        .as_ref()
        .ok_or_else(|| "--quorum-keys is required".to_string())?;
    let file = std::fs::File::open(path)
        .map_err(|e| format!("cannot open QuorumKeys {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file
            .metadata()
            .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} has mode {:03o}; use chmod 600",
                path.display(),
                mode & 0o777
            ));
        }
    }
    let mut raw = Vec::new();
    file.take(MAX_QUORUM_KEYS_BYTES.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|e| format!("cannot read QuorumKeys {}: {e}", path.display()))?;
    if raw.len() as u64 > MAX_QUORUM_KEYS_BYTES {
        return Err(format!(
            "QuorumKeys {} exceeds {MAX_QUORUM_KEYS_BYTES}-byte limit",
            path.display()
        ));
    }
    serde_json::from_slice(&raw).map_err(|e| format!("{} is not a QuorumKeys: {e}", path.display()))
}

fn bft_members(
    cli: &Cli,
    entries: Vec<budlum_core::chain::finality::ValidatorEntry>,
) -> Result<Vec<budlum_core::domain::producer::BftMember>, String> {
    let keys = read_keys(cli)?;
    if keys.bls_seeds.len() != entries.len() {
        return Err("one BLS seed per member is required".into());
    }
    let mut members = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        let bls = budlum_core::crypto::primitives::BlsKeypair::from_seed(&seed::<64>(
            &keys.bls_seeds[index],
            "a BLS seed",
        )?)
        .map_err(|e| format!("a BLS seed: {e}"))?;
        let pq = match keys.pq_seeds.get(index) {
            Some(text) => {
                let pq_seed = seed::<32>(text, "an ML-DSA-65 seed")?;
                let public = budlum_core::crypto::pq::ml_dsa_public_key(
                    budlum_core::crypto::scheme::SchemeId::ML_DSA_65,
                    &pq_seed,
                )
                .map_err(|e| e.to_string())?;
                Some(
                    budlum_core::crypto::primitives::PqKeyPair::from_bytes(&public, &pq_seed)
                        .map_err(|e| e.to_string())?,
                )
            }
            None => None,
        };
        members.push(budlum_core::domain::producer::BftMember { entry, bls, pq });
    }
    Ok(members)
}

fn build_bft(
    cli: &Cli,
    path: &PathBuf,
) -> Result<budlum_core::domain::VerifiedDomainCommitment, String> {
    let job: BftJob = read_json(path, "BftJob")?;
    let members = bft_members(cli, job.members)?;
    budlum_core::domain::producer::build_bft_commitment(
        &job.block,
        job.chain_id,
        job.epoch,
        job.round,
        &members,
        &job.signers,
    )
}

fn load_composite_signers(
    cli: &Cli,
) -> Result<Vec<budlum_core::crypto::composite::CompositeKeypair>, String> {
    let keys = read_keys(cli)?;
    let mut signers = Vec::with_capacity(keys.composite.len());
    for [pq_seed, ed_seed] in &keys.composite {
        signers.push(
            budlum_core::crypto::composite::CompositeKeypair::from_seeds(
                budlum_core::crypto::scheme::SuiteId::VALIDATOR,
                &seed::<32>(pq_seed, "an ML-DSA-65 seed")?,
                &seed::<32>(ed_seed, "an Ed25519 seed")?,
            )
            .map_err(|e| e.to_string())?,
        );
    }
    Ok(signers)
}

fn build_poa(
    cli: &Cli,
    path: &PathBuf,
) -> Result<budlum_core::domain::VerifiedDomainCommitment, String> {
    let job: PoaJob = read_json(path, "PoaJob")?;
    let signers = load_composite_signers(cli)?;
    budlum_core::domain::producer::build_poa_commitment(&job.block, &job.authorities, &signers)
}

fn build_dag(
    cli: &Cli,
    path: &PathBuf,
) -> Result<budlum_core::domain::VerifiedDomainCommitment, String> {
    let job: DagJob = read_json(path, "DagJob")?;
    let signers = load_composite_signers(cli)?;
    budlum_core::domain::producer::build_dag_commitment(
        &job.block,
        job.round,
        &job.authorities,
        &signers,
    )
}

fn build_poh(
    cli: &Cli,
    path: &PathBuf,
) -> Result<budlum_core::domain::VerifiedDomainCommitment, String> {
    let job: PohJob = read_json(path, "PohJob")?;
    let signers = load_composite_signers(cli)?;
    budlum_core::domain::producer::build_poh_commitment(
        &job.block,
        job.seed_tick,
        job.tick_count,
        &job.authorities,
        &signers,
    )
}

fn build_pospace(
    cli: &Cli,
    path: &PathBuf,
) -> Result<budlum_core::domain::VerifiedDomainCommitment, String> {
    let mut job: PospaceJob = read_json(path, "PospaceJob")?;
    let signers = load_composite_signers(cli)?;
    if job.mine_block_hash {
        let prover_kp = signers.get(job.prover_index).ok_or_else(|| {
            format!(
                "PoSpace prover_index {} is out of range for {} signers",
                job.prover_index,
                signers.len()
            )
        })?;
        let prover_pub = prover_kp.public_key().map_err(|e| e.to_string())?;
        let prover_addr = Address::from(prover_pub.ed);
        budlum_core::domain::producer::mine_pospace_block_hash(&mut job.block, &prover_addr)?;
    }
    budlum_core::domain::producer::build_pospace_commitment(
        &job.block,
        job.prover_index,
        &job.authorities,
        &signers,
    )
}

fn load_payload(cli: &Cli) -> Result<budlum_core::domain::VerifiedDomainCommitment, String> {
    if let Some(path) = &cli.bft_spec {
        return build_bft(cli, path);
    }
    if let Some(path) = &cli.poa_spec {
        return build_poa(cli, path);
    }
    if let Some(path) = &cli.dag_spec {
        return build_dag(cli, path);
    }
    if let Some(path) = &cli.poh_spec {
        return build_poh(cli, path);
    }
    if let Some(path) = &cli.pospace_spec {
        return build_pospace(cli, path);
    }
    if let Some(path) = &cli.pow_spec {
        let spec: budlum_core::domain::producer::PowChainSpec = serde_json::from_slice(
            &std::fs::read(path)
                .map_err(|e| format!("cannot read PoW spec {}: {e}", path.display()))?,
        )
        .map_err(|e| format!("{} is not a PowChainSpec: {e}", path.display()))?;
        return budlum_core::domain::producer::build_pow_commitment(&spec);
    }
    if let Some(path) = &cli.bitcoin_spec {
        let spec: budlum_core::domain::producer::BitcoinSpvChainSpec = serde_json::from_slice(
            &std::fs::read(path)
                .map_err(|e| format!("cannot read Bitcoin spec {}: {e}", path.display()))?,
        )
        .map_err(|e| format!("{} is not a BitcoinSpvChainSpec: {e}", path.display()))?;
        if spec
            .blocks
            .iter()
            .any(|block: &budlum_core::domain::producer::BitcoinBlockContent| block.bits == 0)
        {
            return Err(format!(
                "{} contains a BitcoinBlockContent with zero compact bits",
                path.display()
            ));
        }
        return budlum_core::domain::producer::build_bitcoin_spv_commitment(&spec);
    }
    let path = cli
        .payload
        .as_ref()
        .ok_or_else(|| "--payload, --pow-spec, or --bitcoin-spec is required".to_string())?;
    serde_json::from_slice(
        &std::fs::read(path).map_err(|e| format!("cannot read payload {}: {e}", path.display()))?,
    )
    .map_err(|e| format!("payload is not a VerifiedDomainCommitment: {e}"))
}

/// A client whose TLS stack is ready to use.
///
/// reqwest is built against `rustls-tls-webpki-roots-no-provider`, so
/// `Client::new()` panics unless a process-wide provider is installed first.
/// The install is idempotent and keeps an existing default, and doing it here
/// rather than only in `main` covers every entry point - including a test that
/// calls `run` directly, which is the path a `main`-only install leaves open.
fn http_client() -> Result<reqwest::Client, String> {
    budlum_core::crypto::tls::install_default_provider();
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("HTTP client: {e}"))
}

async fn run(cli: Cli) -> Result<(), String> {
    let payload = load_payload(&cli)?;
    if let Some(path) = &cli.write_payload {
        let text = serde_json::to_string_pretty(&payload)
            .map_err(|e| format!("payload serialization: {e}"))?;
        std::fs::write(path, text)
            .map_err(|e| format!("cannot write payload {}: {e}", path.display()))?;
        println!("wrote domain commitment payload to {}", path.display());
        return Ok(());
    }
    let key_file = cli
        .key_file
        .as_ref()
        .ok_or_else(|| "--key-file is required to submit".to_string())?;
    let key = budlum_core::wallet::open_key_file(key_file, cli.password_file.as_deref())?;
    let client = http_client()?;
    let requested_chain_id = cli.signing_chain_id.ok_or_else(|| {
        "--signing-chain-id is required to submit a domain commitment".to_string()
    })?;
    let chain_id = bind_signing_chain_id(
        quantity(
            &rpc_call(&client, &cli.rpc_url, "bud_chainId", serde_json::json!([])).await?,
            "bud_chainId",
        )?,
        requested_chain_id,
    )?;
    let sender = key.address();
    let nonce = quantity(
        &rpc_call(
            &client,
            &cli.rpc_url,
            "bud_getNonce",
            serde_json::json!([sender.to_hex()]),
        )
        .await?,
        "bud_getNonce",
    )?;
    let mut transaction = Transaction::new_with_chain_id(
        sender,
        Address::zero(),
        0,
        cli.fee,
        nonce,
        Vec::new(),
        chain_id,
        TransactionType::Settlement(SettlementTx::SubmitCommitment(Box::new(payload))),
    );
    key.sign(&mut transaction)?;
    let hash = transaction.hash.clone();
    let result = rpc_call(
        &client,
        &cli.rpc_url,
        "bud_sendRawTransaction",
        serde_json::json!([transaction]),
    )
    .await?;
    println!("submitted domain commitment transaction {hash}: {result}");
    Ok(())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("budlum-domain-producer: {error}");
            std::process::ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gap_04_quantity_and_seed_parsers_enforce_canonical_bounds() {
        assert_eq!(quantity(&serde_json::json!("0x2a"), "nonce").unwrap(), 42);
        assert_eq!(quantity(&serde_json::json!("100"), "nonce").unwrap(), 100);
        assert!(quantity(&serde_json::json!(42), "nonce").is_err());
        assert!(quantity(&serde_json::json!("0xzz"), "nonce").is_err());

        let hex32 = "11".repeat(32);
        assert_eq!(seed::<32>(&hex32, "seed").unwrap(), [0x11; 32]);
        assert_eq!(
            seed::<32>(&format!("0x{hex32}"), "seed").unwrap(),
            [0x11; 32]
        );
        assert!(seed::<32>("1111", "seed").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_gap_04_read_keys_refuses_group_or_world_accessible_file() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "budlum_domain_producer_keys_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let cli = Cli {
            rpc_url: "http://127.0.0.1:8545".into(),
            payload: None,
            pow_spec: None,
            bitcoin_spec: None,
            bft_spec: None,
            poa_spec: None,
            dag_spec: None,
            poh_spec: None,
            pospace_spec: None,
            quorum_keys: Some(path.clone()),
            write_payload: Some(path.clone()),
            key_file: None,
            password_file: None,
            fee: 1_000,
            signing_chain_id: None,
        };
        let err = read_keys(&cli).expect_err("0644 quorum keys file must be refused");
        let _ = std::fs::remove_file(&path);
        assert!(err.contains("chmod 600"), "unexpected error: {err}");
    }

    #[test]
    fn a_node_cannot_choose_the_producers_signing_network() {
        assert_eq!(
            bind_signing_chain_id(45_261, 45_261).expect("named network agrees"),
            45_261
        );
        let error = bind_signing_chain_id(45_260, 45_261)
            .expect_err("another network's RPC answer must be refused");
        assert!(error.contains("refusing to sign"), "{error}");
    }

    #[tokio::test]
    async fn submission_checks_the_network_before_signing_or_sending() {
        use super::domain_client_test_support::{rpc, Files};
        use budlum_core::core::transaction::TransactionType;
        use budlum_core::settlement::domains::SettlementTx;

        let files = Files::new();
        let cli = |url| Cli {
            rpc_url: url,
            payload: Some(files.payload.clone()),
            pow_spec: None,
            bitcoin_spec: None,
            bft_spec: None,
            poa_spec: None,
            dag_spec: None,
            poh_spec: None,
            pospace_spec: None,
            quorum_keys: None,
            write_payload: None,
            key_file: Some(files.key.clone()),
            password_file: Some(files.password.clone()),
            signing_chain_id: Some(45262),
            fee: 1_000,
        };
        let (url, calls, server) = rpc(45260).await;
        let error = super::run(cli(url))
            .await
            .expect_err("a node on another network must not sign");
        assert!(error.contains("refusing to sign"), "{error}");
        assert_eq!(*calls.methods.lock().unwrap(), ["bud_chainId"]);
        assert!(calls.transactions.lock().unwrap().is_empty());
        server.stop().unwrap();

        let (url, calls, server) = rpc(45262).await;
        super::run(cli(url))
            .await
            .expect("the named network submits");
        assert_eq!(
            *calls.methods.lock().unwrap(),
            ["bud_chainId", "bud_getNonce", "bud_sendRawTransaction"]
        );
        let transactions = calls.transactions.lock().unwrap();
        assert_eq!(transactions.len(), 1);
        let tx = &transactions[0];
        assert_eq!(tx.chain_id, 45262);
        assert!(matches!(
            tx.tx_type,
            TransactionType::Settlement(SettlementTx::SubmitCommitment(_))
        ));
        assert!(tx.verify(), "the submitted transaction is signed");
        server.stop().unwrap();
    }

    #[test]
    fn bitcoin_spec_builds_a_verified_commitment() {
        use budlum_core::domain::producer::{
            build_bitcoin_spv_commitment, BitcoinBlockContent, BitcoinSpvChainSpec,
        };
        use budlum_core::domain::{
            default_domain, ConsensusKind, FinalityProof, PoWDomainParameters, BITCOIN_SPV_ADAPTER,
        };

        let mut domain = default_domain(3, ConsensusKind::PoW, 0, BITCOIN_SPV_ADAPTER, 1);
        domain.pow_parameters = Some(PoWDomainParameters {
            min_difficulty_bits: 1,
            max_difficulty_bits: 16,
            min_cumulative_work: 2,
            max_headers: 8,
        });
        let spec = BitcoinSpvChainSpec {
            domain,
            parent_hash: [0u8; 32],
            height: 1,
            sequence: 0,
            producer: None,
            blocks: vec![BitcoinBlockContent {
                version: 1,
                merkle_root: [0x55; 32],
                timestamp: 1_700_000_000,
                bits: 0x207f_ffff,
            }],
        };
        let dir = tempfile::tempdir().unwrap();
        let spec_path = dir.path().join("btc.json");
        std::fs::write(&spec_path, serde_json::to_vec(&spec).unwrap()).unwrap();
        let cli = Cli {
            rpc_url: "http://127.0.0.1:8545".into(),
            payload: None,
            pow_spec: None,
            bitcoin_spec: Some(spec_path),
            bft_spec: None,
            poa_spec: None,
            dag_spec: None,
            poh_spec: None,
            pospace_spec: None,
            quorum_keys: None,
            write_payload: None,
            key_file: None,
            password_file: None,
            signing_chain_id: None,
            fee: 1_000,
        };
        let loaded = load_payload(&cli).unwrap();
        let direct = build_bitcoin_spv_commitment(&spec).unwrap();
        assert_eq!(loaded.commitment, direct.commitment);
        assert!(matches!(loaded.proof, FinalityProof::BitcoinSpv { .. }));
    }

    #[test]
    fn cli_rejects_conflicting_spec_flags_and_missing_quorum_keys() {
        for flag in ["--dag-spec", "--poh-spec", "--pospace-spec"] {
            assert!(Cli::try_parse_from([
                "budlum-domain-producer",
                flag,
                "spec.json",
                "--quorum-keys",
                "keys.json",
                "--write-payload",
                "out.json",
            ])
            .is_ok());
            assert!(Cli::try_parse_from([
                "budlum-domain-producer",
                flag,
                "spec.json",
                "--write-payload",
                "out.json",
            ])
            .is_err());
        }
        let conflicting = Cli::try_parse_from([
            "budlum-domain-producer",
            "--dag-spec",
            "dag.json",
            "--poh-spec",
            "poh.json",
            "--quorum-keys",
            "keys.json",
            "--write-payload",
            "out.json",
        ]);
        assert!(
            conflicting.is_err(),
            "two spec flags in one invocation must fail closed rather than silently dropping one"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dag_poh_and_pospace_specs_write_finalizable_payloads() {
        use budlum_core::domain::finality_adapter::{
            poa_pq_authority_set_hash, DagFinalityAdapter, DomainFinalityAdapter, FinalityProof,
            FinalityStatus, PoAAuthorityKey, PohFinalityAdapter, PospaceFinalityAdapter,
        };
        use budlum_core::domain::producer::QuorumBlockSpec;
        use budlum_core::domain::{default_domain, ConsensusKind, VerifiedDomainCommitment};
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let keys_path = dir.path().join("quorum_keys.json");

        let mut authorities = Vec::new();
        let mut composite_seeds = Vec::new();
        for idx in 0..3u8 {
            let pq_seed = [idx + 0x21; 32];
            let ed_seed = [idx + 0x61; 32];
            let kp = budlum_core::crypto::composite::CompositeKeypair::from_seeds(
                budlum_core::crypto::scheme::SuiteId::VALIDATOR,
                &pq_seed,
                &ed_seed,
            )
            .unwrap();
            let pubkey = kp.public_key().unwrap();
            authorities.push(PoAAuthorityKey {
                authority: Address::from(pubkey.ed),
                public_key: pubkey.encode(),
            });
            if idx < 2 {
                composite_seeds.push([hex::encode(pq_seed), hex::encode(ed_seed)]);
            }
        }
        let keys = QuorumKeys {
            bls_seeds: Vec::new(),
            pq_seeds: Vec::new(),
            composite: composite_seeds,
        };
        std::fs::write(&keys_path, serde_json::to_vec(&keys).unwrap()).unwrap();
        std::fs::set_permissions(&keys_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let make_block = |id: u32, kind: ConsensusKind, adapter: &str| {
            let mut domain = default_domain(id, kind, 0, adapter, 1);
            domain.domain_chain_id = 45_262 + u64::from(id);
            domain.config_hash = [id as u8; 32];
            domain.validator_set_hash = poa_pq_authority_set_hash(&domain, &authorities).unwrap();
            QuorumBlockSpec {
                domain,
                parent_hash: [0x11; 32],
                block_hash: [0x22; 32],
                height: 2,
                sequence: 1,
                timestamp_ms: 1_700_000_000_000,
                producer: Some(authorities[0].authority),
                state_root: [0x33; 32],
                tx_root: [0x44; 32],
                event_root: [0x55; 32],
            }
        };

        // 1. --dag-spec
        let dag_block = make_block(11, ConsensusKind::Dag, "dag-tip-vote-v1");
        let dag_domain = dag_block.domain.clone();
        let dag_job = DagJob {
            block: dag_block,
            round: 5,
            authorities: authorities.clone(),
        };
        let dag_spec_path = dir.path().join("dag_job.json");
        let dag_out_path = dir.path().join("dag_out.json");
        std::fs::write(&dag_spec_path, serde_json::to_vec(&dag_job).unwrap()).unwrap();
        super::run(
            Cli::try_parse_from([
                "budlum-domain-producer",
                "--dag-spec",
                dag_spec_path.to_str().unwrap(),
                "--quorum-keys",
                keys_path.to_str().unwrap(),
                "--write-payload",
                dag_out_path.to_str().unwrap(),
            ])
            .unwrap(),
        )
        .await
        .unwrap();
        let dag_written: VerifiedDomainCommitment =
            serde_json::from_slice(&std::fs::read(&dag_out_path).unwrap()).unwrap();
        assert!(matches!(dag_written.proof, FinalityProof::DagPq { .. }));
        assert_eq!(
            DagFinalityAdapter
                .verify_finality(&dag_domain, &dag_written.commitment, &dag_written.proof)
                .unwrap(),
            FinalityStatus::Finalized
        );

        // 2. --poh-spec
        let poh_block = make_block(12, ConsensusKind::Poh, "poh-hash-chain-v1");
        let poh_domain = poh_block.domain.clone();
        let poh_job = PohJob {
            seed_tick: poh_block.parent_hash,
            tick_count: 8,
            block: poh_block,
            authorities: authorities.clone(),
        };
        let poh_spec_path = dir.path().join("poh_job.json");
        let poh_out_path = dir.path().join("poh_out.json");
        std::fs::write(&poh_spec_path, serde_json::to_vec(&poh_job).unwrap()).unwrap();
        super::run(
            Cli::try_parse_from([
                "budlum-domain-producer",
                "--poh-spec",
                poh_spec_path.to_str().unwrap(),
                "--quorum-keys",
                keys_path.to_str().unwrap(),
                "--write-payload",
                poh_out_path.to_str().unwrap(),
            ])
            .unwrap(),
        )
        .await
        .unwrap();
        let poh_written: VerifiedDomainCommitment =
            serde_json::from_slice(&std::fs::read(&poh_out_path).unwrap()).unwrap();
        assert!(matches!(poh_written.proof, FinalityProof::PohPq { .. }));
        assert_eq!(
            PohFinalityAdapter
                .verify_finality(&poh_domain, &poh_written.commitment, &poh_written.proof)
                .unwrap(),
            FinalityStatus::Finalized
        );

        // 3. --pospace-spec with deterministic challenge mining
        let pos_block = make_block(13, ConsensusKind::Pospace, "pospace-plot-v1");
        let pos_domain = pos_block.domain.clone();
        let pos_job = PospaceJob {
            block: pos_block,
            prover_index: 0,
            mine_block_hash: true,
            authorities: authorities.clone(),
        };
        let pos_spec_path = dir.path().join("pos_job.json");
        let pos_out_path = dir.path().join("pos_out.json");
        std::fs::write(&pos_spec_path, serde_json::to_vec(&pos_job).unwrap()).unwrap();
        super::run(
            Cli::try_parse_from([
                "budlum-domain-producer",
                "--pospace-spec",
                pos_spec_path.to_str().unwrap(),
                "--quorum-keys",
                keys_path.to_str().unwrap(),
                "--write-payload",
                pos_out_path.to_str().unwrap(),
            ])
            .unwrap(),
        )
        .await
        .unwrap();
        let pos_written: VerifiedDomainCommitment =
            serde_json::from_slice(&std::fs::read(&pos_out_path).unwrap()).unwrap();
        assert!(matches!(pos_written.proof, FinalityProof::PospacePq { .. }));
        assert_eq!(
            PospaceFinalityAdapter
                .verify_finality(&pos_domain, &pos_written.commitment, &pos_written.proof)
                .unwrap(),
            FinalityStatus::Finalized
        );

        // 4. Out-of-bounds prover_index fails closed
        let mut bad_pos_job = pos_job;
        bad_pos_job.prover_index = 99;
        let bad_pos_path = dir.path().join("bad_pos_job.json");
        std::fs::write(&bad_pos_path, serde_json::to_vec(&bad_pos_job).unwrap()).unwrap();
        let err = super::run(
            Cli::try_parse_from([
                "budlum-domain-producer",
                "--pospace-spec",
                bad_pos_path.to_str().unwrap(),
                "--quorum-keys",
                keys_path.to_str().unwrap(),
                "--write-payload",
                pos_out_path.to_str().unwrap(),
            ])
            .unwrap(),
        )
        .await
        .expect_err("out-of-bounds prover_index must fail closed");
        assert!(err.contains("prover_index"), "{err}");
    }
}
