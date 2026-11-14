//! Build and submit a signed domain-commitment transaction.
//!
//! A domain producer supplies a `VerifiedDomainCommitment` produced by the
//! domain adapter, signs the settlement transaction with a V5 wallet key, and
//! sends it through the public transaction RPC. The node verifies the finality
//! proof again in the block; this tool never writes consensus state locally.
//!
//! The payload file is JSON so an adapter can be implemented in another
//! process without linking node internals. For a PoW domain the tool can
//! build the payload itself: `--pow-spec` takes the domain, the parent and
//! the block contents, mines the header chain and binds the commitment to it
//! (`domain::producer`). For a BFT domain `--bft-spec` signs the checkpoint
//! with the validators' BLS keys (and their ML-DSA-65 keys for the QC half),
//! and for a PoA domain `--poa-spec` signs with the authorities' composite
//! keys; the keys come from a separate mode-0600 file (`--quorum-keys`).
//! `--write-payload` stores the result without submitting it. The signer is a V5 wallet key
//! file sealed with a password (`bud wallet create`); neither the key nor the
//! password is ever taken on the command line.

use budlum_core::core::address::Address;
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::settlement::domains::SettlementTx;
use clap::Parser;
use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "budlum-domain-producer",
    about = "Submit a verified domain commitment"
)]
struct Cli {
    /// Public node JSON-RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,
    /// JSON file containing a VerifiedDomainCommitment.
    #[arg(
        long,
        required_unless_present_any = ["pow_spec", "bft_spec", "poa_spec"],
        conflicts_with_all = ["pow_spec", "bft_spec", "poa_spec"]
    )]
    payload: Option<PathBuf>,
    /// JSON `PowChainSpec`: mine the header chain and build the payload.
    #[arg(long)]
    pow_spec: Option<PathBuf>,
    /// JSON `BftJob`: sign the checkpoint with the BFT validators' keys.
    #[arg(long, requires = "quorum_keys")]
    bft_spec: Option<PathBuf>,
    /// JSON `PoaJob`: sign the block with the PoA authorities' keys.
    #[arg(long, requires = "quorum_keys")]
    poa_spec: Option<PathBuf>,
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
    let answer: Value = client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("{method}: request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("{method}: response was not JSON: {e}"))?;
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

/// A PoA block to sign.
#[derive(Debug, serde::Deserialize)]
struct PoaJob {
    block: budlum_core::domain::producer::QuorumBlockSpec,
    authorities: Vec<budlum_core::domain::finality_adapter::PoAAuthorityKey>,
}

/// The signing seeds, hex. For BFT, `bls_seeds` (64 bytes) and optional
/// `pq_seeds` (32 bytes) align with the job's members. For PoA, `composite`
/// holds one `[ml_dsa_65_seed, ed25519_seed]` pair (32 bytes each) per
/// signing authority.
#[derive(Debug, Default, serde::Deserialize)]
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
    let path = cli
        .quorum_keys
        .as_ref()
        .ok_or_else(|| "--quorum-keys is required".to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
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
    read_json(path, "QuorumKeys")
}

fn build_bft(
    cli: &Cli,
    path: &PathBuf,
) -> Result<budlum_core::domain::VerifiedDomainCommitment, String> {
    let job: BftJob = read_json(path, "BftJob")?;
    let keys = read_keys(cli)?;
    if keys.bls_seeds.len() != job.members.len() {
        return Err("one BLS seed per member is required".into());
    }
    let mut members = Vec::with_capacity(job.members.len());
    for (index, entry) in job.members.into_iter().enumerate() {
        let bls = budlum_core::crypto::primitives::BlsKeypair::from_seed(&seed::<64>(
            &keys.bls_seeds[index],
            "a BLS seed",
        )?);
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
    budlum_core::domain::producer::build_bft_commitment(
        &job.block,
        job.chain_id,
        job.epoch,
        job.round,
        &members,
        &job.signers,
    )
}

fn build_poa(
    cli: &Cli,
    path: &PathBuf,
) -> Result<budlum_core::domain::VerifiedDomainCommitment, String> {
    let job: PoaJob = read_json(path, "PoaJob")?;
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
    budlum_core::domain::producer::build_poa_commitment(&job.block, &job.authorities, &signers)
}

fn load_payload(cli: &Cli) -> Result<budlum_core::domain::VerifiedDomainCommitment, String> {
    if let Some(path) = &cli.bft_spec {
        return build_bft(cli, path);
    }
    if let Some(path) = &cli.poa_spec {
        return build_poa(cli, path);
    }
    if let Some(path) = &cli.pow_spec {
        let spec: budlum_core::domain::producer::PowChainSpec = serde_json::from_slice(
            &std::fs::read(path)
                .map_err(|e| format!("cannot read PoW spec {}: {e}", path.display()))?,
        )
        .map_err(|e| format!("{} is not a PowChainSpec: {e}", path.display()))?;
        return budlum_core::domain::producer::build_pow_commitment(&spec);
    }
    let path = cli
        .payload
        .as_ref()
        .ok_or_else(|| "--payload or --pow-spec is required".to_string())?;
    serde_json::from_slice(
        &std::fs::read(path).map_err(|e| format!("cannot read payload {}: {e}", path.display()))?,
    )
    .map_err(|e| format!("payload is not a VerifiedDomainCommitment: {e}"))
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
    let client = reqwest::Client::new();
    let chain_id = quantity(
        &rpc_call(&client, &cli.rpc_url, "bud_chainId", serde_json::json!([])).await?,
        "bud_chainId",
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
