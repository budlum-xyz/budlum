//! budlum-light: a succinct light-client verifier.
//!
//! Whitepaper v1.1: a light client bootstrapped from a single trusted
//! validator-set commitment, using finality certificates as proofs. This
//! binary verifies a chain export - headers plus finality certificates (BLS
//! or post-quantum) plus the validator-set snapshot - against one trust
//! anchor, and prints each verified checkpoint. It never downloads or replays
//! transaction bodies.
//!
//! Chain export format (JSON):
//!
//! ```json
//! {
//!   "snapshot": <ValidatorSetSnapshot>,
//!   "headers": [<BlockHeader>, ...],
//!   "certificates": [<FinalityCert>, ...],   // BLS path, one per checkpoint
//!   "qc_blobs": [<QcBlob>, ...]              // PQ path, alternative
//! }
//! ```
//!
//! A full node can export this from its own state; the transport that fills
//! the same structures from `GetHeaders` / `GetQcBlob` wire messages is
//! spelled out by `LightClient::sync_plan`.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use budlum_core::chain::finality::{FinalityCert, ValidatorSetSnapshot};
use budlum_core::consensus::qc::QcBlob;
use budlum_core::core::block::BlockHeader;
use budlum_core::light_client::{LightClient, LightClientError, TrustedCheckpoint};
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "budlum-light",
    about = "Succinct light-client verifier bootstrapped from one trusted validator-set commitment"
)]
struct Cli {
    /// `JSON` chain export (snapshot + headers + `certificates`/`qc_blobs`).
    #[arg(long)]
    chain_file: PathBuf,

    /// Trusted checkpoint height.
    #[arg(long)]
    trusted_height: u64,

    /// Trusted block hash at `trusted_height` (64 hex).
    #[arg(long)]
    trusted_hash: String,

    /// Trusted validator-set hash (64 hex). Must come from an out-of-band
    /// trust anchor, never from the export being verified.
    #[arg(long)]
    trusted_set_hash: String,

    /// Finality checkpoint interval of the chain.
    #[arg(long, default_value_t = 10)]
    checkpoint_interval: u64,

    /// The last header height to verify up to (default: the last header).
    #[arg(long)]
    target_height: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
struct ChainExport {
    snapshot: ValidatorSetSnapshot,
    headers: Vec<BlockHeader>,
    #[serde(default)]
    certificates: Vec<FinalityCert>,
    #[serde(default)]
    qc_blobs: Vec<QcBlob>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let raw = match fs::read(&cli.chain_file) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("cannot read {}: {e}", cli.chain_file.display());
            return ExitCode::FAILURE;
        }
    };
    let export: ChainExport = match serde_json::from_slice(&raw) {
        Ok(export) => export,
        Err(e) => {
            eprintln!(
                "cannot parse {} as a chain export: {e}",
                cli.chain_file.display()
            );
            return ExitCode::FAILURE;
        }
    };

    if export.headers.is_empty() {
        eprintln!("chain export carries no headers");
        return ExitCode::FAILURE;
    }

    let trusted = TrustedCheckpoint {
        height: cli.trusted_height,
        block_hash: cli.trusted_hash,
        set_hash: cli.trusted_set_hash,
    };
    let mut client = match LightClient::new(trusted) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("invalid trust anchor: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = client.verify_header_chain(&export.headers) {
        eprintln!("header chain rejected: {e}");
        return ExitCode::FAILURE;
    }

    let target = cli
        .target_height
        .unwrap_or_else(|| export.headers.last().map_or(0, |h| h.index));

    // The anchor itself is not re-verified; everything strictly above it must
    // carry a verified finality certificate.
    let mut next = client.next_checkpoint_height(cli.checkpoint_interval, target);
    while let Some(checkpoint_height) = next {
        let Some(header) = export.headers.iter().find(|h| h.index == checkpoint_height) else {
            eprintln!("no header at checkpoint height {checkpoint_height}");
            return ExitCode::FAILURE;
        };

        // Prefer the BLS certificate when present, else the PQ blob.
        let verified = if let Some(cert) = export
            .certificates
            .iter()
            .find(|c| c.checkpoint_height == header.index && c.checkpoint_hash == header.hash)
        {
            client.verify_checkpoint(header, cert, &export.snapshot)
        } else if let Some(blob) = export
            .qc_blobs
            .iter()
            .find(|b| b.checkpoint_height == header.index && b.checkpoint_hash == header.hash)
        {
            client.verify_pq_checkpoint(header, blob, &export.snapshot)
        } else {
            Err(LightClientError::CertificateBinding(format!(
                "no finality certificate for checkpoint height {checkpoint_height}"
            )))
        };

        match verified {
            Ok(verified) => {
                println!(
                    "CHECKPOINT VERIFIED height={} hash={} epoch={}",
                    verified.height, verified.block_hash, verified.epoch
                );
                if let Err(e) = client.advance(&verified) {
                    eprintln!("cannot advance trust anchor: {e}");
                    return ExitCode::FAILURE;
                }
            }
            Err(e) => {
                eprintln!("checkpoint {checkpoint_height} rejected: {e}");
                return ExitCode::FAILURE;
            }
        }

        next = client.next_checkpoint_height(cli.checkpoint_interval, target);
    }

    let trusted = client.trusted();
    println!(
        "LIGHT CLIENT TRUSTED height={} hash={} set={}",
        trusted.height, trusted.block_hash, trusted.set_hash
    );
    ExitCode::SUCCESS
}
