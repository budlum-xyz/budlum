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
//!   "qc_blobs": [<QcBlob>, ...],             // PQ path, alternative
//!   "global_headers": [                      // optional,
//!     { "header": <GlobalBlockHeader>, "state_root_body": "<64 hex>" }, ...
//!   ]
//! }
//! ```
//!
//! A global header opening extends the verified chain one step: trust
//! anchor, finality certificate, block, global header. The header must have
//! been built at the checkpoint's height, and the checkpoint's state root
//! must reopen with `state_root_body` and the header hash. The opening is
//! what `bud_getGlobalHeaderProof` returns as `header` and `stateRootBody`.
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
use budlum_core::light_client::{
    LightClient, LightClientError, TrustedCheckpoint, VerifiedCheckpoint,
};
use budlum_core::settlement::GlobalBlockHeader;
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

    /// Refuse a verified checkpoint that has no global header opening in the
    /// export, instead of skipping the global header step for it.
    #[arg(long)]
    require_global_headers: bool,
}

#[derive(Debug, serde::Deserialize)]
struct ChainExport {
    snapshot: ValidatorSetSnapshot,
    headers: Vec<BlockHeader>,
    #[serde(default)]
    certificates: Vec<FinalityCert>,
    #[serde(default)]
    qc_blobs: Vec<QcBlob>,
    #[serde(default)]
    global_headers: Vec<GlobalHeaderOpening>,
}

/// A global header and the state-root body that, with the header hash,
/// reopens the checkpoint's state root.
#[derive(Debug, serde::Deserialize)]
struct GlobalHeaderOpening {
    header: GlobalBlockHeader,
    state_root_body: String,
}

/// Parse a 32-byte digest written as 64 hex characters, `0x` optional.
fn decode_hash32(text: &str) -> Result<[u8; 32], String> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    let bytes = hex::decode(digits).map_err(|e| format!("{text} is not hex: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| format!("{text} is not a 32-byte digest"))
}

/// Run the global header step for one verified checkpoint. `Ok(None)` when
/// the export carries no opening for it and none is required.
fn verify_global_opening(
    verified: &VerifiedCheckpoint,
    openings: &[GlobalHeaderOpening],
    required: bool,
) -> Result<Option<String>, String> {
    let Some(opening) = openings
        .iter()
        .find(|o| o.header.checkpoint_height == verified.height)
    else {
        if required {
            return Err(format!(
                "no global header opening for checkpoint height {}",
                verified.height
            ));
        }
        return Ok(None);
    };
    let body = decode_hash32(&opening.state_root_body)?;
    LightClient::verify_global_header(verified, &body, &opening.header)
        .map_err(|e| e.to_string())?;
    Ok(Some(hex::encode(opening.header.calculate_hash_bytes())))
}

/// The interval must be positive: with 0 no checkpoint is ever due, and the
/// run would end as "trusted" without checking a single certificate.
fn check_interval(interval: u64) -> Result<(), String> {
    if interval == 0 {
        return Err("--checkpoint-interval must be greater than 0".to_string());
    }
    Ok(())
}

/// A run that verified no checkpoint proved nothing. The target at or below
/// the anchor, or a range with no multiple of the interval, ends here
/// instead of printing a trusted height with exit code 0.
fn ensure_checkpoints_verified(
    count: usize,
    trusted_height: u64,
    target: u64,
) -> Result<(), String> {
    if count == 0 {
        return Err(format!(
            "no checkpoint above height {trusted_height} up to height {target} was verified"
        ));
    }
    Ok(())
}

/// Largest chain export the tool reads.
const MAX_CHAIN_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Read a file but refuse one longer than `max` bytes.
fn read_bounded(path: &std::path::Path, max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    file.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() as u64 > max {
        return Err(format!("file is larger than {max} bytes"));
    }
    Ok(buf)
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(e) = check_interval(cli.checkpoint_interval) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }

    let raw = match read_bounded(&cli.chain_file, MAX_CHAIN_FILE_BYTES) {
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
    // The network is the one the headers name: a mainnet client refuses
    // BLS-only checkpoints.
    let chain_id = export.headers[0].chain_id;
    let mut client = match LightClient::for_chain(trusted, chain_id) {
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
    let mut verified_count = 0usize;
    let mut next = client.next_checkpoint_height(cli.checkpoint_interval, target);
    while let Some(checkpoint_height) = next {
        let Some(header) = export.headers.iter().find(|h| h.index == checkpoint_height) else {
            eprintln!("no header at checkpoint height {checkpoint_height}");
            return ExitCode::FAILURE;
        };

        // Both halves when the export has both, else whichever it
        // has; a mainnet client refuses the BLS half alone.
        let cert = export
            .certificates
            .iter()
            .find(|c| c.checkpoint_height == header.index && c.checkpoint_hash == header.hash);
        let blob = export
            .qc_blobs
            .iter()
            .find(|b| b.checkpoint_height == header.index && b.checkpoint_hash == header.hash);
        let verified = if let (Some(cert), Some(blob)) = (cert, blob) {
            client.verify_hybrid_checkpoint(header, cert, blob, &export.snapshot)
        } else if let Some(cert) = cert {
            client.verify_checkpoint(header, cert, &export.snapshot)
        } else if let Some(blob) = blob {
            client.verify_pq_checkpoint(header, blob, &export.snapshot)
        } else {
            Err(LightClientError::CertificateBinding(format!(
                "no finality certificate for checkpoint height {checkpoint_height}"
            )))
        };

        match verified {
            Ok(verified) => {
                // The anchorable external root (AR-GE-6 / F-12): the
                // full-node consensus path anchors exactly this root via
                // `AccountState::anchor_external_root` once the matching
                // domain commitment finalizes, and the executor's relayer
                // gate then matches relayer results against it. Printing it
                // here lets an operator check the light-client side of that
                // lifecycle against the full node.
                let external_root = match verified.external_root() {
                    Some(root) => format!("0x{}", hex::encode(root)),
                    None => "-".to_string(),
                };
                println!(
                    "CHECKPOINT VERIFIED height={} hash={} epoch={} external_root={}",
                    verified.height, verified.block_hash, verified.epoch, external_root
                );
                match verify_global_opening(
                    &verified,
                    &export.global_headers,
                    cli.require_global_headers,
                ) {
                    Ok(Some(header_hash)) => println!(
                        "GLOBAL HEADER VERIFIED height={} hash={header_hash}",
                        verified.height
                    ),
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("global header at checkpoint {checkpoint_height} rejected: {e}");
                        return ExitCode::FAILURE;
                    }
                }
                if let Err(e) = client.advance(&verified) {
                    eprintln!("cannot advance trust anchor: {e}");
                    return ExitCode::FAILURE;
                }
                verified_count += 1;
            }
            Err(e) => {
                eprintln!("checkpoint {checkpoint_height} rejected: {e}");
                return ExitCode::FAILURE;
            }
        }

        next = client.next_checkpoint_height(cli.checkpoint_interval, target);
    }

    if let Err(e) = ensure_checkpoints_verified(verified_count, cli.trusted_height, target) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }

    let trusted = client.trusted();
    println!(
        "LIGHT CLIENT TRUSTED height={} hash={} set={}",
        trusted.height, trusted.block_hash, trusted.set_hash
    );
    println!("TRUST MODE {}", client.trust_mode().describe());
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{check_interval, decode_hash32, ensure_checkpoints_verified, read_bounded};

    #[test]
    fn a_state_root_body_must_be_a_32_byte_digest() {
        let digest = "ab".repeat(32);
        assert_eq!(decode_hash32(&digest), Ok([0xab; 32]));
        assert_eq!(decode_hash32(&format!("0x{digest}")), Ok([0xab; 32]));
        assert!(decode_hash32("abcd").is_err());
        assert!(decode_hash32(&"zz".repeat(32)).is_err());
    }

    /// BLG-0705: a run that verifies nothing must not end as trusted.
    #[test]
    fn an_unverified_run_is_refused() {
        assert!(check_interval(0).is_err());
        assert!(check_interval(10).is_ok());
        assert!(ensure_checkpoints_verified(0, 5, 5).is_err());
        assert!(ensure_checkpoints_verified(0, 5, 9).is_err());
        assert!(ensure_checkpoints_verified(1, 5, 20).is_ok());
    }

    #[test]
    fn an_oversized_file_is_refused() {
        let path = std::env::temp_dir().join(format!("budlum_light_bound_{}", std::process::id()));
        std::fs::write(&path, [0u8; 16]).unwrap();
        assert!(read_bounded(&path, 16).is_ok());
        assert!(read_bounded(&path, 15).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
