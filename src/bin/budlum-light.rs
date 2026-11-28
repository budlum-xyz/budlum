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
//!   ],
//!   "finality_reads": [                      // optional, needs the opening
//!     { "certificate": <GlobalFinalityCertificate>,
//!       "proofs": [<DomainFinalityInclusionProof>, ...] }, ...
//!   ]
//! }
//! ```
//!
//! A finality read is a domain row read through a Budlum checkpoint: the
//! certificate must be the one the checkpoint's global header commits to
//! (`finality_certificate_root`), and each proof opens one row of it. One
//! trust anchor therefore verifies the finalized roots of every domain the
//! certificate carries. Each read prints a `FINALITY ANCHOR` line naming the
//! `--trusted-finality-checkpoint` / `--trusted-finality-digest` pair that
//! `bud finality show|route` require, then one `DOMAIN FINALITY VERIFIED`
//! line per row - but only for rows whose verdict is `Established` and which
//! carry every binding named by `--require-binds`. A `Pending` or `Refuted` row
//! is an authenticated fact about the domain, not finality: the read is refused
//! instead of being reported verified. The certificate and proofs are what `bud_getFinalityCertificate`
//! returns as `certificate` and `cert.prove_domain` produces per domain.
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
use budlum_core::crypto::scheme::SchemeStatusRegistry;
use budlum_core::light_client::{
    LightClient, LightClientError, TrustedCheckpoint, VerifiedCheckpoint,
};
use budlum_core::settlement::universal_finality::FinalityBinds;
use budlum_core::settlement::{
    DomainFinalityInclusionProof, FinalityVerdict, GlobalBlockHeader, GlobalFinalityCertificate,
};
use clap::Parser;

/// The network the verifier is configured for.
///
/// A closed set on purpose: the chain the client verifies against is a
/// command-line decision, never a value read from the file under verification.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Network {
    Mainnet,
    Testnet,
    Devnet,
}

impl Network {
    fn chain_id(self) -> u64 {
        let network = match self {
            Self::Mainnet => budlum_core::core::chain_config::Network::Mainnet,
            Self::Testnet => budlum_core::core::chain_config::Network::Testnet,
            Self::Devnet => budlum_core::core::chain_config::Network::Devnet,
        };
        network.chain_id().value()
    }
}

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

    /// The network this export is claimed to be from: `mainnet`, `testnet`
    /// or `devnet`.
    ///
    /// The network decides the security rule the client applies (mainnet
    /// refuses a BLS-only checkpoint), so it comes from the operator and not
    /// from the file being verified. An export whose headers name another chain
    /// than this one is refused before anything is verified: otherwise the
    /// exporter chooses the security level of the verifier.
    #[arg(long, value_enum)]
    network: Network,

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

    /// The scheme and suite statuses the chain publishes, so the verifier
    /// judges a checkpoint by the policy the network actually runs under
    /// rather than by the policy of a fresh genesis.
    ///
    /// JSON, the shape `SchemeStatusRegistry::entries` prints:
    /// `{ "schemes": [[id, status], ...], "suites": [[id, status], ...] }`.
    /// Omitted means genesis statuses, which is the right answer only for a
    /// chain that has never moved a scheme out of its genesis state; a client
    /// tracking a live chain pins it, exactly as it pins the trust anchor,
    /// because the export being verified never carries its own policy.
    #[arg(long)]
    scheme_registry: Option<PathBuf>,

    /// Bindings every read row must carry, as a comma-separated list drawn from
    /// the row's own vocabulary (`state_root,tx_root,event_root,parent`). A row
    /// that lacks a demanded binding is refused, as `bud finality route` refuses
    /// it. Empty demands nothing beyond the row being `Established`.
    #[arg(long, default_value = "")]
    require_binds: String,
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
    #[serde(default)]
    finality_reads: Vec<FinalityRead>,
}

/// One Universal Finality Certificate and the domain rows read out of it.
///
/// The certificate is judged against the global header opening of its own
/// checkpoint, so every row printed from it rests on the trust anchor, not on
/// the exporter: a certificate the header does not commit to proves nothing.
#[derive(Debug, serde::Deserialize)]
struct FinalityRead {
    certificate: GlobalFinalityCertificate,
    proofs: Vec<DomainFinalityInclusionProof>,
}

/// Parse the comma-separated binding names a consumer demands of every row.
/// The names are the row vocabulary's own `Display` names, so a binding can be
/// demanded only under the name a row prints it; an empty list demands nothing.
fn parse_bind_names(names: &str) -> Result<FinalityBinds, String> {
    let mut required = FinalityBinds::NONE;
    for name in names
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        let flag = [
            FinalityBinds::STATE_ROOT,
            FinalityBinds::TX_ROOT,
            FinalityBinds::EVENT_ROOT,
            FinalityBinds::PARENT,
        ]
        .into_iter()
        .find(|flag| flag.to_string() == name)
        .ok_or_else(|| {
            format!(
                "unknown --require-binds name {name}: expected state_root, tx_root, event_root or parent"
            )
        })?;
        required = required.union(flag);
    }
    Ok(required)
}

/// Why a certified row may not be reported as final for a read, or `None`.
///
/// A `Pending` or `Refuted` row carries no finality. An `Established` row is
/// reported only when it carries every binding the read demands. Composition
/// already refuses an `Established` row whose attestation outstrips its binds,
/// so the second refusal guards the consumer if that rule is ever relaxed; it
/// is decided here, at the read, not inherited from the producer.
fn finality_read_refusal(
    verdict: &FinalityVerdict,
    binds: FinalityBinds,
    required: FinalityBinds,
) -> Option<String> {
    if !matches!(verdict, FinalityVerdict::Established) {
        return Some(format!(
            "the row is not Established ({verdict:?}); no value moves on it"
        ));
    }
    if !binds.covers(required) {
        return Some(format!(
            "domain binds {binds} but this read requires {required}"
        ));
    }
    None
}

/// Verify the finality reads bound to `verified` against its verified global
/// header opening, and return the lines to print.
///
/// Each row goes through `LightClient::verify_finality_certificate_domain`:
/// checkpoint trust, the header reopening the finalized state root,
/// `finality_certificate_root == certificate_digest`, certificate integrity
/// and the inclusion path. The anchor line names the flags `bud finality
/// show|route` takes, so the CLI's trust input comes from this verified
/// chain rather than from the node it then queries. Nothing is returned
/// unless every row of every read verified. A verified inclusion is not yet
/// finality: the row is reported only when its verdict is `Established` and it
/// carries every binding in `required_binds`; any other row refuses the read,
/// with the same two sets the value gate names.
fn verify_finality_reads(
    client: &LightClient,
    verified: &VerifiedCheckpoint,
    opening: Option<(&GlobalHeaderOpening, [u8; 32])>,
    reads: &[FinalityRead],
    required_binds: FinalityBinds,
) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    for read in reads
        .iter()
        .filter(|r| r.certificate.checkpoint_height == verified.height)
    {
        let Some((opening, body)) = opening else {
            return Err(format!(
                "finality read for checkpoint {} has no verified global header opening",
                verified.height
            ));
        };
        if read.proofs.is_empty() {
            return Err(format!(
                "finality read for checkpoint {} proves no domain",
                verified.height
            ));
        }
        let digest = hex::encode(read.certificate.certificate_digest);
        lines.push(format!(
            "FINALITY ANCHOR checkpoint={height} digest=0x{digest} \
             bud=--trusted-finality-checkpoint {height} --trusted-finality-digest 0x{digest}",
            height = verified.height
        ));
        for proof in &read.proofs {
            let row = client
                .verify_finality_certificate_domain(
                    verified,
                    &body,
                    &opening.header,
                    &read.certificate,
                    proof,
                )
                .map_err(|e| {
                    format!(
                        "finality read for domain {} at checkpoint {} rejected: {e}",
                        proof.entry.domain_id, verified.height
                    )
                })?;
            // The proof entry is the certified row: its digest was just checked
            // against the certificate's own entry, and the digest absorbs `binds`.
            if let Some(reason) =
                finality_read_refusal(&row.verdict, proof.entry.binds, required_binds)
            {
                return Err(format!(
                    "finality read for domain {} at checkpoint {} refused: {reason}",
                    row.domain_id, verified.height
                ));
            }
            lines.push(format!(
                "DOMAIN FINALITY VERIFIED checkpoint={} domain={} bucket={:?} verdict={:?} \
                 height={} state_root=0x{} guarantee={} binds={}",
                verified.height,
                row.domain_id,
                row.bucket,
                row.verdict,
                row.height,
                hex::encode(row.state_root),
                row.guarantee_label,
                proof.entry.binds
            ));
        }
    }
    Ok(lines)
}

/// Refuse two reads for one checkpoint: which certificate is the
/// checkpoint's is decided by its header, never by the exporter's order.
fn check_finality_reads_unique(reads: &[FinalityRead]) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for read in reads {
        if !seen.insert(read.certificate.checkpoint_height) {
            return Err(format!(
                "duplicate finality read for checkpoint height {}",
                read.certificate.checkpoint_height
            ));
        }
    }
    Ok(())
}

/// Refuse a read whose checkpoint this run never verified: a run must not end
/// as trusted while part of what it was asked to verify went unchecked.
fn ensure_finality_reads_consumed(
    reads: &[FinalityRead],
    verified_heights: &std::collections::BTreeSet<u64>,
) -> Result<(), String> {
    match reads
        .iter()
        .find(|r| !verified_heights.contains(&r.certificate.checkpoint_height))
    {
        Some(read) => Err(format!(
            "finality read for checkpoint height {} names a checkpoint this run never verified",
            read.certificate.checkpoint_height
        )),
        None => Ok(()),
    }
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
/// the export carries no opening for it and none is required; otherwise the
/// verified opening and its decoded state-root body.
fn verify_global_opening<'a>(
    verified: &VerifiedCheckpoint,
    openings: &'a [GlobalHeaderOpening],
    required: bool,
) -> Result<Option<(&'a GlobalHeaderOpening, [u8; 32])>, String> {
    let mut matches = openings
        .iter()
        .filter(|o| o.header.checkpoint_height == verified.height);
    let Some(opening) = matches.next() else {
        if required {
            return Err(format!(
                "no global header opening for checkpoint height {}",
                verified.height
            ));
        }
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(format!(
            "duplicate global header opening for checkpoint height {}",
            verified.height
        ));
    }
    let body = decode_hash32(&opening.state_root_body)?;
    LightClient::verify_global_header(verified, &body, &opening.header)
        .map_err(|e| e.to_string())?;
    Ok(Some((opening, body)))
}

/// Refuse an export whose headers do not all name `expected_chain_id`.
fn validate_headers_chain_id(
    headers: &[BlockHeader],
    expected_chain_id: u64,
    network: Network,
) -> Result<(), String> {
    for header in headers {
        if header.chain_id != expected_chain_id {
            return Err(format!(
                "chain export header at height {} is for chain {}, not for the \
                 {network:?} chain {expected_chain_id} this client is verifying \
                 against; pass --network to match the export",
                header.index, header.chain_id
            ));
        }
    }
    Ok(())
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

/// The `JSON` shape of a pinned scheme-status registry.
#[derive(Debug, serde::Deserialize)]
struct SchemeRegistryFile {
    schemes: Vec<(u16, u8)>,
    suites: Vec<(u16, u8)>,
}

/// Parse a pinned registry file.
///
/// `SchemeStatusRegistry::from_entries` refuses anything that is not exactly
/// the scheme and suite tables - a dropped row, an added one, or a status byte
/// no status uses - so a typo here cannot silently downgrade the policy the
/// client verifies under. An empty file is refused for the same reason
/// `--checkpoint-interval 0` is: it would verify every checkpoint under no
/// policy at all and look green.
///
/// # Errors
///
/// A message naming what the file is not.
fn load_scheme_registry(json: &str) -> Result<SchemeStatusRegistry, String> {
    let file: SchemeRegistryFile =
        serde_json::from_str(json).map_err(|e| format!("scheme registry is not JSON: {e}"))?;
    if file.schemes.is_empty() && file.suites.is_empty() {
        return Err("scheme registry carries no statuses".to_string());
    }
    SchemeStatusRegistry::from_entries(&file.schemes, &file.suites)
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(e) = check_interval(cli.checkpoint_interval) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    let required_binds = match parse_bind_names(&cli.require_binds) {
        Ok(binds) => binds,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

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
    // The network comes from the command line, and the export has to agree with
    // it. Reading it out of `headers[0]` would let an exporter that wants the
    // testnet rule claim the testnet chain id while shipping mainnet history -
    // and the trust anchors on the command line cannot catch that, because they
    // say nothing about which chain produced them.
    let chain_id = cli.network.chain_id();
    if let Err(e) = validate_headers_chain_id(&export.headers, chain_id, cli.network) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    let mut client = match LightClient::for_chain(trusted, chain_id) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("invalid trust anchor: {e}");
            return ExitCode::FAILURE;
        }
    };
    // The pinned policy is installed before a single checkpoint is judged: a
    // family the chain disabled must not verify here merely because a fresh
    // genesis would have allowed it.
    if let Some(path) = &cli.scheme_registry {
        let raw = match read_bounded(path, MAX_CHAIN_FILE_BYTES) {
            Ok(raw) => raw,
            Err(e) => {
                eprintln!("cannot read {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        };
        let registry = match std::str::from_utf8(&raw)
            .map_err(|e| format!("scheme registry is not UTF-8: {e}"))
            .and_then(load_scheme_registry)
        {
            Ok(registry) => registry,
            Err(e) => {
                eprintln!("cannot use {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        };
        client = client.with_scheme_registry(registry);
    }

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
    let mut verified_heights = std::collections::BTreeSet::new();
    if let Err(e) = check_finality_reads_unique(&export.finality_reads) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
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
                // The anchorable external root: the
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
                let opening = match verify_global_opening(
                    &verified,
                    &export.global_headers,
                    cli.require_global_headers,
                ) {
                    Ok(opening) => opening,
                    Err(e) => {
                        eprintln!("global header at checkpoint {checkpoint_height} rejected: {e}");
                        return ExitCode::FAILURE;
                    }
                };
                if let Some((opening, _)) = opening {
                    println!(
                        "GLOBAL HEADER VERIFIED height={} hash={}",
                        verified.height,
                        hex::encode(opening.header.calculate_hash_bytes())
                    );
                }
                match verify_finality_reads(
                    &client,
                    &verified,
                    opening,
                    &export.finality_reads,
                    required_binds,
                ) {
                    Ok(lines) => {
                        for line in lines {
                            println!("{line}");
                        }
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::FAILURE;
                    }
                }
                verified_heights.insert(verified.height);
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
    if let Err(e) = ensure_finality_reads_consumed(&export.finality_reads, &verified_heights) {
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
    use super::{
        check_interval, decode_hash32, ensure_checkpoints_verified, load_scheme_registry,
        read_bounded,
    };

    #[test]
    fn a_state_root_body_must_be_a_32_byte_digest() {
        let digest = "ab".repeat(32);
        assert_eq!(decode_hash32(&digest), Ok([0xab; 32]));
        assert_eq!(decode_hash32(&format!("0x{digest}")), Ok([0xab; 32]));
        assert!(decode_hash32("abcd").is_err());
        assert!(decode_hash32(&"zz".repeat(32)).is_err());
    }

    /// A run that verifies nothing must not end as trusted.
    #[test]
    fn an_unverified_run_is_refused() {
        assert!(check_interval(0).is_err());
        assert!(check_interval(10).is_ok());
        assert!(ensure_checkpoints_verified(0, 5, 5).is_err());
        assert!(ensure_checkpoints_verified(0, 5, 9).is_err());
        assert!(ensure_checkpoints_verified(1, 5, 20).is_ok());
    }

    /// A pinned registry is the chain's policy, so a file that does not name
    /// exactly the scheme and suite tables is refused instead of repaired.
    #[test]
    fn a_pinned_registry_must_be_the_whole_table() {
        let genesis = budlum_core::crypto::scheme::SchemeStatusRegistry::genesis();
        let (schemes, suites) = genesis.entries();
        let as_json = |schemes: &[(u16, u8)], suites: &[(u16, u8)]| {
            serde_json::json!({ "schemes": schemes, "suites": suites }).to_string()
        };
        let json = as_json(&schemes, &suites);
        assert_eq!(
            load_scheme_registry(&json).expect("the genesis table round-trips"),
            genesis
        );

        let mut short = schemes.clone();
        short.pop();
        let json = as_json(&short, &suites);
        assert!(
            load_scheme_registry(&json).is_err(),
            "a table missing a row is refused, not accepted as the policy"
        );

        let mut bad = schemes.clone();
        bad[0] = (bad[0].0, 0xfe);
        let json = as_json(&bad, &suites);
        assert!(
            load_scheme_registry(&json).is_err(),
            "a status byte no status uses is refused"
        );

        assert!(load_scheme_registry("{\"schemes\":[],\"suites\":[]}").is_err());
        assert!(load_scheme_registry("not json").is_err());
    }

    #[test]
    fn an_oversized_file_is_refused() {
        let path = std::env::temp_dir().join(format!("budlum_light_bound_{}", std::process::id()));
        std::fs::write(&path, [0u8; 16]).unwrap();
        assert!(read_bounded(&path, 16).is_ok());
        assert!(read_bounded(&path, 15).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mixed_chain_header_after_index_zero_is_refused() {
        use super::{validate_headers_chain_id, BlockHeader, Network};
        use budlum_core::core::block::Block;

        let testnet_id = Network::Testnet.chain_id();
        let mut h0 = BlockHeader::from_block(&Block::new(0, "00".repeat(32), vec![]));
        h0.chain_id = testnet_id;
        let mut h1 = BlockHeader::from_block(&Block::new(1, h0.hash.clone(), vec![]));
        h1.chain_id = Network::Mainnet.chain_id();

        let err = validate_headers_chain_id(&[h0, h1], testnet_id, Network::Testnet)
            .expect_err("mixed chain_id in trailing header must be refused");
        assert!(err.contains("height 1"));
    }

    #[test]
    fn duplicate_global_header_opening_for_same_height_is_refused() {
        use super::{
            verify_global_opening, GlobalBlockHeader, GlobalHeaderOpening, VerifiedCheckpoint,
        };

        let verified = VerifiedCheckpoint {
            height: 10,
            block_hash: "11".repeat(32),
            set_hash: "22".repeat(32),
            epoch: 1,
            state_root: "33".repeat(32),
        };
        let z = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
        let json = format!(
            "{{\"version\":7,\"global_height\":1,\"previous_global_hash\":{z},\
             \"chain_id\":45261,\"timestamp_ms\":1000,\"domain_registry_root\":{z},\
             \"domain_commitment_root\":{z},\"message_root\":{z},\"bridge_state_root\":{z},\
             \"replay_nonce_root\":{z},\"proposer\":null,\"settlement_finality_root\":{z},\
             \"checkpoint_height\":10}}"
        );
        let header: GlobalBlockHeader =
            serde_json::from_str(&json).expect("valid GlobalBlockHeader JSON");
        let o1 = GlobalHeaderOpening {
            header: header.clone(),
            state_root_body: "44".repeat(32),
        };
        let o2 = GlobalHeaderOpening {
            header,
            state_root_body: "55".repeat(32),
        };
        let err = verify_global_opening(&verified, &[o1, o2], false)
            .expect_err("conflicting duplicate openings for one height must be refused");
        assert!(err.contains("duplicate global header opening"));
    }
}

/// Reading another network's finalized row through a Budlum checkpoint: the
/// certificate must be the one the checkpoint's global header commits to,
/// and nothing the exporter adds on its own may pass.
#[cfg(test)]
mod finality_read_tests {
    use super::{
        check_finality_reads_unique, ensure_finality_reads_consumed, verify_finality_reads,
        FinalityRead, GlobalHeaderOpening, LightClient, TrustedCheckpoint, VerifiedCheckpoint,
    };
    use budlum_core::core::account::AccountState;
    use budlum_core::crypto::facts::QuantumClass;
    use budlum_core::settlement::universal_finality::FinalityBinds;
    use budlum_core::settlement::{
        compose_global_finality_certificate, DomainFinalityEntry, FinalityGuarantee,
        FinalityReversibility, FinalityVerdict, GlobalBlockHeader, GlobalFinalityCertificate,
        FINALITY_BINDS_ALL,
    };
    use std::collections::BTreeSet;

    const HEIGHT: u64 = 10;

    fn row(domain_id: u32, state_byte: u8) -> DomainFinalityEntry {
        DomainFinalityEntry {
            domain_id,
            height: 100 + u64::from(domain_id),
            checkpoint_height: HEIGHT,
            state_root: [state_byte; 32],
            adapter_id: "pow-header-v1".to_owned(),
            adapter_version: 1,
            finality_proof_hash: [0x11; 32],
            guarantee_backing_hash: [0x22; 32],
            bond_atoms: 1_000_000,
            binds: budlum_core::settlement::universal_finality::FinalityBinds::ALL,
            guarantee: FinalityGuarantee {
                reversibility: FinalityReversibility::ProbabilisticWork { confirmations: 6 },
                quantum_posture: QuantumClass::Hash,
                attestation: FINALITY_BINDS_ALL,
                slashable_backing: false,
                fault_tolerance_bps: 4_999,
            },
            verdict: FinalityVerdict::Established,
        }
    }

    fn certificate(state_byte: u8) -> GlobalFinalityCertificate {
        compose_global_finality_certificate(&[row(1, state_byte), row(2, state_byte + 1)])
            .expect("compose the certificate")
    }

    fn header(committed: &GlobalFinalityCertificate) -> GlobalBlockHeader {
        GlobalBlockHeader {
            version: 2,
            global_height: 0,
            previous_global_hash: [0u8; 32],
            chain_id: 1,
            timestamp_ms: 1,
            domain_registry_root: [1u8; 32],
            domain_commitment_root: [2u8; 32],
            message_root: [3u8; 32],
            bridge_state_root: [4u8; 32],
            replay_nonce_root: [5u8; 32],
            proposer: None,
            settlement_finality_root: [6u8; 32],
            storage_root: None,
            ai_root: None,
            identity_root: None,
            checkpoint_height: HEIGHT,
            external_intake_root: None,
            app_binding_root: None,
            delegation_root: None,
            object_layer_root: None,
            proof_root: None,
            proven_height: 0,
            ulp_domains_root: None,
            finality_certificate_root: Some(committed.certificate_digest),
        }
    }

    /// A checkpoint whose finalized state root reopens with `body` and the
    /// header hash, and a client anchored at that checkpoint - built from the
    /// public API only, the way an exporter's output would carry them.
    fn anchored(
        committed: &GlobalFinalityCertificate,
    ) -> (
        LightClient,
        VerifiedCheckpoint,
        GlobalHeaderOpening,
        [u8; 32],
    ) {
        let body = [0x42u8; 32];
        let header = header(committed);
        let state_root = AccountState::root_from_opening(&body, &header.calculate_hash_bytes());
        let checkpoint = VerifiedCheckpoint {
            height: HEIGHT,
            block_hash: "aa".repeat(32),
            set_hash: "bb".repeat(32),
            epoch: 1,
            state_root: hex::encode(state_root),
        };
        let client = LightClient::new(TrustedCheckpoint {
            height: HEIGHT,
            block_hash: "aa".repeat(32),
            set_hash: "bb".repeat(32),
        })
        .expect("light client anchored at the checkpoint");
        let opening = GlobalHeaderOpening {
            header,
            state_root_body: hex::encode(body),
        };
        (client, checkpoint, opening, body)
    }

    fn read(cert: GlobalFinalityCertificate, domains: &[u32]) -> FinalityRead {
        let proofs = domains
            .iter()
            .map(|d| cert.prove_domain(*d).expect("domain is in the certificate"))
            .collect();
        FinalityRead {
            certificate: cert,
            proofs,
        }
    }

    #[test]
    fn a_committed_certificate_yields_verified_rows_and_the_cli_anchor() {
        let honest = certificate(0x01);
        let digest = hex::encode(honest.certificate_digest);
        let (client, checkpoint, opening, body) = anchored(&honest);
        let lines = verify_finality_reads(
            &client,
            &checkpoint,
            Some((&opening, body)),
            &[read(honest, &[1, 2])],
            FinalityBinds::NONE,
        )
        .expect("rows the header commits to verify");
        assert_eq!(
            lines.len(),
            3,
            "one anchor line and one line per domain: {lines:?}"
        );
        assert!(lines[0].starts_with(&format!(
            "FINALITY ANCHOR checkpoint={HEIGHT} digest=0x{digest}"
        )));
        assert!(lines[0].contains(&format!(
            "--trusted-finality-checkpoint {HEIGHT} --trusted-finality-digest 0x{digest}"
        )));
        assert!(lines[1].starts_with(&format!(
            "DOMAIN FINALITY VERIFIED checkpoint={HEIGHT} domain=1 "
        )));
        assert!(lines[1].contains(&format!("state_root=0x{}", "01".repeat(32))));
        assert!(lines[2].starts_with(&format!(
            "DOMAIN FINALITY VERIFIED checkpoint={HEIGHT} domain=2 "
        )));
    }

    #[test]
    fn a_pending_row_is_refused_instead_of_being_reported_verified() {
        let mut stalled = row(2, 0x03);
        stalled.verdict = FinalityVerdict::Pending {
            reason:
                budlum_core::settlement::universal_finality::FinalityPendingReason::EvidenceMissing,
        };
        let cert = compose_global_finality_certificate(&[row(1, 0x01), stalled])
            .expect("compose the certificate");
        let (client, checkpoint, opening, body) = anchored(&cert);
        let err = verify_finality_reads(
            &client,
            &checkpoint,
            Some((&opening, body)),
            &[read(cert, &[2])],
            FinalityBinds::NONE,
        )
        .expect_err("a Pending row carries no finality to verify");
        assert!(err.contains("not Established"), "{err}");
        assert!(err.contains("EvidenceMissing"), "{err}");
    }

    #[test]
    fn a_refuted_row_is_refused_instead_of_being_reported_verified() {
        let mut rejected = row(2, 0x03);
        rejected.verdict = FinalityVerdict::Refuted { code: 7 };
        let cert = compose_global_finality_certificate(&[row(1, 0x01), rejected])
            .expect("compose the certificate");
        let (client, checkpoint, opening, body) = anchored(&cert);
        let err = verify_finality_reads(
            &client,
            &checkpoint,
            Some((&opening, body)),
            &[read(cert, &[2])],
            FinalityBinds::NONE,
        )
        .expect_err("a Refuted row carries no finality to verify");
        assert!(err.contains("not Established"), "{err}");
        assert!(err.contains("Refuted"), "{err}");
    }

    #[test]
    fn the_verified_line_names_the_binds_the_row_carries() {
        let honest = certificate(0x01);
        let (client, checkpoint, opening, body) = anchored(&honest);
        let lines = verify_finality_reads(
            &client,
            &checkpoint,
            Some((&opening, body)),
            &[read(honest, &[1])],
            FinalityBinds::NONE,
        )
        .expect("rows the header commits to verify");
        assert!(lines[1].contains(" binds=all"), "{}", lines[1]);
    }

    #[test]
    fn a_row_lacking_a_demanded_bind_is_refused_with_both_sets() {
        use super::finality_read_refusal;
        let both = FinalityBinds::EVENT_ROOT.union(FinalityBinds::TX_ROOT);
        let reason = finality_read_refusal(
            &FinalityVerdict::Established,
            FinalityBinds::EVENT_ROOT,
            both,
        )
        .expect("the row lacks the demanded transaction-root binding");
        assert!(
            reason.contains("binds event_root but this read requires tx_root|event_root"),
            "{reason}"
        );
        assert!(
            finality_read_refusal(&FinalityVerdict::Established, FinalityBinds::ALL, both)
                .is_none(),
            "a row that carries the demand is reported"
        );
        assert!(
            finality_read_refusal(
                &FinalityVerdict::Established,
                FinalityBinds::NONE,
                FinalityBinds::NONE
            )
            .is_none(),
            "an empty demand asks only that the row be Established"
        );
        // The verdict is decided first: a Refuted row that carries every binding
        // is still refused.
        assert!(
            finality_read_refusal(
                &FinalityVerdict::Refuted { code: 7 },
                FinalityBinds::ALL,
                FinalityBinds::NONE
            )
            .is_some(),
            "a Refuted row is refused whatever it binds"
        );
    }

    #[test]
    fn a_thin_established_row_cannot_reach_the_read_path() {
        // Composition refuses the thin row outright: an Established row may not
        // claim an attestation its binds do not cover.
        let mut thin = row(1, 0x01);
        thin.binds = FinalityBinds::EVENT_ROOT;
        assert!(compose_global_finality_certificate(&[thin, row(2, 0x02)]).is_err());
        // A certificate assembled around such a row anyway (counts and bucket
        // roots kept, the row swapped) fails integrity inside the read path, so
        // it is refused there and nothing is printed as verified.
        let mut forged = certificate(0x01);
        forged.established[0].binds = FinalityBinds::EVENT_ROOT;
        let (client, checkpoint, opening, body) = anchored(&forged);
        let err = verify_finality_reads(
            &client,
            &checkpoint,
            Some((&opening, body)),
            &[read(forged, &[1])],
            FinalityBinds::NONE,
        )
        .expect_err("a thin Established row is not a certificate");
        assert!(err.contains("AttestationUnbound"), "{err}");
    }

    #[test]
    fn bind_names_come_from_the_row_vocabulary() {
        use super::parse_bind_names;
        let both = parse_bind_names(" tx_root, event_root").expect("known names");
        assert!(both.covers(FinalityBinds::TX_ROOT) && both.covers(FinalityBinds::EVENT_ROOT));
        assert!(!both.covers(FinalityBinds::STATE_ROOT));
        assert!(parse_bind_names("")
            .expect("empty demands nothing")
            .is_empty());
        assert!(parse_bind_names("state_root,tx_root,event_root,parent")
            .expect("all four")
            .is_all());
        assert!(parse_bind_names("ALL").is_err());
        assert!(parse_bind_names("tx_root,signer").is_err());
    }

    #[test]
    fn a_self_consistent_forgery_the_header_does_not_commit_to_is_refused() {
        let honest = certificate(0x01);
        let (client, checkpoint, opening, body) = anchored(&honest);
        let err = verify_finality_reads(
            &client,
            &checkpoint,
            Some((&opening, body)),
            &[read(certificate(0xEE), &[1])],
            FinalityBinds::NONE,
        )
        .expect_err("a certificate composed from invented rows must not verify");
        assert!(err.contains("rejected"), "unexpected error: {err}");
    }

    #[test]
    fn a_read_without_a_verified_global_header_opening_is_refused() {
        let honest = certificate(0x01);
        let (client, checkpoint, _opening, _body) = anchored(&honest);
        let err = verify_finality_reads(
            &client,
            &checkpoint,
            None,
            &[read(honest, &[1])],
            FinalityBinds::NONE,
        )
        .expect_err("no opening, nothing to bind the certificate to");
        assert!(
            err.contains("no verified global header opening"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_read_that_proves_no_domain_is_refused() {
        let honest = certificate(0x01);
        let (client, checkpoint, opening, body) = anchored(&honest);
        let err = verify_finality_reads(
            &client,
            &checkpoint,
            Some((&opening, body)),
            &[read(honest, &[])],
            FinalityBinds::NONE,
        )
        .expect_err("an anchor nothing was verified against must not be printed");
        assert!(err.contains("proves no domain"), "unexpected error: {err}");
    }

    #[test]
    fn a_read_for_another_checkpoint_is_left_for_that_checkpoint() {
        let honest = certificate(0x01);
        let (client, checkpoint, opening, body) = anchored(&honest);
        let mut later = read(certificate(0x01), &[1]);
        later.certificate.checkpoint_height = HEIGHT + 10;
        let lines = verify_finality_reads(
            &client,
            &checkpoint,
            Some((&opening, body)),
            &[later],
            FinalityBinds::NONE,
        )
        .expect("a read for another checkpoint is not judged here");
        assert!(lines.is_empty());
    }

    #[test]
    fn two_reads_for_one_checkpoint_are_refused() {
        let err = check_finality_reads_unique(&[
            read(certificate(0x01), &[1]),
            read(certificate(0x01), &[2]),
        ])
        .expect_err("which of two certificates is the checkpoint's is not the exporter's call");
        assert!(
            err.contains("duplicate finality read"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_read_for_a_checkpoint_this_run_never_verified_is_refused() {
        let reads = [read(certificate(0x01), &[1])];
        let err = ensure_finality_reads_consumed(&reads, &BTreeSet::from([HEIGHT + 10]))
            .expect_err("an unread finality read must not end the run as trusted");
        assert!(err.contains("never verified"), "unexpected error: {err}");
        assert!(ensure_finality_reads_consumed(&reads, &BTreeSet::from([HEIGHT])).is_ok());
    }

    #[test]
    fn the_export_shape_carries_certificate_and_proofs() {
        let honest = certificate(0x01);
        let proof = honest.prove_domain(1).expect("proof");
        let value = serde_json::json!({ "certificate": honest, "proofs": [proof] });
        let parsed: FinalityRead = serde_json::from_value(value).expect("export shape parses");
        assert_eq!(parsed.proofs.len(), 1);
        assert_eq!(parsed.certificate.checkpoint_height, HEIGHT);
    }
}
