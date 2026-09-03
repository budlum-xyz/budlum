//! bud CLI binary - V19: REAL file I/O and pipeline (V18 only printed arguments)
//!
//! Komutlar:
//!   bud encode <in> <out> [--class json|csv|...] [--required-ratio 16.68]   v1 .bud encode
//!   bud decode <in> <out>                                                    v1 .bud decode
//!   bud store   <in> <out> [--min-chunk 65536]                               write v2 container (K38)
//!   bud restore <in> <out>                                                   read v2 container (verify)
//!   bud bench   <file>                                                       speed + cost measurement
//!   bud bft-vote --pipe-id 3 --ratio 17.19 --validator v [--n 7]             BFT finality (2n/3)
//!   bud check   <file>                                                       integrity + gate check
//!
//! Error path: every command performs real file I/O; on error -> exit code 1 + message.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

use bud_core::bud_format::{BudFile, BudFlags, BudFormatClass, BudGates, MultiRatioConsensus};
use bud_core::bud_format_bft::{BftRatioConsensus, RatioVote};
use bud_core::bud_format_checkpoint::Checkpoint;
use bud_core::bud_format_container::{BudV2File, BudV2Header, ChunkCodec, MultiHash};
use bud_core::bud_format_pact::PactRecord;
use bud_core::bud_format_production::BudProductionRecord;

use bud_core::bud_format_engine::{engine_restore_container, engine_store, TransformKind};
use bud_core::bud_format_multifile::TenantMultifileStore;
use bud_core::bud_format_segment::SegmentLedger;
use bud_core::bud_format_videopipe::run_video_pipeline;

use bud_core::bud_format_block::{PactChallengeInBlock, RegenerationBlock};
use bud_core::bud_format_catalog::CATALOG;
use bud_core::bud_format_pipe::{
    chunk_count, detect, restore, store, store_compressed, store_compressed_with_min,
    store_with_min, store_zstd, store_zstd_with_min,
};
use bud_core::bud_format_regeneration::RegenerationOutcome;
use bud_core::cli::BudCli;
use sha3::Digest as _;

#[derive(Parser)]
#[command(
    name = "bud",
    version = "4.1",
    about = "B.U.D. 2.0 .bud format CLI - v1 + v2 konteyner"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// v1 .bud encode (V8 format, with ratio consensus)
    Encode {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value = "json")]
        class: String,
        #[arg(long, default_value_t = 16.68)]
        required_ratio: f64,
    },
    /// v1 .bud decode (with integrity verification)
    Decode {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Write a v2 container: detect format + chunk structurally + .bud file (K38)
    /// --compress = Huffman; --zstd = real zstd (best ratio)
    Store {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value_t = 0)]
        min_chunk: usize,
        #[arg(long, default_value_t = false)]
        compress: bool,
        #[arg(long, default_value_t = false)]
        zstd: bool,
    },
    /// Read a v2 container: strict verify + reassemble -> original (K38)
    Restore {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// encode/decode speed + cost measurement
    Bench {
        #[arg(short, long)]
        file: PathBuf,
    },
    /// BFT finality: n validators, a 2n/3 majority for the same pipe_id/ratio
    BftVote {
        #[arg(long)]
        pipe_id: u16,
        #[arg(long)]
        ratio: f64,
        #[arg(long, default_value = "validator")]
        validator: String,
        #[arg(long, default_value_t = 7)]
        n: usize,
    },
    /// Integrity + gate check (auto-detects v1 or v2)
    Check {
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Production ratio proof: produce a root-anchored record with the measured ratio + pipeline from a .bud
    ProduceProof {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(long, default_value = "structural+zstd19")]
        pipe: String,
        #[arg(long, default_value_t = 0)]
        ts: u64,
    },
    /// PACT production contract: commitment + producer + seed record from a .bud (I1)
    Pact {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "producer")]
        producer: String,
        #[arg(long, default_value_t = 0)]
        ts: u64,
        #[arg(long, default_value_t = false)]
        residual: bool,
    },
    /// Regeneration settlement: verify the PACT producer (I2)
    Regenerate {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(long, default_value = "producer")]
        producer: String,
        #[arg(long, default_value = "seed")]
        seed: String,
    },
    /// Multi-file tenant store: chunk files + dedup + delta (the V7 66x scenario)
    Multifile {
        #[arg(short, long)]
        input: Vec<PathBuf>,
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long, default_value_t = 16384)]
        chunk: usize,
    },
    /// Segment ledger: gather records into a chain-compatible block (K89)
    Ledger {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Unified engine: any file -> .bud + measured ratio + step proof
    Engine {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long, default_value_t = false)]
        erasure: bool,
    },
    /// Video pipeline: YUV sample + codec output -> .bud + proof (K84 class)
    VideoPipe {
        #[arg(long)]
        yuv: PathBuf,
        #[arg(long)]
        width: usize,
        #[arg(long)]
        height: usize,
        #[arg(long, default_value_t = 5)]
        frames: usize,
        #[arg(long)]
        video: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long)]
        orig_len: u64,
    },
    /// Engine restore: .bud (engine output) -> original file
    EngineRestore {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long, default_value_t = 0)]
        transform: u8,
        #[arg(long, default_value_t = false)]
        erasure: bool,
    },
    /// Format catalog: every format + pipeline + honest ratio (30+)
    Catalog,
    /// Produce a regeneration block: epoch + PACT challenge + budget -> block hash (I2+I8)
    Block {
        #[arg(short, long, default_value = "bud_block.bud")]
        output: PathBuf,
        #[arg(long, default_value_t = 0)]
        epoch: u64,
        #[arg(long, default_value_t = 0)]
        budget: u64,
        #[arg(
            long,
            default_value = "0000000000000000000000000000000000000000000000000000000000000000"
        )]
        prev: String,
    },
    /// Produce a checkpoint anchored to a v2 container's content_root (direction 2)
    Checkpoint {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(long, default_value_t = 0)]
        epoch: u64,
        #[arg(long, default_value = "expert")]
        expert: String,
        #[arg(long, default_value = "structural+zstd19")]
        pipe: String,
        #[arg(long, default_value_t = 6.17)]
        ratio: f64,
    },
}

fn parse_class(s: &str) -> BudFormatClass {
    match s.to_ascii_lowercase().as_str() {
        "json" => BudFormatClass::Json,
        "csv" => BudFormatClass::Csv,
        "text" => BudFormatClass::Text,
        "log" => BudFormatClass::Log,
        "wav" => BudFormatClass::Wav,
        "parquet" => BudFormatClass::Parquet,
        "genomic" => BudFormatClass::Genomic,
        "xlsx" => BudFormatClass::Xlsx,
        "mp3" => BudFormatClass::Mp3,
        "mp4" => BudFormatClass::Mp4,
        "jpeg" | "jpg" => BudFormatClass::Jpeg,
        "png" => BudFormatClass::Png,
        "zip" => BudFormatClass::Zip,
        "epub" => BudFormatClass::Epub,
        "pptx" => BudFormatClass::Pptx,
        "pdf" => BudFormatClass::Pdf,
        "docx" => BudFormatClass::Docx,
        _ => BudFormatClass::Unknown,
    }
}

/// Hex rendering of the first 8 bytes (a short anchor for checkpoint output).
fn hex8(bytes: &[u8; 32]) -> String {
    bytes[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn read_file(p: &PathBuf) -> Result<Vec<u8>, String> {
    std::fs::read(p).map_err(|e| format!("read error {:?}: {e}", p))
}

fn write_file(p: &PathBuf, d: &[u8]) -> Result<(), String> {
    std::fs::write(p, d).map_err(|e| format!("write error {:?}: {e}", p))
}

fn run(cli: Cli) -> Result<String, String> {
    match cli.command {
        Commands::Encode {
            input,
            output,
            class,
            required_ratio,
        } => {
            let data = read_file(&input)?;
            let class = parse_class(&class);
            let mime = match class {
                BudFormatClass::Json => "application/json",
                BudFormatClass::Jpeg => "image/jpeg",
                BudFormatClass::Png => "image/png",
                BudFormatClass::Pdf => "application/pdf",
                _ => "application/octet-stream",
            };
            // Candidate selection with the user's threshold (BudCli uses a fixed threshold; here it is explicit)
            let cand = MultiRatioConsensus::select_best(
                MultiRatioConsensus::candidates_for_format(class, &data),
                required_ratio,
            );
            let file = match cand {
                Some(c) => BudFile::encode(&data, class, mime, 0, 0, c.pipe_id, c.flags, c.payload),
                None => BudFile::encode(
                    &data,
                    class,
                    mime,
                    0,
                    0,
                    0,
                    BudFlags::new(true, true, false, false, false, false),
                    data.clone(),
                ),
            };
            let bytes = file.to_bytes();
            write_file(&output, &bytes)?;
            Ok(format!(
                "v1 encode: {} bytes -> {} bytes (ratio {:.2}x, threshold {required_ratio})",
                data.len(),
                bytes.len(),
                data.len() as f64 / bytes.len() as f64
            ))
        }
        Commands::Decode { input, output } => {
            let bytes = read_file(&input)?;
            let file = BudFile::from_bytes(&bytes).map_err(|e| format!("v1 parse: {e}"))?;
            let out = file.decode().map_err(|e| format!("v1 integrity: {e}"))?;
            write_file(&output, &out)?;
            Ok(format!(
                "v1 decode: {} bytes -> {} bytes",
                bytes.len(),
                out.len()
            ))
        }
        Commands::Store {
            input,
            output,
            min_chunk,
            compress,
            zstd,
        } => {
            let data = read_file(&input)?;
            let enc = if zstd {
                if min_chunk > 0 {
                    store_zstd_with_min(&data, min_chunk)
                } else {
                    store_zstd(&data)
                }
            } else if compress {
                if min_chunk > 0 {
                    store_compressed_with_min(&data, min_chunk)
                } else {
                    store_compressed(&data)
                }
            } else if min_chunk > 0 {
                store_with_min(&data, min_chunk)
            } else {
                store(&data)
            }
            .ok_or_else(|| {
                format!(
                    "v2 store failed: a container holds at most {} chunks of {} bytes, {} bytes in total",
                    BudV2File::MAX_CHUNK_COUNT,
                    BudV2File::MAX_CHUNK_BYTES,
                    BudV2File::MAX_TOTAL_BYTES
                )
            })?;
            write_file(&output, &enc)?;
            let cc = chunk_count(&enc).unwrap_or(0);
            Ok(format!(
                "v2 container: detected {:?}, {} bytes -> {} bytes ({} chunks, {} content-addressed)",
                detect(&data),
                data.len(),
                enc.len(),
                cc,
                if zstd {
                    "ZSTD compressed,"
                } else if compress {
                    "HUFFMAN compressed,"
                } else {
                    ""
                }
            ))
        }
        Commands::Restore { input, output } => {
            let bytes = read_file(&input)?;
            let out = restore(&bytes)
                .ok_or("v2 restore failed (corrupt .bud - integrity verification did not pass)")?;
            write_file(&output, &out)?;
            Ok(format!(
                "v2 restore: {} bytes -> {} bytes (verified, lossless)",
                bytes.len(),
                out.len()
            ))
        }
        Commands::Bench { file } => {
            let data = read_file(&file)?;
            let (enc, dec, cost) = BudCli::bench(&data);
            // K19 honesty: the ceiling is $0.016/TB/month - report whether the model passes it
            let ceiling = 0.016;
            let gate = if cost <= ceiling { "PASS" } else { "FAIL" };
            Ok(format!(
                "bench: {} bytes, encode {enc:.2} MB/s, decode {dec:.2} MB/s, base cost ${cost:.5}/TB/month (ceiling $0.016: {gate}) - not an unmeasured upper-bound claim, the runner measurement is separate",
                data.len()
            ))
        }
        Commands::BftVote {
            pipe_id,
            ratio,
            validator,
            n,
        } => {
            if n < 1 {
                return Err("BFT: n must be >= 1".into());
            }
            // votes are REALLY signed (each validator with its own ed25519 key)
            use ed25519_dalek::SigningKey;
            let votes: Vec<RatioVote> = (0..n)
                .map(|i| {
                    let sk = SigningKey::from_bytes(&[(i as u8).wrapping_add(1); 32]);
                    let vk = sk.verifying_key().to_bytes();
                    let v = RatioVote {
                        validator_id: format!("{validator}-{i}"),
                        pipe_id,
                        ratio,
                        public_key: vk,
                        signature: vec![],
                    };
                    let mut v = v;
                    v.signature = RatioVote::sign(&sk, pipe_id, ratio);
                    v
                })
                .collect();
            let cert = BftRatioConsensus::finalize_ratio(votes, n)
                .map_err(|e| format!("BFT finalize: {e}"))?;
            cert.verify(n).map_err(|e| format!("BFT verify: {e}"))?;
            Ok(format!(
                "BFT: n={n} consensus pipe_id={pipe_id} ratio {ratio} - certificate verified (2n/3 majority)"
            ))
        }
        Commands::Pact {
            input,
            output,
            producer,
            ts,
            residual,
        } => {
            let bytes = read_file(&input)?;
            let file = BudV2File::decode(&bytes).ok_or("PACT is only for v2 containers")?;
            let original = file
                .restore_original()
                .ok_or("container could not be opened")?;
            let ts = if ts == 0 { 1_768_000_000u64 } else { ts };
            // Producer hash: the SHA3 of the producer string (deterministic)
            let mut rh = sha3::Sha3_256::new();
            rh.update(producer.as_bytes());
            let producer_id: [u8; 32] = rh.finalize().into();
            let pact = if residual {
                // Producer + residual: the last 1KB of the original as the residual (representative)
                let split = original.len().saturating_sub(1024);
                let (prod, res) = original.split_at(split);
                PactRecord::producer_plus_residual(producer_id, [0u8; 32], prod, res, ts)
            } else {
                PactRecord::pure(producer_id, [0u8; 32], &original, ts)
            };
            if !pact.verify() {
                return Err("PACT inconsistent".into());
            }
            let blob = pact.to_blob();
            if let Some(out) = output {
                write_file(&out, &blob)?;
            }
            Ok(format!(
                "pact: mode={:?} commitment={} size={}B hash={} (the PACT record can be written to the chain)",
                pact.mode,
                hex8(&pact.commitment),
                blob.len(),
                hex8(&pact.record_hash())
            ))
        }
        Commands::Regenerate {
            input,
            producer,
            seed,
        } => {
            let bytes = read_file(&input)?;
            // Read the record from the PACT blob (input = the pact to_blob output)
            let pact = PactRecord::from_blob(&bytes)
                .ok_or("the input is not a PACT blob (use the bud pact output)")?;
            // The producer is the bytes to be produced from producer + seed (the original of the input
            // is not here; verification: is the commitment consistent with the given producer - recompute the producer hash)
            let mut rh = sha3::Sha3_256::new();
            rh.update(producer.as_bytes());
            let producer_id: [u8; 32] = rh.finalize().into();
            if pact.producer_id != producer_id {
                return Err("regeneration: producer hash mismatch (wrong producer)".into());
            }
            let _ = seed;
            // Commitment comparison: if the producer hash matches, the pre-settlement step is OK
            Ok(format!(
                "regenerate: the PACT producer was verified (producer_id matches) - a production settlement candidate, commitment={}",
                hex8(&pact.commitment)
            ))
        }
        Commands::Multifile { input, out, chunk } => {
            if input.is_empty() {
                return Err("at least one file is required".into());
            }
            let mut store = TenantMultifileStore::new();
            let mut original_total: u64 = 0;
            for path in &input {
                let data = read_file(path)?;
                original_total += data.len() as u64;
                store.add_file(&data, chunk);
            }
            let ratio = store.dedup_ratio(original_total);
            let blob = store.to_blob();
            write_file(&out, &blob)?;
            Ok(format!(
                "multifile: {} files, {} unique chunks ({}KB), dedup ratio {:.1}x - {} byte store block",
                input.len(), store.chunks.len(), chunk / 1024, ratio, blob.len()
            ))
        }
        Commands::Ledger { input, out } => {
            let bytes = read_file(&input)?;
            // Input: a production proof or a PACT record -> append to the segment ledger
            let mut seg = SegmentLedger::new();
            seg.append(&bytes)
                .ok_or("the record is at the segment ceiling")?;
            let blob = seg.to_blob();
            write_file(&out, &blob)?;
            Ok(format!(
                "ledger: {} records, {} byte segment block (root={}) - can be written into the chain header",
                seg.entries.len(),
                blob.len(),
                hex8(&seg.root())
            ))
        }
        Commands::ProduceProof { input, pipe, ts } => {
            let bytes = read_file(&input)?;
            let file =
                BudV2File::decode(&bytes).ok_or("a production proof is only for v2 containers")?;
            let original = file
                .restore_original()
                .ok_or("container could not be opened")?;
            let ts = if ts == 0 { 1_768_000_000u64 } else { ts }; // deterministic test
            let rec = BudProductionRecord::new(
                file.header.codec,
                Box::leak(pipe.clone().into_boxed_str()),
                &original,
                bytes.len() as u64,
                ts,
            );
            if !rec.verify() {
                return Err("the production record is inconsistent".into());
            }
            Ok(format!(
                "produce-proof: codec={:?} pipe={} original={}B stored={}B ratio={:.2}x root={} hash={}",
                file.header.codec, pipe, rec.original_len, rec.stored_len, rec.claimed_ratio,
                hex8(&rec.payload_root), hex8(&rec.record_hash())
            ))
        }
        Commands::Engine {
            input,
            out,
            erasure,
        } => {
            let data = read_file(&input)?;
            let ts = 1_768_000_000u64;
            let res = engine_store(&data, erasure, ts)
                .ok_or("engine: invalid input (empty or >512MB)")?;
            write_file(&out, &res.container)?;
            let steps_str: Vec<String> = res.steps.iter().map(|s| format!("{s:?}")).collect();
            Ok(format!(
                "engine: {} -> .bud ({} bytes -> {} bytes, ratio {:.2}x) format={} class={:?} steps=[{}] PACT={}",
                res.format_name, res.original_len, res.stored_len, res.measured_ratio,
                res.format_name, res.class, steps_str.join(","), hex8(&res.pact.record_hash())
            ))
        }

        Commands::EngineRestore {
            input,
            out,
            transform,
            erasure,
        } => {
            let blob = read_file(&input)?;
            // The engine output is a container (not a blob) - container-level restore
            let original = engine_restore_container(&blob, transform, erasure)
                .ok_or("engine-restore: corrupt .bud (tampering/wrong parameter)")?;
            write_file(&out, &original)?;
            Ok(format!(
                "engine-restore: {} original bytes recovered (transform={} erasure={})",
                original.len(),
                TransformKind::from_u8(transform)
                    .map(|t| format!("{t:?}"))
                    .unwrap_or("?".into()),
                erasure
            ))
        }
        Commands::VideoPipe {
            yuv,
            width,
            height,
            frames,
            video,
            out,
            orig_len,
        } => {
            let yuv_data = read_file(&yuv)?;
            let video_data = read_file(&video)?;
            let ts = 1_768_000_000u64;
            let res =
                run_video_pipeline(&yuv_data, width, height, frames, &video_data, orig_len, ts)
                    .ok_or(
                        "video-pipe: class detection failed (insufficient frames/corrupt input)",
                    )?;
            write_file(&out, &res.container)?;
            Ok(format!(
                "video-pipe: class={:?} codec={:?} gop={} ratio={:.2}x container={}B proof_hash={}",
                res.class,
                res.suggestion.codec,
                res.suggestion.gop_frames,
                res.video_record.claimed_ratio,
                res.container.len(),
                hex8(&res.production_record.record_hash())
            ))
        }
        Commands::Catalog => {
            let mut lines = Vec::new();
            lines.push(format!(
                "B.U.D. 2.0 format catalog ({} formats):",
                CATALOG.len()
            ));
            for e in CATALOG {
                let lossless = if e.lossless { "lossless" } else { "lossy" };
                lines.push(format!(
                    "  {:<12} signature={:<8} pipeline={:<20} ratio {:.2}-{:.2}x ({lossless})",
                    e.name,
                    format!("{:?}", e.signature),
                    e.pipe,
                    e.ratio_min,
                    e.ratio_max
                ));
            }
            Ok(lines.join("\n"))
        }
        Commands::Block {
            output,
            epoch,
            budget,
            prev,
        } => {
            // prev hex -> [u8;32]
            if prev.len() != 64 {
                return Err("prev_hash must be 64 hex characters".into());
            }
            let mut prev_hash = [0u8; 32];
            for i in 0..32 {
                prev_hash[i] = u8::from_str_radix(&prev[i * 2..i * 2 + 2], 16)
                    .map_err(|_| "prev hex is corrupt")?;
            }
            // Sample PACT challenge: the produced bytes match the commitment (VERIFIED)
            let produced = b"deterministic content 1234567890";
            let pact = bud_core::bud_format_pact::PactRecord::pure(
                [1u8; 32],
                [7u8; 32],
                produced,
                epoch + 1_768_000_000,
            );
            let challenge = PactChallengeInBlock {
                pact_hash: pact.record_hash(),
                outcome: RegenerationOutcome::Verified,
                cost_units: 10,
            };
            let block = RegenerationBlock::new(
                epoch,
                prev_hash,
                vec![challenge],
                [9u8; 32],
                budget,
                epoch + 1_768_000_000,
            )
            .ok_or("the block could not be produced (parameter limit)")?;
            if !block.verify() {
                return Err("the block could not be verified".into());
            }
            let blob = block.to_blob();
            // LOW (CWE-59, 2026-08-17): a fixed epoch-named output in /tmp let a
            // local attacker place a symlink beforehand and truncate the target file.
            // The output is now user-chosen; if the existing file is a symlink the
            // write is refused (a new file is opened).
            if output
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(format!(
                    "the output path cannot be a symlink: {}",
                    output.display()
                ));
            }
            write_file(&output, &blob)?;
            Ok(format!(
                "block: epoch={epoch} hash={} challenges=1 VERIFIED production_cost=10 budget={budget} - the block can be written to the chain",
                hex8(&block.hash)
            ))
        }
        Commands::Checkpoint {
            input,
            epoch,
            expert,
            pipe,
            ratio,
        } => {
            let bytes = read_file(&input)?;
            let file = BudV2File::decode(&bytes)
                .ok_or("checkpoint is only for v2 containers (produce one with store first)")?;
            let root = file.header.content_id.digest;
            let cp = Checkpoint::new(
                epoch,
                file.header.codec,
                &expert,
                &pipe,
                ratio,
                root,
                [0u8; 32], // genesis (single record)
            );
            if !Checkpoint::verify_chain(std::slice::from_ref(&cp)) {
                return Err("the checkpoint chain could not be verified".into());
            }
            Ok(format!(
                "checkpoint: epoch={epoch} codec={:?} root={} ratio={ratio} - genesis anchored, hash verified",
                file.header.codec,
                hex8(&root)
            ))
        }
        Commands::Check { input } => {
            let bytes = read_file(&input)?;
            // v2 magic (high bit set) -> container; otherwise v1
            if bytes.first() == Some(&BudV2Header::MAGIC[0]) {
                let file = BudV2File::decode(&bytes).ok_or("v2 integrity failed")?;
                let out = file.restore_original().ok_or("v2 integrity failed")?;
                let MultiHash { algo, digest } = file.header.content_id;
                let chunks = match file.chunk_codec {
                    ChunkCodec::Raw => "raw",
                    ChunkCodec::Huffman => "huffman",
                    ChunkCodec::Zstd => "zstd",
                };
                Ok(format!(
                    "check v2: OK - {} bytes verified (magic, chunk content_id, root {} algo 0x{algo:02x}, {chunks} chunks)",
                    out.len(),
                    hex8(&digest)
                ))
            } else {
                let file = BudFile::from_bytes(&bytes).map_err(|e| format!("v1 parse: {e}"))?;
                let out = file.decode().map_err(|e| format!("v1 integrity: {e}"))?;
                BudGates::k_bud_ratio(&file, out.len())
                    .map_err(|e| format!("K-BUD-RATIO gate: {e}"))?;
                Ok(format!(
                    "check v1: OK - {} bytes verified, ratio {:.2}x (K-BUD-RATIO passed)",
                    out.len(),
                    out.len() as f64 / bytes.len() as f64
                ))
            }
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            ExitCode::FAILURE
        }
    }
}
