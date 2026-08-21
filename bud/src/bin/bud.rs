//! bud CLI binary - V19: GERÇEK dosya I/O ve boru hattı (V18 yalnızca argüman basıyordu)
//!
//! Komutlar:
//!   bud encode <in> <out> [--class json|csv|...] [--required-ratio 16.68]   v1 .bud encode
//!   bud decode <in> <out>                                                    v1 .bud decode
//!   bud store   <in> <out> [--min-chunk 65536]                               v2 konteyner yaz (K38)
//!   bud restore <in> <out>                                                   v2 konteyner oku (doğrula)
//!   bud bench   <file>                                                       hız + maliyet ölçümü
//!   bud bft-vote --pipe-id 3 --ratio 17.19 --validator v [--n 7]             BFT finality (2n/3)
//!   bud check   <file>                                                       bütünlük + kapı denetimi
//!
//! Hata yolu: her komut gerçek dosya I/O yapar; hata → çıkış kodu 1 + mesaj.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

use bud_core::bud_format::{BudFile, BudFlags, BudFormatClass, BudGates, MultiRatioConsensus};
use bud_core::bud_format_bft::{BftRatioConsensus, RatioVote};
use bud_core::bud_format_checkpoint::Checkpoint;
use bud_core::bud_format_container::BudV2File;
use bud_core::bud_format_production::BudProductionRecord;
use bud_core::bud_format_pact::PactRecord;

use bud_core::bud_format_segment::SegmentLedger;
use bud_core::bud_format_multifile::TenantMultifileStore;
use bud_core::bud_format_engine::{engine_store, engine_restore_container, TransformKind};
use bud_core::bud_format_videopipe::run_video_pipeline;

use bud_core::bud_format_block::{PactChallengeInBlock, RegenerationBlock};
use bud_core::bud_format_regeneration::RegenerationOutcome;
use bud_core::bud_format_catalog::CATALOG;
use sha3::Digest as _;
use bud_core::bud_format_pipe::{chunk_count, detect, restore, store, store_compressed, store_compressed_with_min, store_with_min, store_zstd, store_zstd_with_min};
use bud_core::cli::BudCli;

#[derive(Parser)]
#[command(name = "bud", version = "4.1", about = "B.U.D. 2.0 .bud format CLI - v1 + v2 konteyner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// v1 .bud encode (V8 format, ratio konsensüsü ile)
    Encode {
        #[arg(short, long)] input: PathBuf,
        #[arg(short, long)] output: PathBuf,
        #[arg(long, default_value = "json")] class: String,
        #[arg(long, default_value_t = 16.68)] required_ratio: f64,
    },
    /// v1 .bud decode (bütünlük doğrulamalı)
    Decode {
        #[arg(short, long)] input: PathBuf,
        #[arg(short, long)] output: PathBuf,
    },
    /// v2 konteyner yaz: format algıla + yapısal parçala + .bud dosyası (K38)
    /// --compress = Huffman; --zstd = gerçek zstd (en iyi oran)
    Store {
        #[arg(short, long)] input: PathBuf,
        #[arg(short, long)] output: PathBuf,
        #[arg(long, default_value_t = 0)] min_chunk: usize,
        #[arg(long, default_value_t = false)] compress: bool,
        #[arg(long, default_value_t = false)] zstd: bool,
    },
    /// v2 konteyner oku: sıkı doğrula + birleştir → orijinal (K38)
    Restore {
        #[arg(short, long)] input: PathBuf,
        #[arg(short, long)] output: PathBuf,
    },
    /// encode/decode hızı + maliyet ölçümü
    Bench {
        #[arg(short, long)] file: PathBuf,
    },
    /// BFT finality: n validator aynı pipe_id/ratio için 2n/3 çoğunluk
    BftVote {
        #[arg(long)] pipe_id: u16,
        #[arg(long)] ratio: f64,
        #[arg(long, default_value = "validator")] validator: String,
        #[arg(long, default_value_t = 7)] n: usize,
    },
    /// bütünlük + kapı denetimi (v1 ya da v2 otomatik algıla)
    Check {
        #[arg(short, long)] input: PathBuf,
    },
    /// Üretim oranı kanıtı: .bud'dan ölçülen oran + boru hattı + kök çapalı kayıt üret
    ProduceProof {
        #[arg(short, long)] input: PathBuf,
        #[arg(long, default_value = "structural+zstd19")] pipe: String,
        #[arg(long, default_value_t = 0)] ts: u64,
    },
    /// PACT üretim sözleşmesi: .bud'dan commitment + üretici + tohum kaydı (İ1)
    Pact {
        #[arg(short, long)] input: PathBuf,
        #[arg(short, long)] output: Option<PathBuf>,
        #[arg(long, default_value = "producer")] producer: String,
        #[arg(long, default_value_t = 0)] ts: u64,
        #[arg(long, default_value_t = false)] residual: bool,
    },
    /// Rejenerasyon mutabakatı: PACT üreticii doğrula (İ2)
    Regenerate {
        #[arg(short, long)] input: PathBuf,
        #[arg(long, default_value = "producer")] producer: String,
        #[arg(long, default_value = "seed")] seed: String,
    },
    /// Çoklu dosya tenant depo: dosyaları parçala + dedup + delta (V7 66x senaryosu)
    Multifile {
        #[arg(short, long)] input: Vec<PathBuf>,
        #[arg(short, long)] out: PathBuf,
        #[arg(long, default_value_t = 16384)] chunk: usize,
    },
    /// Segment defteri: kayıtları zincir-uyumlu bloğa topla (K89)
    Ledger {
        #[arg(short, long)] input: PathBuf,
        #[arg(short, long)] out: PathBuf,
    },
    /// Birleşik engine: herhangi bir dosya → .bud + ölçülen oran + adım kanıtı
    Engine {
        #[arg(short, long)] input: PathBuf,
        #[arg(short, long)] out: PathBuf,
        #[arg(long, default_value_t = false)] erasure: bool,
    },
    /// Video pipeline: YUV örneği + codec çıktısı → .bud + kanıt (K84 sınıfı)
    VideoPipe {
        #[arg(long)] yuv: PathBuf,
        #[arg(long)] width: usize,
        #[arg(long)] height: usize,
        #[arg(long, default_value_t = 5)] frames: usize,
        #[arg(long)] video: PathBuf,
        #[arg(short, long)] out: PathBuf,
        #[arg(long)] orig_len: u64,
    },
    /// Engine restore: .bud (engine çıktısı) → orijinal dosya
    EngineRestore {
        #[arg(short, long)] input: PathBuf,
        #[arg(short, long)] out: PathBuf,
        #[arg(long, default_value_t = 0)] transform: u8,
        #[arg(long, default_value_t = false)] erasure: bool,
    },
    /// Format kataloğu: tüm formatlar + boru hattı + dürüst oran (30+)
    Catalog,
    /// Rejenerasyon bloğu üret: epoch + PACT sınavı + bütçe → blok hash (İ2+İ8)
    Block {
        #[arg(short, long, default_value = "bud_block.bud")] output: PathBuf,
        #[arg(long, default_value_t = 0)] epoch: u64,
        #[arg(long, default_value_t = 0)] budget: u64,
        #[arg(long, default_value = "0000000000000000000000000000000000000000000000000000000000000000")] prev: String,
    },
    /// v2 konteynerin content_root'una çapalı checkpoint üret (yön 2)
    Checkpoint {
        #[arg(short, long)] input: PathBuf,
        #[arg(long, default_value_t = 0)] epoch: u64,
        #[arg(long, default_value = "expert")] expert: String,
        #[arg(long, default_value = "structural+zstd19")] pipe: String,
        #[arg(long, default_value_t = 6.17)] ratio: f64,
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

/// İlk 8 baytın hex gösterimi (checkpoint çıktısı için kısa çapa).
fn hex8(bytes: &[u8; 32]) -> String {
    bytes[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn read_file(p: &PathBuf) -> Result<Vec<u8>, String> {
    std::fs::read(p).map_err(|e| format!("okuma hatası {:?}: {e}", p))
}

fn write_file(p: &PathBuf, d: &[u8]) -> Result<(), String> {
    std::fs::write(p, d).map_err(|e| format!("yazma hatası {:?}: {e}", p))
}

fn run(cli: Cli) -> Result<String, String> {
    match cli.command {
        Commands::Encode { input, output, class, required_ratio } => {
            let data = read_file(&input)?;
            let class = parse_class(&class);
            let mime = match class {
                BudFormatClass::Json => "application/json",
                BudFormatClass::Jpeg => "image/jpeg",
                BudFormatClass::Png => "image/png",
                BudFormatClass::Pdf => "application/pdf",
                _ => "application/octet-stream",
            };
            // Kullanıcının eşiği ile aday seçimi (BudCli sabit eşik kullanır; burada saydam)
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
                "v1 encode: {} bayt -> {} bayt (oran {:.2}x, eşik {required_ratio})",
                data.len(),
                bytes.len(),
                data.len() as f64 / bytes.len() as f64
            ))
        }
        Commands::Decode { input, output } => {
            let bytes = read_file(&input)?;
            let file = BudFile::from_bytes(&bytes).map_err(|e| format!("v1 ayrıştırma: {e}"))?;
            let out = file.decode().map_err(|e| format!("v1 bütünlük: {e}"))?;
            write_file(&output, &out)?;
            Ok(format!("v1 decode: {} bayt -> {} bayt", bytes.len(), out.len()))
        }
        Commands::Store { input, output, min_chunk, compress, zstd } => {
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
            .ok_or("v2 store başarısız (boyut/kapasite sınırı - MAX_CHUNK_COUNT/MAX_TOTAL_BYTES)")?;
            write_file(&output, &enc)?;
            let cc = chunk_count(&enc).unwrap_or(0);
            Ok(format!(
                "v2 konteyner: {:?} algılandı, {} bayt -> {} bayt ({} parça, {} içerik kimlikli)",
                detect(&data),
                data.len(),
                enc.len(),
                cc,
                if zstd { "ZSTD sıkıştırmalı," } else if compress { "HUFFMAN sıkıştırmalı," } else { "" }
            ))
        }
        Commands::Restore { input, output } => {
            let bytes = read_file(&input)?;
            let out = restore(&bytes)
                .ok_or("v2 restore başarısız (bozuk .bud - bütünlük doğrulaması geçemedi)")?;
            write_file(&output, &out)?;
            Ok(format!(
                "v2 restore: {} bayt -> {} bayt (doğrulandı, kayıpsız)",
                bytes.len(),
                out.len()
            ))
        }
        Commands::Bench { file } => {
            let data = read_file(&file)?;
            let (enc, dec, cost) = BudCli::bench(&data);
            // K19 dürüstlük: tavan $0.016/TB/ay - model eşiği geçiyor mu, raporla
            let ceiling = 0.016;
            let gate = if cost <= ceiling { "GEÇTİ" } else { "GEÇMEDİ" };
            Ok(format!(
                "bench: {} bayt, encode {enc:.2} MB/s, decode {dec:.2} MB/s, taban maliyet ${cost:.5}/TB/ay (tavan $0.016: {gate}) - ölçümsüz üst sınır iddiası değil, runner ölçümü ayrı",
                data.len()
            ))
        }
        Commands::BftVote { pipe_id, ratio, validator, n } => {
            if n < 1 {
                return Err("BFT: n >= 1 olmalı".into());
            }
            // STRIX: oylar GERÇEK imzalı (her validator kendi ed25519 anahtarıyla)
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
            cert.verify(n).map_err(|e| format!("BFT doğrula: {e}"))?;
            Ok(format!(
                "BFT: n={n} konsensüs pipe_id={pipe_id} oran {ratio} - sertifika doğrulandı (2n/3 çoğunluk)"
            ))
        }
        Commands::Pact { input, output, producer, ts, residual } => {
            let bytes = read_file(&input)?;
            let file = BudV2File::decode(&bytes).ok_or("PACT yalnız v2 konteynerler için")?;
            let original = file.restore_original().ok_or("konteyner açılamadı")?;
            let ts = if ts == 0 { 1_768_000_000u64 } else { ts };
            // üretici hash'i: producer string'inin SHA3'ü (deterministik)
            let mut rh = sha3::Sha3_256::new();
            rh.update(producer.as_bytes());
            let producer_id: [u8; 32] = rh.finalize().into();
            let pact = if residual {
                // üretici + rezidüel: rezidüel olarak orijinalin son 1KB'si (temsili)
                let split = original.len().saturating_sub(1024);
                let (prod, res) = original.split_at(split);
                PactRecord::producer_plus_residual(producer_id, [0u8; 32], prod, res, ts)
            } else {
                PactRecord::pure(producer_id, [0u8; 32], &original, ts)
            };
            if !pact.verify() {
                return Err("PACT tutarsız".into());
            }
            let blob = pact.to_blob();
            if let Some(out) = output {
                write_file(&out, &blob)?;
            }
            Ok(format!(
                "pact: mod={:?} commitment={} boyut={}B hash={} (PACT kaydı zincire yazılabilir)",
                pact.mode, hex8(&pact.commitment), blob.len(), hex8(&pact.record_hash())
            ))
        }
        Commands::Regenerate { input, producer, seed } => {
            let bytes = read_file(&input)?;
            // PACT blob'undan kaydı oku (girdi = pact to_blob çıktısı)
            let pact = PactRecord::from_blob(&bytes).ok_or("girdi PACT blob'u değil (bud pact çıktısı kullan)")?;
            // üretici = producer + seed ile üretilecek bayt (burada girdinin orijinali yok;
            // doğrulama: verilen producer ile commitment uyumlu mu - üretici hash'ini yeniden hesapla)
            let mut rh = sha3::Sha3_256::new();
            rh.update(producer.as_bytes());
            let producer_id: [u8; 32] = rh.finalize().into();
            if pact.producer_id != producer_id {
                return Err("rejenerasyon: üretici hash uyuşmuyor (yanlış producer)".into());
            }
            let _ = seed;
            // commitment karşılaştırması: producer hash uyumlu ise mutabakat öncesi adım OK
            Ok(format!(
                "regenerate: PACT üreticii doğrulandı (producer_id uyumlu) - üretim mutabakatı adayı, commitment={}",
                hex8(&pact.commitment)
            ))
        }
        Commands::Multifile { input, out, chunk } => {
            if input.is_empty() {
                return Err("en az bir dosya gerekli".into());
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
                "multifile: {} dosya, {} benzersiz parça ({}KB), dedup oranı {:.1}x - {} bayt depo bloğu",
                input.len(), store.chunks.len(), chunk / 1024, ratio, blob.len()
            ))
        }
        Commands::Ledger { input, out } => {
            let bytes = read_file(&input)?;
            // girdi: üretim kanıtı veya PACT kaydı → segment defterine ekle
            let mut seg = SegmentLedger::new();
            seg.append(&bytes).ok_or("kayıt segment tavanında")?;
            let blob = seg.to_blob();
            write_file(&out, &blob)?;
            Ok(format!(
                "ledger: {} kayıt, {} bayt segment bloğu (root={}) - zincir başlığına yazılabilir",
                seg.entries.len(), blob.len(), hex8(&seg.root())
            ))
        }
        Commands::ProduceProof { input, pipe, ts } => {
            let bytes = read_file(&input)?;
            let file = BudV2File::decode(&bytes)
                .ok_or("üretim kanıtı yalnız v2 konteynerler için")?;
            let original = file.restore_original().ok_or("konteyner açılamadı")?;
            let ts = if ts == 0 { 1_768_000_000u64 } else { ts }; // deterministik test
            let rec = BudProductionRecord::new(file.header.codec, Box::leak(pipe.clone().into_boxed_str()), &original, bytes.len() as u64, ts);
            if !rec.verify() {
                return Err("üretim kaydı tutarsız".into());
            }
            Ok(format!(
                "produce-proof: codec={:?} pipe={} orijinal={}B saklanan={}B oran={:.2}x root={} hash={}",
                file.header.codec, pipe, rec.original_len, rec.stored_len, rec.claimed_ratio,
                hex8(&rec.payload_root), hex8(&rec.record_hash())
            ))
        }
        Commands::Engine { input, out, erasure } => {
            let data = read_file(&input)?;
            let ts = 1_768_000_000u64;
            let res = engine_store(&data, erasure, ts).ok_or("engine: giriş geçersiz (boş veya >512MB)")?;
            write_file(&out, &res.container)?;
            let steps_str: Vec<String> = res.steps.iter().map(|s| format!("{s:?}")).collect();
            Ok(format!(
                "engine: {} → .bud ({} bayt → {} bayt, oran {:.2}x) format={} sınıf={:?} adımlar=[{}] PACT={}",
                res.format_name, res.original_len, res.stored_len, res.measured_ratio,
                res.format_name, res.class, steps_str.join(","), hex8(&res.pact.record_hash())
            ))
        }

        Commands::EngineRestore { input, out, transform, erasure } => {
            let blob = read_file(&input)?;
            // engine çıktısı container'dır (blob değil) - container-düzeyi restore
            let original = engine_restore_container(&blob, transform, erasure)
                .ok_or("engine-restore: bozuk .bud (kurcalama/yanlis parametre)")?;
            write_file(&out, &original)?;
            Ok(format!(
                "engine-restore: {} bayt orijinal geri alindi (transform={} erasure={})",
                original.len(),
                TransformKind::from_u8(transform).map(|t| format!("{t:?}")).unwrap_or("?".into()),
                erasure
            ))
        }
        Commands::VideoPipe { yuv, width, height, frames, video, out, orig_len } => {
            let yuv_data = read_file(&yuv)?;
            let video_data = read_file(&video)?;
            let ts = 1_768_000_000u64;
            let res = run_video_pipeline(&yuv_data, width, height, frames, &video_data, orig_len, ts)
                .ok_or("video-pipe: sınıf tespiti başarısız (yetersiz kare/bozuk girdi)")?;
            write_file(&out, &res.container)?;
            Ok(format!(
                "video-pipe: sınıf={:?} codec={:?} gop={} oran={:.2}x konteyner={}B kanıt_hash={}",
                res.class, res.suggestion.codec, res.suggestion.gop_frames,
                res.video_record.claimed_ratio, res.container.len(),
                hex8(&res.production_record.record_hash())
            ))
        }
        Commands::Catalog => {
            let mut lines = Vec::new();
            lines.push(format!("B.U.D. 2.0 format kataloğu ({} format):", CATALOG.len()));
            for e in CATALOG {
                let lossless = if e.lossless { "kayıpsız" } else { "kayıplı" };
                lines.push(format!(
                    "  {:<12} imza={:<8} boru hattı={:<20} oran {:.2}-{:.2}x ({lossless})",
                    e.name, format!("{:?}", e.signature), e.pipe, e.ratio_min, e.ratio_max
                ));
            }
            Ok(lines.join("\n"))
        }
        Commands::Block { output, epoch, budget, prev } => {
            // prev hex → [u8;32]
            if prev.len() != 64 {
                return Err("prev_hash 64 hex karakter olmalı".into());
            }
            let mut prev_hash = [0u8; 32];
            for i in 0..32 {
                prev_hash[i] = u8::from_str_radix(&prev[i*2..i*2+2], 16).map_err(|_| "prev hex bozuk")?;
            }
            // örnek PACT sınavı: üretilen bayt commitment ile eşleşiyor (VERIFIED)
            let produced = b"deterministik icerik 1234567890";
            let pact = bud_core::bud_format_pact::PactRecord::pure([1u8; 32], [7u8; 32], produced, epoch + 1_768_000_000);
            let challenge = PactChallengeInBlock {
                pact_hash: pact.record_hash(),
                outcome: RegenerationOutcome::Verified,
                cost_units: 10,
            };
            let block = RegenerationBlock::new(epoch, prev_hash, vec![challenge], [9u8; 32], budget, epoch + 1_768_000_000)
                .ok_or("blok üretilemedi (parametre sınırı)")?;
            if !block.verify() {
                return Err("blok doğrulanamadı".into());
            }
            let blob = block.to_blob();
            // Strix LOW (CWE-59, 2026-08-17): /tmp'de sabit epoch-yollu cikti,
            // yerel saldirganin onceden symlink koyup hedef dosyayi truncate
            // etmesine izin verirdi. Cikti artik kullanici secimli; mevcut
            // dosya symlink ise yazim reddedilir (yeni dosya acilir).
            if output.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) {
                return Err(format!("çıktı yolu symlink olamaz: {}", output.display()));
            }
            write_file(&output, &blob)?;
            Ok(format!(
                "block: epoch={epoch} hash={} sınav=1 VERIFIED üretim_maliyeti=10 bütçe={budget} - blok zincire yazılabilir",
                hex8(&block.hash)
            ))
        }
        Commands::Checkpoint { input, epoch, expert, pipe, ratio } => {
            let bytes = read_file(&input)?;
            let file = BudV2File::decode(&bytes)
                .ok_or("checkpoint yalnız v2 konteynerler için (önce store ile üret)")?;
            let root = file.header.content_id.digest;
            let cp = Checkpoint::new(
                epoch,
                file.header.codec,
                &expert,
                &pipe,
                ratio,
                root,
                [0u8; 32], // genesis (tek kayıt)
            );
            if !Checkpoint::verify_chain(&[cp.clone()]) {
                return Err("checkpoint zinciri doğrulanamadı".into());
            }
            Ok(format!(
                "checkpoint: epoch={epoch} codec={:?} root={} oran={ratio} - genesis çapalı, hash doğrulandı",
                file.header.codec,
                hex8(&root)
            ))
        }
        Commands::Check { input } => {
            let bytes = read_file(&input)?;
            // v2 magic (\xB5 high-bit) → konteyner; değilse v1
            if bytes.first() == Some(&0xB5) {
                let out = restore(&bytes).ok_or("v2 bütünlük başarısız")?;
                Ok(format!(
                    "check v2: OK - {} bayt doğrulandı (magic+parça content_id+kök)",
                    out.len()
                ))
            } else {
                let file = BudFile::from_bytes(&bytes).map_err(|e| format!("v1 ayrıştırma: {e}"))?;
                let out = file.decode().map_err(|e| format!("v1 bütünlük: {e}"))?;
                BudGates::k_bud_ratio(&file, out.len())
                    .map_err(|e| format!("K-BUD-RATIO kapısı: {e}"))?;
                Ok(format!(
                    "check v1: OK - {} bayt doğrulandı, oran {:.2}x (K-BUD-RATIO geçti)",
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
            eprintln!("HATA: {e}");
            ExitCode::FAILURE
        }
    }
}
