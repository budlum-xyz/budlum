//! B.U.D. 2.0 - Quad-Ring + Fidelity Core + Quantum Chain + .bud Format + BFT + Registry + Economics + CLI + Integration + Real FFI + Revolutionary + Optical + Transpile + SecureDB + Ultra

#![forbid(unsafe_code)]

pub mod bud_fixed_point;
pub mod bud_format;
pub mod bud_format_autozstd;
pub mod bud_format_av2;
pub mod bud_format_bft;
pub mod bud_format_block;
pub mod bud_format_bloom;
pub mod bud_format_catalog;
pub mod bud_format_checkpoint;
pub mod bud_format_columnar;
pub mod bud_format_container;
pub mod bud_format_crop;
pub mod bud_format_culling;
pub mod bud_format_das;
pub mod bud_format_dbdelta;
pub mod bud_format_dedup;
pub mod bud_format_dictionary;
pub mod bud_format_economics;
pub mod bud_format_edge;
pub mod bud_format_encpact;
pub mod bud_format_engine;
pub mod bud_format_erasure;
pub mod bud_format_exepdf;
pub mod bud_format_fastcdc;
pub mod bud_format_fidelitygate;
pub mod bud_format_fountain;
pub mod bud_format_genomic;
pub mod bud_format_governance;
pub mod bud_format_guardian;
pub mod bud_format_huffman;
pub mod bud_format_hw;
pub mod bud_format_integration;
pub mod bud_format_jpegre;
pub mod bud_format_lazyrepair;
pub mod bud_format_logfield;
pub mod bud_format_lowrank;
pub mod bud_format_lrc;
pub mod bud_format_markdown;
pub mod bud_format_matrix;
pub mod bud_format_media;
pub mod bud_format_model;
pub mod bud_format_msr;
pub mod bud_format_multifile;
pub mod bud_format_nvc;
pub mod bud_format_office;
pub mod bud_format_optical;
pub mod bud_format_pact;
pub mod bud_format_pcap;
pub mod bud_format_pgm;
pub mod bud_format_pipe;
pub mod bud_format_pointcloud;
pub mod bud_format_por;
pub mod bud_format_prodcost;
pub mod bud_format_production;
pub mod bud_format_qos;
pub mod bud_format_ratioconsensus;
pub mod bud_format_real;
pub mod bud_format_realcorpus;
pub mod bud_format_recipe;
pub mod bud_format_regeneration;
pub mod bud_format_registry;
pub mod bud_format_repairband;
pub mod bud_format_revolutionary;
pub mod bud_format_scrub;
pub mod bud_format_secure_db;
pub mod bud_format_securededup;
pub mod bud_format_segment;
pub mod bud_format_serviceclass;
pub mod bud_format_shamir;
pub mod bud_format_social;
pub mod bud_format_social2;
pub mod bud_format_telemetry;
pub mod bud_format_timeseries;
pub mod bud_format_tiny;
pub mod bud_format_transpile;
pub mod bud_format_tricore;
pub mod bud_format_ultra;
pub mod bud_format_video;
pub mod bud_format_videopipe;
pub mod bud_format_view;
pub mod bud_format_wal;
pub mod bud_format_zkbridge;
pub mod churn;
pub mod cli;
pub mod fidelity;
pub mod gates;
pub mod price;
pub mod provider;
pub mod quantum;
pub mod quantum_chain;
pub mod ratio;

pub use bud_fixed_point::{
    fixed_div, fixed_from_int, fixed_mul, fixed_ratio, fixed_sqrt, fixed_to_int, FIXED_FRAC_BITS,
    FIXED_ONE,
};
pub use bud_format::{
    BudFile, BudFlags, BudFormatClass, BudGates, MultiRatioConsensus, BUD_MAGIC, BUD_VERSION,
};
pub use bud_format_bft::{BftRatioConsensus, RatioFinalityCert, RatioVote};
pub use bud_format_block::{PactChallengeInBlock, RegenerationBlock, BLOCK_MAGIC};
pub use bud_format_catalog::{by_name, catalog_detect, catalog_size, FormatCatalogEntry, CATALOG};
pub use bud_format_checkpoint::Checkpoint;
pub use bud_format_columnar::{
    columnar_decode, columnar_encode, columnar_from_blob, columnar_to_blob, ColumnarMode,
    JsonColumnar, COLUMNAR_MAGIC,
};
pub use bud_format_container::{
    content_id, structural_join, structural_split, structural_split_compact, BudV2File,
    BudV2Header, ChunkCodec, FormatCodec, MultiHash, StructuralKind,
};
pub use bud_format_crop::{CropDerivation, CROP_MAGIC, MCU_SIZE};
pub use bud_format_culling::{ClusterTier, CullingPlan, CULL_MAGIC};
pub use bud_format_das::{das_root, DasOwnership, DasProof, DasSampler, DAS_MAGIC};
pub use bud_format_dedup::{DedupOutcome, PowChallenge, TenantDedup};
pub use bud_format_dictionary::{TenantDictionary, DICT_MAGIC};
pub use bud_format_economics::{
    egress_cost, flat_holds_ceiling, flat_price, holds_egress, residual_holds_price,
    residual_price, tape_cost_per_tb_month, tape_holds_ceiling, ArchiveTier, BudEconomics,
    EconomicsGates, EgressZone, GlobalDedup, MerkleTrie, TAPE_USD_PER_TB_MONTH,
};
pub use bud_format_engine::{
    engine_restore_container, engine_restore_full, engine_restore_raw, engine_store, EngineResult,
    PipeStep, TransformKind, ENGINE_MAGIC,
};
pub use bud_format_erasure::{CauchyMds, ERASURE_MAGIC};
pub use bud_format_exepdf::{
    ExeKind, ExeSectionSplit, PdfStreamSplit, EXE_SPLIT_MAGIC, PDF_SPLIT_MAGIC,
};
pub use bud_format_fastcdc::{
    FastCdcSplit, FASTCDC_MAGIC, FCDC_AVG_CHUNK, FCDC_MAX_CHUNK, FCDC_MIN_CHUNK,
};
pub use bud_format_huffman::{HuffmanCoder, BUD_HFM_MAGIC};
pub use bud_format_integration::{
    BudErasure, BudLivingThreshold, BudStorageAssignment, IntegrationGates,
};
pub use bud_format_jpegre::{JpegAnalysis, JPEG_RE_MAGIC};
pub use bud_format_logfield::{
    parse_nginx_line, LogFieldColumnar, NginxField, LOGFIELD_MAGIC, NGINX_FIELDS,
};
pub use bud_format_lrc::{LrcRecord, LrcScheme, LRC_MAGIC};
pub use bud_format_markdown::{MarkdownSplit, MdSection, MD_MAGIC};
pub use bud_format_model::{FloatKind, ModelFloatSplit, MODEL_MAGIC};
pub use bud_format_multifile::{MultifileChunk, TenantMultifileStore, DEFAULT_CHUNK, MULTI_MAGIC};
pub use bud_format_optical::{LogTemplate, LogTemplateMiner, OpticalGates, OpticalPrompt};
pub use bud_format_pact::{PactMode, PactRecord, PACT_MAGIC};
pub use bud_format_pipe::{
    chunk_count, detect, restore, restore_json_columnar, store, store_compressed,
    store_compressed_with_min, store_json_columnar, store_with_min, store_zstd,
    store_zstd_with_min, DEFAULT_MIN_CHUNK,
};
pub use bud_format_por::{PorChallenge, PorKey, PorResponse, PorTag};
pub use bud_format_production::{BudProductionRecord, ProductionGates};
pub use bud_format_ratioconsensus::{
    class_of, ContentClass, RatioCandidateAgent, RatioConsensus, RATIO_CONS_MAGIC,
};
pub use bud_format_real::{
    zstd_compress, zstd_decompress_safe, RealBench, RealCompressor, ZSTD_MAX_DECOMPRESSED,
};
pub use bud_format_regeneration::{
    RegenerationChallenge, RegenerationOutcome, RegenerationRecord, REGEN_MAGIC,
};
pub use bud_format_registry::{
    DictLoopDetector, MimeRegistry, RatioProof, RegistryGates, SecondPreimageResistantMerkle,
};
pub use bud_format_revolutionary::{
    ColumnarTransform, CompactTable, Evidence, Fact, HybridSearch, RevolutionaryGates,
    SecretRedactor, SqliteChunk,
};
pub use bud_format_secure_db::{SecureDbGates, SecureEmbeddedDb};
pub use bud_format_segment::{SegmentLedger, SEGMENT_MAGIC};
pub use bud_format_shamir::{ShamirShare, SHAMIR_MAGIC};
pub use bud_format_social::{SocialBridgeRecord, SocialPlatform};
pub use bud_format_timeseries::{TimeSeriesColumnar, TS_MAGIC};
pub use bud_format_transpile::{AstTransform, BashTranspile, TranspileGates};
pub use bud_format_ultra::{CodeTarif, DiffusionPrompt, Log4Layer, UltraGates};
pub use bud_format_video::{
    classify_content, BudVideoRecord, VideoCodec, VideoContentClass, VideoGates, VideoSuggestion,
};
pub use bud_format_videopipe::{run_video_pipeline, VideoPipelineResult, VIDEO_PIPE_MAGIC};
pub use bud_format_view::{CompiledView, KeySchema, VIEW_MAGIC};
pub use churn::{ChurnFixture, ChurnResult, QuadRing};
pub use cli::BudCli;
pub use fidelity::{ContentId, FidelityCore, FidelityError, RenderFormat};
pub use gates::{GateResult, GateSuite};
pub use price::{Expansion, PriceError, PriceModel};
pub use provider::{Provider, ProviderClass, ProviderError};
pub use quantum::{QuantumError, QuantumSuite};
pub use quantum_chain::{
    DualWallet, FiatShamirTranscript, HybridFinalityVote, HybridTx, MobileSelfProvider,
    QuantumChainGates, Sha3Hasher, MAX_BLOCK_BYTES, PQ_SCHEME_ID_FINAL,
};
pub use ratio::{FormatClass, Pipe, RatioResult};
#[cfg(feature = "bud3")]
pub mod bud_format_optical_transfer;
#[cfg(feature = "bud3")]
pub mod bud_format_qrmatrix;
#[cfg(feature = "bud3")]
pub mod bud_format_recipe_record;
#[cfg(feature = "bud3")]
pub mod bud_format_spec;
pub mod bud_format_wire;
// `bud_format_hardening` and `bud_format_qrvideo` are 3.0 modules but they had
// no gate: two `#[cfg(feature = "bud3")]` attributes were written on top of
// each other above (a repeated attribute is equivalent to a single gate for the
// compiler, the extra one is swallowed silently) and these two were left
// OUTSIDE the gate. The result: the default (bud2) build also pulled in the
// QR-video surface, so 3.0 code compiled while 3.0 was off. The duplicates were
// removed and both modules were moved under the gate they belong to.
#[cfg(all(test, feature = "bud3"))]
pub mod bud3_live_test;
pub mod bud_format_edition;
#[cfg(feature = "bud3")]
pub mod bud_format_hardening;
#[cfg(feature = "bud3")]
pub mod bud_format_qrvideo;
#[cfg(feature = "bud3")]
pub mod bud_format_r3fix;
#[cfg(feature = "bud3")]
pub mod bud_format_ux;
