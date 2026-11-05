//! The adopted B.U.D. compression methods, kept for the B.U.D. 3.0 codec
//! registry: lossless transforms only. The lossy, economic and generative
//! layers of the old tree are gone with the removal.
//! Exposed for the B.U.D. 3.0 codec registry: the registry wires these
//! transforms.

#![forbid(unsafe_code)]

pub mod bud_format_autozstd;
pub mod bud_format_bloom;
pub mod bud_format_catalog;
pub mod bud_format_columnar;
pub mod bud_format_container;
pub mod bud_format_crop;
pub mod bud_format_dbdelta;
pub mod bud_format_dictionary;
pub mod bud_format_exepdf;
pub mod bud_format_fastcdc;
pub mod bud_format_genomic;
pub mod bud_format_huffman;
pub mod bud_format_jpegre;
pub mod bud_format_logfield;
pub mod bud_format_markdown;
pub mod bud_format_media;
pub mod bud_format_model;
pub mod bud_format_multifile;
pub mod bud_format_office;
pub mod bud_format_pcap;
pub mod bud_format_pgm;
pub mod bud_format_pointcloud;
pub mod bud_format_r3fix;
pub mod bud_format_ratioconsensus;
pub mod bud_format_real;
pub mod bud_format_timeseries;
pub mod bud_format_tiny;
pub mod bud_format_wal;
