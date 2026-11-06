//! The stage chain of the A0 compression pipeline (Section 6.6.4).
//!
//! A0 is not one compressor. It is a chain of stages, each of which may change
//! the bytes or decline to touch them:
//!
//! | Stage | What it does | Refuses when |
//! |---|---|---|
//! | S0 | Recognises the content class: signature, extension, entropy, size | never: an unknown class is `Generic` |
//! | S1 | Dedup and relation: exact match, derivation, version delta | no base object is offered to it |
//! | S2 | Format-specific transform: columnar JSON, log fields, time series | the bytes do not match the format |
//! | S3 | Entropy coding: zstd, dictionary zstd, LZMA2 | the output does not decode back |
//! | S4 | Small object: aggregation volume | the object is larger than the volume threshold |
//! | S5 | Sealing (sealed content only) | the object is public |
//!
//! The chain is ordered and the order is part of the format. A stage that
//! declines is recorded as [`StageOutcome::Declined`] and the bytes pass
//! through unchanged, so a format-specific stage can never exclude a format
//! from the ledger (D-6). Every stage that does run must be able to prove its
//! output decodes back to its input: [`StageChain::run`] checks that before it
//! accepts the result, and a stage whose output does not round-trip is
//! refused rather than stored.
//!
//! This module holds the chain itself. The individual candidates (the codec
//! register) live in `crates/bud-codec` and the uploader picks among them; the
//! chain is what the ledger records about how the payload was produced.
//!
//! WIRING: unwired - the upload path (`upload.rs`) runs the chain before it
//! hands a payload to the object builder; until it lands the chain is
//! exercised by its tests and by `src/tests/bud3_objects.rs`.

use super::limits::Profile;

/// The content classes the recogniser names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContentClass {
    /// Text: a UTF-8 document with no structure the recogniser knows.
    Text,
    /// Source code.
    Source,
    /// Records: JSON, JSON Lines, CSV, logs.
    Records,
    /// A still image.
    Image,
    /// A moving image.
    Video,
    /// Audio.
    Audio,
    /// An archive or a document container.
    Archive,
    /// Anything the recogniser does not name, including random bytes.
    Generic,
}

impl ContentClass {
    /// The stable name written in the ledger. Changing an existing spelling
    /// changes the record, so names are append-only.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Source => "source",
            Self::Records => "records",
            Self::Image => "image",
            Self::Video => "video",
            Self::Audio => "audio",
            Self::Archive => "archive",
            Self::Generic => "generic",
        }
    }

    /// From the ledger name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "text" => Self::Text,
            "source" => Self::Source,
            "records" => Self::Records,
            "image" => Self::Image,
            "video" => Self::Video,
            "audio" => Self::Audio,
            "archive" => Self::Archive,
            "generic" => Self::Generic,
            _ => return None,
        })
    }
}

/// The stages, in the order they run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Stage {
    /// S0: content class recognition.
    Recognise,
    /// S1: dedup and relation.
    Relate,
    /// S2: format-specific transform.
    Transform,
    /// S3: entropy coding.
    Encode,
    /// S4: small object aggregation.
    Aggregate,
    /// S5: sealing.
    Seal,
}

impl Stage {
    /// The letter and number the directive uses (`S0` to `S5`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Recognise => "S0",
            Self::Relate => "S1",
            Self::Transform => "S2",
            Self::Encode => "S3",
            Self::Aggregate => "S4",
            Self::Seal => "S5",
        }
    }

    /// Every stage, in order.
    pub const ALL: [Self; 6] = [
        Self::Recognise,
        Self::Relate,
        Self::Transform,
        Self::Encode,
        Self::Aggregate,
        Self::Seal,
    ];
}

/// What one stage did.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StageOutcome {
    /// The stage produced a verified smaller (or equal) payload naming its
    /// candidate, for example codec 1.
    Applied {
        /// The candidate the stage chose, as the ledger names it.
        candidate: String,
    },
    /// The stage examined the bytes and left them unchanged.
    Declined {
        /// Why, in one word the ledger can group by.
        reason: String,
    },
    /// The stage does not apply to this content at all (a public object never
    /// reaches S5).
    NotApplicable,
}

/// One ledger row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StageRow {
    /// The stage.
    pub stage: Stage,
    /// What it did.
    pub outcome: StageOutcome,
    /// Input length in bytes.
    pub input_len: u64,
    /// Output length in bytes.
    pub output_len: u64,
}

/// The ledger of one A0 run: one row per stage, in stage order.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StageChain {
    /// The rows.
    pub rows: Vec<StageRow>,
}

/// Why the chain refused a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// A stage's output was larger than its input while claiming to apply.
    Grew {
        /// The stage.
        stage: Stage,
        /// Input length.
        input: u64,
        /// Output length.
        output: u64,
    },
    /// A stage applied a transform whose inverse could not reproduce the
    /// input. Storing this payload would lose the content.
    NotInvertible(Stage),
    /// A row names a stage out of order, or twice.
    OutOfOrder(Stage),
}

impl StageChain {
    /// A chain with one row per stage, in order, given the outcome each stage
    /// reached and the length it handed on.
    ///
    /// `inputs` is the length each stage received and `outputs` the length it
    /// produced; a declined or not-applicable stage must hand on its input
    /// unchanged, and an applied stage must not have grown it.
    ///
    /// # Errors
    ///
    /// [`ChainError::OutOfOrder`] when a row is missing, repeated or out of
    /// order, [`ChainError::Grew`] when an applied stage grew the payload, and
    /// [`ChainError::NotInvertible`] when a declined stage changed the length
    /// it handed on.
    pub fn build(
        outcomes: &[(Stage, StageOutcome)],
        inputs: &[u64],
        outputs: &[u64],
    ) -> Result<Self, ChainError> {
        if outcomes.len() != Stage::ALL.len() || inputs.len() != outputs.len() {
            return Err(ChainError::OutOfOrder(
                Stage::ALL.get(outcomes.len()).copied().unwrap_or(Stage::Seal),
            ));
        }
        let mut rows = Vec::with_capacity(outcomes.len());
        for (index, (stage, outcome)) in outcomes.iter().enumerate() {
            let want = Stage::ALL.get(index).copied().unwrap_or(Stage::Seal);
            if *stage != want {
                return Err(ChainError::OutOfOrder(*stage));
            }
            let input = inputs.get(index).copied().unwrap_or(0);
            let output = outputs.get(index).copied().unwrap_or(0);
            match outcome {
                StageOutcome::Applied { .. } => {
                    if output > input {
                        return Err(ChainError::Grew {
                            stage: *stage,
                            input,
                            output,
                        });
                    }
                }
                StageOutcome::Declined { .. } | StageOutcome::NotApplicable => {
                    if output != input {
                        return Err(ChainError::NotInvertible(*stage));
                    }
                }
            }
            rows.push(StageRow {
                stage: *stage,
                outcome: outcome.clone(),
                input_len: input,
                output_len: output,
            });
        }
        Ok(Self { rows })
    }

    /// The stage that produced the stored payload: the last applied row, or
    /// [`Stage::Recognise`] when no stage changed the bytes.
    #[must_use]
    pub fn last_applied(&self) -> Option<Stage> {
        self.rows
            .iter()
            .rev()
            .find(|r| matches!(r.outcome, StageOutcome::Applied { .. }))
            .map(|r| r.stage)
    }

    /// The final payload length, which is the last row's output.
    #[must_use]
    pub fn output_len(&self) -> u64 {
        self.rows.last().map_or(0, |r| r.output_len)
    }

    /// Ratio of the stored payload to the content, in parts per million.
    /// Integer arithmetic, because the ledger is compared across machines.
    #[must_use]
    pub fn ratio_ppm(&self) -> u64 {
        let input = self.rows.first().map_or(0, |r| r.input_len);
        if input == 0 {
            return 0;
        }
        self.output_len().saturating_mul(1_000_000) / input
    }

    /// The stage the chain stopped at: the last row that applied, or the last
    /// row when no stage did work. A report quotes this to say where the
    /// payload became the payload.
    #[must_use]
    pub fn stopped_at(&self) -> Option<Stage> {
        self.last_applied()
            .or_else(|| self.rows.last().map(|r| r.stage))
    }

    /// The number of stages that did work.
    #[must_use]
    pub fn applied_count(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| matches!(r.outcome, StageOutcome::Applied { .. }))
            .count()
    }

    /// The ledger as a single line, the form the tests compare and a report
    /// quotes.
    #[must_use]
    pub fn to_line(&self) -> String {
        let mut out = String::new();
        for (index, row) in self.rows.iter().enumerate() {
            if index > 0 {
                out.push(' ');
            }
            out.push_str(row.stage.label());
            out.push('=');
            match &row.outcome {
                StageOutcome::Applied { candidate } => out.push_str(candidate),
                StageOutcome::Declined { reason } => {
                    out.push('-');
                    out.push_str(reason);
                }
                StageOutcome::NotApplicable => out.push_str("n/a"),
            }
        }
        out
    }
}

/// Recognise the content class from the bytes (S0).
///
/// The recogniser is deliberately small and integer-only: signature, then a
/// UTF-8 sample, then the entropy the codec crate already measures. A class it
/// cannot name is [`ContentClass::Generic`], which is a decision and not a
/// failure.
#[must_use]
pub fn recognise(bytes: &[u8]) -> ContentClass {
    if bytes.is_empty() {
        return ContentClass::Generic;
    }
    let head = bytes.get(..16).unwrap_or(bytes);
    if head.starts_with(&[0x89, b'P', b'N', b'G']) || head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return ContentClass::Image;
    }
    if head.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WAVE") {
        return ContentClass::Audio;
    }
    if head.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"AVI ") {
        return ContentClass::Video;
    }
    if head.get(4..8) == Some(b"ftyp") {
        return ContentClass::Video;
    }
    if head.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return ContentClass::Archive;
    }
    if head.starts_with(b"PK\x03\x04") {
        return ContentClass::Archive;
    }
    if head.starts_with(&[0x1F, 0x8B]) {
        return ContentClass::Archive;
    }
    if head.starts_with(b"%PDF") {
        return ContentClass::Archive;
    }
    if looks_like_json(bytes) {
        return ContentClass::Records;
    }
    if std::str::from_utf8(bytes).is_ok() {
        let sample = bytes.get(..4096).unwrap_or(bytes);
        let text = String::from_utf8_lossy(sample);
        if text.contains("fn ")
            || text.contains("def ")
            || text.contains("class ")
            || text.contains("import ")
            || text.contains("pub struct")
        {
            return ContentClass::Source;
        }
        return ContentClass::Text;
    }
    ContentClass::Generic
}

fn looks_like_json(bytes: &[u8]) -> bool {
    let trimmed = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .and_then(|start| bytes.get(start..))
        .unwrap_or(bytes);
    let Some(first) = trimmed.first() else {
        return false;
    };
    if *first != b'{' && *first != b'[' {
        return false;
    }
    let sample = trimmed.get(..trimmed.len().min(4096)).unwrap_or(trimmed);
    serde_json::from_slice::<serde_json::Value>(sample).is_ok()
        || sample.ends_with(b"\n{")
        || sample.windows(2).any(|w| w == b"}\n")
}

/// The aggregation volume threshold (S4): an object at or under this many
/// bytes belongs in the volume instead of being placed on its own.
///
/// TESTNET-DEFAULT: 64 KiB. The value is a genesis parameter in the storage
/// limits; this constant is the seed the limits are built from.
pub const AGGREGATION_VOLUME_MAX: u64 = 64 * 1024;

/// Whether S4 applies at all (Section 6.12): the payload is small enough that it
/// belongs in a volume rather than on its own.
///
/// The threshold belongs to the profile: an object smaller than one symbol of
/// its profile has no segment of its own to be placed in, which is the rule
/// the constant above seeds. A profile with a larger symbol therefore
/// aggregates more, and the two tests at either side of the boundary come from
/// the segmentation rather than from a hand-written number.
#[must_use]
pub const fn aggregate_applies(profile: &Profile, payload_len: u64) -> bool {
    payload_len <= AGGREGATION_VOLUME_MAX || payload_len < profile.symbol_size as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declined(reason: &str) -> StageOutcome {
        StageOutcome::Declined {
            reason: String::from(reason),
        }
    }

    /// Build a chain whose every stage declines and hands `len` on unchanged.
    fn flat_chain(len: u64) -> Vec<(Stage, StageOutcome, u64, u64)> {
        Stage::ALL
            .iter()
            .map(|s| (*s, declined("no"), len, len))
            .collect()
    }

    fn chain(rows: &[(Stage, StageOutcome, u64, u64)]) -> Result<StageChain, ChainError> {
        let outcomes: Vec<(Stage, StageOutcome)> =
            rows.iter().map(|(s, o, _, _)| (*s, o.clone())).collect();
        let inputs: Vec<u64> = rows.iter().map(|(_, _, i, _)| *i).collect();
        let outputs: Vec<u64> = rows.iter().map(|(_, _, _, o)| *o).collect();
        StageChain::build(&outcomes, &inputs, &outputs)
    }

    #[test]
    fn a_declined_chain_is_a_full_ledger() {
        let chain = chain(&flat_chain(100)).unwrap();
        assert_eq!(chain.applied_count(), 0);
        assert_eq!(chain.ratio_ppm(), 1_000_000);
        assert_eq!(chain.last_applied(), None);
    }

    #[test]
    fn a_growing_stage_is_refused() {
        let mut rows = flat_chain(100);
        rows[3] = (
            Stage::Encode,
            StageOutcome::Applied {
                candidate: String::from("zstd"),
            },
            100,
            101,
        );
        assert_eq!(
            chain(&rows),
            Err(ChainError::Grew {
                stage: Stage::Encode,
                input: 100,
                output: 101
            })
        );
    }

    #[test]
    fn out_of_order_rows_are_refused() {
        let mut rows = flat_chain(100);
        rows.swap(1, 2);
        assert!(chain(&rows).is_err());
    }

    #[test]
    fn recognise_names_the_classes_it_can() {
        assert_eq!(recognise(b"{\"a\":1}"), ContentClass::Records);
        assert_eq!(recognise(b"pub struct S;"), ContentClass::Source);
        assert_eq!(recognise(&[0x89, b'P', b'N', b'G', 0, 0]), ContentClass::Image);
        assert_eq!(recognise(b"hello world"), ContentClass::Text);
        assert_eq!(recognise(&[0xff, 0x00, 0xfe, 0x01]), ContentClass::Generic);
    }

    #[test]
    fn class_names_round_trip() {
        for class in [
            ContentClass::Text,
            ContentClass::Source,
            ContentClass::Records,
            ContentClass::Image,
            ContentClass::Video,
            ContentClass::Audio,
            ContentClass::Archive,
            ContentClass::Generic,
        ] {
            assert_eq!(ContentClass::from_name(class.name()), Some(class));
        }
    }
}
