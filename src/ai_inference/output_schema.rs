//! The Markdown output schema rule for AI inference layer outputs.
//!
//! Education report (stage 9): every output this layer produces is Markdown,
//! and an output that fails the schema check is **rejected and regenerated**,
//! never downgraded to a format it was not. This module is the schema; the
//! executor applies it before a result enters the registry, so a malformed
//! output never reaches the SocialFi NFT bridge or the Pollen `DataAsset`
//! record that follow finalization.
//!
//! The checks are deliberately the ones a machine can agree on:
//!
//! 1. strict UTF-8 (no replacement of undecodable bytes);
//! 2. non-empty after trimming;
//! 3. heading hierarchy does not skip a level while descending (a `##`
//!    following a `#` is fine; a `###` immediately after a `#` is not).
//!    Level 0 (no heading) is always reachable from any level - a heading
//!    cannot "skip" from nothing;
//! 4. code fences are balanced: a fence that opens has to close, and a fence
//!    inside a fence is a closer, not a nested fence (CommonMark toggling);
//! 5. tables are well formed: every row of a table block declares the same
//!    number of columns, and the row after the header is a separator row.
//!
//! Nothing here judges prose. A single paragraph is valid Markdown; the rule
//! is about the shape the layer contract promises, not about style.

use std::fmt;

/// Why an output was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputSchemaError {
    /// The bytes are not valid UTF-8.
    NotUtf8,
    /// The output is empty (or whitespace only).
    Empty,
    /// A heading skips a level while descending.
    HeadingSkip { line: usize, from: usize, to: usize },
    /// A code fence opens and never closes (or closes what was never opened).
    UnbalancedFence { line: usize },
    /// A table row disagrees with the header's column count, or a table block
    /// has no separator row after the header.
    TableMismatch { line: usize },
    /// The output exceeds the largest allowed size (defense in depth; the
    /// bounded wrapper already enforces the byte ceiling).
    TooLarge { bytes: usize },
}

impl fmt::Display for OutputSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8 => write!(f, "output is not valid UTF-8"),
            Self::Empty => write!(f, "output is empty"),
            Self::HeadingSkip { line, from, to } => write!(
                f,
                "heading on line {line} skips a level: {} after {}",
                "#".repeat(*to),
                "#".repeat(*from)
            ),
            Self::UnbalancedFence { line } => {
                write!(f, "unbalanced code fence around line {line}")
            }
            Self::TableMismatch { line } => {
                write!(f, "malformed table around line {line}")
            }
            Self::TooLarge { bytes } => {
                write!(f, "output too large: {bytes} bytes")
            }
        }
    }
}

impl std::error::Error for OutputSchemaError {}

/// The analyzer's own ceiling; `BoundedBytes` caps `output_ref` at 64 KiB
/// already, this is an independent check so the schema cannot be bypassed by
/// a wrapper that is widened.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Length of a line of `|`-separated cells, or 0 when the line is not a row.
fn row_columns(line: &str) -> Option<usize> {
    let trimmed = line.trim();
    if !(trimmed.starts_with('|') && trimmed.ends_with('|')) {
        return None;
    }
    Some(trimmed.matches('|').count() - 1)
}

/// Is this a separator row (`|---|---|` or `|:--|` or `|---:|` style)?
fn is_separator_row(line: &str) -> bool {
    let Some(cols) = row_columns(line) else {
        return false;
    };
    if cols == 0 {
        return false;
    }
    let cells = line
        .trim()
        .trim_matches('|')
        .split('|')
        .map(str::trim)
        .collect::<Vec<_>>();
    cells.iter().all(|c| {
        !c.is_empty()
            && c.chars().all(|ch| ch == '-' || ch == ':' || ch == ' ')
    })
}

/// Validate an AI inference layer output against the Markdown schema.
///
/// # Errors
///
/// [`OutputSchemaError`] naming the first violation. The caller refuses the
/// output; it is never converted into a near-miss format.
pub fn validate_markdown_output(bytes: &[u8]) -> Result<(), OutputSchemaError> {
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(OutputSchemaError::TooLarge { bytes: bytes.len() });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| OutputSchemaError::NotUtf8)?;
    if text.trim().is_empty() {
        return Err(OutputSchemaError::Empty);
    }

    let mut level: usize = 0;
    let mut seen_heading = false;
    let mut in_fence = false;
    let mut fence_open_line = 0usize;
    let mut table_buffer: Vec<(usize, String)> = Vec::new();

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw.trim();

        // Fence toggling before anything else: inside a fence nothing is a
        // heading or a table row.
        if trimmed.starts_with("```") {
            if !in_fence {
                in_fence = true;
                fence_open_line = line_no;
            } else {
                in_fence = false;
            }
            // Any fence line ends a pending table block.
            if !table_buffer.is_empty() {
                check_table(&table_buffer)?;
                table_buffer.clear();
            }
            continue;
        }
        if in_fence {
            continue;
        }

        // Heading: a run of `#`s followed by a space, at the start of the line.
        let lead_hashes = trimmed.chars().take_while(|c| *c == '#').count();
        if lead_hashes > 0 && trimmed[lead_hashes..].starts_with(' ') {
            let new_level = lead_hashes;
            // The first heading may be any level; only a *descent* is bounded.
            if seen_heading && new_level > level + 1 {
                return Err(OutputSchemaError::HeadingSkip {
                    line: line_no,
                    from: level,
                    to: new_level,
                });
            }
            // Ascending to any shallower level is always fine.
            seen_heading = true;
            level = new_level;
            if !table_buffer.is_empty() {
                check_table(&table_buffer)?;
                table_buffer.clear();
            }
            continue;
        }

        // Table rows accumulate; a blank line or any non-row line closes the
        // table block so it can be checked as one.
        let cols = row_columns(trimmed);
        let is_row = cols.is_some();
        if is_row {
            table_buffer.push((line_no, trimmed.to_string()));
            continue;
        }
        if !table_buffer.is_empty() {
            check_table(&table_buffer)?;
            table_buffer.clear();
        }
    }

    if in_fence {
        return Err(OutputSchemaError::UnbalancedFence { line: fence_open_line });
    }
    if !table_buffer.is_empty() {
        check_table(&table_buffer)?;
    }
    Ok(())
}

/// Validate one table block: header, separator, consistent columns.
fn check_table(rows: &[(usize, String)]) -> Result<(), OutputSchemaError> {
    let (first_line, header) = &rows[0];
    let header_cols = row_columns(header).unwrap_or(0);
    if rows.len() == 1 {
        // A single `|` line is not a table; nothing to enforce.
        return Ok(());
    }
    let (_, second) = &rows[1];
    if !is_separator_row(second) {
        return Err(OutputSchemaError::TableMismatch { line: *first_line });
    }
    for (line, row) in rows.iter().skip(2) {
        if row_columns(row) != Some(header_cols) {
            return Err(OutputSchemaError::TableMismatch { line: *line });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_paragraph_is_valid() {
        assert!(validate_markdown_output(b"just words\n\nmore words").is_ok());
    }

    #[test]
    fn a_document_with_headings_is_valid() {
        let doc = "# Title\n\n## Section\n\n### Sub\n\ntext\n";
        assert!(validate_markdown_output(doc.as_bytes()).is_ok());
    }

    #[test]
    fn skipping_a_level_while_descending_is_refused() {
        let doc = "# Title\n\n### Sub\n";
        let err = validate_markdown_output(doc.as_bytes()).unwrap_err();
        assert_eq!(
            err,
            OutputSchemaError::HeadingSkip { line: 3, from: 1, to: 3 }
        );
    }

    #[test]
    fn ascending_to_any_level_is_allowed() {
        // Ascend from 3 to 1 (any shallower level), then descend by exactly
        // one: both are fine.
        let doc = "### Deep\n\n# Back\n\n## Shallower descent\n";
        assert!(validate_markdown_output(doc.as_bytes()).is_ok());
    }

    #[test]
    fn unbalanced_fence_is_refused() {
        let doc = "text\n```rust\nlet x = 1;\n";
        let err = validate_markdown_output(doc.as_bytes()).unwrap_err();
        assert_eq!(err, OutputSchemaError::UnbalancedFence { line: 2 });
    }

    #[test]
    fn balanced_fence_is_accepted_even_with_hash_rows_inside() {
        let doc = "## Title\n\n```\n# not a heading\n```\n";
        assert!(validate_markdown_output(doc.as_bytes()).is_ok());
    }

    #[test]
    fn a_table_with_a_separator_and_consistent_columns_is_valid() {
        let doc = "| a | b |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |\n";
        assert!(validate_markdown_output(doc.as_bytes()).is_ok());
    }

    #[test]
    fn a_table_without_a_separator_row_is_refused() {
        let doc = "| a | b |\n| 1 | 2 |\n";
        let err = validate_markdown_output(doc.as_bytes()).unwrap_err();
        assert!(matches!(err, OutputSchemaError::TableMismatch { .. }));
    }

    #[test]
    fn a_table_with_a_mismatched_column_is_refused() {
        let doc = "| a | b |\n|---|---|\n| 1 | 2 | 3 |\n";
        let err = validate_markdown_output(doc.as_bytes()).unwrap_err();
        assert!(matches!(err, OutputSchemaError::TableMismatch { .. }));
    }

    #[test]
    fn empty_output_is_refused() {
        assert_eq!(
            validate_markdown_output(b"   \n  "),
            Err(OutputSchemaError::Empty)
        );
    }

    #[test]
    fn invalid_utf8_is_refused() {
        assert_eq!(
            validate_markdown_output(&[0xff, 0xfe, 0x00]),
            Err(OutputSchemaError::NotUtf8)
        );
    }

    #[test]
    fn oversized_output_is_refused() {
        let big = vec![b'a'; MAX_OUTPUT_BYTES + 1];
        assert!(matches!(
            validate_markdown_output(&big),
            Err(OutputSchemaError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_single_pipe_line_is_not_treated_as_a_table() {
        assert!(validate_markdown_output(b"| not a table at all").is_ok());
    }
}
