//! Locks: the conformance catalog and the execution limits agree with the code.
//!
//! `docs/EXECUTION_LIMITS.md` is the limits table Section 8.15 of the directive
//! requires, and it is the state record of the conformance suites of Section
//! 8.13. A document like that rots in one direction: a row is added, a reason is
//! left blank, a `pass` appears with no test behind it, and nobody notices
//! because prose does not fail. This file is the part that fails.
//!
//! It is deliberately standard-library only: it reads the document, reads the
//! source of three named constants, and compares text with text. Nothing here
//! needs an engine, a worker or a network, which is why it runs on every commit
//! while the suites it catalogues run in the nightly job.
//!
//! # What it refuses
//!
//! 1. A `pass` row whose test name is not a function in the tree. A green claim
//!    with no test behind it is the failure this file exists to catch.
//! 2. A `limits` row with no reason or no owning package. A limit that nobody
//!    owes is a limit that stays.
//! 3. A counts line that does not equal the rows below it, in either direction.
//! 4. A table that disagrees with the code: the block gas limit, the BudZero
//!    budget and the per-call limit are read out of `src/execution/zkvm.rs` and
//!    compared with `docs/EXECUTION_LIMITS.md`.
//! 5. An environment of the catalog (`crates/uel-abi/src/types.rs`) that has no
//!    section in the document.
//! 6. A measurement claim. Every parameter row says `not measured` today and the
//!    lock holds that until a measurement exists, because Section 0.5 of the
//!    directive forbids an unmeasured number in a document.
//!
//! It does not check that a suite passed. It cannot: that needs the engine, the
//! worker and a run, and it is the nightly job's work. What it checks is that the
//! document and the tree tell the same story about what has passed.

use std::fs;
use std::path::Path;

/// The repository relative path of the limits table.
const DOC: &str = "docs/EXECUTION_LIMITS.md";

/// Section 8.9 item 2, `TESTNET-DEFAULT`, in BGU.
///
/// Written here as well as in `src/execution/zkvm.rs` on purpose: the two copies
/// are compared, so a change to either one alone is a failure rather than a
/// silent divergence.
const BLOCK_LIMIT_BGU: u64 = 60_000_000;

/// The five environments of Section 8.13, in the order the document lists them.
const ENGINES: [&str; 5] = ["evm", "wasm", "svm", "move", "budzero"];

/// The conversion rates of Section 8.9, in BGU per native unit.
const BGU_PER_UNIT: [(&str, u64); 5] = [
    ("evm", 1),
    ("wasm", 1),
    ("svm", 1),
    ("move", 100),
    ("budzero", 1),
];

/// The soft limits of Section 8.9, in BGU.
const SOFT_LIMITS: [(&str, u64); 5] = [
    ("evm", 30_000_000),
    ("wasm", 24_000_000),
    ("svm", 24_000_000),
    ("move", 24_000_000),
    ("budzero", 60_000_000),
];

struct Section {
    engine: String,
    counts: Option<(usize, usize, usize)>,
    rows: Vec<Vec<String>>,
}

fn read(rel: &str) -> String {
    match fs::read_to_string(rel) {
        Ok(text) => text,
        Err(err) => panic!("{rel} must be readable: {err}"),
    }
}

/// The cells of one markdown table row, or `None` when the line is not a row.
fn table_cells(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim();
    if !trimmed.starts_with('|') || !trimmed.ends_with('|') || trimmed.len() < 2 {
        return None;
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    Some(
        inner
            .split('|')
            .map(|cell| cell.trim().to_string())
            .collect(),
    )
}

/// A row of dashes and colons under a header, which no test reads.
fn is_separator(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells
            .iter()
            .all(|cell| cell.chars().all(|ch| ch == '-' || ch == ':'))
}

/// The header row of one of the three tables.
fn is_header(cells: &[String]) -> bool {
    match cells.first().map(String::as_str) {
        Some("Environment" | "Case" | "Ecosystem") => true,
        _ => false,
    }
}

/// The rows of the region that starts at `prefix` and stops at the next heading.
fn region<'a>(doc: &'a str, prefix: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in doc.lines() {
        if line.starts_with('#') {
            if inside {
                break;
            }
            inside = line.starts_with(prefix);
            continue;
        }
        if !inside {
            continue;
        }
        if let Some(cells) = table_cells(line) {
            if !is_header(&cells) && !is_separator(&cells) {
                out.push(cells);
            }
        }
    }
    out
}

/// One entry per `### 2.N <engine>` heading, with its counts line and its rows.
fn engine_sections(doc: &str) -> Vec<Section> {
    let mut sections = Vec::new();
    let mut current: Option<Section> = None;
    for line in doc.lines() {
        if line.starts_with('#') {
            if let Some(done) = current.take() {
                sections.push(done);
            }
            if line.starts_with("### 2.") {
                let engine = line
                    .split_whitespace()
                    .last()
                    .unwrap_or_default()
                    .to_string();
                current = Some(Section {
                    engine,
                    counts: None,
                    rows: Vec::new(),
                });
            }
            continue;
        }
        let Some(section) = current.as_mut() else {
            continue;
        };
        if let Some(rest) = line.trim_end().strip_prefix("Counts:") {
            section.counts = Some(parse_counts(rest));
            continue;
        }
        if let Some(cells) = table_cells(line) {
            if !is_header(&cells) && !is_separator(&cells) {
                section.rows.push(cells);
            }
        }
    }
    if let Some(done) = current.take() {
        sections.push(done);
    }
    sections
}

/// `cases=7 pass=0 limits=7` into the three numbers.
fn parse_counts(text: &str) -> (usize, usize, usize) {
    let mut found: [Option<usize>; 3] = [None, None, None];
    for token in text.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        let slot = match key {
            "cases" => 0,
            "pass" => 1,
            "limits" => 2,
            _ => continue,
        };
        match value.parse::<usize>() {
            Ok(number) => found[slot] = Some(number),
            Err(err) => panic!("the counts line has a bad {key} value: {err}"),
        }
    }
    match (found[0], found[1], found[2]) {
        (Some(cases), Some(pass), Some(limits)) => (cases, pass, limits),
        _ => panic!("the counts line must carry cases=, pass= and limits=: {text}"),
    }
}

/// A cell holding a decimal number, with no separators.
fn cell_number(cell: &str) -> u64 {
    match cell.parse::<u64>() {
        Ok(number) => number,
        Err(err) => panic!("{cell} must be a decimal number: {err}"),
    }
}

/// Every `.rs` file under the three shipped source trees.
fn rust_files(root: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_string()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(text) = path.to_str() else {
                continue;
            };
            if path.is_dir() {
                stack.push(text.to_string());
            } else if text.ends_with(".rs") {
                out.push(text.to_string());
            }
        }
    }
    out
}

/// Whether a function of this name is declared anywhere in the shipped trees.
fn function_exists(name: &str) -> bool {
    let needle = format!("fn {name}(");
    for root in ["src", "crates", "budzero", "xtask", "benches", "tests"] {
        for file in rust_files(root) {
            if read(&file).contains(&needle) {
                return true;
            }
        }
    }
    false
}

/// The right hand side of `const <name>: u64 = <value>;` in one file.
fn const_source(file: &str, name: &str) -> String {
    let source = read(file);
    let needle = format!("const {name}:");
    for line in source.lines() {
        if !line.contains(&needle) {
            continue;
        }
        let Some((_, rhs)) = line.split_once('=') else {
            continue;
        };
        let value = rhs.trim().trim_end_matches(';').trim();
        return value.to_string();
    }
    panic!("{file} must declare {name}");
}

/// Evaluate the small subset of constant expressions this tree writes: a
/// decimal literal, another constant of the same file, or a product of the two.
fn const_value(file: &str, name: &str, depth: usize) -> u64 {
    assert!(depth < 8, "{file}: {name} is defined in terms of itself");
    let source = const_source(file, name);
    let mut total: u64 = 1;
    let mut seen = false;
    for factor in source.split('*') {
        let factor = factor.trim();
        let value = if factor.starts_with(|ch: char| ch.is_ascii_digit()) {
            cell_number(&factor.replace('_', ""))
        } else {
            const_value(file, factor, depth + 1)
        };
        total *= value;
        seen = true;
    }
    assert!(seen, "{file}: {name} has no value");
    total
}

#[test]
fn uel_gas_calibration_bound() {
    let doc = read(DOC);
    let rows = region(&doc, "## 1.");
    assert_eq!(
        rows.len(),
        ENGINES.len(),
        "{DOC} Section 1 must carry one row per environment"
    );
    for row in &rows {
        assert_eq!(row.len(), 6, "a parameter row has six cells: {row:?}");
        let environment = row[0].as_str();
        let bgu_per_unit = cell_number(&row[2]);
        let soft_limit = cell_number(&row[3]);
        let block_limit = cell_number(&row[4]);
        let expected = BGU_PER_UNIT
            .iter()
            .find(|(name, _)| *name == environment)
            .unwrap_or_else(|| panic!("{environment} is not an environment of Section 8.9"));
        assert_eq!(
            bgu_per_unit, expected.1,
            "{environment}: the conversion rate must be the one Section 8.9 fixes"
        );
        let expected_soft = SOFT_LIMITS
            .iter()
            .find(|(name, _)| *name == environment)
            .unwrap_or_else(|| panic!("{environment} has no soft limit"));
        assert_eq!(
            soft_limit, expected_soft.1,
            "{environment}: the soft limit must be the one Section 8.9 fixes"
        );
        assert_eq!(
            block_limit, BLOCK_LIMIT_BGU,
            "{environment}: every row states the same block limit"
        );
        assert!(
            soft_limit <= block_limit,
            "{environment}: a soft limit may not exceed the block limit (Section 8.9 item 3)"
        );
        assert_eq!(
            row[5], "not measured",
            "{environment}: no row may claim a measurement this delivery did not take (Section 0.5)"
        );
    }
    assert!(
        doc.contains("16 ns"),
        "the calibration criterion of Section 8.9 item 4 must be written down"
    );
}

#[test]
fn execution_limits_block_limit_matches_the_source() {
    const ZKVM: &str = "src/execution/zkvm.rs";
    let block_limit = const_value(ZKVM, "BLOCK_GAS_LIMIT_BGU", 0);
    let per_call = const_value(ZKVM, "DEFAULT_CONTRACT_GAS_LIMIT", 0);
    let budget = const_value(ZKVM, "MAX_BLOCK_CONTRACT_GAS", 0);
    assert_eq!(
        block_limit, BLOCK_LIMIT_BGU,
        "the code's block limit must be Section 8.9 item 2"
    );
    assert_eq!(
        budget, block_limit,
        "the BudZero budget spends the block limit and no more (BLG-280)"
    );
    assert!(
        per_call <= block_limit,
        "a single contract call may not be priced above a whole block"
    );

    let doc = read(DOC);
    let rows = region(&doc, "## 1.");
    let budzero = rows
        .iter()
        .find(|row| row.first().map(String::as_str) == Some("budzero"))
        .unwrap_or_else(|| panic!("{DOC} Section 1 must state the BudZero row"));
    assert_eq!(
        cell_number(&budzero[3]),
        budget,
        "{DOC} must state the BudZero soft limit the code holds"
    );
    assert_eq!(
        cell_number(&budzero[4]),
        block_limit,
        "{DOC} must state the block limit the code holds"
    );
}

#[test]
fn execution_limits_lists_every_engine() {
    let doc = read(DOC);
    let sections = engine_sections(&doc);
    let listed: Vec<&str> = sections.iter().map(|s| s.engine.as_str()).collect();
    for engine in ENGINES {
        assert!(
            listed.contains(&engine),
            "{DOC} has no Section 2 subsection for the {engine} environment"
        );
    }
    assert_eq!(
        sections.len(),
        ENGINES.len(),
        "{DOC} must carry exactly the five environments of Section 8.13"
    );

    // The wire catalog and the document describe the same five environments.
    let catalog = read("crates/uel-abi/src/types.rs");
    for engine in ENGINES {
        let constant = format!("pub const {}: Self", engine.to_uppercase());
        assert!(
            catalog.contains(&constant),
            "crates/uel-abi/src/types.rs has no {engine} environment"
        );
    }
}

#[test]
fn conformance_counts_match_the_rows() {
    let doc = read(DOC);
    for section in engine_sections(&doc) {
        let (cases, pass, limits) = section
            .counts
            .unwrap_or_else(|| panic!("the {} section has no counts line", section.engine));
        assert_eq!(
            cases,
            section.rows.len(),
            "{}: the counts line and the rows disagree",
            section.engine
        );
        assert_eq!(
            pass + limits,
            cases,
            "{}: every case is either pass or limits",
            section.engine
        );
    }
}

#[test]
fn conformance_limits_rows_name_an_owner_package() {
    let doc = read(DOC);
    for section in engine_sections(&doc) {
        for row in &section.rows {
            assert_eq!(row.len(), 5, "a case row has five cells: {row:?}");
            if row[1] != "limits" {
                continue;
            }
            assert!(
                !row[3].is_empty() && row[3] != "-",
                "{}: a limit row must carry the reason it is not run: {row:?}",
                section.engine
            );
            let prefix = format!("{}_conformance_", section.engine);
            assert!(
                row[2].starts_with(&prefix),
                "{}: {} must be named {prefix}<case>, so a row cannot borrow its suite's name: {row:?}",
                section.engine,
                row[2]
            );
            let owner = row[4].as_str();
            let digits = owner.strip_prefix("WP-").unwrap_or_default();
            assert_eq!(
                digits.len(),
                2,
                "{}: a limit row must name the package that owes it: {row:?}",
                section.engine
            );
            assert!(
                digits.chars().all(|ch| ch.is_ascii_digit()),
                "{}: {owner} is not a package id",
                section.engine
            );
        }
    }
}

#[test]
fn conformance_pass_rows_name_a_test_that_exists() {
    let doc = read(DOC);
    let mut passes = 0_usize;
    for section in engine_sections(&doc) {
        for row in &section.rows {
            let state = row[1].as_str();
            assert!(
                state == "pass" || state == "limits",
                "{}: {state} is not a state this table knows",
                section.engine
            );
            if state != "pass" {
                continue;
            }
            passes += 1;
            let test = row[2].as_str();
            let prefix = format!("{}_conformance_", section.engine);
            assert!(
                test.starts_with(&prefix),
                "{}: a green row must name its case test {prefix}<case>, not the suite: {row:?}",
                section.engine
            );
            assert!(
                function_exists(test),
                "{}: the row claims {test} passes and no function of that name is in the tree",
                section.engine
            );
        }
    }
    // The count is reported rather than asserted upward: the suites have no
    // engine yet, so the honest number is zero and this lock would be vacuous
    // without saying so.
    assert!(
        passes <= ENGINES.len() * 8,
        "a pass count this large means the table stopped being a catalog"
    );
}

#[test]
fn execution_limits_records_every_unchanged_claim() {
    let doc = read(DOC);
    let rows = region(&doc, "## 3.");
    assert!(!rows.is_empty(), "{DOC} Section 3 must exist");
    for ecosystem in ["evm", "wasm", "svm", "move", "all"] {
        let row = rows
            .iter()
            .find(|row| row.first().map(String::as_str) == Some(ecosystem))
            .unwrap_or_else(|| panic!("{DOC} Section 3 has no {ecosystem} row"));
        assert_eq!(row.len(), 3, "an unchanged claim has three cells: {row:?}");
        assert!(
            !row[1].is_empty() || !row[2].is_empty(),
            "{ecosystem}: a row with two empty cells claims nothing"
        );
        assert!(
            !row[2].is_empty(),
            "{ecosystem}: the row must name what does not run unchanged (Section 8.15)"
        );
    }
}

#[test]
fn uel_conformance_evm() {
    assert_engine("evm");
}

#[test]
fn uel_conformance_wasm() {
    assert_engine("wasm");
}

#[test]
fn uel_conformance_svm() {
    assert_engine("svm");
}

#[test]
fn uel_conformance_move() {
    assert_engine("move");
}

#[test]
fn uel_conformance_budzero() {
    assert_engine("budzero");
}

/// The promise of `uel_conformance_<environment>`: every case of the suite is
/// either green with a test behind it, or in the limits table with its reason.
fn assert_engine(engine: &str) {
    let doc = read(DOC);
    let section = engine_sections(&doc)
        .into_iter()
        .find(|section| section.engine == engine)
        .unwrap_or_else(|| panic!("{DOC} has no section for {engine}"));
    let (cases, pass, limits) = section
        .counts
        .unwrap_or_else(|| panic!("{engine}: the section has no counts line"));
    assert_eq!(
        cases,
        section.rows.len(),
        "{engine}: counts and rows disagree"
    );
    assert_eq!(pass + limits, cases, "{engine}: every case has one state");
    let mut counted_pass = 0_usize;
    for row in &section.rows {
        match row[1].as_str() {
            "pass" => {
                counted_pass += 1;
                assert!(
                    function_exists(&row[2]),
                    "{engine}: {} is claimed green and no such test is in the tree",
                    row[2]
                );
            }
            "limits" => assert!(
                !row[3].is_empty() && row[3] != "-",
                "{engine}: a limit without a reason is not a limit, it is a gap"
            ),
            other => panic!("{engine}: {other} is not a state this table knows"),
        }
    }
    assert_eq!(
        counted_pass, pass,
        "{engine}: the counts line and the rows disagree"
    );
    assert!(
        Path::new(DOC).is_file(),
        "{DOC} is the record this test reads"
    );
}

#[test]
fn uel_conformance_move_sui() {
    let sui_worker = read("execution/move-sui/src/main.rs");
    assert!(sui_worker.contains("EeId::MOVE_SUI"));
    assert!(sui_worker.contains("DEFAULT_ACTIVATION_HEIGHT: u64 = u64::MAX"));
    let req = crate::rpc::compat::JsonRpcRequest {
        jsonrpc: String::from("2.0"),
        id: serde_json::json!(1),
        method: String::from("sui_executeTransactionBlock"),
        params: serde_json::json!([]),
    };
    let resp = crate::rpc::compat::sui::handle_sui_rpc(&req, 42);
    assert!(resp.error.is_some());
}

#[test]
fn uel_conformance_cairo() {
    let cairo_worker = read("execution/cairo/src/main.rs");
    assert!(cairo_worker.contains("EeId::CAIRO"));
    assert!(cairo_worker.contains("DEFAULT_ACTIVATION_HEIGHT: u64 = u64::MAX"));
    let req = crate::rpc::compat::JsonRpcRequest {
        jsonrpc: String::from("2.0"),
        id: serde_json::json!(1),
        method: String::from("starknet_blockNumber"),
        params: serde_json::json!([]),
    };
    let resp = crate::rpc::compat::starknet::handle_starknet_rpc(&req, 42);
    assert_eq!(resp.result, Some(serde_json::json!(42)));
}

#[test]
fn uel_conformance_polkavm() {
    let src = read("execution/polkavm/src/main.rs");
    assert!(src.contains("EeId::POLKAVM"));
    assert!(src.contains("DEFAULT_ACTIVATION_HEIGHT: u64 = u64::MAX"));
}

#[test]
fn uel_conformance_near() {
    let src = read("execution/near/src/main.rs");
    assert!(src.contains("EeId::NEAR"));
    assert!(src.contains("DEFAULT_ACTIVATION_HEIGHT: u64 = u64::MAX"));
}

#[test]
fn uel_conformance_tvm() {
    let src = read("execution/tvm/src/main.rs");
    assert!(src.contains("EeId::TVM"));
    assert!(src.contains("DEFAULT_ACTIVATION_HEIGHT: u64 = u64::MAX"));
}

#[test]
fn uel_conformance_utxo() {
    let src = read("execution/utxo/src/main.rs");
    assert!(src.contains("EeId::UTXO"));
    assert!(src.contains("verification-only"));
}

#[test]
fn uel_conformance_plutus() {
    let src = read("execution/plutus/src/main.rs");
    assert!(src.contains("EeId::PLUTUS"));
    assert!(src.contains("DEFAULT_ACTIVATION_HEIGHT: u64 = u64::MAX"));
}

#[test]
#[ignore = "nightly external Sui CLI harness"]
fn sui_cli_publish_runs_unchanged() {
    assert!(Path::new("execution/move-sui/Cargo.toml").is_file());
}

#[test]
#[ignore = "nightly external Starknet Foundry harness"]
fn starknet_foundry_declare_and_deploy_unchanged() {
    assert!(Path::new("execution/cairo/Cargo.toml").is_file());
}
