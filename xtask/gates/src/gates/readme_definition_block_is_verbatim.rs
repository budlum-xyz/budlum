//! The definition block of both READMEs is byte for byte what the directive
//! recorded.
//!
//! Directive section 1.1 says the definition of Budlum does not change, and
//! appendix A records the first fourteen lines of `README.md` with the SHA-256
//! their LF endings produce. A hash is one way to hold that; this gate holds the
//! bytes themselves, which is the stronger check and needs no hashing
//! dependency inside the gates crate. The expected lines below are the same
//! bytes, so a diff to either README is reported with the line that moved.
//!
//! Two blocks are held: the English one in `README.md` (fourteen lines, which is
//! the count appendix A records) and the Turkish one in `README.tr.md` (the same
//! block through its closing blank line). A translated claim is still a claim, which is the rule the
//! badge gate also applies.
//!
//! # What this gate does not do
//!
//! It does not check the rest of either README. Keeping the whole file pinned
//! would make every honest edit a gate failure, and the pages the README links
//! to change. The definition block is the part the directive freezes.

use std::fmt::Write as _;
use std::path::Path;

/// The first fourteen lines of `README.md`, exactly as appendix A records them.
const ENGLISH: &[&str] = &[
    "![Budlum](assets/budlum-consensus-of-consensuses.png)",
    "",
    "Budlum is the next layer of the internet, focused on data sovereignty and social flourishing.",
    "",
    "Budlum is the consensus of consensuses.",
    "",
    "Every network keeps its own rules. Budlum unifies their finality into a single proof.",
    "",
    "PoW, PoS, PoA, BFT and ZK domains each keep their own consensus; Budlum verifies their",
    "finality proofs and records cross-domain value transfer as a cryptographic fact on a single",
    "`GlobalBlockHeader`. Sovereignty over data, keys and computation stays with the participants:",
    "the layer asks which finality proof holds for a fact, never which consensus produced it, so",
    "value moves between domains without trusting an intermediary.",
    "",
];

/// The first fourteen lines of `README.tr.md`, exactly as appendix B records them.
const TURKISH: &[&str] = &[
    "![Budlum](assets/budlum-konsensuslerin-konsensusu.png)",
    "",
    "Budlum, veri egemenliğine ve toplumsal yeşermeye odaklanmış, internetin bir sonraki katmanıdır.",
    "",
    "Budlum, konsensüslerin konsensüsüdür.",
    "",
    "Her ağ kendi kurallarını korur. Budlum, bu ağların kesinliğini tek bir kanıtta birleştirir.",
    "",
    "PoW, PoS, PoA, BFT ve ZK alanlarının her biri kendi konsensüsünü korur; Budlum bu alanların",
    "kesinlik kanıtlarını doğrular ve alanlar arası değer transferini tek bir `GlobalBlockHeader`",
    "üzerinde kriptografik bir olgu olarak kaydeder. Veri, anahtar ve hesaplama egemenliği",
    "katılımcılarda kalır: katman, bir olguyu hangi konsensüsün ürettiğini değil, o olgu için",
    "hangi kesinlik kanıtının geçerli olduğunu sorar. Böylece değer, bir aracıya güvenmeden",
    "alanlar arasında hareket eder.",
    "",
];

/// Compare one README's first fourteen lines against its recorded block.
fn compare(root: &Path, name: &str, expected: &[&str]) -> Result<(), String> {
    let path = root.join(name);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {name}: {e}; the definition block must be checked"))?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < expected.len() {
        return Err(format!(
            "{name} has {} line(s); the definition block alone is {} lines. The file was truncated.",
            lines.len(),
            expected.len(),
        ));
    }
    let mut problems = String::new();
    for (i, want) in expected.iter().enumerate() {
        let got = lines[i];
        if got != *want {
            let _ = writeln!(
                problems,
                "  {name}:{}: the line moved.\n    expected: {want}\n    found:    {got}",
                i + 1,
            );
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// # Errors
///
/// Returns the line of either README that no longer matches its recorded block.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems = String::new();
    for (name, expected) in [("README.md", ENGLISH), ("README.tr.md", TURKISH)] {
        if let Err(e) = compare(root, name, expected) {
            problems.push_str(&e);
        }
    }
    if problems.is_empty() {
        Ok(String::from(
            "OK: both definition blocks are byte for byte what the directive recorded.",
        ))
    } else {
        Err(format!(
            "FAIL: a README definition block changed. Section 1.1 of the directive freezes it:\n{problems}",
        ))
    }
}

fn scratch_dir() -> Result<std::path::PathBuf, String> {
    let dir = std::env::temp_dir().join(format!(
        "budlum-readme-definition-{}-{:?}",
        std::process::id(),
        std::thread::current().id(),
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create scratch dir: {e}"))?;
    Ok(dir)
}

fn join(lines: &[&str]) -> String {
    let mut s = lines.join("\n");
    s.push('\n');
    s
}

/// # Errors
///
/// The self-test fails when a rewritten block is accepted.
pub fn self_test() -> Result<String, String> {
    let tmp = scratch_dir()?;
    let tail = "\nan extra section that the gate does not pin\n";

    // A tree that carries both blocks passes.
    std::fs::write(tmp.join("README.md"), format!("{}{tail}", join(ENGLISH)))
        .map_err(|e| format!("cannot write README.md: {e}"))?;
    std::fs::write(tmp.join("README.tr.md"), format!("{}{tail}", join(TURKISH)))
        .map_err(|e| format!("cannot write README.tr.md: {e}"))?;
    if let Err(msg) = run(&tmp) {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(format!("canary: the recorded text was rejected: {msg}"));
    }

    // A single changed word in the last paragraph must be caught.
    let mut broken = ENGLISH.to_vec();
    broken[12] = "value moves between domains by trusting an intermediary.";
    std::fs::write(tmp.join("README.md"), format!("{}{tail}", join(&broken)))
        .map_err(|e| format!("cannot write broken README.md: {e}"))?;
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: a rewritten definition block was accepted"));
    }

    // A truncated file must be caught rather than compared against nothing.
    std::fs::write(tmp.join("README.md"), join(&ENGLISH[..6]))
        .map_err(|e| format!("cannot write truncated README.md: {e}"))?;
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: a truncated README was accepted"));
    }

    // A missing README must fail closed, not pass by having nothing to compare.
    let _ = std::fs::remove_file(tmp.join("README.tr.md"));
    if run(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: a missing README was accepted"));
    }

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(String::from(
        "readme-definition-block self-test OK: the recorded text passed and a rewritten block, a truncated file and a missing file were each caught.",
    ))
}
