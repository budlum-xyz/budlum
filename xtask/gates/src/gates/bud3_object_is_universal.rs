//! Every content class enters one object, including zero bytes.
//!
//! Section 6.3.2 names one object model. A class of content that is refused
//! an object, or that gets a second object type of its own, is the failure
//! this gate exists for: the old editions had three recipe models, and the
//! way a fourth arrived was always a class with "its own" path.
//!
//! # What is checked
//!
//! 1. The object module exists and declares the canonical layout: the magic
//!    `B3`, version 1 and the four flag bits by name, so a fifth flag cannot
//!    appear without a reviewer reading the inventory beside it.
//! 2. The object path carries no content-class branch that refuses input: the
//!    builder takes a byte slice, and no code in `src/storage/bud3/` rejects a
//!    payload by its class. The recogniser (S0) names classes; naming is not
//!    refusing.
//! 3. Zero bytes round trip like any other length: the acceptance test
//!    `bud3_every_format_round_trips` exists, and its sample list carries the
//!    zero byte and the one byte case.
//!
//! # What it cannot see
//!
//! It reads source text, so a refusal assembled at run time out of pieces
//! would pass. The reason it is still worth running is that the positive half
//! (the acceptance test and its sample list) fails when somebody deletes the
//! zero byte case, which is the way this property actually gets lost.

use std::fmt::Write as _;
use std::path::Path;

/// The object module and its format module.
const OBJECT: &str = "src/storage/bud3/object.rs";
const BOF1: &str = "src/storage/bud3/bof1.rs";
/// The acceptance test that carries the round trip for every class.
const TEST_FILE: &str = "src/tests/bud3_objects.rs";
const TEST_NAME: &str = "bud3_every_format_round_trips";

/// The flag bits the format defines, with the bit they occupy.
///
/// A new flag is a new object shape, so it has to be added here in the same
/// change that writes it, which is the point of the list.
const FLAGS: &[(&str, u8)] = &[
    ("SEALED", 1),
    ("LIVE", 2),
    ("HAS_BASE", 4),
    ("HAS_CONTEXT", 8),
];

/// The content classes the recogniser names. Section 6.6.4 S0 has to name
/// every class it can see and invent nothing; a class added to the recogniser
/// without being added here is a class nobody reviewed the object path for.
const CLASSES: &[&str] = &[
    "Text",
    "Source",
    "Records",
    "Image",
    "Video",
    "Audio",
    "Archive",
    "Generic",
];

/// Read a repository file, naming it when it is missing.
fn read(root: &Path, rel: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(rel)).map_err(|e| format!("read {rel}: {e}"))
}

/// Run the gate.
///
/// # Errors
///
/// A finding, as a sentence.
pub fn run(root: &Path) -> Result<String, String> {
    let bof1 = read(root, BOF1)?;
    let object = read(root, OBJECT)?;
    let test = read(root, TEST_FILE)?;

    // 1. The magic and the version.
    if !bof1.contains("pub const MAGIC: [u8; 2] = *b\"B3\";") {
        return Err(String::from(
            "the BOF-1 magic is not `B3`: the object format every identity and storage path \
             commits to starts with those two bytes",
        ));
    }
    if !bof1.contains("pub const VERSION: u8 = 1;") {
        return Err(String::from("the BOF-1 version is not 1"));
    }

    // 2. Every flag bit is defined by value, and the values are distinct.
    let mut seen: Vec<u8> = Vec::new();
    for (name, bit) in FLAGS {
        let needle = format!("pub const {name}: u8 = 1 << ");
        if !bof1.contains(&needle) {
            return Err(format!(
                "the BOF-1 flag {name} is gone: an object shape exists only if the format \
                 names it, and {BOF1} no longer does"
            ));
        }
        if seen.contains(bit) {
            return Err(format!("two BOF-1 flags occupy bit {bit}"));
        }
        seen.push(*bit);
    }

    // 3. The object path has one builder and no class refusal.
    if !object.contains("pub fn public_header(") {
        return Err(format!(
            "{OBJECT} no longer builds a public header: the one object model needs one \
             builder, not a builder per content class"
        ));
    }
    for phrase in ["refuse_class", "unsupported class", "unsupported content"] {
        if object.to_lowercase().contains(phrase) {
            return Err(format!(
                "{OBJECT} refuses content by class ({phrase}): every class enters the object \
                 model, and the codec chain is what declines to compress a class it cannot \
                 improve"
            ));
        }
    }

    // 4. The recogniser's class list matches this gate's list.
    let stages = read(root, "src/storage/bud3/stages.rs")?;
    for class in CLASSES {
        if !stages.contains(&format!("    {class},")) && !stages.contains(&format!("{class} =>")) {
            return Err(format!(
                "the content class {class} is missing from the object path: the gate and \
                 `stages.rs` name the same set, so a class cannot be added on one side only"
            ));
        }
    }

    // 5. The acceptance test exists and carries the two edge lengths.
    if !test.contains(&format!("fn {TEST_NAME}(")) {
        return Err(format!(
            "{TEST_FILE} does not carry `{TEST_NAME}`: the round trip over every content class \
             is the evidence for Section 6.3.2, and without it nothing asserts it"
        ));
    }
    if !test.contains("\"zero bytes\"") || !test.contains("\"one byte\"") {
        return Err(format!(
            "`{TEST_NAME}` dropped the zero byte or the one byte case: an empty object and a \
             single byte are the two lengths a size check gets wrong"
        ));
    }

    let mut msg = String::new();
    let _ = writeln!(
        msg,
        "bud3 object is universal OK: magic B3, version 1, {} flag bit(s), {} content \
         class(es), one public header builder, the round trip carries zero bytes",
        FLAGS.len(),
        CLASSES.len()
    );
    Ok(msg)
}

/// The canary: a removed magic, a removed flag, a class refusal and a missing
/// zero byte case must each fail.
///
/// # Errors
///
/// A finding when the canary itself does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-bud3-object")?;
    let write = |rel: &str, text: &str| -> Result<(), String> {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&p, text).map_err(|e| e.to_string())
    };

    let flags: String = FLAGS
        .iter()
        .map(|(name, bit)| format!("    pub const {name}: u8 = 1 << {bit};\n"))
        .collect();
    let classes: String = CLASSES
        .iter()
        .map(|c| format!("    {c},\n"))
        .collect();
    let samples = "        (\"zero bytes\", Vec::new()),\n        (\"one byte\", vec![1]),\n";
    let test = format!("fn {TEST_NAME}() {{\n{samples}}}\n");

    let bof1 = format!(
        "pub const MAGIC: [u8; 2] = *b\"B3\";\n\
         pub const VERSION: u8 = 1;\n\
         impl Flags {{\n{flags}}}\n"
    );
    let object = String::from("pub fn public_header() {}\n");
    let stages = format!("pub enum ContentClass {{\n{classes}}}\n");

    write(BOF1, &bof1)?;
    write(OBJECT, &object)?;
    write("src/storage/bud3/stages.rs", &stages)?;
    write(TEST_FILE, &test)?;
    run(&dir).map_err(|e| format!("canary: the healthy tree failed: {e}"))?;

    // A removed magic.
    write(BOF1, &bof1.replace("*b\"B3\"", "*b\"B4\""))?;
    if run(&dir).is_ok() {
        return Err(String::from("canary: a changed magic passed"));
    }
    write(BOF1, &bof1)?;

    // A removed flag.
    write(
        BOF1,
        &bof1.replace("    pub const LIVE: u8 = 1 << 1;\n", ""),
    )?;
    if run(&dir).is_ok() {
        return Err(String::from("canary: a removed flag passed"));
    }
    write(BOF1, &bof1)?;

    // A class refusal in the object path.
    write(
        OBJECT,
        "pub fn public_header() {}\n// Refused: unsupported content\n",
    )?;
    if run(&dir).is_ok() {
        return Err(String::from("canary: a class refusal passed"));
    }
    write(OBJECT, &object)?;

    // A class missing from the object path.
    write(
        "src/storage/bud3/stages.rs",
        &format!("pub enum ContentClass {{\n{}}}\n", classes.replace("    Audio,\n", "")),
    )?;
    if run(&dir).is_ok() {
        return Err(String::from("canary: a missing class passed"));
    }
    write("src/storage/bud3/stages.rs", &stages)?;

    // A dropped zero byte case.
    write(
        TEST_FILE,
        &format!("fn {TEST_NAME}() {{\n        (\"one byte\", vec![1]),\n}}\n"),
    )?;
    if run(&dir).is_ok() {
        return Err(String::from("canary: a dropped zero byte case passed"));
    }

    Ok(String::from(
        "bud3-object-is-universal canary OK: a changed magic, a removed flag, a class refusal, \
         a missing class and a dropped zero byte case each failed",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bud3_object_is_universal_gate() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
