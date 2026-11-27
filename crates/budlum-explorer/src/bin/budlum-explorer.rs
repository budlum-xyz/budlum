//! The `budlum-explorer` command line, for looking at classification and the evidence
//! badge.
//!
//! No network. This binary **fetches** nothing; it shows how the typed input is
//! classified and what evidence strength it is labelled with. Fetching happens
//! in the browser itself, through an implementation of
//! [`budlum_explorer::fetch::Transport`].
//!
//! ```text
//! budlum-explorer classify ayaz.bud
//! budlum-explorer name-rule "javascript:alert(1)"
//! budlum-explorer self-test
//! ```

#![forbid(unsafe_code)]

use budlum_explorer::patchset;
use budlum_explorer::{
    evidence::{Claim, Strength},
    Evidence,
};
use budlum_explorer::{name_rule, query};
use std::io::Read;
use std::path::Path;

const MAX_PATCH_LIST_BYTES: u64 = 1024 * 1024;

fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> Result<String, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if meta.file_type().is_symlink() {
        return Err(String::from("refusing to follow symlink"));
    }
    if !meta.file_type().is_file() {
        return Err(String::from("refusing non-regular file"));
    }
    if meta.len() > max_bytes {
        return Err(format!("file exceeds {max_bytes} byte limit"));
    }
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if (buf.len() as u64) > max_bytes {
        return Err(format!("file exceeds {max_bytes} byte limit"));
    }
    String::from_utf8(buf).map_err(|_| String::from("file is not valid UTF-8"))
}

fn usage() -> String {
    String::from(
        "budlum-explorer <command> [argument]\n\
         \n\
         commands:\n\
         \x20 classify <input>    says which class the typed input falls into\n\
         \x20 name-rule <name>    puts the name through the name rule\n\
         \x20 patch-list <path>   parses a patch list and prints it canonically\n\
         \x20 self-test           runs the internal canaries\n",
    )
}

fn classify_cmd(input: &str) -> i32 {
    let q = query::classify(input);
    println!("input    : {input}");
    println!("display  : {}", name_rule::display_form(input));
    println!("class    : {q:?}");
    match q {
        query::Query::RefusedName { .. }
        | query::Query::RefusedScheme { .. }
        | query::Query::Ambiguous { .. } => 1,
        _ => 0,
    }
}

fn name_cmd(name: &str) -> i32 {
    match name_rule::check_name(name) {
        Ok(()) => {
            let suffix = name_rule::suffix_of(name).unwrap_or_default();
            let resolvable = name_rule::RESOLVABLE_SUFFIXES.contains(&suffix);
            println!("{name}: accepted (suffix .{suffix}, resolver: {resolvable})");
            0
        }
        Err(rejection) => {
            println!("{name}: refused -- {rejection}");
            println!("display: {}", name_rule::display_form(name));
            1
        }
    }
}

fn patch_list_cmd(path: &str) -> i32 {
    let text = match read_bounded_regular_file(Path::new(path), MAX_PATCH_LIST_BYTES) {
        Ok(text) => text,
        Err(reason) => {
            eprintln!("{path} could not be read: {reason}");
            return 2;
        }
    };
    match patchset::parse_list(&text) {
        Ok(entries) => {
            print!("{}", patchset::render_list(&entries));
            0
        }
        Err(e) => {
            eprintln!("{path}: {e}");
            1
        }
    }
}

/// Internal canaries. Each one measures a behaviour that must not fail
/// silently.
fn self_test() -> i32 {
    let mut problems: Vec<String> = Vec::new();

    // 1. A scheme is never a name.
    for input in ["javascript:alert(1)", "data:text/html,x", "file:///etc"] {
        if !matches!(query::classify(input), query::Query::RefusedScheme { .. }) {
            problems.push(format!("{input} was not refused as a scheme"));
        }
    }

    // 2. An ordinary name passes; if it does not, that is a name ban.
    for name in ["ayaz.bud", "a-b.bud", "x1.eth"] {
        if name_rule::check_name(name).is_err() {
            problems.push(format!("{name} is an ordinary name and was refused"));
        }
    }

    // 3. Empty evidence does not say `verified`.
    if budlum_explorer::Evidence::new().weakest() != Strength::Refused {
        problems.push(String::from("an unmeasured answer counted as verified"));
    }

    // 4. An empty patch check does not count as a pass.
    if patchset::check_list_matches_disk(&[], &[]).is_ok() {
        problems.push(String::from("a vacuous patch check passed"));
    }

    // 5. No foreign brand may remain in a patch name.
    let brand_probe = format!("{}-x.patch", patchset::forbidden_brand_tokens()[0]);
    if patchset::check_patch_shape(&brand_probe, "+++ b/browser/a.js\n", &["browser/"]).is_ok() {
        problems.push(String::from(
            "a patch name carrying a foreign brand was accepted",
        ));
    }

    // 6. A mixed-script name is displayed as punycode.
    if name_rule::display_form("\u{0430}yaz.bud") != "xn--yaz-5cd.bud" {
        problems.push(String::from(
            "a homograph name was not displayed as punycode",
        ));
    }

    // 7. Scheme prefixes stay intact in display_form and classify case-insensitively.
    if name_rule::display_form("https://\u{0430}yaz.bud/") != "https://xn--yaz-5cd.bud/" {
        problems.push(String::from(
            "display_form corrupted a URL scheme prefix before a punycode label",
        ));
    }
    if !matches!(
        query::classify("HTTPS://example.com/"),
        query::Query::HttpsUrl(_)
    ) {
        problems.push(String::from(
            "uppercase HTTPS:// was not classified as HttpsUrl",
        ));
    }

    // 8. A blank claim reason never yields Verified.
    let blank_claim = Evidence::new().with(Claim::new("canary", Strength::Verified, "   "));
    if blank_claim.weakest() != Strength::Refused {
        problems.push(String::from("a blank-reason claim was not refused"));
    }

    if problems.is_empty() {
        println!(
            "budlum-explorer {} self-test: PASSED (8 canaries)",
            budlum_explorer::VERSION
        );
        0
    } else {
        for p in &problems {
            println!("  {p}");
        }
        println!(
            "budlum-explorer self-test: FAILED ({} finding(s))",
            problems.len()
        );
        1
    }
}

fn dispatch(args: &[String]) -> i32 {
    match args.split_first() {
        None => {
            print!("{}", usage());
            2
        }
        Some((cmd, rest)) => match (cmd.as_str(), rest) {
            ("classify", [input]) => classify_cmd(input),
            ("name-rule", [name]) => name_cmd(name),
            ("patch-list", [path]) => patch_list_cmd(path),
            ("self-test", []) => self_test(),
            _ => {
                print!("{}", usage());
                2
            }
        },
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(dispatch(&args));
}

#[cfg(test)]
mod tests {
    use super::*;
    use budlum_explorer::patchset::Verdict;

    #[test]
    fn the_self_test_passes_in_this_tree() {
        assert_eq!(self_test(), 0);
    }

    #[test]
    fn classification_exit_codes_separate_refusals_from_answers() {
        assert_eq!(classify_cmd("ayaz.bud"), 0);
        assert_eq!(classify_cmd("javascript:alert(1)"), 1);
    }

    #[test]
    fn the_name_command_reports_both_outcomes() {
        assert_eq!(name_cmd("ayaz.bud"), 0);
        assert_eq!(name_cmd("UPPER.bud"), 1);
    }

    #[test]
    fn a_verdict_that_is_vacuous_is_not_ok() {
        assert!(!Verdict::Vacuous(String::from("x")).is_ok());
        assert!(Verdict::Pass(String::from("x")).is_ok());
    }

    #[test]
    fn exp07_patch_list_rejects_symlink_oversized_and_extra_cli_args() {
        let dir = std::env::temp_dir().join(format!("budlum_exp07_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // 1. Valid regular patch list passes.
        let good = dir.join("good.list");
        std::fs::write(&good, "browser/patches/01.patch\n").unwrap();
        assert_eq!(patch_list_cmd(good.to_str().unwrap()), 0);

        // 2. Symlink must be refused (exit 2), never followed.
        #[cfg(unix)]
        {
            let link = dir.join("link.list");
            std::os::unix::fs::symlink(&good, &link).unwrap();
            assert_eq!(
                patch_list_cmd(link.to_str().unwrap()),
                2,
                "symlink patch list must be refused"
            );
        }

        // 3. Oversized patch list (> 1 MiB) must be refused (exit 2).
        let big = dir.join("big.list");
        std::fs::write(&big, vec![b'#'; 1024 * 1024 + 64]).unwrap();
        assert_eq!(
            patch_list_cmd(big.to_str().unwrap()),
            2,
            "oversized patch list must be refused"
        );

        let _ = std::fs::remove_dir_all(&dir);

        // 4. Extra trailing CLI arguments must be rejected (exit 2) rather than dropped.
        assert_eq!(
            dispatch(&[
                String::from("classify"),
                String::from("ayaz.bud"),
                String::from("extra"),
            ]),
            2
        );
        assert_eq!(
            dispatch(&[String::from("self-test"), String::from("extra")]),
            2
        );
        assert_eq!(
            dispatch(&[String::from("classify"), String::from("ayaz.bud")]),
            0
        );
    }
}
