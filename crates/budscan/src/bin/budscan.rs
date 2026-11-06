//! The `budscan` command line, for looking at classification and the evidence
//! badge.
//!
//! No network. This binary **fetches** nothing; it shows how the typed input is
//! classified and what evidence strength it is labelled with. Fetching happens
//! in the browser itself, through an implementation of
//! [`budscan::fetch::Transport`].
//!
//! ```text
//! budscan classify ayaz.bud
//! budscan name-rule "javascript:alert(1)"
//! budscan self-test
//! ```

use budscan::evidence::Strength;
use budscan::patchset;
use budscan::{name_rule, query};

fn usage() -> String {
    String::from(
        "budscan <command> [argument]\n\
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
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("{path} could not be read");
        return 2;
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
    if budscan::Evidence::new().weakest() != Strength::Refused {
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

    if problems.is_empty() {
        println!(
            "budscan {} self-test: PASSED (6 canaries)",
            budscan::VERSION
        );
        0
    } else {
        for p in &problems {
            println!("  {p}");
        }
        println!("budscan self-test: FAILED ({} finding(s))", problems.len());
        1
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.split_first() {
        None => {
            print!("{}", usage());
            2
        }
        Some((cmd, rest)) => match (cmd.as_str(), rest.first()) {
            ("classify", Some(input)) => classify_cmd(input),
            ("name-rule", Some(name)) => name_cmd(name),
            ("patch-list", Some(path)) => patch_list_cmd(path),
            ("self-test", _) => self_test(),
            _ => {
                print!("{}", usage());
                2
            }
        },
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use budscan::patchset::Verdict;

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
}
