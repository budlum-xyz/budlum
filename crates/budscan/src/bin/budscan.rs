//! `budscan` komut satiri: siniflandirma ve kanit rozetini gormek icin.
//!
//! Ag yok. Bu ikili bir sey **getirmez**; yazilan seyin nasil
//! siniflandirildigini ve hangi kanit gucuyle etiketlendigini gosterir.
//! Getirme, tarayicinin kendisinde bir [`budscan::fetch::Transport`]
//! uygulamasiyla yapilir.
//!
//! ```text
//! budscan siniflandir ayaz.bud
//! budscan ad-kurali "javascript:alert(1)"
//! budscan kendini-sina
//! ```

use budscan::evidence::Strength;
use budscan::patchset;
use budscan::{name_rule, query};

fn usage() -> String {
    String::from(
        "budscan <komut> [arguman]\n\
         \n\
         komutlar:\n\
         \x20 siniflandir <girdi>   yazilan seyin hangi sinifa girdigini soyler\n\
         \x20 ad-kurali <ad>        adi ad kuralindan gecirir\n\
         \x20 yama-listesi <yol>    yama listesini ayristirir ve kanonik bicimde yazar\n\
         \x20 kendini-sina          ic kanaryalari calistirir\n",
    )
}

fn classify_cmd(input: &str) -> i32 {
    let q = query::classify(input);
    println!("girdi     : {input}");
    println!("gosterim  : {}", name_rule::display_form(input));
    println!("sinif     : {q:?}");
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
            println!("{name}: kabul (sonek .{suffix}, cozumleyici: {resolvable})");
            0
        }
        Err(rejection) => {
            println!("{name}: red -- {rejection}");
            println!("gosterim: {}", name_rule::display_form(name));
            1
        }
    }
}

fn patch_list_cmd(path: &str) -> i32 {
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("{path} okunamadi");
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

/// Ic kanaryalar: her biri, bozuldugunda sessiz kalmamasi gereken bir
/// davranisi olcuyor.
fn self_test() -> i32 {
    let mut problems: Vec<String> = Vec::new();

    // 1. Sema hicbir zaman ad olmaz.
    for input in ["javascript:alert(1)", "data:text/html,x", "file:///etc"] {
        if !matches!(query::classify(input), query::Query::RefusedScheme { .. }) {
            problems.push(format!("{input} sema olarak reddedilmedi"));
        }
    }

    // 2. Siradan bir ad gecer; gecmezse bu bir ad yasagidir.
    for name in ["ayaz.bud", "a-b.bud", "x1.eth"] {
        if name_rule::check_name(name).is_err() {
            problems.push(format!("{name} siradan bir ad ve reddedildi"));
        }
    }

    // 3. Bos kanit `dogrulandi` demez.
    if budscan::Evidence::new().weakest() != Strength::Refused {
        problems.push(String::from("olculmemis bir cevap dogrulanmis sayildi"));
    }

    // 4. Bos bir yama kontrolu gecmis sayilmaz.
    if patchset::check_list_matches_disk(&[], &[]).is_ok() {
        problems.push(String::from("bosta kalan yama kontrolu gecti"));
    }

    // 5. Bir yamanin adinda yabanci marka kalamaz.
    let brand_probe = format!("{}-x.patch", patchset::forbidden_brand_tokens()[0]);
    if patchset::check_patch_shape(&brand_probe, "+++ b/browser/a.js\n", &["browser/"]).is_ok() {
        problems.push(String::from("yabanci marka tasiyan yama adi kabul edildi"));
    }

    // 6. Karisik yazi sistemli bir ad punycode gosterilir.
    if name_rule::display_form("\u{0430}yaz.bud") != "xn--yaz-5cd.bud" {
        problems.push(String::from("homograf ad punycode gosterilmedi"));
    }

    if problems.is_empty() {
        println!(
            "budscan {} kendini-sina: GECTI (6 kanarya)",
            budscan::VERSION
        );
        0
    } else {
        for p in &problems {
            println!("  {p}");
        }
        println!("budscan kendini-sina: DUSTU ({} bulgu)", problems.len());
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
            ("siniflandir", Some(input)) => classify_cmd(input),
            ("ad-kurali", Some(name)) => name_cmd(name),
            ("yama-listesi", Some(path)) => patch_list_cmd(path),
            ("kendini-sina", _) => self_test(),
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
