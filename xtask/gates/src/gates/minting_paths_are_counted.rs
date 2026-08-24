//! Every path that creates supply must be counted and bound to the ceiling.
//!
//! A fixed supply ceiling is a bound only if **every single supply-creating path** asks it.
//! If one path is left out the ceiling becomes only a document:
//! a reader believes 100 million is the upper bound while the code does something else.
//!
//! Olculen sey su: `try_add_balance` cagiran her uretim satiri ya
//! is a **transfer** (it takes existing money from one place to another: a refund,
//! ucret, kilit cozme) ya da **basim**dir (yeni para yaratir). Basim olanlar
//! `try_mint_balance` cagirmali; o fonksiyon tavani denetleyen tek yerdir.
//!
//! # Neden bir liste tutuluyor
//!
//! The gate **cannot infer** from the source which call is a transfer and which is a mint
//! - that is an accounting question, not a syntax question. So
//! yuzden asagida her `try_add_balance` cagri yerinin neden tasima oldugu tek
//! it is written once. When a new call is added the gate goes red and whoever adds it
//! kisiyi bu soruyu cevaplamaya zorlar: bu yeni para mi, yoksa yer degistiren
//! para mi?
//!
//! The friction is deliberate. Silently adding a supply-creating path is the most expensive
//! mistake this chain can make; the cost of the gate is writing one line of
//! rationale.

use std::fmt::Write as _;
use std::path::Path;

/// Denetlenen kaynak dosyalar.
const SOURCES: &[&str] = &["src/chain/blockchain.rs", "src/core/account.rs"];

/// Tavani denetleyen tek fonksiyon.
const MINT_FN: &str = "try_mint_balance";

/// Tavan denetimi olmadan bakiye ekleyen fonksiyon.
const MOVE_FN: &str = "try_add_balance";

/// Beklenen `try_add_balance` cagri sayisi ve her birinin neden **tasima**
/// oldugu.
///
/// The count is kept deliberately: if a call is added the total changes and the gate fires.
/// The rationales tell the reader why those lines do not ask the ceiling.
const TRANSFER_JUSTIFICATIONS: &[(&str, usize, &str)] = &[
    (
        "src/chain/blockchain.rs",
        11,
        "bridge unlock and refund (existing locked money is returned), \
         storage deal refunds and operator bond refunds (money that was \
         borclandirilmis para), ucret dagitimi (odenmis ucretin paylastirilmasi). \
         Hicbiri yeni arz yaratmaz.",
    ),
    (
        "src/core/account.rs",
        2,
        "one is the release of the unbonding queue (money already committed as stake \
         and already counted against the ceiling is returned - not new supply \
         but supply changing category); the other is the body of `try_mint_balance` itself, \
         the line that performs the actual addition after checking the ceiling.",
    ),
];

/// Bir satirin uretim kodu mu test kodu mu oldugunu kabaca ayirt eder.
///
/// Testler tavandan muaf: orada bir hesabi fonlamak kurulumun parcasi.
fn production_lines(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut in_tests = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        // The boundary is only a column-zero `mod tests`: `#[cfg(test)]` is not production
        // kodunda da geciyor (test-only dallar, test-only yardimcilar), o
        // yuzden onu sinir saymak dosyanin yarisini gorunmez yapardi.
        if line.starts_with("mod tests") || line.starts_with("pub mod tests") {
            in_tests = true;
        }
        // Comments do not count: a function name appearing in a rationale text is not a
        // call. A line starting with `fn` does not count either - the definition of the
        // function is not a call to it.
        if in_tests || t.starts_with("//") || t.starts_with("pub fn") || t.starts_with("fn ") {
            continue;
        }
        out.push((i + 1, line));
    }
    out
}

/// # Errors
///
/// Bakiye ekleyen cagrilarin sayisi gerekcelendirilmis sayidan farkliysa.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems = String::new();
    let mut minting = 0usize;
    let mut moving = 0usize;

    for source in SOURCES {
        let text = std::fs::read_to_string(root.join(source))
            .map_err(|e| format!("{source} okunamadi: {e}"))?;
        let lines = production_lines(&text);

        let found_move = lines
            .iter()
            .filter(|(_, l)| l.contains(MOVE_FN) && !l.contains(MINT_FN))
            .count();
        let found_mint = lines.iter().filter(|(_, l)| l.contains(MINT_FN)).count();
        moving += found_move;
        minting += found_mint;

        let Some((_, expected, why)) = TRANSFER_JUSTIFICATIONS
            .iter()
            .find(|(name, _, _)| name == source)
        else {
            continue;
        };

        if found_move != *expected {
            let _ = write!(
                problems,
                "\n  {source}: {found_move} adet `{MOVE_FN}` cagrisi var, \
                 the justified count is {expected}.\n    \
                 Recorded rationale: {why}\n    \
                 Yeni bir cagri eklendiyse su soru cevaplanmali: bu yeni para mi \
                 (then `{MINT_FN}` must be used, it checks the ceiling) or money that \
                 merely changes place (then the rationale must be written into this gate)? \
                 If a call was deleted the count must be updated."
            );
        }
    }

    if !problems.is_empty() {
        return Err(format!("minting-paths-are-counted:{problems}"));
    }
    if minting == 0 {
        return Err(format!(
            "minting-paths-are-counted: hic `{MINT_FN}` cagrisi bulunamadi. \
             If the ceiling check was removed the supply cap is only a document."
        ));
    }

    Ok(format!(
        "minting-paths-are-counted OK: {minting} mint calls are bound to the ceiling, \
         {moving} transfer calls are justified"
    ))
}

/// # Errors
///
/// Kapi test kodunu uretimden ayirt edemezse.
pub fn self_test() -> Result<String, String> {
    let sample = r"
        fn production() {
            self.state.try_add_balance(&a, 1)?;
            self.state.try_mint_balance(&b, 2)?;
        }
#[cfg(test)]
mod tests {
    fn setup() {
        state.try_add_balance(&c, 3);
        state.try_add_balance(&d, 4);
    }
}
    ";
    let lines = production_lines(sample);
    let moves = lines
        .iter()
        .filter(|(_, l)| l.contains(MOVE_FN) && !l.contains(MINT_FN))
        .count();
    let mints = lines.iter().filter(|(_, l)| l.contains(MINT_FN)).count();
    if moves != 1 {
        return Err(format!(
            "self_test: uretimde 1 tasima beklenirdi, {moves} sayildi (test modulu sizmis olabilir)"
        ));
    }
    if mints != 1 {
        return Err(format!(
            "self_test: uretimde 1 basim beklenirdi, {mints} sayildi"
        ));
    }
    // An example in a comment line must not be counted.
    let commented = "        // self.state.try_add_balance(&a, 1);";
    if !production_lines(commented).is_empty() {
        return Err("self_test: yorumdaki cagri sayildi".into());
    }
    Ok("minting-paths-are-counted self-test OK: the test module and comments are outside the count".into())
}
