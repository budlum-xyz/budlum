//! Arz yaratan her yol sayilmis ve tavana bagli olmali.
//!
//! Sabit bir arz tavani, ancak **arz yaratan her yolun tamami** onu sorarsa
//! bir sinirdir. Tek bir yol disarida kalirsa tavan yalnizca bir belge olur:
//! okuyan kisi 100 milyonun ust sinir oldugunu sanir, kod baska bir sey yapar.
//!
//! Olculen sey su: `try_add_balance` cagiran her uretim satiri ya
//! **tasima**dir (var olan parayi bir yerden alip baska yere koyar: iade,
//! ucret, kilit cozme) ya da **basim**dir (yeni para yaratir). Basim olanlar
//! `try_mint_balance` cagirmali; o fonksiyon tavani denetleyen tek yerdir.
//!
//! # Neden bir liste tutuluyor
//!
//! Kapi, hangi cagrinin tasima hangisinin basim oldugunu kaynaktan
//! **cikaramaz** - bu bir muhasebe sorusu, bir sozdizimi sorusu degil. O
//! yuzden asagida her `try_add_balance` cagri yerinin neden tasima oldugu tek
//! tek yaziliyor. Yeni bir cagri eklendiginde kapi kirmizi yanar ve ekleyen
//! kisiyi bu soruyu cevaplamaya zorlar: bu yeni para mi, yoksa yer degistiren
//! para mi?
//!
//! Zahmetli olmasi kasitli. Arz yaratan bir yolun sessizce eklenmesi, bu
//! zincirin verebilecegi en pahali hatadir; kapinin maliyeti bir satir
//! gerekce yazmak.

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
/// Sayi bilerek tutuluyor: bir cagri eklenirse toplam degisir ve kapi yanar.
/// Gerekceler, o satirlarin neden tavani sormadigini okuyana anlatir.
const TRANSFER_JUSTIFICATIONS: &[(&str, usize, &str)] = &[
    (
        "src/chain/blockchain.rs",
        11,
        "kopru kilidi cozme ve iade (var olan kilitli para geri veriliyor), \
         depolama anlasmasi iadeleri ve operator bag iadeleri (daha once \
         borclandirilmis para), ucret dagitimi (odenmis ucretin paylastirilmasi). \
         Hicbiri yeni arz yaratmaz.",
    ),
    (
        "src/core/account.rs",
        2,
        "biri unbonding kuyrugunun serbest birakilmasi (daha once stake olarak \
         taahhut edilmis, tavana zaten sayilan para geri veriliyor - yeni arz \
         degil, kategori degistiren arz); digeri `try_mint_balance`'in kendi \
         govdesi, tavani denetledikten sonra asil eklemeyi yapan satir.",
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
        // Sinir yalnizca sutun sifirdaki `mod tests`: `#[cfg(test)]` uretim
        // kodunda da geciyor (test-only dallar, test-only yardimcilar), o
        // yuzden onu sinir saymak dosyanin yarisini gorunmez yapardi.
        if line.starts_with("mod tests") || line.starts_with("pub mod tests") {
            in_tests = true;
        }
        // Yorumlar sayilmaz: bir gerekce metninde gecen fonksiyon adi cagri
        // degildir. `fn` ile baslayan satir da sayilmaz - fonksiyonun kendi
        // tanimi, ona yapilan bir cagri degil.
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
                 gerekcelendirilmis sayi {expected}.\n    \
                 Kayitli gerekce: {why}\n    \
                 Yeni bir cagri eklendiyse su soru cevaplanmali: bu yeni para mi \
                 (o zaman `{MINT_FN}` kullanilmali, tavani denetler) yoksa yer \
                 degistiren para mi (o zaman gerekce bu kapiya yazilmali)? \
                 Bir cagri silindiyse sayi guncellenmeli."
            );
        }
    }

    if !problems.is_empty() {
        return Err(format!("minting-paths-are-counted:{problems}"));
    }
    if minting == 0 {
        return Err(format!(
            "minting-paths-are-counted: hic `{MINT_FN}` cagrisi bulunamadi. \
             Tavan denetimi kaldirildiysa arz tavani yalnizca bir belgedir."
        ));
    }

    Ok(format!(
        "minting-paths-are-counted OK: {minting} basim cagrisi tavana bagli, \
         {moving} tasima cagrisi gerekcelendirilmis"
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
    // Yorum satirindaki bir ornek sayilmamali.
    let commented = "        // self.state.try_add_balance(&a, 1);";
    if !production_lines(commented).is_empty() {
        return Err("self_test: yorumdaki cagri sayildi".into());
    }
    Ok("minting-paths-are-counted self-test OK: test modulu ve yorumlar sayimin disinda".into())
}
