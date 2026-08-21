//! RFC 3492 Punycode kodlayicisi (yalniz kodlama yonu).
//!
//! # Neden burada, neden bir bagimlilik degil
//!
//! Bir tarayicinin adres cubugu, kabul etmedigi bir adi **gostermek** zorunda
//! kalabilir: gecmiste duran, bir baglantinin ustunde beliren, bir hatada
//! yazilan ad. O anda ASCII disi baytlari oldugu gibi cizmek, homograf
//! saldirisinin yasadigi bosluktur. Punycode gostermek, gosterilen sey ile
//! cozulen seyi ayni yapar.
//!
//! Cozme yonu bilerek yok. Bu tarayici punycode bir etiketi Unicode'a
//! **cevirmez**: `xn--` ile baslayan bir ad zaten ASCII'dir, ad kuralindan
//! gecer ve oldugu gibi cozulur. Kod cozmek yalniz onu daha guzel gostermek
//! icin gerekirdi ve "daha guzel gosterme" bu modulun kacindigi seydir.
//!
//! # Parametreler
//!
//! RFC 3492 §5: `base=36`, `tmin=1`, `tmax=26`, `skew=38`, `damp=700`,
//! `initial_bias=72`, `initial_n=128`, `delimiter='-'`. Bunlar tanimin parcasi,
//! ayarlanabilir bir sey degil; degistirilirse cikti punycode olmaz.

const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;
const DELIMITER: char = '-';

/// RFC 3492 `adapt`.
fn adapt(mut delta: u32, numpoints: u32, firsttime: bool) -> u32 {
    delta = if firsttime { delta / DAMP } else { delta / 2 };
    delta += delta / numpoints;
    let mut k = 0;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + (BASE - TMIN + 1) * delta / (delta + SKEW)
}

/// 0..=35 icin punycode rakami.
fn digit_char(d: u32) -> char {
    debug_assert!(d < BASE);
    // `d < BASE` oldugu icin daralma imkansiz, ama `as` ile yazmak o
    // imkansizligi derleyiciye degil okuyucuya birakir.
    let d = u8::try_from(d).unwrap_or(0);
    let c = if d < 26 { b'a' + d } else { b'0' + (d - 26) };
    c as char
}

/// Bir etiketi punycode'a cevirir (`xn--` oneki **dahil degil**).
///
/// Zaten tamamen ASCII olan bir etiket icin `None` doner: onun punycode
/// karsiligi kendisidir ve `xn--` eklemek onu baska bir ad yapar.
///
/// Tasma durumunda da `None` doner. RFC'nin `punycode_overflow` durumu
/// pratikte 32 karakterle sinirli bir adda gorulemez, ama sessizce yanlis bir
/// dizgi uretmek yerine hicbir sey uretmemek, cagiranin ne oldugunu bilmesini
/// saglar.
#[must_use]
pub fn encode_label(input: &str) -> Option<String> {
    if input.is_ascii() {
        return None;
    }

    let chars: Vec<char> = input.chars().collect();
    let mut output = String::with_capacity(chars.len() * 2);

    // Temel (ASCII) kod noktalari once, sirasi bozulmadan.
    let basic_count = chars
        .iter()
        .filter(|c| c.is_ascii())
        .inspect(|c| output.push(**c))
        .count();
    let mut handled = u32::try_from(basic_count).ok()?;
    let basic = handled;
    if basic > 0 {
        output.push(DELIMITER);
    }

    let total = u32::try_from(chars.len()).ok()?;
    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;

    while handled < total {
        // Kalanlar arasinda >= n olan en kucuk kod noktasi.
        let next_cp = chars
            .iter()
            .map(|c| *c as u32)
            .filter(|cp| *cp >= n)
            .min()?;

        delta = delta.checked_add((next_cp - n).checked_mul(handled + 1)?)?;
        n = next_cp;

        for &c in &chars {
            let cp = c as u32;
            if cp < n {
                delta = delta.checked_add(1)?;
            }
            if cp == n {
                let mut rest = delta;
                let mut k = BASE;
                loop {
                    let threshold = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if rest < threshold {
                        break;
                    }
                    output.push(digit_char(
                        threshold + (rest - threshold) % (BASE - threshold),
                    ));
                    rest = (rest - threshold) / (BASE - threshold);
                    k += BASE;
                }
                output.push(digit_char(rest));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }

    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_3492_vectors() {
        // RFC 3492 §7.1 ornekleri (kucuk harfe cevrilmis biciminde).
        // Arapca: "leylimahabbetlerinincesizce..." degil, RFC'nin (A) ornegi.
        assert_eq!(
            encode_label("\u{0644}\u{064A}\u{0647}\u{0645}\u{0627}\u{0628}\u{062A}\u{0643}\u{0644}\u{0645}\u{0648}\u{0634}\u{0639}\u{0631}\u{0628}\u{064A}\u{061F}")
                .as_deref(),
            Some("egbpdaj6bu4bxfgehfvwxn")
        );
        // Cince (basitlestirilmis), RFC (B).
        assert_eq!(
            encode_label(
                "\u{4ED6}\u{4EEC}\u{4E3A}\u{4EC0}\u{4E48}\u{4E0D}\u{8BF4}\u{4E2D}\u{6587}"
            )
            .as_deref(),
            Some("ihqwcrb4cv8a8dqg056pqjye")
        );
        // Cekce, RFC (D): temel kod noktalari + ayirici.
        assert_eq!(
            encode_label("Pro\u{010D}prost\u{011B}nemluv\u{00ED}\u{010D}esky").as_deref(),
            Some("Proprostnemluvesky-uyb24dma41a")
        );
    }

    #[test]
    fn one_cyrillic_letter_in_a_latin_word() {
        // Mimari belgesinin ornegi: `аyaz` (ilk harf Kiril U+0430).
        //
        // NOT: mimari notundaki bu deger
        // icin `xn--yaz-hlc.bud` yaziyor. Olculdu ve yanlis: RFC 3492'nin
        // kendi algoritmasi ve Python'un `str.encode("idna")` referansi
        // ikisi de `xn--yaz-5cd.bud` uretiyor. Belge duzeltildi; buradaki
        // deger hesaplanan degerdir, kopyalanan degil.
        assert_eq!(encode_label("\u{0430}yaz").as_deref(), Some("yaz-5cd"));
    }

    #[test]
    fn ascii_is_not_punycoded() {
        assert_eq!(encode_label("ayaz"), None);
        assert_eq!(encode_label(""), None);
    }
}
