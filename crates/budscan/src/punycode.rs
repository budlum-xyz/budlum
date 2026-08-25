//! The RFC 3492 Punycode encoder (the encoding direction only).
//!
//! # Why it is here and why it is not a dependency
//!
//! A browser's address bar may have to **display** a name it does not accept:
//! a name sitting in history, appearing over a link, or typed into an error.
//! Drawing the non-ASCII bytes as they are at that moment is the gap the
//! homograph attack lives in. Displaying punycode makes what is displayed the
//! same as what is resolved.
//!
//! The decoding direction is deliberately absent. This browser does not
//! **convert** a punycode label back to Unicode: a name starting with `xn--`
//! is already ASCII, passes the name rule and resolves as it is. Decoding
//! would only be needed to display it more prettily, and "displaying it more
//! prettily" is exactly what this module avoids.
//!
//! # Parameters
//!
//! RFC 3492 section 5: `base=36`, `tmin=1`, `tmax=26`, `skew=38`, `damp=700`,
//! `initial_bias=72`, `initial_n=128`, `delimiter='-'`. These are part of the
//! definition, not something tunable; change them and the output is not
//! punycode.

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

/// The punycode digit for 0..=35.
fn digit_char(d: u32) -> char {
    debug_assert!(d < BASE);
    // Narrowing is impossible because `d < BASE`, but writing it with `as`
    // would leave that impossibility to the reader rather than the compiler.
    let d = u8::try_from(d).unwrap_or(0);
    let c = if d < 26 { b'a' + d } else { b'0' + (d - 26) };
    c as char
}

/// Converts a label to punycode (the `xn--` prefix is **not included**).
///
/// Returns `None` for a label that is already entirely ASCII: its punycode
/// form is itself, and adding `xn--` would make it a different name.
///
/// Also returns `None` on overflow. The RFC's `punycode_overflow` case cannot
/// occur in practice for a name limited to 32 characters, but producing
/// nothing rather than silently producing a wrong string lets the caller know
/// what happened.
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
        // The RFC 3492 section 7.1 examples (in their lowercased form).
        // Arabic: the RFC's (A) example.
        assert_eq!(
            encode_label("\u{0644}\u{064A}\u{0647}\u{0645}\u{0627}\u{0628}\u{062A}\u{0643}\u{0644}\u{0645}\u{0648}\u{0634}\u{0639}\u{0631}\u{0628}\u{064A}\u{061F}")
                .as_deref(),
            Some("egbpdaj6bu4bxfgehfvwxn")
        );
        // Chinese (simplified), RFC (B).
        assert_eq!(
            encode_label(
                "\u{4ED6}\u{4EEC}\u{4E3A}\u{4EC0}\u{4E48}\u{4E0D}\u{8BF4}\u{4E2D}\u{6587}"
            )
            .as_deref(),
            Some("ihqwcrb4cv8a8dqg056pqjye")
        );
        // Czech, RFC (D): basic code points plus the delimiter.
        assert_eq!(
            encode_label("Pro\u{010D}prost\u{011B}nemluv\u{00ED}\u{010D}esky").as_deref(),
            Some("Proprostnemluvesky-uyb24dma41a")
        );
    }

    #[test]
    fn one_cyrillic_letter_in_a_latin_word() {
        // The example from the architecture document: `ayaz` with a Cyrillic
        // first letter (U+0430).
        //
        // NOTE: the architecture note used to write `xn--yaz-hlc.bud` for this
        // value. It was measured and it is wrong: RFC 3492's own algorithm and
        // Python's `str.encode("idna")` reference both produce
        // `xn--yaz-5cd.bud`. The document was corrected; the value here is the
        // computed one, not a copied one.
        assert_eq!(encode_label("\u{0430}yaz").as_deref(), Some("yaz-5cd"));
    }

    #[test]
    fn ascii_is_not_punycoded() {
        assert_eq!(encode_label("ayaz"), None);
        assert_eq!(encode_label(""), None);
    }
}
