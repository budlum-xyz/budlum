//! Chat şablonu - yapısal taslak.
//!
//! the upstream vendor V4'ün gerçek şablonu `encoding_dsv4`dür ve HF tokenizer
//! config'inden okunur. Bu modül marker icat etmez; yalnızca sıralamayı
//! (system → user → assistant) yapısal olarak sabitler. Üretimde tokenizer
//! config'iyle birebir eşleşme testi zorunludur (bkz.
//! `docs/EGITIM_VERISI_STRATEJISI` §6: "Use the V4 chat template
//! (encoding_dsv4). Do not roll your own.").

use crate::jsonl::InstructionRecord;

/// Yapısal şablon taslağı: gerçek marker'lar üretimde tokenizer'dan gelir.
/// Bu fonksiyonun çıktısı eğitimde KULLANILMAZ - yalnızca kayıt sırasını
/// gösteren bir taslaktır.
#[must_use]
pub fn render_structural(rec: &InstructionRecord) -> String {
    let mut out = String::new();
    if let Some(system) = &rec.system {
        out.push_str(&format!("[system] {system}\n"));
    }
    out.push_str(&format!("[user] {}\n", rec.user));
    out.push_str(&format!("[assistant] {}\n", rec.assistant));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_render_keeps_turn_order() {
        let rec = InstructionRecord {
            system: Some("s".to_string()),
            user: "u".to_string(),
            assistant: "a".to_string(),
        };
        let rendered = render_structural(&rec);
        let s = rendered.find("[system]").unwrap();
        let u = rendered.find("[user]").unwrap();
        let a = rendered.find("[assistant]").unwrap();
        assert!(s < u && u < a);
    }
}
