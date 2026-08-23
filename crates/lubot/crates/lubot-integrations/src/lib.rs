// Unsafe kilidi: bu crate su an 0 unsafe. Bir `unsafe` blok girdigi an
// derleme FAIL eder (regresyon kapisi). Ana crate ile ayni politika.
#![forbid(unsafe_code)]
//! # lubot-integrations - dış veri adaptör iskeleti
//!
//! Kapalı-devre ilkesiyle dış servislere bağlanmak için yeniden
//! kullanılabilir desenler: WebSocket bağlantı yönetimi, REST istek/yanıt
//! modelleri, toplu mesaj ayrıştırma ve kapatma (kill) sinyali.
//!
//! Bu crate bağlantıyı kendisi kurmaz; taşıyıcıyı (tokio-tungstenite,
//! reqwest vb.) çağıran taraf seçer. Böylece testler ve farklı çalışma
//! zamanları için bağımlılıksız kalır.

pub mod rest;
pub mod ws;

/// Toplu mesaj ayrıştırma yardımcısı: gelen bir JSON değerini, tek bir
/// nesne ya da nesne dizisi olmasına bakmadan vektöre çevirir.
///
/// # Errors
///
/// Değer ne dizi ne de nesne ise.
pub fn as_items(value: serde_json::Value) -> Result<Vec<serde_json::Value>, String> {
    match value {
        serde_json::Value::Array(items) => Ok(items),
        serde_json::Value::Object(_) => Ok(vec![value]),
        other => Err(format!("beklenen nesne/dizi, gelen: {other}")),
    }
}

/// Durum iletisini denetler: `{"T":"success","msg":"connected"}` veya
/// `{"T":"success","msg":"authenticated"}` biçimindeki bağlantı/oturum
/// bildirimlerini tanır.
#[must_use]
pub fn is_success_connected_or_authed(item: &serde_json::Value) -> bool {
    let is_success = item.get("T").and_then(serde_json::Value::as_str) == Some("success");
    let msg = item
        .get("msg")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    is_success && matches!(msg, "connected" | "authenticated")
}

/// Kanonik sembol eşleme: verilen sembolü yapılandırılmış listede büyük
/// harfle arar; tam eşleşme yoksa son karakteri atılmış halini dener
/// (bazı sağlayıcılar `BTC` yerine `BTCUSD`/`BTCUSDT` gönderir).
#[must_use]
pub fn canonical_symbol(symbol: &str, known: &std::collections::BTreeSet<String>) -> String {
    let s = symbol.trim().to_uppercase();
    if known.contains(&s) {
        return s;
    }
    // Try every prefix, longest first. The previous form dropped exactly one
    // character, so `BTCUSD` -> `BTCUS` never matched `BTC` and the documented
    // `BTCUSDT` case could not work either; the suffix is not one character.
    // Longest-first keeps the match greedy: with both `BTC` and `BTCU` known,
    // `BTCUSD` resolves to `BTCU`.
    // `char_indices` keeps the cut on a UTF-8 boundary; `s[..n]` on a byte
    // index would panic mid-character.
    let cuts: Vec<usize> = s.char_indices().map(|(i, _)| i).skip(1).collect();
    for i in cuts.into_iter().rev() {
        if known.contains(&s[..i]) {
            return s[..i].to_string();
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_items_normalizes_scalar_and_array() {
        let single = serde_json::json!({"a": 1});
        assert_eq!(as_items(single).unwrap().len(), 1);
        let many = serde_json::json!([{"a": 1}, {"b": 2}]);
        assert_eq!(as_items(many).unwrap().len(), 2);
        assert!(as_items(serde_json::json!(42)).is_err());
    }

    #[test]
    fn connection_messages_detected() {
        assert!(is_success_connected_or_authed(
            &serde_json::json!({"T": "success", "msg": "connected"})
        ));
        assert!(is_success_connected_or_authed(
            &serde_json::json!({"T": "success", "msg": "authenticated"})
        ));
        assert!(!is_success_connected_or_authed(
            &serde_json::json!({"T": "error", "msg": "connected"})
        ));
        assert!(!is_success_connected_or_authed(
            &serde_json::json!({"T": "success", "msg": "x"})
        ));
    }

    #[test]
    fn canonical_symbol_matches_trimmed_suffix() {
        let known = std::collections::BTreeSet::from(["BTC".to_string(), "ETH".to_string()]);
        assert_eq!(canonical_symbol(" btc ", &known), "BTC");
        assert_eq!(canonical_symbol("BTCUSD", &known), "BTC");
        assert_eq!(canonical_symbol("ETHUSDT", &known), "ETH");
        assert_eq!(canonical_symbol("SOL", &known), "SOL"); // bilinmeyen -> olduğu gibi
    }
}
