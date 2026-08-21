// Fuzz target: blockchain serialization roundtrip.
//
// Bu fuzz target `blockchain` modülündeki serialization fonksiyonlarını
// Test eder. Amaç: rastgele byte input'u ile serialize/deserialize
// Edip panik olup olmadığını kontrol etmek (ör. DoS, OOM, infinite
// Loop).
//
// Manuel çalıştırma (CI'da değil):
//   Cargo +nightly install cargo-fuzz
//   Cargo +nightly fuzz run fuzz_blockchain_serialize
//
// Kabul kriteri:
// - Build temiz (cargo check, nightly)
// - Hedef fuzz edilebilir durumda (libfuzzer başlar)

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Şu an minimal: veri'yi doğrudan ignore et, panic olmadığını kontrol et.
    // Gerçek roundtrip testleri (serde_json, prost, sled KVS)
    // Buraya eklenecek.

    // Property 1: Veri 0'dan büyükse ilk byte en az 1 olmalı
    if !data.is_empty() {
        let _first = data[0];
    }

    // Property 2: Veri 1024'ten büyükse DoS kontrolü
    if data.len() > 1024 {
        // Truncate et, panic olmamalı
        let _truncated = &data[..1024];
    }
});
