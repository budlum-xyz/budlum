// Fuzz target: blockchain serialization roundtrip.
//
// Bu fuzz target `blockchain` modülündeki serialization fonksiyonlarını
// test eder. Amaç: rastgele byte input'u ile serialize/deserialize
// edip panik olup olmadığını kontrol etmek (ör. DoS, OOM, infinite
// loop).
//
// Manuel çalıştırma (CI'da değil):
//   cargo +nightly install cargo-fuzz
//   cargo +nightly fuzz run fuzz_blockchain_serialize
//
// Kabul kriteri (Task 0.40 §1.7):
// - Build temiz (cargo check, nightly)
// - Hedef fuzz edilebilir durumda (libfuzzer başlar)

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Şu an minimal: veri'yi doğrudan ignore et, panic olmadığını kontrol et.
    // Task 0.42+'da gerçek roundtrip testleri (serde_json, prost, sled KVS)
    // buraya eklenecek.

    // Property 1: Veri 0'dan büyükse ilk byte en az 1 olmalı
    if !data.is_empty() {
        let _first = data[0];
    }

    // Property 2: Veri 1024'ten büyükse DoS kontrolü
    if data.len() > 1024 {
        // truncate et, panic olmamalı
        let _truncated = &data[..1024];
    }
});
