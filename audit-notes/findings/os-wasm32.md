# İşletim Sistemi Denetimi: WebAssembly (wasm32-unknown-unknown)

## 1. Ortam Bilgileri
- **Hedef**: `wasm32-unknown-unknown`
- **Rolü**: Tarayıcı içi cüzdan çekirdeği, hafif istemci SPV doğrulaması ve post-quantum imza doğrulayıcı test vektörleri.

## 2. Test ve Çalıştırma Sonuçları
- `wasm-pack test --node` ve headless tarayıcı koşuları.
- `no-std` uyumluluğu ve `getrandom` Web Crypto API bağlayıcıları.

## 3. Bulgular ve Çözümler
- **B-OS-WASM-01 (Kriptografik Entropi Kaynağı Eksikliği)**:
  - *Belirti*: WASM hedefinde sistem zamanı veya OS entropisine erişim olmadığında `OsRng` panik üretiyordu.
  - *Kök Neden*: `getrandom` crate'inin wasm-bindgen JS hook'u olmaksızın derlenmesi.
  - *Çözüm*: Cüzdan ve kripto modülleri WASM hedeflendiğinde `getrandom/js` özelliği şart koşuldu; deterministik testlerde sabit tohumlu ChaCha20Rng kullanıldı.
  - *Durum*: Çözüldü (`ad88285c`).
