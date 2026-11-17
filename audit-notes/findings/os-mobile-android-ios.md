# İşletim Sistemi Denetimi: Mobil Hedefler (Android NDK & iOS SDK)

## 1. Ortam Bilgileri
- **Hedefler**: `aarch64-linux-android`, `x86_64-linux-android`, `aarch64-apple-ios`, `aarch64-apple-ios-sim`
- **Rolü**: `mobile/core/`, `mobile/ffi/`, iOS ve Android hafif cüzdan ve doğrulayıcı runtime'ları.

## 2. Test ve Çalıştırma Sonuçları
- C FFI dışa aktarım (export) yüzeyi, bellek sızıntısı analizi.
- Arka plan pil tüketimi ve uyku modu (sleep/wake) ağ bağlantı kesintileri.

## 3. Bulgular ve Çözümler
- **B-OS-MOB-01 (C FFI Ham Gösterici Bellek Temizliği)**:
  - *Belirti*: FFI arayüzünden C tarafına aktarılan string ve buffer göstericilerinin serbest bırakılmasında çift serbest bırakma (`double free`) riski.
  - *Kök Neden*: `CString::into_raw` sonrası karşı tarafın bellek iadesini Budlum FFI `budlum_free_string` çağrısıyla yapmaması.
  - *Çözüm*: FFI sınırında açık `budlum_free_buffer` API'si zorunlu kılındı ve FFI testlerinde sanitizers ile doğrulandı.
  - *Durum*: Çözüldü (`5d912761`).
