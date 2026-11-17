# İşletim Sistemi Denetimi: Alpine Linux 3.21 musl x86_64

## 1. Ortam Bilgileri
- **C Kütüphanesi**: `musl libc 1.2.5`
- **Rolü**: Hafif Docker imajları (`wolfi-base`, `alpine`) ve statik ikili dağıtımlar (`x86_64-unknown-linux-musl`).

## 2. Test ve Çalıştırma Sonuçları
- Statik derleme (`cargo build --target x86_64-unknown-linux-musl`).
- Yığın (stack) boyutu ve bellek ayırıcı (mimalloc) kontrolleri.

## 3. Bulgular ve Çözümler
- **B-OS-ALP-01 (musl Varsayılan Yığın Boyutu Sınırı)**:
  - *Belirti*: musl libc üzerinde çalışan thread'lerde derin özyinelemeli (recursive) STARK FRI kanıt doğrulamalarında yığın taşması (`SIGSEGV stack overflow`).
  - *Kök Neden*: musl libc varsayılan thread stack boyutunun glibc'ye göre çok daha küçük (128 KB - 80 KB) olması.
  - *Çözüm*: Rayon ve kanıtlayıcı thread havuzu başlatılırken `.stack_size(8 * 1024 * 1024)` (8 MB) açıkça yapılandırıldı.
  - *Durum*: Çözüldü (`ed5faed7`).
