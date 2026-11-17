# İşletim Sistemi Denetimi: Windows (MSVC x86_64)

## 1. Ortam Bilgileri
- **İşletim Sistemi**: Windows Server 2022 / Windows 11 (`windows-latest`)
- **Derleyici**: MSVC (cl.exe) + Rust
- **Rolü**: Windows düğüm işletmecileri ve masaüstü istemci determinizmi.

## 2. Test ve Çalıştırma Sonuçları
- Dosya yolu ayracı (`\` vs `/`), dosya kilitleme ve `sled` / `rocksdb` kalıcılık testleri.

## 3. Bulgular ve Çözümler
- **B-OS-WIN-01 (Dosya Kilitleme ve Açık Handle Çakışması)**:
  - *Belirti*: Testler tamamlanırken geçici veritabanı klasörünün silinememesi (`Access is denied: OS error 5`).
  - *Kök Neden*: Windows üzerinde açık kalan file handle'ların dosya silinmesine izin vermemesi (POSIX unlink vs Windows CreateFile SHARE_DELETE).
  - *Çözüm*: Veritabanı ve snapshot nesnelerine açık `drop()` ve flush çağrıları eklendi.
  - *Durum*: Çözüldü (`ad88285c`).
