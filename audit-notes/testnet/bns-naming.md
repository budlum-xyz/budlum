# Testnet Tasarımı: .bud Alan Adı Servisi (BNS)

## 1. Gereksinim
`BNS_DIREKTIF.md` uyarınca:
- Her kayıt adı tam olarak bir etiket ve `.bud` son ekinden oluşur (Örn: `ayaz.bud`).
- Etiket uzunluğu 3 ile 32 karakter arasındadır (`.bud` sayılmaz). 3 karakterli isimler 100 kat ücret öder.
- BNS kaydı hiçbir yönetim eylemiyle dondurulamaz, iptal edilemez veya devralınamaz.
- Alan adı pazarı (Marketplace), teklif verme (Offers), B.U.D. 3.0 depolama bağlama ve Sparse Merkle Tree (SMT) kanıtları testnet için tamdır.

## 2. Mevcut Durum
- `src/bns/` modülü altında:
  - `registry.rs`: Ana BNS kayıt ve ücret hesaplama mantığı,
  - `types.rs`: `NameRecord`, `BnsError`, durum tanımları,
  - `smt.rs`: Sparse Merkle Tree kök ve dahil olma kanıtları,
  - `offers.rs`: Alan adı teklif ve pazar altyapısı,
  - `bud3.rs`: B.U.D. 3.0 içerik kimliği (CID) bağlayıcıları.

## 3. İlgili İşlem Türleri (Transaction Types)
- `BnsRegister`: Alan adı tescili,
- `BnsTransfer`: Alan adı devri,
- `BnsUpdateRecord`: İsim kaydı ve yönlendirme güncellemesi,
- `BnsRenew`: Süre uzatma,
- `BnsListForSale`: Satışa çıkarma,
- `BnsBuy`: Pazar üzerinden satın alma,
- `BnsMakeOffer`: Teklif sunma,
- `BnsAcceptOffer`: Teklifi kabul etme.

## 4. İlgili Dosyalar
- `src/bns/registry.rs`
- `src/bns/types.rs`
- `src/bns/smt.rs`
- `src/core/transaction.rs`
- `src/execution/executor.rs`
- `src/rpc/`
- `proto/budlum/network/protocol.proto`

## 5. Doğrulama ve Testler
- `cargo test --lib bns::`
- `src/tests/bns_acceptance.rs`
- `src/tests/bns_safety.rs`
- `xtask/gates/src/gates/bns_gate.rs`
