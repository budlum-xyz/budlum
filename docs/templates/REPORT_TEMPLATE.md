# TASKX.Y_TOPIC_ARENAn — Report Title

> **TR Özet:** (2–5 satır — raporun konusu, en kritik bulgu/sonuç, durum etiketi.)

| Metadata | Değer |
|---|---|
|  |  X.Y (boşluklu, kanonik kural) |
| Tarih | YYYY-MM-DD HH:MM UTC+3 |
| HEAD SHA | `abcdef1` (**yalnızca `git cat-file -t` ile doğrulanmış SHA**) |
| Yazar | ARENAn |
| Durum | 🔵 Aktif / 🟢 Kanonik / ⚪ Arşiv |
| Kullanıcı kararları | (varsa soru-id + seçenek: Q1(a), Q2(b)…) |

---

## 1. Executive summary

(≤10 satır. İddia → kanıt eşlemesi zorunlu. Sahte-yeşil/şişirme iddia YASAK.)

## 2. Scope

- İncelenen dosyalar/modüller (satır referanslı: `src/foo.rs:123`).
- Kapsam dışı (bilinçli bırakılanlar + neden).

## 3. Findings

| ID | Şiddet | Bulgu | Kanıt (dosya:satır / komut çıktısı) | Durum |
|---|---|---|---|---|
| F-1 | C/H/M/L | … | … | Açık / Fix `sha` / Kapalı |

## 4. Evidence

Her iddia için: çalıştırılan komut + özet çıktı + SHA. CI hakemdir:
`cargo fmt --all -- --check`, `cargo clippy --lib --tests -- -D warnings`, `cargo test --lib` (+ BudZero karşılıkları).

## 5. Debts → next

(Dürüst borç listesi — stub/TODO/ignore nedeni ve hedef . "Kanıtsız mainnet-ready/audited ibaresi yasak" kuralı geçerli.)

## 6. Decisions (user)

(Kullanıcı onayına sunulan sorular + seçilen seçenekler.)

---

Yazar: ARENAn — commit trailer: `Co-authored-by: ARENAn <arenan@budlum.ai>`
