# Budlum Denetim ve Testnet Hazirlik Raporu

Tarih: 2026-11-16. Son guncelleme: 2026-11-17. Repo: budlum-xyz/budlum.

Bu dosya denetim PR'inin dizinidir. Tum denetim kayitlari `audit-notes/`
altinda durur. Kod duzeltmeleri kendi PR'larinda, kanitlari bu dizinde.

## 1. Canli Durum Tablosu

| PR | Dal -> Hedef | Bas SHA | Acik Strix | Cozulmemis Dizi | Merge Durumu |
|---|---|---|---|---|---|
| #126 | testnet -> main | `eae0f009` | 0 | 0 | mergeable, blocked (CI) |
| #164 | garden -> testnet | `aeb2fbc2` | 0 | 0 | mergeable, blocked (CI) |
| #183 | budlum-stack -> garden | `462d7d5d` | 0 | 0 | mergeable, blocked (CI) |

Uc PR'da da acik Strix bulgusu ve cozulmemis yorum dizisi kalmadi. Kalan is
yalnizca CI kosularinin yesile donmesi ve Strix re-review onayi.

## 2. Kayitlar

- `plan.md`: denetim plani, ortam matrisi, dizin ve modul envanteri.
- `strix-ledger.md`: Strix bulgu defteri `S-<PR>-<no>` satirlari ve toplu
  duzeltme listesi `B-0012`..`B-0029`, her biri dosya, satir, onem, durum,
  commit SHA ile.
- `testnet/index.md`: `THE_BUDLUM_DIREKTIF.md` baslik ve madde dizini.
- `testnet/aggregation-phases.md`: agregasyon modulu faz envanteri, hangi faz
  hangi dosyada, hangi olcum yapildi.
- `findings/`: tek tek bulgu dosyalari. `scenario11-finality-stall.md` ilk
  ornek. Yeni bulgular ayni bicimde eklenir.

## 3. Bulgu Duzeyi Ozeti

`strix-ledger.md` icinde `B-` satirlari su dagilimda:

| Onem | Adet | Ornek |
|---|---|---|
| Critical | 3 | B-0012 relay hop, B-0013 senkron strike, B-0014 odul havuzu |
| High | 6 | B-0015 B.U.D.3 onarim, B-0016 P2P sinirlar, B-0017 governor, B-0018 kolon tavan, B-0023 oy anahtari, B-0028 agregasyon depo tavani |
| Medium | 5 | B-0019, B-0021, B-0024, B-0026, B-0027 |
| Low | 3 | B-0020, B-0025, B-0029 |

Her satir su bicimde: yol ve satir, ne oldugu, neden yanlis oldugu, etkisi,
duzeltme, durum ve kanit commit SHA'si.

## 4. Denetim Alanlari ve Kapsam

| Alan | Modul | Durum |
|---|---|---|
| Fikir birligi: PoW | `src/consensus/pow.rs`, `src/mining` | tarandi |
| Fikir birligi: PoS | `src/consensus/pos.rs`, `src/tokenomics` | tarandi |
| Fikir birligi: BFT | `src/consensus/{qc,handoff,hotstuff,finality}.rs` | tarandi |
| Fikir birligi: izole PoA | `src/consensus/poa.rs`, `src/settlement/domains.rs` | tarandi |
| Yerlesim ilkelleri | `src/settlement/`, `src/core/account.rs` | tarandi |
| BudZero ve BudZKVM | `budzero/{bud-vm,bud-proof,bud-compiler}` | kismi, faz envanteri `testnet/aggregation-phases.md` |
| `budlum-wallet-core` | `crates/` | tarandi |
| B.U.D. depolama | `src/storage/bud3` | tarandi |
| Ekosistem modulleri | `src/{garden,ai,budlumxyz,domain}` | tarandi |
| CI ve tedarik zinciri | `.github/workflows`, `xtask/gates`, `supply-chain/` | tarandi |

## 5. Kapi Durumu

`budlum-gates --all` yerel olarak calistirildi: 165 kapi, 1222 dosya. Tek FAIL
`cargo-vet` ve bu ortamda `cargo-vet` kurulu olmadigi icin beklenen sonuc.
`cargo fmt --all -- --check` temiz. GitHub tarafinda zorunlu kapilar: fmt,
clippy `-D warnings`, test, CodeQL, Zizmor, Gitleaks, cargo-audit, cargo-deny,
Semgrep, dependency review.

## 6. Uygulanan Kurallar

Yeni `#[allow(...)]` yok. Yeni `#[ignore]` yok. Eski commit sabitleme yok.
Mantik zayiflatma yok. Force-push, gecmis yeniden yazimi, koruma baypasi yok.
Tum commitler `Lubo's Ruler <ayazkussann@gmail.com>` kimligiyle. Lisans
PolyForm Shield License 1.0.0 olarak kalir. `VerifyMerkle` 64 derinlik uretimde
kapali, `AggMode` ana agda `Off`.
