# Rejenerasyon & BudZero ZKVM — Domain Skill

> Bu skill, workspace'i devralan her ajanın rejenerasyon (üretim = mutabakat)
> ve BudZero ZKVM icadı üzerinde çalışmadan önce okuması gereken özet bilgi
> katmanıdır. Kaynaklar: `budlum` budzero/ docs + kodu, PLAN.md §W,
> DEPOLAMA-ZERO-* belgeleri. Her madde canlı koda bağlanır; belge değil kod
> gerçektir.

## 1. Rejenerasyon nedir (tek cümle)

**"Bayt sakla + kanıtla" değil; "talep anında üret + hash'le + commitment'la
uzlaş."** Üretim, ayrı ispat sistemi değil, mutabakatın kendisidir.

## 2. Kod haritası

| Yüzey | Dosya | Anahtar semboller |
|---|---|---|
| Rejenerasyon çekirdeği | `bud/src/bud_format_regeneration.rs` | `RegenerationChallenge::verify`, `verify_with_residual`, `RegenerationRecord` (blob, tamper-red), `regeneration_beats_proof` (%1 kuralı) |
| PACT | `bud/src/bud_format_pact.rs` | `PactRecord::pure/producer_plus_residual/residual_only` |
| zk köprü | `bud/src/bud_format_zkbridge.rs` | `engine_to_witness` (STARK-friendly witness trace) |
| Kapı | `xtask/gates/src/gates/regeneration.rs` | bağımsız Keccak-256, bağımsız ISA encode, `regenerate_storage_challenge_program`, `discover_producers`, `verify_convergence` |
| VM | `budzero/bud-vm/src/lib.rs` | `Vm::step`, `run_receipt`, `poseidon4_hash` (=30 tur), `merkle_poseidon_round`, `field_*_goldilocks` |
| ISA | `budzero/bud-isa/src/lib.rs` | 35 opcode (0x00–0x22), `MainnetActivation`, `IsaProfile` |
| AIR | `budzero/bud-proof/src/plonky3_air.rs` | 730+ sütun; selector booleanity/exclusivity/opcode-binding; LogUp 3 akümülatör (REG/MEM+STORAGE/PROG); `COL_CPU_ACTIVE` padding izolasyonu |
| Prover/verifier | `budzero/bud-proof/src/plonky3_prover.rs` | `DefaultAdapter::verify`, program hash Keccak bağlama |
| L1 entegrasyonu | `src/execution/zkvm.rs`, `src/prover/mod.rs` | `decode_program`, `zk_program_hash` |
| AI guest | `src/ai/execution/guest.rs` | `build_matmul_guest_program`, `GuestMemoryLayout`, `stark_program_hash_from_words` (kanonik), `program_hash_from_words` (tagged) |

## 3. Kanonik program-hash kuralı (kapının kalbi)

- Kanonik form: **kelimeler little-endian, ETİKETSİZ Keccak-256.**
- Verifier (`plonky3_prover.rs`) bu formu AIR'e bağlar; diğerleri ona uyar.
- 4+ üretim noktası vardır (`src/prover/mod.rs`, `src/ai/execution/guest.rs`,
  `src/domain/storage_deal.rs`, `src/execution/zkvm.rs`, `budzero/.../plonky3_prover.rs`).
- Kapı Keccak'ı kendi içinde uygular (hiçbir ağaç kütüphanesini kullanmaz) ve
  ISA kodlamayı kendi yazar — iki taraf ancak bağımsızsa karşılaştırma kanıttır.
- Tagged hash yalnız `src/ai/execution/guest.rs` (BDLM_AI_GUEST_PROGRAM_V1, kayıt
  kimliği) için haklıdır; başka yerde tag = sapma bulgusu.

## 4. Yakınsama (convergence) — kapının değişmez özelliği

1. **Idempotence:** ikinci yeniden üretim = birinci (iki düğüm aynı kaynaktan
   aynı yere varır).
2. **Onarım:** bozulmuş girdi kanonik hale GERİ getirilir, yalnız reddedilmez
   ("geri üretilsin" bu).
3. Sapma reddi yayın öncesidir; çalışma zamanı kendini değiştiren düğüm
   = uzlaşma bölünmesi.

## 5. BudZero ZKVM kritik gerçekler

- **Goldilocks alanı** P = 2^64 − 2^32 + 1; `u64` makine tamsayısı değil.
- **Poseidon:** 30 tur (R_F=8, R_P=22), alpha=7, genişlik 8; RC/MDS tek kaynakta
  (`bud_vm`); AIR bütün turları kısıtlar; VM ile AIR aynı tur sayısında
  (kilit testi: `vm_hash_still_matches_the_air_round_count`).
- **LogUp CTL:** REG / MEM+STORAGE (STORAGE_BASE=2<<60) / PROG; 3 Fiat-Shamir
  challenge (alpha, beta, gamma); sonunda her akümülatör 0.
- **R0 koruması:** dst_idx=0 ise rd_val_new=0 (VM + AIR).
- **Padding izolasyonu:** COL_CPU_ACTIVE; pad satırları LogUp'a girmez; Halt
  sonrası PC/register donar.
- **Mainnet kapıları:** VerifyMerkle + VerifyInference default KAPALI
  (harici denetim / devre yok); privacy üçlüsü (0x20–0x22) açık (30 tur Poseidon
  yüzünden).
- **VerifyMerkle AIR:** 64 genişletme satırı; yön bitleri merkle_key'e bağlı
  (rem = 2·rem' + bit); sibling/key bellek LogUp'ına bağlı (adres AIR türetir);
  son tur çıktısı köke inverse witness ile bağlı.
- **VerifyInference:** VM rd=0 (fail-closed); AIR yalnız booleanity + opcode
  binding + 8 genişletme satırında commitment zinciri tutarlılığı. Gerçek devre
  yok — "kapalı" dürüstlüğü bozmadan geliştirilebilir tek yüzey budur.
- **Program CTL çokluk:** `COL_PROG_MULT` (753) — dallanma/loop'ta atlanan
  komut dengesizliği; pre_active ile çarpım 0 kısıtı.

## 6. Ölçüm disiplini (bu alanda tekrar eden tuzaklar)

- "Sayı yazıldı, ölçülmedi" sınıfı: her kapı sayısını üreten komutla yeniden üret.
- Kanarya olmadan yeşil rapor kanıt değildir; kanarya da yanılabilir
  (pipefail | grep örneği).
- Kırmızı görülmeden yeşil sayılmaz; gerçek ağaca enjeksiyon, sonra geri alma.
- Fiat-Shamir sırası ve program-hash formu değişirse proof formatı kırılır
  (proof_format_release_checklist).
- Full `cargo test --lib` OOM → izole crate / `-p` hedefli test.
- **event_digest tuzağı (2026-08-27 ölçüldü):** Log event'i üreten programların
  proof'unda `ExecutionPublicInputs.event_digest` = `event_digest_from_events(&receipt.events)`
  (birikimli limb toplamı); düz Keccak veya [0;32] verilirse verify `InvalidProof`.
  storage-challenge'da Log yok → [0;32] çalışır; private-transfer/matmul'de var.
- **Kanoniic program bench sayıları (2026-08-27, release, tek örnek):**
  storage-challenge 66 satır / 0.270s prove / 0.019s verify;
  private-transfer 12 satır / 0.166s / 0.016s; matmul-2-3-2 90 satır / 0.548s / 0.022s.
  `regeneration_beats_proof` eşiği (üretim < %1 × proof): kapı üretimi ms altı,
  prove yüzlerce ms — eşik rahatça tutar; yine de kanonik sayılar burada.
