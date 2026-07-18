# AI Inference Layer (modül README'si)

**Bu dosya, Phase 10 Bölüm 4 modül-ayrımı kuralı gereği AI layer'ın kendi README'sidir.**
Kök `README.md` yalnızca dashboard'dur; olgunluk/risk uyarıları burada yaşar.

## Durum

- **Olgunluk:** canlı (ADIM2 + P5 ship edildi — verifier ağ'ı + RPC + ZKVM host-call).
- **Kod konumu:** `src/ai/` — `mod.rs` (soft-incentive ödül + P5 deadline/escrow),
  `registry.rs` (`AiRegistry` — request/result/outcome + agreement threshold +
  equivocation detection), `types.rs` (`AiModelSpec`, `AiInferenceRequest/Result/Outcome`,
  `AiRequestId`, `BoundedBytes`).
- **Test sayısı:** 76 (`#[test]` sayımı).
- **RPC uçları (6):** `bud_aiGetModel`, `bud_aiRegisterModel`, `bud_aiSubmitRequest`,
  `bud_aiSubmitResult`, `bud_aiGetOutcome`, `bud_aiGetActiveVerifiers`.
- **ZKVM host-call:** `Syscall imm=6` → `0x00A1_00A1` event → `AiInferenceRequest`
  otomatik oluşturma (`budzero/bud-vm/src/lib.rs`).

## Olgunluk uyarıları (Bölüm 4 kuralı)

- ⚠️ **Attestation model (Faz-1).** On-chain AI inference = off-chain hesaplama +
  on-chain attestation (k-of-n verifier agreement). **zkML DEĞİL** — büyük modelleri
  zincirde prove etmek 2026'da pratik değil (determinizm sorunu). Faz-2 kısıtlı
  model sınıfları için STARK-provable inference (BudZKVM).
- ⚠️ **Determinizm riski.** Aynı model farklı donanımda farklı çıktı verebilir →
  `agreement_threshold` hiç sağlanmayabilir. "Bounded model class" whitelist veya
  attestation sınırları mainnet öncesi dokümante edilmeli.
- ⚠️ **AI ↔ B.U.D. AccessGrant entegrasyonu YOK (F10.5-07).** `input_ref` opak
  `Vec<u8>`; eğer bir B.U.D. `DataAsset`'ine işaret ediyorsa `AiVerifier` hesaplamadan
  ÖNCE geçerli `AccessGrant` kontrolü ZORUNLU (Bölüm 2.2). Ayrı RFC adayı (P5).

## Güvenlik (P5 ship edildi)

- **Deadline enforcement:** `request_deadline_blocks` / `result_deadline_blocks`
  (request/result expiry → reject).
- **Equivocation detection:** aynı verifier çakışan commitment → dispute flag.
- **Fee escrow reclaim:** timeout'da fee iadesi (Bulgu 4-5 P5).
- **Soft-incentive:** minority verifier slash EDİLMEZ (sadece reward dışı).

## Sıradaki

AI ↔ B.U.D. AccessGrant entegrasyonu (P5 RFC, pollen P1 sonrası). Dispute/timeout
edge-case test matrisi (ARENA2-T1).
