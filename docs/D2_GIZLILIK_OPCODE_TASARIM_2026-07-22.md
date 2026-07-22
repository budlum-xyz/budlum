# D2 — Gizlilik Katmanı Opcode Tasarımı (Poseidon) — 2026-07-22

**Karar (Ayaz, Bölüm 10 çözüldü):** v1'de dahil, Poseidon, paralel izole subtree, kullanıcı view-key, TEE opt-in cüzdan.
**Hazırlayan:** ARENA1 · **Durum:** Tasarım dokümanı (implementation multi-session). Kod yazımına hazır — tüm kararlar çözüldü.

---

## 0. Mevcut altyapı (doğrulandı)

- `budzero/bud-isa/src/lib.rs`: `Opcode` enum (u8 repr), **0x00–0x1F kullanımda**. Sonraki boş: **0x20**.
- **`Poseidon = 0x19` ZATEN VAR** — hash opcode'u tanımlı. Implementasyonun wired olup olmadığı implementation'da doğrulanmalı.
- `MainnetActivation` gate pattern'i hazır: `requires_mainnet_activation()`, `allows(opcode)`, `decode_for_mainnet`. VerifyMerkle + VerifyInference bu pattern'le staged rollout. Yeni gizlilik opcode'ları aynı gate'i kullanır.
- `budzero/bud-vm/`, `budzero/bud-proof/` (plonky3_air.rs, plonky3_prover.rs, adapter.rs), `budzero/bud-state/` mevcut.

## 1. Yeni opcode ailesi (0x20–0x22)

| Opcode | Değer | Anlam | Semantics (rd/rs1/rs2/imm) |
|---|---|---|---|
| `PrivacyCommit` | 0x20 | amount + recipient + blinding_factor → commitment hash (zincire sadece hash yazılır) | rd=hedef reg (commitment hash), rs1=amount ptr, rs2=recipient ptr, imm=blinding |
| `NullifierCheck` | 0x21 | harcanan commitment'ı işaretleyen tek-kullanımlık nullifier; çifte-harcama önler (hangi commitment açıklanmadan) | rd=0/1 (valid/spent), rs1=nullifier ptr, rs2=secret ptr |
| `SumConservation` | 0x22 | "girdiler toplamı = çıktılar toplamı" miktarlara bakmadan (homomorfik commitment) | rd=0/1, rs1=input commitments ptr, rs2=output commitments ptr |

Encoding: mevcut `Instruction { opcode, rd, rs1, rs2, imm }` formatına uyar (rd/rs1/rs2 5-bit, imm 32-bit). `decode_any`'e 0x20/0x21/0x22 arm'ları eklenir.

## 2. Mainnet gating (staged rollout)

```rust
pub fn requires_mainnet_activation(&self) -> bool {
    matches!(self, Opcode::VerifyMerkle | Opcode::VerifyInference
             | Opcode::PrivacyCommit | Opcode::NullifierCheck | Opcode::SumConservation)
}
```
`MainnetActivation`'a 3 yeni flag: `privacy_commit_enabled`, `nullifier_check_enabled`, `sum_conservation_enabled`. Default = false (ceremony sonrası açılır). Mevcut test pattern'leri (`*_default_rejects_*`, `*_full_allows_*`) kopyalanır.

## 3. Poseidon hash (0x19 — wired mı kontrol)

- 0x19 opcode tanımlı. VM execution tarafında gerçek Poseidon permutation bağlı mı, yoksa stub mı — **implementation'da doğrulanmalı** (`bud-vm` execute dalı + `bud-proof` AIR constraint).
- Gerekirse Goldilocks/Mersenne field üzerinde Poseidon permutation impl. (Plonky3 field-native).
- Commitment = `Poseidon(amount || recipient || blinding_factor)`.

## 4. Note/UTXO modeli — PARALEL İZOLE SUBTREE (karar Bölüm 10 #2)

- `bud-state`: mevcut account-model'e **dokunmadan**, ayrı bir **note subtree** eklenir.
- `Note { commitment_hash, nullifier_hash, .. }` ayrı state alanında (Bölüm 7 izolasyonu: NFT/B.U.D./Pollen state'i ile paylaşılmaz).
- Sum-conservation: girdi note'larının commitment'ları toplamı = çıktı note'ları toplamı (homomorfik).

## 5. View-key (karar Bölüm 10 #3 — kullanıcı üretir)

- Kullanıcı cüzdanında view-key üretilir/saklanır. Zcash deseni: işlem sahibi view-key'i yetkiliye (BDDK) manuel paylaşır.
- Bu opcode seviyesinde değil — cüzdan/UX katmanı + selective disclosure protokolü. Tasarım notu olarak kayıt; implementation cüzdan tarafında.

## 6. Constraint set (bud-vm / bud-proof)

- Her yeni opcode için AIR constraint (plonky3_air.rs):
  - PrivacyCommit: commitment = Poseidon(inputs) eşitliği.
  - NullifierCheck: nullifier = Poseidon(secret), nullifier set'te yok.
  - SumConservation: Σinput_commitments == Σoutput_commitments (homomorfik toplam).
- Execution trace'e yeni sütunlar (public/private input ataması — Bölüm 3).

## 7. İzolasyon (Bölüm 7)

Gizlilik opcode'ları YALNIZCA transfer ailesini kapsar. `NftRegistry`/`ContentId`, `Pollen AccessGrant`/`StorageRegistry` bu opcode'ları **çağırmaz** — ayrı state alanlarında yaşarlar.

## 8. Implementation fazları (multi-session)

1. **Faz A:** 3 opcode + decode + MainnetActivation gate (bud-isa). cargo check.
2. **Faz B:** Poseidon permutation impl/wiring (bud-vm execute + 0x19 doğrulama).
3. **Faz C:** Note subtree (bud-state, paralel izole).
4. **Faz D:** AIR constraint'ler (bud-proof).
5. **Faz E:** TEE opt-in cüzdan toggle (Bölüm 10 #5) + view-key UX.
6. **Faz F:** E2E gizli transfer testi (commit → nullifier → sum-conservation round-trip).

Her faz ayrı CI-yeşil staging commit. Sandbox test-OOM → CI yegâne doğrulayıcı.

---

*Tüm Bölüm 10 kararları çözüldü (MAINNET_KARARLAR D2). Bu doküman implementation'a köprü. Faz A en düşük riskli başlangıç.*
