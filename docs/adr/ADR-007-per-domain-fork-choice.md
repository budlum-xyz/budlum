# ADR-007: Per-Domain Fork-Choice

**Durum:** Kabul Edildi  
**Tarih:** 2026-07-20  
**Karar Verici:** Kullanıcı (onay) — Phase 11.6 karar turu q6

## Bağlam
Multi-consensus L1 vizyonu: PoW/PoS/BFT/PoA domain'leri. Tek global fork-choice consensus çeşitliliğini sınırlar (amaca aykırı). `ConsensusDomain` abstraction'ı var ama `fork_choice` methodu netleşmemiş.

## Karar
**Per-domain fork-choice + spec-first finalize:**
- `ConsensusDomain` trait'ine `fork_choice(&self, candidates) -> ResolvedHead` methodu eklenir.
- Her domain kendi kuralını uygular:
  - **PoW:** longest-chain (most cumulative work).
  - **PoS:** LMD-GHOST.
  - **BFT:** instant finality (2/3 imza = kesin).
  - **PoA:** round-robin (sıralı leader).
- **Domain lifecycle** (start/stop/upgrade proposal-driven) ayrı modül (`src/domain/lifecycle.rs`).
- `DOMAIN_FORK_CHOICE_SPEC.md` finalize edilir, sonra kod.

## Sonuçlar
- **Pozitif:** Multi-consensus vizyonu korunur; modüler; her domain kendi güvenlik modelini uygular.
- **Negatif:** 4 fork-choice impl'i test edilmeli (PoW reorg, BFT equivocation, PoS nothing-at-stake, PoA leader skip).
- **Risk:** Domain'ler arası finality etkileşimi (cross-domain message finality bağımlılığı) net tasarlanmalı.

## Uygunluk
Master-context (multi-consensus, domain izolasyonu) ile tam uyumlu.

## İlgili
- `docs/DOMAIN_FORK_CHOICE_SPEC.md` (finalize — Phase 11.6)
- `src/consensus/mod.rs` (ConsensusDomain trait — Phase 11.8)
- `src/domain/lifecycle.rs` (domain lifecycle — Phase 11.8)
