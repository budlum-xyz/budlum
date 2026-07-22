# ADR-003: Node Sınıflandırması — Full Node (pruning) + Archive Node

**Durum:** Kabul Edildi
**Tarih:** 2026-07-20
**Karar Verici:** Kullanıcı (onay) — Task 11.6 karar turu q3

## Bağlam
Mainnet node operatörlerine ne sunulacağı belirsizdi. Üç seçenek: sadece archive (basit ama yüksek disk → az node → merkezileşme), full+archive split (Ethereum modeli), stateless (çok ileri/araştırma).

## Karar
**Full node (pruning default) + Archive node split:**
- **Full node:** recent state + N blok history pruned (düşük disk, çoğu operatör için varsayılan).
- **Archive node:** full history (sorgulama/index için).
- `config/mainnet.toml`'de `features.pruning` flag'i (Task 11.2'de mevcut) = true (full) / false (archive).
- **Her node finalized checkpoint snapshot'larını tutar** (restore için).

## Sonuçlar
- **Pozitif:** Düşük disk gereksinimi → node sayısı artar → merkezileşme riski düşer; Ethereum modeli (operatörler tanıyor); mevcut config altyapısı.
- **Negatif:** İki node profili test/dokümante edilmeli.
- **Risk:** Pruning yanlış implementasyon → finalized state kaybı (snapshot retantion bunu önlüyor).

## Uygunluk
Master-context nötr.

## İlgili
- `docs/STATE_PRUNING_SPEC.md` (Task 11.4 — finalize Task 11.10)
- `config/mainnet.toml` (`features.pruning`)
- `src/storage/pruning.rs` (implementasyon — Task 11.10)
- ADR-002 (storage spec-first)
