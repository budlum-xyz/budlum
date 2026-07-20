# ADR-001: PoS Validator Ödülleri — Genesis Validation Reward Pool

**Durum:** Kabul Edildi  
**Tarih:** 2026-07-20  
**Karar Verici:** Kullanıcı (onay) — Phase 11.6 karar turu q1

## Bağlam
Budlum sabit 100M arza sahip + iki burn mekanizması (metabolic burn + bridge burn). Bu nedenle PoS validator ödülleri yeni emisyonla (inflationary) finanse edilemez. Ağ güvenliği için validator'lere ödeme zorunlu; kaynak belirsizse güvenlik bütçesi garanti edilemez. Seçenekler: saf fee (Bitcoin), hibrit, burn redirect, genesis pool.

## Karar
**Genesis validation reward pool:** Toplam arzın ~%8-12'si (`config/mainnet-genesis.json`'da pre-allocate) validation/treasury için ayrılır. Epoch-bazlı dağıtım schedule'ı ile active validator set'e orantılı dağıtılır. Emisyon yok (sabit arz bozulmaz).

## Sonuçlar
- **Pozitif:** Öngörülebilir güvenlik bütçesi; düşük aktivitede bile validator teşviki; sabit arz korunur; Ethereum Beacon Chain + birçok PoS ile uyumlu.
- **Negatif:** Pool tükendiğinde (yıllar sonra) economy fee-only'a geçmeli — geçiş planı şimdiden tasarlanmalı.
- **Risk:** Pool tahsis oranı yanlış seçilirse ya güvensiz (çok küçük) ya da gereksiz merkezileşme (çok büyük).

## Uygunluk
Sabit arz ilkesiyle tam uyumlu (emisyon = 0). Master-context ile çelişmiyor.

## İlgili
- `docs/GENESIS_REWARD_POOL_SPEC.md` (detaylı spec)
- ADR-006 (EIP-1559 fee — hibrit tamamlayıcı)
- `config/mainnet-genesis.json` (pool pre-allocation)
- `src/tokenomics/` (implementasyon — Phase 11.8)
