# ADR-006: Fee/Gas Mekanizması — EIP-1559

**Durum:** Kabul Edildi
**Tarih:** 2026-07-20
**Karar Verici:** Kullanıcı (onay) —  karar turu q9

## Bağlam
ADR-001 (genesis pool) validator temel ödülünü netleştirdi. Tx fee pricing + dağıtım ayrı: sabit fee (basit ama spam), metabolic burn extension (kompleks), EIP-1559 (base fee burn + priority fee validator).

## Karar
**EIP-1559 benzeri model:**
- **Base fee:** dinamik (blok yoğunluğuna göre adjustment), **yakılır** (deflationary).
- **Priority fee (tip):** kullanıcı öder, **validator'e** gider (aktivite teşviki).
- Mevcut `metabolic burn` ile **uyumlu** (paralel mekanizma — biri tx fee, diğeri usage-based storage burn).
- `Transaction` yapısına `max_fee` / `priority_fee` alanları (geri uyumlu migration — eski `fee` alanı map).

## Sonuçlar
- **Pozitif:** Ethereum standardı (operatörler tanıyor); öngörülebilir fee tahmini; deflationary base fee; validator aktivite teşviki.
- **Negatif:** Base fee adjustment algoritması doğru ayarlanmalı (yoğunluk osilasyonu).
- **Risk:** Eski tx formatı (sabit fee) ile uyumsuzluk → migration testi zorunlu.

## Uyum
Sabit arz + ADR-001 (pool) ile tutarlı (base fee burn arzı düşürür, pool ödülü sabit).

## İlgili
- `docs/EIP1559_FEE_MARKET_SPEC.md` (detaylı spec — )
- `src/chain/fee_market.rs` (implementasyon — )
- ADR-001 (genesis pool — validator ödül complement)
- `bud_estimateGas` RPC (zaten var, EIP-1559'a bağlanır)
