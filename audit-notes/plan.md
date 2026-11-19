# Plan

Bu dosya bu dalın yol haritasıdır. Amaç, Budlum'u testnet'e ulaştırmak ve
Strix bulgularının hepsini kapatmak.

## Sıralama

1. Uç derlenebilir olsun. Her birleşme sonrası derleme ve kapılar doğrulanır.
2. Strix bulguları güncel uçta teker teker incelenir. Öncelik HIGH.
3. Konsensüs aileleri eksiksiz olsun. Eksik aileler için adaptor yazılır.
4. Testnet açılış kapısı (TLG) tamamlanır.

## Şu anki durum

- Uç `027296e` (`budlum-stack`). `aa3529c`'dan 11 yeni commit geldi.
- Uçte dört yeni adaptör dosyası var: `based_preconf.rs`, `ton_catchain.rs`,
  `mina_recursive.rs`, `stellar_fba.rs`. Bunların **hiçbirine bir giriş
  yolu (admission path) yok**: `AdapterSpec`'e variant eklenmemiş, pin
  haritasına işlenmemiş, `register_domain` onları tanımıyor. Modül ve
  domain tag olarak duruyorlar. Ayrıntı: `strix-ledger.md`, B-0012.
- 8 HIGH bulgunun 7'si kod ile kapanmış, biri (Garden 1015) güven modeliyle
  açıklanmış. Ayrıntı: `strix-ledger.md`.
- Konsensüs haritası: `07-konsens-us-tarihi.md`.

## Sırada

1. Yeni ucun derlemesi ve CI kapıları (clippy, fmt, test).
2. Dört yetim adaptörü bağlamak veya açıkça kapatılacak diye kayda geçmek.
3. 22 MEDIUM ve 10 LOW bulgunun yeni uçta teker teker doğrulanması.
4. PoSpace + VDF adaptörü (iki parça birlikte).
5. Restaking için güven ölçüsü; çok yükseklikli ışık istemcisi.
