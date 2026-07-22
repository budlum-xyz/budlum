# ADR-008: Ağ Sertleştirme — Full v1'de

**Durum:** Kabul Edildi
**Tarih:** 2026-07-20
**Karar Verici:** Kullanıcı (onay) —  karar turu q7

## Bağlam
p2p katmanı libp2p üzerinden (kad/identify/gossipsub) ama reputation, eclipse bound, NAT traversal derin değil. Eclipse/sybil saldırılarına karşı dayanıklılık belirsiz.

## Karar
**Tam ağ sertleştirme v1'de:**
- **Peer reputation/banlama:** skorlama (invalid msg, timeout, equivocation) → banlama threshold + TTL.
- **DHT bucket tuning:** Kademlia routing parametreleri.
- **NAT hole-punching:** libp2p relay/auto-nat (config-driven).
- **Peer diversity enforcement:** ekip H2'de eklenen `/24 subnet bound`'u genişlet (per ASN, per IP range; outbound peer çeşitliliği).
- **Network chaos/fault injection test suite** (partition, Byzantine, eclipse, sybil).

## Sonuçlar
- **Pozitif:** Eclipse/sybil dayanıklılığı; operatör güveni; test altında kanıtlanmış savunma.
- **Negatif:** Spec + test süresi uzun; mainnet tarihini riske atabilir (kullanıcı "tarihe bol zaman var" dedi → kabul edilebilir).
- **Risk:** Reputation yanlış ayar → legitimate peer'lar banlanır → reputasyon tuning testi zorunlu.

## Uygunluk
Master-context nötr (p2p katmanı).

## İlgili
- `docs/NETWORK_HARDENING_SPEC.md` ( — finalize )
- `src/network/reputation.rs` (implementasyon — )
- `src/tests/network_chaos.rs` (chaos suite — )
- H2 hardening (ekip 261df88) — temel alınır
