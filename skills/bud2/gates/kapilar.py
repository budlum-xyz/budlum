#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""B.U.D. 2.0 — protokol kapilari (v7 §13 + §29/§30 bulgulari).

Kapi, bir yapilandirmayi KAYDEDILEMEZ kilan sert kuraldir. Iskelette bile
bulunmasinin sebebi: v7'de RS(28,4) aylarca "sampiyon" olarak tablolarda
durdu ve HICBIR ZAMAN yasal degildi (KP2'yi kiriyordu, 28 disk > R=8).
Kapi kodda olmazsa belge yalan soyler.

Uygulananlar:
  KP1  bilgi payi kilidi   — f kayiptan sonra kalan depo >= 1 olmali
  KP2  onarim yaricapi     — bir onarim en fazla R disk uyandirabilir
  KP7  devir kapasitesi    — dugum, onarim penceresinde kotasini devredebilmeli
  KX   XOR-only            — GF(2^8) carpmasi gerektiren kod reddedilir
  KF   fiyat tavani        — $/TB/ay tavani asan yapilandirma kaydedilmez
"""
from __future__ import annotations
from dataclasses import dataclass

__all__ = ["KapiSonucu", "kp1", "kp2", "kp2_prime", "kp7", "kx", "kf", "hepsi",
           "dokuz", "R_VARSAYILAN", "TAVAN_USD_TB_AY", "AFR_VARSAYILAN",
           "ONARIM_SAAT", "HEDEF_DOKUZ"]

import math

R_VARSAYILAN = 8              # v7 §13.2 arsiv onerisi (KP2 -- eski, sabit esik)
TAVAN_USD_TB_AY = 0.032       # kullanici tavani (D7)

# --- KP2' parametreleri (V7-KP2-GENISLIK.md §5) ---
# KP2 bir ENERJI kapisi sanilmisti; olcum dayaniklilik kapisi oldugunu gosterdi.
# Sabit R esigi f'e gore 4,21 / 7,41 / 10,57 dokuz veriyor -- 6,37 dokuzluk
# yayilim. Dogru esik dogrudan hedef dokuz uzerinden yazilir.
AFR_VARSAYILAN = 0.0138       # Backblaze Q1-2026 (V7-COK-YOLLU-BORU §13 bandi)
ONARIM_SAAT = 20e6 / 140 / 3600            # 20 TB @ 140 MB/s = 39,68 saat
HEDEF_DOKUZ = 7.0             # V7-KP2-GENISLIK.md §5.1 onerisi


@dataclass(frozen=True)
class KapiSonucu:
    ad: str
    gecti: bool
    aciklama: str

    def __bool__(self) -> bool:
        return self.gecti


def kp1(N: int, e: float, f: int) -> KapiSonucu:
    """Bilgi payi kilidi: f dugum gidince kalan (N-f)/N * e >= 1 olmali."""
    kalan = (N - f) / N * e
    return KapiSonucu("KP1", kalan >= 1.0 - 1e-9,
                      f"f={f} kayiptan sonra kalan depo {kalan:.3f} "
                      f"({'yeterli' if kalan >= 1 else 'VERI KAYBI'})")


def kp2(onarim_diski: int, R: int = R_VARSAYILAN) -> KapiSonucu:
    """Onarim yaricapi: 'k > R olan kod kaydedilmez' (v7 §13.2)."""
    return KapiSonucu("KP2", onarim_diski <= R,
                      f"onarim {onarim_diski} disk uyandirir, tavan R={R}")


def dokuz(N: int, f: int, afr: float = AFR_VARSAYILAN,
          onarim_saat: float = ONARIM_SAAT) -> float:
    """N diskli, f pariteli grubun yillik dayaniklilik 'dokuz' sayisi.

    Model: ilk ariza sonrasi onarim penceresinde kalan N-1 diskten f tanesi
    daha giderse veri kaybolur. measure-kp2.py ile AYNI formul.
    """
    lam = afr / 8760.0
    p = 1.0
    for i in range(f):
        p *= min(1.0, (N - 1 - i) * lam * onarim_saat)
    p_yil = N * afr * p
    return -math.log10(max(p_yil, 1e-300))


def kp2_prime(N: int, f: int, hedef: float = HEDEF_DOKUZ,
              afr: float = AFR_VARSAYILAN) -> KapiSonucu:
    """KP2' — dayaniklilik kapisi (KP2'nin olculmus yeniden tanimi).

    Sabit `R <= 8` yerine `dokuz(N, f) >= hedef`. Gerekce
    V7-KP2-GENISLIK.md §5: R=8 esigi f'e gore 4,21 ile 10,57 dokuz
    arasinda saliniyordu; tek bir garanti vermiyordu.

    Bu esik f=1'i (tek parite) kendiliginden eler: olculen tabloda f=1
    hicbir hedefi tutturamiyor.
    """
    d = dokuz(N, f, afr)
    return KapiSonucu("KP2'", d >= hedef - 1e-9,
                      f"N={N} f={f} -> {d:.2f} dokuz "
                      f"(hedef {hedef:.1f}, AFR %{afr*100:.3f})")


def kp7(tutulan_tb: float, uplink_mbit: float, pencere_gun: int = 7) -> KapiSonucu:
    """Devir kapasitesi: dugum kotasini onarim penceresinde aktarabilmeli."""
    tavan_tb = pencere_gun * 86400 * uplink_mbit / 8 / 1024 / 1024
    return KapiSonucu("KP7", tutulan_tb <= tavan_tb,
                      f"{uplink_mbit:.0f} Mbit ile {pencere_gun} gunde en fazla "
                      f"{tavan_tb:.1f} TB devredilir, tutulan {tutulan_tb:.1f} TB")


def kx(aile: str) -> KapiSonucu:
    """XOR-only kisiti: GF carpmasi gerektiren kod reddedilir (v7 §30)."""
    return KapiSonucu("KX", aile == "xor",
                      f"kod ailesi '{aile}'"
                      + ("" if aile == "xor" else " — GF carpmasi, XOR DEGIL"))


def kf(usd_tb_ay: float, tavan: float = TAVAN_USD_TB_AY) -> KapiSonucu:
    """Fiyat tavani."""
    return KapiSonucu("KF", usd_tb_ay <= tavan + 1e-12,
                      f"${usd_tb_ay:.5f}/TB/ay, tavan ${tavan:.3f}")


def hepsi(*sonuclar: KapiSonucu) -> tuple[bool, list[KapiSonucu]]:
    """Tum kapilari degerlendir; kiranlari dondur."""
    kiran = [s for s in sonuclar if not s.gecti]
    return (len(kiran) == 0), kiran


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from core.xor_code import kod_uret, KOD_KATALOGU

    print("B.U.D. 2.0 kapi denetimi — XOR katalogu\n")
    for ad in KOD_KATALOGU:
        k = kod_uret(ad)
        ok, kiran = hepsi(kp1(k.N, k.e, k.f), kp2(k.onarim), kx("xor"))
        durum = "KAYDEDILEBILIR" if ok else "RED: " + ", ".join(x.ad for x in kiran)
        print(f"  {k.ad:16s} e={k.e:.3f} f={k.f} onarim={k.onarim}d  -> {durum}")

    print("\nKarsi ornek — v7'de aylarca sampiyon duran RS(28,4):")
    ok, kiran = hepsi(kp1(32, 32/28, 4), kp2(28), kx("gf"))
    print(f"  RS(28,4) e={32/28:.3f} f=4 onarim=28d  -> "
          f"{'KAYDEDILEBILIR' if ok else 'RED'}")
    for x in kiran:
        print(f"     {x.ad} KIRILDI: {x.aciklama}")
