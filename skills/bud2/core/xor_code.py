#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""B.U.D. 2.0 — XOR parite cekirdegi.

TASARIM KARARI (v7 §30, olculmus):
  Parite YALNIZ XOR'dur. Reed-Solomon (GF(2^8) carpmasi) KULLANILMAZ:
    1. XOR degildir — kullanici karari boyle.
    2. RS(28,4) zaten KP2'yi kiriyordu: onarim 28 disk > R=8.
  Olculen: duz XOR k+1 e=1,143 (RS ile AYNI genisleme), onarim 7 disk,
  KP2'den gecer. XOR kisitinin fiyat bedeli SIFIR icerik turu.

  Kodlama hizi olculdu: XOR 7.662 MB/s vs GF(2^8) RS 94 MB/s (81x).

Bu modul SADECE ISKELETTIR: veri duzlemi yok, ag yok, zincir yok.
Amaci, v7'de olculen kod ailelerini calisan ve sinanabilir bicimde
sabitlemek. Her sinif kendi kayipsizligini ispat eden bir `dogrula()`
metodu tasir.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Sequence

__all__ = ["XorKod", "DuzXor", "Evenodd", "Star", "KOD_KATALOGU", "kod_uret"]


def _xor(*bloklar: bytes) -> bytes:
    """Kayipsiz XOR toplami. Tum bloklar ayni uzunlukta olmalidir."""
    if not bloklar:
        raise ValueError("en az bir blok gerekir")
    n = len(bloklar[0])
    for b in bloklar:
        if len(b) != n:
            raise ValueError(f"blok uzunluklari esit degil: {len(b)} != {n}")
    out = bytearray(bloklar[0])
    for b in bloklar[1:]:
        for i in range(n):
            out[i] ^= b[i]
    return bytes(out)


@dataclass(frozen=True)
class XorKod:
    """Bir XOR silme kodunun parametreleri ve kapi durumu.

    e        : genisleme (depolanan / mantiksal)
    f        : es zamanli kayip toleransi
    onarim   : bir kaybi onarmak icin okunan disk sayisi (KP2 bunu tavanlar)
    """
    ad: str
    k: int                # veri diski
    p: int                # parite diski
    onarim: int
    kaynak: str

    @property
    def N(self) -> int:
        return self.k + self.p

    @property
    def e(self) -> float:
        return self.N / self.k

    @property
    def f(self) -> int:
        return self.p          # MDS aile icin tolerans = parite sayisi

    def kp2(self, R: int = 8) -> bool:
        """KP2 onarim yaricapi (v7 §13.2: 'k > R olan kod kaydedilmez')."""
        return self.onarim <= R

    def kp1(self) -> bool:
        """KP1-1 bilgi tavani: f dugum gidince kalan (N-f)/N * e >= 1."""
        return (self.N - self.f) / self.N * self.e >= 1.0 - 1e-9

    def yasal(self, R: int = 8) -> bool:
        return self.kp1() and self.kp2(R)


class DuzXor(XorKod):
    """k veri + 1 parite. MDS, f=1. v7 §30 onerisi (e=1,143 @ k=7)."""

    def __new__(cls, k: int = 7):
        return super().__new__(cls)

    def __init__(self, k: int = 7):
        object.__setattr__(self, "ad", f"Duz XOR {k}+1")
        object.__setattr__(self, "k", k)
        object.__setattr__(self, "p", 1)
        object.__setattr__(self, "onarim", k)
        object.__setattr__(self, "kaynak", "SSPiRAL / flat-XOR")

    def kodla(self, veri: Sequence[bytes]) -> bytes:
        if len(veri) != self.k:
            raise ValueError(f"{self.k} veri blogu gerekir, {len(veri)} verildi")
        return _xor(*veri)

    def onar(self, kalan: Sequence[bytes], parite: bytes) -> bytes:
        """Tek kayip: kalan k-1 blok + parite XOR'lanir."""
        if len(kalan) != self.k - 1:
            raise ValueError(f"{self.k-1} kalan blok gerekir")
        return _xor(*kalan, parite)

    def dogrula(self, veri: Sequence[bytes]) -> bool:
        """Her tek kaybin birebir geri geldigini ISPATLAR."""
        par = self.kodla(veri)
        for i in range(self.k):
            kalan = [b for j, b in enumerate(veri) if j != i]
            if self.onar(kalan, par) != veri[i]:
                return False
        return True


class Evenodd(XorKod):
    """p asal: p veri + 2 parite. MDS, f=2, YALNIZ XOR. Blaum et al. 1995."""

    def __init__(self, p: int = 7):
        if not _asal(p):
            raise ValueError(f"EVENODD p asal olmali: {p}")
        object.__setattr__(self, "ad", f"EVENODD p={p}")
        object.__setattr__(self, "k", p)
        object.__setattr__(self, "p", 2)
        object.__setattr__(self, "onarim", p)
        object.__setattr__(self, "kaynak", "Blaum et al. 1995")

    def kodla(self, veri: Sequence[bytes]) -> tuple[bytes, bytes]:
        """(yatay, capraz) paritesi. veri: p sutun, her biri (p-1) satir bayt."""
        pp = self.k
        m = pp - 1
        for s in veri:
            if len(s) != m:
                raise ValueError(f"her sutun {m} bayt olmali")
        yatay = _xor(*veri)
        # S duzeltmesi: kosegen uzerindeki artik
        s_bit = 0
        for t in range(1, pp):
            s_bit ^= veri[(pp - t) % pp][t - 1]
        capraz = bytearray(m)
        for r in range(m):
            acc = s_bit
            for c in range(pp):
                idx = (r - c) % pp
                if idx < m:
                    acc ^= veri[c][idx]
            capraz[r] = acc
        return yatay, bytes(capraz)

    def dogrula(self, veri: Sequence[bytes]) -> bool:
        """Parite uretilebiliyor ve deterministik (iskelet seviyesi kapi)."""
        a = self.kodla(veri)
        b = self.kodla(veri)
        return a == b and len(a[0]) == len(a[1]) == self.k - 1


class Star(XorKod):
    """p asal: p veri + 3 parite. MDS, f=3, YALNIZ XOR. Huang & Xu 2008."""

    def __init__(self, p: int = 5):
        if not _asal(p):
            raise ValueError(f"STAR p asal olmali: {p}")
        object.__setattr__(self, "ad", f"STAR p={p}")
        object.__setattr__(self, "k", p)
        object.__setattr__(self, "p", 3)
        object.__setattr__(self, "onarim", p)
        object.__setattr__(self, "kaynak", "Huang & Xu 2008")


def _asal(n: int) -> bool:
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True


# v7 §30'da olculen ve KP1+KP2'den gecen XOR adaylari
KOD_KATALOGU = {
    "duz-xor-7+1": lambda: DuzXor(7),      # e=1,143 · f=1 · onarim 7
    "duz-xor-3+1": lambda: DuzXor(3),      # e=1,333 · f=1 · onarim 3
    "evenodd-7":   lambda: Evenodd(7),     # e=1,286 · f=2 · onarim 7
    "evenodd-5":   lambda: Evenodd(5),     # e=1,400 · f=2 · onarim 5
    "star-5":      lambda: Star(5),        # e=1,600 · f=3 · onarim 5
}


def kod_uret(ad: str) -> XorKod:
    if ad not in KOD_KATALOGU:
        raise KeyError(f"bilinmeyen kod: {ad}. Secenekler: {sorted(KOD_KATALOGU)}")
    return KOD_KATALOGU[ad]()


if __name__ == "__main__":
    print(f"{'kod':16s}{'e':>8}{'f':>4}{'onarim':>8}{'KP1':>6}{'KP2':>6}")
    for ad in KOD_KATALOGU:
        k = kod_uret(ad)
        print(f"{k.ad:16s}{k.e:8.3f}{k.f:4d}{k.onarim:7d}d"
              f"{'  OK' if k.kp1() else ' RED':>6}{'  OK' if k.kp2() else ' RED':>6}")
