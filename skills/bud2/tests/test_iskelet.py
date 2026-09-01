#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""B.U.D. 2.0 iskelet testleri — stdlib unittest, bagimlilik yok.

Testler v7 olcumlerine BAGLANIR: bud2 parametreleri corpus/xor.json ile
tutarsizsa test kirilir. Iskelet, belgeden bagimsiz surukleneMEZ.

    python3 bud2/tests/test_iskelet.py
"""
import os, sys, json, unittest, random

KOK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KOK)
sys.path.insert(0, os.path.dirname(KOK))
from core.xor_code import DuzXor, Evenodd, Star, kod_uret, KOD_KATALOGU
from gates.kapilar import kp1, kp2, kp7, kx, kf, hepsi, R_VARSAYILAN, TAVAN_USD_TB_AY

CORPUS = os.path.join(os.path.dirname(KOK), "corpus", "xor.json")


class KayipsizlikTesti(unittest.TestCase):
    """XOR kodu gercekten kayipsiz mi — calisan ispat."""

    def test_duz_xor_tek_kayip_geri_doner(self):
        rng = random.Random(11)
        for k in (3, 7):
            kod = DuzXor(k)
            veri = [bytes(rng.randrange(256) for _ in range(512)) for _ in range(k)]
            self.assertTrue(kod.dogrula(veri), f"k={k} tek kayip geri donmedi")

    def test_duz_xor_parite_deterministik(self):
        kod = DuzXor(7)
        veri = [bytes([i]) * 64 for i in range(7)]
        self.assertEqual(kod.kodla(veri), kod.kodla(veri))

    def test_duz_xor_bos_veri_reddedilir(self):
        with self.assertRaises(ValueError):
            DuzXor(7).kodla([b"x" * 8] * 6)      # 7 yerine 6 blok

    def test_farkli_uzunluk_reddedilir(self):
        with self.assertRaises(ValueError):
            DuzXor(3).kodla([b"aaa", b"bb", b"ccc"])

    def test_evenodd_parite_uretilir(self):
        rng = random.Random(12)
        p = 7
        veri = [bytes(rng.randrange(256) for _ in range(p - 1)) for _ in range(p)]
        self.assertTrue(Evenodd(p).dogrula(veri))

    def test_evenodd_asal_olmayan_reddedilir(self):
        with self.assertRaises(ValueError):
            Evenodd(8)

    def test_star_asal_olmayan_reddedilir(self):
        with self.assertRaises(ValueError):
            Star(9)


class KapiTesti(unittest.TestCase):
    """Kapilar, v7'nin yaptigi hatayi tekrar etmeye izin vermemeli."""

    def test_rs28_4_reddedilir(self):
        """v7'de aylarca sampiyon duran RS(28,4) KP2 ve KX'i kirmali."""
        ok, kiran = hepsi(kp1(32, 32/28, 4), kp2(28), kx("gf"))
        self.assertFalse(ok)
        self.assertEqual({x.ad for x in kiran}, {"KP2", "KX"})

    def test_katalogdaki_her_kod_yasal(self):
        for ad in KOD_KATALOGU:
            k = kod_uret(ad)
            ok, kiran = hepsi(kp1(k.N, k.e, k.f), kp2(k.onarim), kx("xor"))
            self.assertTrue(ok, f"{ad} kapi kirdi: {[x.ad for x in kiran]}")

    def test_kp2_sinirda(self):
        self.assertTrue(kp2(R_VARSAYILAN).gecti)
        self.assertFalse(kp2(R_VARSAYILAN + 1).gecti)

    def test_kp1_iki_kayipta_duz_xor_kirilir(self):
        """Duz XOR 3+1 f=1'dir; f=2 iddiasi KP1'i kirmali."""
        self.assertTrue(kp1(4, 4/3, 1).gecti)
        self.assertFalse(kp1(4, 4/3, 2).gecti)

    def test_kp7_ev_hatti(self):
        """100 Mbit ile 7 gunde 7,2 TB — v7 §22.3."""
        self.assertTrue(kp7(7.0, 100).gecti)
        self.assertFalse(kp7(10.0, 100).gecti)

    def test_kf_tavan(self):
        self.assertTrue(kf(TAVAN_USD_TB_AY).gecti)
        self.assertFalse(kf(TAVAN_USD_TB_AY + 1e-6).gecti)

    def test_kx_sadece_xor(self):
        self.assertTrue(kx("xor").gecti)
        self.assertFalse(kx("gf").gecti)
        self.assertFalse(kx("kopya").gecti)


class OlcumBaglantisiTesti(unittest.TestCase):
    """Iskelet parametreleri v7 olcumleriyle (corpus/xor.json) ayni mi."""

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(CORPUS):
            raise unittest.SkipTest("corpus/xor.json yok")
        with open(CORPUS, encoding="utf-8") as fo:
            cls.X = json.load(fo)
        cls.aile = {a["ad"]: a for a in cls.X["aileler"]}

    def test_parametreler_olcumle_ayni(self):
        esleme = {"duz-xor-7+1": "Duz XOR 7+1", "duz-xor-3+1": "Duz XOR 3+1",
                  "evenodd-7": "EVENODD p=7", "evenodd-5": "EVENODD p=5",
                  "star-5": "STAR p=5"}
        for anahtar, olcum_ad in esleme.items():
            k = kod_uret(anahtar); o = self.aile[olcum_ad]
            self.assertAlmostEqual(k.e, o["e"], places=6, msg=f"{olcum_ad} e")
            self.assertEqual(k.f, o["f"], f"{olcum_ad} f")
            self.assertEqual(k.onarim, o["onarim"], f"{olcum_ad} onarim")
            self.assertTrue(o["gecer"], f"{olcum_ad} olcumde kapi kiriyor")

    def test_rs_olcumde_de_yasadisi(self):
        rs = self.aile["RS(28,4)"]
        self.assertEqual(rs["aile"], "gf")
        self.assertFalse(rs["kp2"], "RS(28,4) olcumde KP2 gecmis gorunuyor")
        self.assertEqual(rs["onarim"], 28)

    def test_xor_kisitinin_bedeli_sifir(self):
        self.assertEqual(self.X["bedel"]["tur_farki"], 0)

    def test_duz_xor_7_rs_ile_ayni_genisleme(self):
        self.assertAlmostEqual(kod_uret("duz-xor-7+1").e,
                               self.aile["RS(28,4)"]["e"], places=6)


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ===========================================================================
# KP2' — dayaniklilik kapisi (V7-KP2-GENISLIK.md §5)
# Bu testler OLCUME baglidir: corpus/kp2.json ile ayni sayilar cikmali.
# ===========================================================================
def test_kp2_prime_secilen_kodu_gecirir():
    """EVENODD p=7 (N=9, f=2) hedefi tutturmali."""
    from gates.kapilar import kp2_prime
    r = kp2_prime(9, 2)
    assert r.gecti, r.aciklama


def test_kp2_prime_tek_pariteyi_eler():
    """f=1 HICBIR hedefi tutturamaz -- olculen bulgu."""
    from gates.kapilar import kp2_prime
    for N in range(2, 60):
        assert not kp2_prime(N, 1).gecti, f"N={N} f=1 gecmemeliydi"


def test_kp2_prime_genislik_arttikca_duser():
    """Ayni f'te N buyudukce dokuz DUSER (grup genisligi etkisi)."""
    from gates.kapilar import dokuz
    d = [dokuz(N, 2) for N in (9, 13, 15)]
    assert d[0] > d[1] > d[2], d


def test_kp2_prime_olcumle_ayni_sayiyi_verir():
    """Kapi kodu ile measure-kp2.py AYNI dokuzu uretmeli (belge=kod)."""
    import json, pathlib
    from gates.kapilar import dokuz
    yol = pathlib.Path(__file__).resolve().parents[2] / "corpus" / "kp2.json"
    if not yol.exists():
        return                                    # korpus yoksa atla
    K = json.loads(yol.read_text(encoding="utf-8"))
    for g in K["genislik"]:
        hesap = dokuz(g["N"], 2)
        assert abs(hesap - g["dokuz"]) < 0.01, (g["ad"], hesap, g["dokuz"])


def test_kp2_prime_afr_duyarli():
    """AFR kotulestikce kapi SIKILASIR -- A34 bulgusunun kod karsiligi."""
    from gates.kapilar import kp2_prime
    iyi = kp2_prime(9, 2, afr=0.0085)
    kotu = kp2_prime(9, 2, afr=0.030)
    assert iyi.gecti
    assert not kotu.gecti, "AFR %3'te N=9 f=2 hedefi tutturmamali"


def test_eski_kp2_ile_yeni_kp2_prime_celisebilir():
    """Eski sabit R esigi ile yeni dayaniklilik esigi AYNI SEY DEGIL.

    EVENODD p=13 (N=15, f=2, onarim 13 disk) eski KP2'de de duser (13 > 8),
    ama sebebi farklidir: eski kapi 'cok disk uyandi' der, yeni kapi
    'dayaniklilik yetmiyor' der. STAR p=5 ise eski kapida gecerken
    (5 <= 8) yeni kapida da geciyor -- ortusme tesadufi degil, ikisi de
    grup genisligini sinirliyor.
    """
    from gates.kapilar import kp2, kp2_prime
    assert not kp2(13).gecti                      # eski: 13 disk > R=8
    assert not kp2_prime(15, 2).gecti             # yeni: 6,83 < 7,0
    assert kp2(5).gecti and kp2_prime(8, 3).gecti  # STAR p=5 ikisinden de gecer
