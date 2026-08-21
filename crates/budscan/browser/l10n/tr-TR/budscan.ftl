# Budscan adres cubugu rozeti - Turkce.
#
# Dort deger, budscan::evidence::Strength ile bire bir. Bir tanesini
# birlestirmek, cekirdegin olctugu bir ayrimi gizlemek olurdu.

budscan-badge-verified =
    .value = dogrulandi
    .tooltiptext = Getirilen baytlarin ozeti beklenen kimlige esit.

budscan-badge-transport-only =
    .value = yalniz tasima
    .tooltiptext = TLS kimin gonderdigini soyluyor, neyin gonderildigini degil. Bu siradan web.

budscan-badge-claim-only =
    .value = yalniz beyan
    .tooltiptext = Bir dugum cevap verdi ama kanit dogrulanmadi. Baytlar tutarli olabilir ve yine de istenen isme ait olmayabilir.

budscan-badge-refused =
    .value = reddedildi
    .tooltiptext = Icerik gosterilmiyor. Sebep bu rozetin uzerinde yaziyor.

# Red sayfalari

budscan-refusal-title = Bu adres acilmadi

budscan-refusal-name-rule = Ad kurali bu adi reddetti: { $reason }

budscan-refusal-scheme = { $scheme } semasi adres cubugundan acilmaz.

budscan-refusal-hash-mismatch =
    Getirilen baytlar beklenen kimligi uretmedi.
    Beklenen: { $expected }
    Gelen: { $produced }

budscan-refusal-no-fetcher =
    Bu hedef icin bir getirici yok. HTTPS'e dusurmek, dogrulanmamis icerigi
    dogrulanmis gibi gostermek olurdu.

budscan-refusal-expired = Bu isim suresi dolmus bir kayda ait.

budscan-refusal-ambiguous =
    Yazilan sey birden fazla seye benziyor ve tahmin edilmiyor:
    { $candidates }
