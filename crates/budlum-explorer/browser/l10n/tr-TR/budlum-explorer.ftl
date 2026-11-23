# Budlum Explorer adres çubuğu rozeti - Türkçe.
#
# This file is a user-facing localisation, so its strings are Turkish by
# design; they are the product, not untranslated source text. Only this header
# is in English, for the reader of the tree.
#
# Dört değer, budlum_explorer::evidence::Strength ile bire bir. Bir tanesini
# birleştirmek, çekirdeğin ölçtüğü bir ayrımı gizlemek olurdu.

budlum-explorer-badge-verified =
    .value = doğrulandı
    .tooltiptext = Getirilen baytların özeti beklenen kimliğe eşit.

budlum-explorer-badge-transport-only =
    .value = yalnız taşıma
    .tooltiptext = TLS kimin gönderdiğini söylüyor, neyin gönderildiğini değil. Bu sıradan web.

budlum-explorer-badge-claim-only =
    .value = yalnız beyan
    .tooltiptext = Bir düğüm cevap verdi ama kanıt doğrulanmadı. Baytlar tutarlı olabilir ve yine de istenen isme ait olmayabilir.

budlum-explorer-badge-refused =
    .value = reddedildi
    .tooltiptext = İçerik gösterilmiyor. Sebep bu rozetin üzerinde yazıyor.

# Red sayfaları

budlum-explorer-refusal-title = Bu adres açılmadı

budlum-explorer-refusal-name-rule = Ad kuralı bu adı reddetti: { $reason }

budlum-explorer-refusal-scheme = { $scheme } şeması adres çubuğundan açılmaz.

budlum-explorer-refusal-hash-mismatch =
    Getirilen baytlar beklenen kimliği üretmedi.
    Beklenen: { $expected }
    Gelen: { $produced }

budlum-explorer-refusal-no-fetcher =
    Bu hedef için bir getirici yok. HTTPS'e düşürmek, doğrulanmamış içeriği
    doğrulanmış gibi göstermek olurdu.

budlum-explorer-refusal-expired = Bu isim süresi dolmuş bir kayda ait.

budlum-explorer-refusal-ambiguous =
    Yazılan şey birden fazla şeye benziyor ve tahmin edilmiyor:
    { $candidates }
