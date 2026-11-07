# Budlum Explorer adres çubuğu rozeti - Türkçe.
#
# This file is a user-facing localisation, so its strings are Turkish by
# design; they are the product, not untranslated source text. Only this header
# is in English, for the reader of the tree.
#
# Dört değer, budlum_explorer::evidence::Strength ile bire bir. Bir tanesini
# birleştirmek, çekirdeğin ölçtüğü bir ayrımı gizlemek olurdu.

explorer-badge-verified =
    .value = doğrulandı
    .tooltiptext = Getirilen baytların özeti beklenen kimliğe eşit.

explorer-badge-transport-only =
    .value = yalnız taşıma
    .tooltiptext = TLS kimin gönderdiğini söylüyor, neyin gönderildiğini değil. Bu sıradan web.

explorer-badge-claim-only =
    .value = yalnız beyan
    .tooltiptext = Bir düğüm cevap verdi ama kanıt doğrulanmadı. Baytlar tutarlı olabilir ve yine de istenen isme ait olmayabilir.

explorer-badge-refused =
    .value = reddedildi
    .tooltiptext = İçerik gösterilmiyor. Sebep bu rozetin üzerinde yazıyor.

# Red sayfaları

explorer-refusal-title = Bu adres açılmadı

explorer-refusal-name-rule = Ad kuralı bu adı reddetti: { $reason }

explorer-refusal-scheme = { $scheme } şeması adres çubuğundan açılmaz.

explorer-refusal-hash-mismatch =
    Getirilen baytlar beklenen kimliği üretmedi.
    Beklenen: { $expected }
    Gelen: { $produced }

explorer-refusal-no-fetcher =
    Bu hedef için bir getirici yok. HTTPS'e düşürmek, doğrulanmamış içeriği
    doğrulanmış gibi göstermek olurdu.

explorer-refusal-expired = Bu isim süresi dolmuş bir kayda ait.

explorer-refusal-ambiguous =
    Yazılan şey birden fazla şeye benziyor ve tahmin edilmiyor:
    { $candidates }
