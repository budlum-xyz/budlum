# agency-agents skill (msitarzewski/agency-agents)

Cekilme: 2026-08-04. Kaynak: https://github.com/msitarzewski/agency-agents

Budlum icin secilen yedi ajan ve NEDEN secildikleri:

## security-blockchain-security-auditor.md
Severity siniflandirmasi bizim bulgu dosyamiza dogrudan uygulanabilir:
- **Critical**: dogrudan fon kaybi, protokol iflasi, kalici DoS, ozel yetki gerekmez
- **High**: kosullu fon kaybi (belirli durum gerekir), yetki yukseltme
- **Medium**: griefing, gecici DoS, belirli kosullarda deger sizmasi
- **Low**: en iyi pratik sapmalari
Kural: "bir bulguyu catismadan kacinmak icin informational isaretleme; kullanici
fonu kaybettirebiliyorsa High ya da Critical'dir."
Kural: "her bulgu ya bir PoC ya da somut saldiri senaryosu icermeli."

## security-ai-generated-code-auditor.md  ← BIZE EN YAKINI
"Assistant demoyu gecmek icin optimize etti, uretimde yasamak icin degil."
Bizim H110'umuzun ayni sozu: gelistiriciler "yesil tik"e guvenir, oysa o tik
cogu zaman "hicbir tarayici calismadi" demektir.
Kurallar:
- Kanit iddianin onunde: exploit ve fix yan yana olmadan satir isaretleme
- Rescan olmadan "duzeldi" deme
- Heuristik kontrolde yanlis pozitif yerine yanlis negatifi sec; sürekli
  bos alarm veren arac susturulur, susturulan arac hicbir seyi korumaz
- Kapsami abartma: neyi kontrol ettigini, neyi ETMEDIGINI ve guven
  seviyeni bildir

## testing-reality-checker.md
"Varsayilan NEEDS WORK." Uretime hazir demek icin ezici kanit gerekir.
Bizim kapanis formatimizdaki "acik kalan risk" satirinin gerekcesi.

## testing-evidence-collector.md
"Her seyi kanitla." Iddia degil olcum.

## engineering-code-reviewer.md
## security-appsec-engineer.md
## grant-writer.md
Hibe dosyasi (Adsız_doküman.md) uzerinde calisirken: iddia ile kod
arasindaki farki kapatmak icin.
