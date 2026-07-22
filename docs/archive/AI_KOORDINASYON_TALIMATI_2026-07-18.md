# Koordinasyon Talimatı — Ayaz

**[2026-07-18 19:00 UTC+3] AYAZ — dış-denetim bulgularına dayalı süreç talimatı**

**Kime:** ARENA1, ARENA2, ARENA3 (ve bundan sonra katılacak her instance)
**Kapsam:** STATUS_ONLINE.md + Actions geçmişinin dış-denetimi (Claude ile) sonrası tespit edilen 5 sorun için bağlayıcı kural.

---

## 1) "Koordineliyiz / doğrulandı" beyanı artık CI-linksiz yazılmaz

Test-sayısı kuralı zaten var (yalnız CI summary satırından). Bunu genişletiyorum: **süreç/koordinasyon hakkında yapılan her özet ifade** ("main yeşil", "X ile Y örtüştü", "koordineli ilerliyoruz" vb.) de aynı disipline tabidir — commit SHA + run linki olmadan STATUS_ONLINE'a yazılmaz. Gerekçe: dışarıdan yaptığım denetimde anlatı ile CI/PR durumu arasında fark bulundu (repo transferi sonrası README'de eski clone/badge kalıntısı, "7 RPC" gibi eski sayılar RFC'lerde uzun süre düzeltilmeden kalmış).

## 2) Yeni/ikinci instance kuralı

Bir ajan handle'ı (ör. ARENA3) aynı anda **birden gorevla instance** olarak STATUS_ONLINE'a yazamaz. Bir handle altında ikinci bir instance kendini tanıttığında, ilk iş **bana (Ayaz'a) doğrulatmaktır** — ben onaylamadan o instance'ın girdileri diğer ajanlar tarafından yetkili kabul edilmez. Gerekçe: geçmişte yetkisiz ikinci bir ARENA3 instance'ı ortaya çıkmış ve ancak benim müdahalemle durdurulmuştu.

## 3) Büyük iş = önce CI-yeşil zemin doğrulaması, sonra kapsam genişletmesi

Yeni modül/refactor/kapsam genişletmesi işine **mevcut main'in CI'da yeşil olduğu bağımsız olarak doğrulanmadan** başlanmaz. Bir ajanın kendi işine başlamadan önce `git fetch` + son Actions run'ının sonucunu görmesi zorunlu adım, atlanabilir formalite değil. Gerekçe: bir önceki ARENA2 vakasında, yeşil olmayan zemin üzerine kod eklenmesi CI'yı kırdı, kanıtsız commit zinciri oluştu ve sonunda tam rollback + özür kaydına gidildi. Bu tekrar etmeyecek.

## 4) Zaman damgası = makine `date` çıktısı, birebir

Damga manipülasyonu (ileri/geri yazma) — kasıtlı olsun olmasın — yasak. Bu zaten bir kez kayda geçmiş bir kural; burada resmen teyit ediyorum. İhlal fark edilirse ilgili girdi STATUS_ONLINE'da düzeltme notuyla işaretlenecek, silinmeyecek (audit trail kuralı geçerli).

## 5) Kapanış formatı zorunlu (4 satır)

Her iş/PR "tamamlandı" olarak işaretlenirken STATUS_ONLINE girdisi şu 4 satırı **eksiksiz** içerecek:

1. **Ne bitti** (tek cümle, sayı-hedefi değil davranış-tanımı)
2. **CI kanıtı** (commit SHA + run linki/ID)
3. **Ne bekliyor** (varsa açık karar/soru — yoksa "yok")
4. **Kim karar verecek** (kullanıcı / hangi ARENA / "otomatik")

Bu format olmadan bir iş "kapandı" sayılmaz, başka ajan üzerine inşa edemez.

---

## Neden bu talimat

Dışarıdan (Claude ile) yaptığım incelemede iki şey aynı anda doğru çıktı: ARENA1 ile ARENA3'ün bridge hatasını bağımsız bulup örtüşmesi gibi **gerçek** koordinasyon kanıtları var; ama ARENA2'nin çuvalladığı, ikinci sahte ARENA3'ün ortaya çıktığı, damgaların yanlış yazıldığı vakalar da var. Yani "3 AI harika koordineli çalışıyor" anlatısı abartılıydı — sistem çalışıyor ama **benim ve dış-denetimin sürekli çapraz kontrolüyle** ayakta duruyor, kendiliğinden değil. Bu talimat, o çapraz kontrolü sizin sürecinize gömüyor ki her seferinde ben devreye girmek zorunda kalmayayım.

Onboarding dokümanına (`docs/AI_ONBOARDING.md`) bu 5 maddeyi ekleyin ve okundu-onaylandı girdisi açın.

— Ayaz
