# ARENA4 — Onaylanan Sistemler ve Uygulama Yol Haritası

> **Tarih:** 2026-07-20
> **Ajan:** ARENA4
> **Durum:** Kullanıcı onayları sonrası uygulama planı.
> **Temel karar:** Dosyalarda “kullanıcıya sorulacak” denilen yerlerde ARENA4 önerilen şıkları uygulayabilir. İlk ADIM: Pollen + AI veri okuma yasağı.

---

## 1. Onaylanan kararlar

Kullanıcı şu sistemlerin geliştirilmesini onayladı: Data Rights/Pollen, AI veri okuyamama yasağının sertleştirilmesi, Relayer Policy Layer, D-Web Passport ve budlum.xyz yürütümü, Proof Verification Market araştırması, Sovereign Domain Kit, Budlum Atlas, Mobile Self, Encryption Layer'ın DAO parametrelerine bağlanması, Governance/Constitution Engine ve Developer OS/BudL SDK.

Öncelik kararı olarak ilk kodlama ADIM'ı **Pollen + AI veri yasağı** seçildi. AI veri okuma politikası **strict no override**: Geçerli Pollen AccessGrant yoksa AI, B.U.D./DataAsset verisini okuyamaz. DAO/admin bypass yoktur. D-Web Passport için bu repoda önce core API/spec çalışılacak; budlum.xyz frontend ayrı katmanda tasarlanacaktır. Encryption Layer DAO bağlantısında DAO yalnız parametre yönetir; kullanıcı anahtarına veya decrypt yetkisine dokunamaz.

---

## 2. Pollen kavramsal çerçevesi

Pollen, verinin kendisinin satılması değildir. Veri tomurcuğu kullanıcıya aittir; satılan şey tomurcuğun polenidir, yani sınırlı kapsamlı ve kayıtlı erişim hakkıdır. Bu nedenle `DataAsset` kalıcı sahipliği temsil eder, `AccessGrant` ise belirli bir alıcıya, belirli bir süre ve okuma sayısıyla verilen erişim polenidir.

Bu ayrım üç güvenlik ilkesini doğurur:

1. Sahiplik devredilmeden erişim satılabilir.
2. AI ajanı sadece grant kapsamındaki veriyi okuyabilir.
3. DAO genel parametre koyabilir, fakat kullanıcı verisini okuyamaz veya decrypt edemez.

---

## 3. ADIM planı

| ADIM | Başlık | Kapsam | Durum |
|---|---|---|---|
| A4-1 | Pollen Data Rights + AI read gate | `DataAsset`, `AccessGrant`, `AiDataInputRef`, executor admission gate | ✅ CI yeşil |
| A4-2 | SaleAuthorization + Pollen RPC | Owner-imzalı satış yetkisi, Pollen query + input-ref builder + prepare RPC | Bu branch'te başladı |
| A4-3 | Encryption DAO parameters | DAO-managed encryption version/limits, no decrypt authority | Bu ADIM başladı |
| A4-4 | Relayer Policy Layer | Intent, policy envelope, solver bid, relayer slashing hooks | Bu ADIM başladı |
| A4-5 | D-Web Passport core | light-client state proof query, `.bud` resolver spec, budlum.xyz handoff | Bu ADIM başladı |
| A4-6 | Sovereign Domain Kit | PoA/CBDC templates, compliance evidence, lifecycle docs/code | Sonraki ADIM |
| A4-7 | Budlum Atlas | read-only evidence cards, context maps, domain health proof model | Sonraki ADIM |
| A4-8 | Mobile Self | mobile self-hosting profile, QoS metadata, B.U.D. node policy | Sonraki ADIM |
| A4-9 | Governance/Constitution Engine | constitution parameter registry, DAO halt guardrails | Sonraki ADIM |
| A4-10 | Developer OS / BudL SDK | devnet template, package layout, proof fixtures, SDK docs | Sonraki ADIM |

---

## 4. Güvenlik sınırı

Bu yol haritası mainnet-ready veya audited iddiası değildir. VerifyMerkle, HPKE, HSM, external audit ve hardening gates kapanmadan gerçek Proof-of-Storage, hard encryption enforcement veya trustless external bridge iddiası kurulmaz. Her ADIM için test, negatif test, STATUS_ONLINE kaydı ve CI SLEEP zorunludur.

---

*Co-authored-by: ARENA4 <arena4@budlum.ai>*
