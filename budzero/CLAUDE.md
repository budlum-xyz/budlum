# CLAUDE.md — budzkvm (BudZero)

> Bu dosya AI ajanları (Cursor / Claude Code) her oturumda otomatik okur.
> Master Context + bu repoya özel kurallar aşağıdadır. Kapsam: sadece `budzkvm`
> (ZK-STARK sanal makinesi). Ağ/L1 (`budlum-core`) ve diğer bileşenler (DeEd,
> SocialFi, B.U.D., Budlum Go, DeArt, katılım bankası) bu talimat setinin
> dışındadır.

---

## 1. Master Context

```
PROJE: Budlum — "Evrensel Mutabakat Katmanı" (Universal Settlement Layer)
Açık kaynaklı, çok-konsensüslü (PoW/PoS/BFT + izole bir PoA domain) bir
Layer-1 blok zinciri.

Mimari ilkeler:
- Ağın GENELİ PERMISSIONLESS: PoW/PoS/BFT domain'lerinde validator/verifier/
  relayer kaydı için whitelist, onay mekanizması veya merkezi kapı YOK.
  Katılım = stake yatırma. Güvenlik ekonomik teşvik (stake) + slashing ile
  sağlanır, izinle değil.
- İSTİSNA — PoA domain: Kurumsal/regüle taraflar (bankalar, katılım bankası
  pilotu gibi) için bilinçli, izole bir permissioned alt-alan. Bu domain'e
  girişte KYC/onay gerekir — bu, ağın geri kalanının permissionless
  önermesini bozmaz çünkü sınırları net ve izoledir. PoA domain kuralları
  diğer domain'lere sızmamalı.
- ConsensusDomain: farklı konsensüs mekanizmalarının izole alanlar (domain)
  olarak bir arada yaşayabildiği bir soyutlama.
- CrossDomainMessage: domain'ler arası mesajlaşma primitive'i, replay
  koruması ve sıralama garantisiyle.
- Modülerlik önceliklidir. Monolitik entegrasyon ile modüler/unbundling tezi
  (bkz. Celestia, EigenLayer) arasındaki gerilimi varsayımla çözme — belirsizse
  soru sor.

YASAK: PoW/PoS/BFT domain'lerindeki validator/verifier/relayer rollerine
whitelist, admin-approval veya merkezi izin adımı ekleme. PoA domain'inin
izinli kurallarını diğer domain'lere sızdırma veya tersini yapma.
```

---

## 2. `budzkvm`

```
KAPSAM: ZK-STARK sanal makine, Plonky3 0.5.2 üzerine.
MEVCUT DURUM:  tamam (31 opcode, 51 test). 'e geçiliyor.

- BudL_SPEC.md dosyası YOKSA önce onu üret (syntax, tip sistemi, opcode
  eşlemesi) ve bunu onaylat — spec olmadan derleyici genişletme yaptırma.

- L1 ↔ ZKVM köprüsü: budlum-core'daki CrossDomainMessage primitive'i
  üzerinden yapılmalı, ayrı bir köprü protokolü icat ETTİRME.

- Permissionless prover/verifier:
  * Kanıt üretimi (proving) ve doğrulama (verification) uçları izin
    gerektirmeden herkese açık olmalı.
  * Prover'lar için ekonomik teşvik modeli (ücret, ödül) tanımlı olsun;
    merkezi bir "yetkili prover listesi" OLMAMALI.

- Her yeni opcode için zorunlu: (a) test, (b) BudL_SPEC.md güncellemesi,
  (c) gas/cost modeli tanımı.

KABUL KRİTERLERİ:
- Yeni opcode eklerken mevcut 51 testin hepsi geçmeli.
- Proof doğrulama akışı, budlum-core'daki permissionless registry ile
  entegre test edilmeli (bir prover'ın herhangi bir izin olmadan kanıt
  gönderip doğrulatabildiğini kontrol eden test).
```

---

## 3. Genel Standartlar

- Her yeni modül testsiz merge edilmez.
- README'de "bu repo neyi YAPMAZ" bölümü olsun (kapsam sızıntısını önlemek için).
- AI bir mimari belirsizlikle karşılaşırsa, varsayım yapıp kod yazmak yerine
  `// TODO(karar-gerekli): ...` yorumu bırakıp devam etsin.
- Cross-repo bağımlılık (Verifier Registry, ConsensusDomain, CrossDomainMessage)
  paket/submodule olarak referans verilsin, kopyala-yapıştır edilmesin.

---

## 4. Notlar

-  monorepo düzeninde bu workspace `budlum-core` tarafından `bud-isa`,
  `bud-vm`, `bud-proof` in-tree path crate'leri olarak tüketilir. Harici
  sibling checkout veya commit pin'i kullanma.
- `budlum-core` tarafında permissionless registry ve kanonik `SlashingReport`
  evidence formatı uygulanmıştır (bkz. `budlum-core/src/registry/`).
- **Permissionless prover entegrasyonu TAMAMLANDI** (, bkz.
  `budlum-core/src/prover/mod.rs`): Model B (tam açık gönderim). Kanıt
  `CrossDomainMessage` (kind=Custom("zk-proof")) ile core'a gider; core `bud_proof`
  ile NATIVE STARK doğrular; kayıt (`roles::PROVER`) sadece ödül için opsiyonel.
  Bu tarafta (BudZKVM) proof üretimi mevcut `bud-proof` adapter'ı üzerinden yapılır;
  ayrı bir köprü protokolü veya izin/whitelist mekanizması icat ETME.
```
