# Budlum Bug Bounty Programı —  Kararı (2.4=C)

**Durum:** Taslak ()
**Geçerlilik:** Mainnet v1 lansmanından itibaren
**Yöneten:** ARENA1 / AI Birliği koordinasyonu

---

## 1. Kapsam (In Scope)

| Bileşen | Kategori | Öncelik |
|---------|----------|---------|
| `src/consensus/` | Consensus bypass, double-spend, fork manipulation | Kritik |
| `src/chain/finality.rs` | BLS aggregate signature forgery, quorum bypass | Kritik |
| `src/crypto/pkcs11.rs` | HSM key extraction, mock→production leakage | Kritik |
| `src/cross_domain/bridge.rs` | Replay mint, lock bypass, asset drain | Kritik |
| `src/cross_domain/evm/` | F10 EVM receipt proof forgery, RLP/MPT bypass, header-chain spoof, deposit-log mismatch exploit | Kritik |
| `src/network/node.rs` | P2P DoS, eclipse attack, poisoned snapshot | Yüksek |
| `src/rpc/server.rs` | RPC auth bypass, rate limit bypass, spray OOM | Yüksek |
| `src/domain/storage_deal.rs` | Storage deal manipulation, challenge bypass | Yüksek |
| `budzero/bud-proof/` | ZK proof soundness break, invalid proof acceptance | Kritik |
| `budzero/bud-vm/` | VM escape, opcode abuse, gas manipulation | Yüksek |

## 2. Dışarıda (Out of Scope)

- Social engineering, phishing, fiziksel saldırılar
- Daha önce `STATUS_ONLINE.md`'de raporlanmış ve işlem görmüş bulgular
- Third-party dependency CVE'leri (aşağıdaki "Dependency Policy"ye bakın)
- Testnet / devnet-only konfigürasyonlar (mainnet spesifik olmalı)

## 3. Ödül Seviyeleri (Tahmini)

| Seviye | Örnek Bulgu | Ödül (USD) |
|--------|-------------|------------|
| **Kritik** | Consensus bypass, key extraction, bridge asset drain, ZK soundness break | $50,000–$100,000 |
| **Yüksek** | DoS with permanent state corruption, RPC auth bypass, P2P eclipse | $10,000–$25,000 |
| **Orta** | Rate limit bypass, information leak, economic manipulation | $2,500–$5,000 |
| **Düşük** | Best practice violation, documentation inconsistency | $500–$1,000 |

> **Not:** Ödüller 'te bug bounty platformu (immunefi.com, Q6 kararı: bug_bounty) ile entegre edildiğinde kesinleşecek.  10-soru anket Q6: bug_bounty seçildi (harici firma değil, immunefi tipi platform).

**Güncelleme ( Q6):** Immunefi entegrasyonu için `https://immunefi.com/bounty/budlum` taslak başvurusu hazırlanacak; kritik bulgular için $50k-$100k aralığı korunuyor. Mainnet self-audited olduğu için immunefi "medium" tier ile başlanacak, audit sonrası "high" tier'e yükseltilecek.

## 4. Raporlama Süreci

1. **Başvuru:** `security@budlum.network` (PGP key: `0xBUDLUM-SECURITY` — 'te yayınlanacak)
2. **Triage:** 72 saat içinde ilk yanıt
3. **Değerlendirme:** 14 gün içinde ön değerlendirme
4. **Düzeltme:** Kritik bulgular 30 gün içinde patch
5. **Açıklama:** Araştırmacı onayıyla coordinated disclosure (90 gün)

## 5. Kurallar

- Mainnet üzerinde test yapılmaz; testnet kopyası kullanılır.
- Veri kaybına veya servis kesintisine neden olunmaz.
- Bulgu raporlanmadan önce üçüncü tarafla paylaşılmaz.
- `AI_BIRLIGI.md` §6.1 (force-push yasağı) geçerlidir.

## 6. Dependency Policy

`cargo audit` tarafından tespit edilen CVE'ler (örneğin `protobuf`, `pqcrypto-*`, `ring`) bu program kapsamında **değerlendirilmez** — bunlar ayrı bir dependency upgrade 'inde ele alınır. Ancak, bir dependency CVE'sinin Budlum spesifik bir exploit chain'ine dönüştürülebildiği kanıtlanırsa, "Kritik" seviyede değerlendirilebilir.

---

**Sonraki adım:** 'te immunefi.com veya benzeri bir platforma kayıt + PGP key yayınlama.

---

## 7.  Augmentation — F10 kapsam + safe harbor + immunefi (F29)

> **Kaynak:**  F29 (🔴 mainnet-blocker, MR-8). Bu bölüm F29 kapanış
> kriterlerini ekler. **Yazar:** ARENA1 ( yöneticisi), 2026-07-18.

### 7.1 F10 EVM ChainAdapter kapsamı (PR #52 + #53 shipled)

F10 (Universal Relayer gerçek Ethereum köprüsü, H4 kapatma) main'e girdi.
**Kritik** saldırı yüzeyleri:

- `src/cross_domain/evm/rlp.rs` — RLP decode canonical-form bypass (non-canonical
  encoding kabul → kanıt uydurma). Negatif test matrisi var ama fuzz bulunabilir.
- `src/cross_domain/evm/mpt.rs` — Merkle-Patricia trie verifier: fake proof,
  inline-node abuse, missing-node bypass, panic-on-garbage (DoS).
- `src/cross_domain/evm/receipt.rs` — receipt decode: typed envelope confusion,
  status misclassification, log address/topic0 spoof.
- `src/cross_domain/evm/header.rs` — header chain: parent-hash forgery, number
  gap, fork-field injection (fork-tolerant decode → bypass yüzeyi).
- `src/cross_domain/evm/verify.rs` — `verify_evm_receipt` orchestrator: herhangi
  bir adımı atlatma, insufficient-confirmation bypass, deposit-log payload
  manipulation (amount/asset/recipient decode exploit).

**Ödül seviyesi:** Kritik ($50k-$100k) — fon kaybına yol açabilecek receipt
forgery / bridge drain. **Kabul:** Budlum bağımsız verify yaptığı için relayer
yanıltma yüzeyi sınırlı; yine de MPT/RLP impl bug'leri yüksek değerli.

### 7.2 Safe harbor / responsible disclosure (yasal)

**Good-faith araştırmacı koruması:** Bu program, aşağıdaki koşulları sağlayan
araştırmacıları **iyi niyetli** kabul eder ve yasal takip'ten muaftır:

1. Sadece **owned/test hesapları** ile test; üçüncü parti fon/veriye dokunulmaz.
2. Mainnet üzerinde **fonu/veriyi riske atmayan** salt-kanıt seviyesinde test
   (read-only RPC, proof construction, local node). Production-state mutation YASAK.
3. Bulgu, üçüncü tarafla paylaşılmadan **önce** `security@budlum.network`'e
   raporlanır (§4 süreç).
4. 90 gün coordinated-disclosure penceresine uyulur (erken public disclosure yasal
   korumayı düşürebilir).
5. Saldırı, servis kesintisine (DoS) veya kalıcı state corruption'a yol açtıysa:
   araştırmacı derhal durdurur ve etkileri bildirir.

**Out-of-safe-harbor:** mainnet'te gerçek fon drain, kullanıcı verisi sızıntısı,
social engineering, üçüncü parti altyapı (RPC provider, HSM vendor) saldırısı —
bunlar program kapsamı dışı + yasal süreç konusu.

### 7.3 Immunefi başvuru durumu (netleştirme)

- **Mevcut:** Immunefi taslak başvuru hazırlanmadı ( Q6 = bug_bounty
  kararı var, başvuru bekliyor).
- **Tier kararı:** Mainnet **self-audited** (external audit yok) → Immunefi
  **Medium tier** ile başlanır (kapsam: Kritik/Yüksek/Orta; max ödül Medium
  tier limitinde).
- **High tier yükseltme koşulu:** External audit (MR-8 ikinci ayağı) tamamlandıktan
  sonra High tier'e geçiş. Audit firm seçimi kullanıcı kararı (M7 debt).
- **Mainnet öncesi:** program **live** olamaz (testnet/devnet dışı kapsam yok).
  Immunefi launch = mainnet T+1d (§9.5 ceremony timeline ile senkron).

### 7.4 MR-8 kapanış kriterleri (F29)

MR-8 (external audit / bug bounty) kapanması için:

- [ ] §7.1 F10 kapsamı review onayı (ARENA3 kripto domain)
- [ ] §7.2 safe harbor yasal review (kullanıcı / counsel)
- [ ] §7.3 Immunefi Medium tier başvurusu submitted (mainnet T+1d)
- [ ] PGP key `security@budlum.network` yayınlanmış ( debt)
- [ ] (Opsiyonel) External audit firm seçimi + sözleşme (M7, High tier için)

**Bu doküman hâlâ taslak** — Immunefi live olana kadar MR-8 🟡 kalır. F29 🔴 →
MR-8 kapanışıyla ✅ (bug bounty launch yeterli; firm opsiyonel).

---

*Co-authored-by: ARENA1 <arena1@budlum.ai> (F29 augmentation, )*
