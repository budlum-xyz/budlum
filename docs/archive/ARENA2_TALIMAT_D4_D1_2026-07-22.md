# ARENA2 TALİMATI — D4 (Verifier Registry Birleştirme) + D1 (Permissionless Relayer)

**Tarih:** 2026-07-22
**Hazırlayan:** ARENA1 · **Hedef ajan:** ARENA2
**Yetkili (karar sahibi):** Ayaz
**Öncelik sırası (Ayaz):** G4 > D3 > D4 > D1 > D2 — bu talimat D4 ve D1'i kapsar (ARENA1 D3+D2'yi yapar). G1/G2/G3 kapsam dışı.
**Bu doküman eksiksizdir:** alınan kararlar, doğrulanmış kod gerçekleri, dosya yolları, kabul kriterleri, kurallar — hepsi içinde. ARENA2 bunu tek başına uygulayabilir.

---

## 0. Sen kimsin / durum

- Sen ARENA2'sin. Budlum ekosisteminde (blockchain + dezentralize AI) çalışan bir AI ajansısın. İşleri yönlendiren **Ayaz**.
- Budlum ana kod tabanı: `github.com/budlum-xyz/budlum` (~89K satır Rust, 35 CI gate).
- Bu talimat ARENA1 tarafından hazırlandı; körü körüne inanma — **her iddiayı kodla doğrula** (genel kural 6). Aşağıdaki "doğrulanmış gerçekler" bölümü ARENA1 tarafından grep+read ile teyit edildi, ama sen tekrar doğrula.
- Diğer ajanlar: ARENA1 (D3+D2 yapıyor), ARENA3/ARENA4 şu an aktif değil.

---

## 1. Genel kurallar (her görev için geçerli)

1. **CI yegâne yargıçtır.** Başarı iddiası ancak CI yeşil ile yapılır. Rapor metni kanıt sayılmaz.
2. **Kritik/yüksek madde açıkken yeni kapsam açma.** D4/D1 bitmeden yeni özellik spec'i/doküman commit etme.
3. **"Kapalı"/"✅" işareti sadece bağımsız doğrulanabilir kanıtla (CI run linki, test, commit hash).** Kendi beyanı = kanıt değil.
4. **Körü körüne inanma — kodla doğrula.** Bu talimattaki satır numaraları/iddialar önce grep/read ile teyit edilsin.
5. **Karar noktalarında sor.** Belirsizlikte `ask_user` kullan, süreci canlı tut, erken kapatma.
6. **Coverage/test eşiğini geçmek için test silme veya `#[ignore]` ile gizleme yasak.**
7. **`budlumdevnet` salt-okunur referanstır — asla değiştirme.** Üretilmiş secret commit edilmez.
8. Semver gate çalışıyor — public API değişikliği kırıcıysa dikkat. (EIP-1559 gibi istisnalar zaten eklendi.)
9. Token'u persistent dokümana/dosyaya **yazma** — session bağlamından al (bkz. §9).
10. Tüm kurallar her görev için geçerli.

---

## 2. Kapsam

### Senin işin (ARENA2)
- **D4** — Verifier Registry birleştirme (önce yap)
- **D1** — Permissionless relayer (D4'ten sonra; D1 → D4 bağımlılığı var)

### Senin işin DEĞİL (ARENA1 yapıyor — bu modüllere dokunma)
- **D3** — Legacy declared-depth proof kaldırma (proof/ISA modülleri)
- **D2** — Gizlilik katmanı Poseidon opcode'ları (bud-isa / bud-vm / bud-state / wallet)

Paralel çalışma kuralı (#14 talimat): bağımsız modüller. Senin modüllerin (verifier-registry, relayer, bridge) ARENA1'inkilerden (proof, bud-isa/vm/state) ayrı. Çakışma yok — kendi alanında kal.

---

## 3. Alınan kararlar (Ayaz tarafından verildi — TEKRAR SORMA)

Bu kararlar `docs/MAINNET_KARARLAR_2026-07-22.md` içinde kayıtlı. Tüm kararlar için tam bağlam:

| ID | Karar | Sonuç |
|---|---|---|
| **D1** | Relayer güven modeli | **PERMISSIONLESS** — herkes relayer çalıştırır; slashing + bond/stake gerekir |
| **D2** | Gizlilik katmanı (ARENA1) | v1'de dahil, Poseidon, note=paralel izole subtree, view-key=kullanıcı, exec-conf=TEE opt-in cüzdan |
| **D3** | Legacy proof (ARENA1) | Tamamen kaldır |
| **D4** | Verifier Registry | **v1'DE BİRLEŞTİR** — tek stake-tabanlı registry, 4 alanı kapsar |

**Senin için kritik olanlar:**
- **D4 = birleştir v1'de** (ayrı kalma/erteleme değil — Ayaz birleştirme dedi).
- **D1 = permissionless** (single-operator/threshold değil). Slashing + bond şart.

Bu ikisi birbirini güçlendirir: permissionless relayer → stake + slashing gerekir → unified stake-tabanlı registry'ye doğal oturur (D4).

---

## 4. Doğrulanmış gerçekler — ARENA2'nin başlangıç noktası

> ⚠️ **Önemli sürpriz:** Verifier Registry **zaten** stake-tabanlı + permissionless bir crate olarak mevcut. D4 "sıfırdan registry kur" değil, **"mevcut registry'nin 4 tüketiciyi kapsadığını doğrula + bypass eden varsa bağla"** işidir. Aşağıdaki her satırı teyit et.

### 4.1 Verifier Registry crate'i: `budzero/verifier-registry/`
Dosyalar: `lib.rs`, `registry.rs` (32KB — ana mantık), `role.rs`, `evidence.rs`, `params.rs`, `address.rs`.

- **`lib.rs:10`** — *"**Permissionless entry.** The ONLY gate is meeting the `min_stake` floor."* → Registry zaten permissionless + stake-tabanlı. **D4'ün temeli hazır.**
- **`role.rs:14`** — `pub struct RoleId(pub u32)` — **açık newtype (enum DEĞİL)**; yeni roller kolayca eklenebilir.
- **Roller (`role.rs` `roles` modülü):**

| RoleId | Constant | Anlam |
|---|---|---|
| 1 | `VALIDATOR` | konsensüs validator |
| 2 | `VERIFIER` = `MASTER_VERIFIER` | (aynı id — not) |
| 3 | `RELAYER` | **D1 bunu kullanır** |
| 4 | `PROVER` | proof üreticisi |
| 5 | `STORAGE_OPERATOR` | B.U.D. storage |
| 6 | `AI_VERIFIER` | AI doğrulama |
| 7 | `ATTESTER` | **supply-chain attester** |
| 8 | `LUBOT_OPERATOR` | Lubot operatör |

- **Slashing mevcut** (`evidence.rs`): `SlashingProof` enum — `DoubleSign`, `Liveness`, `Other`, `InvalidSignatureSpam`. `SlashingCondition` (`registry.rs`). `SlashingReport`.
- **Stake parametreleri** (`params.rs`): `min_stake` (varsayılan **1000**), `unbonding_epochs` (varsayılan **7**), slash fraction **%100** (kanıtlı kötü niyet tüm bond'u yakar — `params.rs:70`).
- **Kayıt metotları** (`registry.rs`): `register_master_verifier(...)`, `is_active_master_verifier(...)`, `get(account, role)`.

### 4.2 Relayer binary: `src/bin/budlum-relayer.rs`
- **207 satır, skeleton.** F10.4. CLI yapısı + `RelayerConfig` + `RelayDirection` ("eth-to-bud" / "bud-to-eth") var.
- Üst yorum: *"Budlum'a `submit_relay_proof` ile submit eder (registry kapısı, stake)"* — relayer'ın zaten stake-tabanlı registry'ye bağlanması tasarlanmış.
- *"Bu binary mainnet sonrası öncelik (F10.4). Şimdilik iskelet."* → D1 bunu skeletten üretime taşır.
- RFC kaynağı: `docs/RFC_F10_EVM_CHAIN_ADAPTER.md` §4-5.

### 4.3 Bridge doğrulama yolu (mevcut)
- `src/cross_domain/bridge_relayer.rs:78` — universal relayer (pending relays, proof verification).
- `src/cross_domain/evm/adapter.rs:9` — *"relayer proof üretir, Budlum verify eder (Q1)"*.
- `src/execution/executor.rs:494` — *"Relayer EVM Proofs — cryptographic verification"*; `:538` *"Universal Relayer: External result verified and recorded"*.

### 4.4 Ek bağlam
- EIP-1559 fee distribution üretimde bağlı (`blockchain.rs:2676`, mint-only, double-charge yok).
- CI son teyit yeşil: `68c8d91` (35/35). Son HEAD'ler sandbox öncesi: budlum `a7971d1`, budlum-core `9980bd1` (CI kuyrukta olabilir — §9'a bak).

---

## 5. D4 GÖREVİ — Verifier Registry Birleştirme (ÖNCE YAP)

**Karar:** v1'de tek stake-tabanlı registry; DeEd master verifiers + SocialFi content validator + relayer + supply-chain attester hepsi aynı registry'yi kullanır.

**Mainnet hazırlığı talimatı #16'nın asıl sorusu:** "Mevcut RoleId-tabanlı Verifier Registry bu dört kullanım alanını kapsıyor mu?" — sen bunu **doğrula**.

### 5.1 Adımlar
1. **Kapsam doğrulaması (önce bu):** 4 tüketicinin her birinin `budzero/verifier-registry` üzerinden mi kayıt olduğu, yoksa kendi ayrı güven mantığı mı kullandığını grep+read ile çıkar:
   - **DeEd / Master Verifier** → `MASTER_VERIFIER` rolü kullanılıyor mu? (`registry.rs:254 register_master_verifier`)
   - **SocialFi content validator** → hangi rol? (`AI_VERIFIER`? `ATTESTER`? ayrı mı?)
   - **Relayer** → `RELAYER` rolü (RoleId(3)) gerçekten bridge submit kapısında kullanılıyor mu?
   - **Supply-chain attester** → `ATTESTER` rolü (RoleId(7)) — Budlum Go / supply-chain tarafı bunu kullanıyor mu?
2. **Bypass tespiti:** registry'yi bypass edip kendi "güvenilir mi / nasıl slash" mantığını ayrı çözen bir yol varsa, listele.
3. **Bağlama (wire):** bypass edilen tüketicileri tek registry'ye çek. RoleId yeni newtype olduğu için yeni rol eklemek ucuz (`RoleId(N)`).
4. **Slashing kapsamı:** her rol için geçerli slashing koşullarının `SlashingCondition` ile uyumlu olduğunu doğrula. Relayer için griefing/fronting/yanlış-relay koşulu ekle (D1 ile koordineli).
5. **Test:** mevcut registry testlerini (`registry.rs` test bloğu, `evidence.rs` testleri) kırma. Kapsam testleri ekle.

### 5.2 D4 kabul kriteri
- [ ] 4 tüketici × registry kullanım matrisi çıktı alındı (dokümante).
- [ ] Bypass edilen tüketici varsa bağlandı (veya "v1'de ayrı kalır" gerekçesiyle kapatıldı — ama Ayaz birleştirme dedi, tercihen bağla).
- [ ] `cargo check -j 1 --workspace` (sandbox 2GB) temiz.
- [ ] CI 35/35 yeşil (runner doğrulayıcı).
- [ ] Commit hash + CI run linki raporlandı.
- [ ] Mevcut `LUBOT_OPERATOR = RoleId(8)` dahil tüm rol sabitleri korundu (regresyon yok).

### 5.3 D4 risk
- Registry crate'i zaten hazır olduğu için iş büyük ihtimalle **kapsam doğrulaması + küçük wiring**, sıfırdan inşa değil. Önce doğrula, sonra minimum değişiklik.

---

## 6. D1 GÖREVİ — Permissionless Relayer (D4'TEN SONRA)

**Karar:** Permissionless — herkes relayer çalıştırır. Slashing + bond/stake gerekir.

**Bağımlılık:** D4 (RELAYER rolü + slashing) tamamlanmadan D1'e başlama.

### 6.1 Adımlar
1. **Skeletten üretime:** `src/bin/budlum-relayer.rs` (207 satır skeleton) → production relay loop:
   - Ethereum RPC client (reqwest/alloy) — deposit event gözlemi.
   - Budlum RPC client — `submit_relay_proof` (registry kapısı + stake).
   - F10.1/F10.2 proof paketi üretimi (MPT + header chain + receipt).
   - Bud→ETH yönü: burn event + finality proof → Ethereum bridge kontratı.
2. **Permissionless kayıt:** relayer, D4'ün `RELAYER` rolü (RoleId(3)) ile `min_stake` (1000) bond yatırarak kayıt olur. Tek gate = stake.
3. **Slashing (griefing/fronting/yanlış-relay):** `SlashingCondition`'a relayer'a özel koşul ekle (D4 ile koordineli). Kanıt: `SlashingProof::Other` veya yeni varyant.
4. **Challenge penceresi:** bridge tarafında open relayer set + challenge (kötü relay itirazı) — RFC F10 §4-5'e göre.
5. **Test:** relay proof round-trip, slashing tetik, stake kilidi.

### 6.2 D1 kabul kriteri
- [ ] `budlum-relayer.rs` production loop derleniyor (cargo build).
- [ ] Relayer, registry üzerinden stake ile kayıt oluyor (permissionless).
- [ ] Griefing/fronting/yanlış-relay için slashing bağlı.
- [ ] `cargo check -j 1` temiz, CI yeşil.
- [ ] Commit hash + CI run linki.

### 6.3 D1 risk
- Production Ethereum RPC + proof üretimi **yüksek efor**. RFC F10'yu tam oku (`docs/RFC_F10_EVM_CHAIN_ADAPTER.md`, `docs/RFC_F10_5_BUD_TO_ETH_SOLIDITY.md`). Eğer tek seferde bitmezse, staging commit'lerle ilerle (her biri CI yeşil).

---

## 7. Sıra & bağımlılık

```
D4 (kapsam doğrulama → wire) ──► D1 (relayer production + slashing)
                                  ▲
                          D4'ün RELAYER rolü + slashing gerekir
```

- **D4 önce.** D4'ün RELAYER rolü + slashing altyapısı olmadan D1 bağlanamaz.
- D4 içinde önce **§5.1 kapsam doğrulaması** (sadece okuma) — sonuç beklenmedikse `ask_user` ile dur, körü körüne ilerleme.

---

## 8. Ortam / sandbox kısıtları

- Her bash çağrısının başında: `source /home/user/setup.sh` (Rust 1.94.0 + protoc + git recovery'yi geri yükler).
- `protoc` `/home/user/bin/protoc`'ta (setup.sh chmod +x yapar).
- `rust-toolchain.toml` 1.94.0 sabitler.
- Sandbox: **2GB RAM, 2 CPU**. `cargo check --lib -j 1` çalışır (~3dk). **`cargo test` codegen OOM yapar** — tam test CI runner'ında (7GB) koşar. CI yegâne doğrulayıcı.
- `.git` turlar arasında silinebilir — setup.sh recovery + `git fetch` + `reset --mixed` gerekebilir. Çalışma dizini: `/home/user/repos/budlum/`.

---

## 9. Push / CI mekanizması

- Push formatı: `git push "https://x-access-token:${TOKEN}@github.com/budlum-xyz/budlum.git" main`
- **TOKEN session'a özeldir, silinecek.** Persistent dokümana/dosyaya YAZMA. Token değerini session bağlamından al (ARENA1'in talimat özetinde). Emin değilsen Ayaz'a sor.
- CI durumunu kontrol et: GitHub Actions API veya `gh` CLI ile `budlum-xyz/budlum` main branch. CI kuyrukta/queued olabilir (GitHub runner gecikmesi, kod hatası değil). Bekle, sonra doğrula.

---

## 10. Raporlama formatı

Her görev kapanışında:
1. **Commit hash** + etkilenen dosyalar.
2. **CI run linki** (yeşil teyit).
3. D4 için: **4 tüketici × registry matrisi** (kapsadı/bypass/bağlandı).
4. D1 için: relayer production durum + slashing koşulları.
5. Açık 🔴/🟡 bulgu sayısı (hedef 0/0).
6. Sonraki adım.

---

## 11. Dosya yolu referansı (doğrulanmış)

| Dosya | İçerik |
|---|---|
| `budzero/verifier-registry/src/lib.rs` | permissionless entry açıklaması (lib.rs:10) |
| `budzero/verifier-registry/src/registry.rs` | ana registry mantığı (32KB), register/get/slash |
| `budzero/verifier-registry/src/role.rs` | RoleId newtype + 8 rol sabiti |
| `budzero/verifier-registry/src/evidence.rs` | SlashingProof/SlashingReport |
| `budzero/verifier-registry/src/params.rs` | min_stake=1000, unbonding=7, slash %100 |
| `src/bin/budlum-relayer.rs` | D1 hedefi — 207 satır skeleton |
| `src/cross_domain/bridge_relayer.rs` | universal relayer |
| `src/cross_domain/evm/adapter.rs` | relayer proof → Budlum verify |
| `src/execution/executor.rs:494,538` | Relayer EVM proof verification |
| `docs/RFC_F10_EVM_CHAIN_ADAPTER.md` | D1 tasarım kaynağı |
| `docs/RFC_F10_5_BUD_TO_ETH_SOLIDITY.md` | Bud→ETH yönü |
| `docs/MAINNET_KARARLAR_2026-07-22.md` | tüm kararlar (D1-D4) |
| `docs/operations/PRODUCTION_RUNBOOK.md` §5 | PoW bridge / mint policy |

---

## 12. Özet kontrol listesi (ARENA2)

- [ ] §1 kuralları oku (CI yargıç, doğrula-kodu, sor, kapsam disiplini).
- [ ] §3 kararları içselleştir (D4=birleştir, D1=permissionless — sorma, uygula).
- [ ] §4 doğrulanmış gerçekleri **kendin tekrar grep/read ile teyit et**.
- [ ] D4 §5: önce kapsam doğrulaması → wire → CI yeşil → rapor.
- [ ] D1 §6: D4 sonrası relayer production + slashing → CI yeşil → rapor.
- [ ] Her kapanışta commit hash + CI linki.

*Karıldı (compiled) by ARENA1, 2026-07-22. Kararlar Ayaz tarafından ask_user akışında verildi. Tüm gerçekler kod düzeyinde doğrulandı — ama ARENA2 tekrar teyit etmeli (kural 6).*
