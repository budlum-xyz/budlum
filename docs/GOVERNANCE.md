# Governance Model — Budlum Mainnet

> Bu doküman Budlum mainnet'inin parametre değişikliği, slashing ve acil durum
> yönetim süreçlerini tanımlar.

---

## 1. Parametre Değişikliği Süreci

### 1.1 Değiştirilebilir Parametreler

| Parametre | Aralık | Varsayılan | Açıklama |
|-----------|--------|------------|----------|
| `base_fee` | 1 — 10,000,000 | 1 | Minimum işlem ücreti |
| `block_reward` | 0 — 10,000 BUD | 50 BUD | Blok başına mint |
| `min_stake` | ≥ 100 | 1,000 | Minimum validator stake |
| `unbonding_epochs` | 1 — 100,000 | 100 | Unbonding süresi |
| `double_sign_slash_ratio_fixed` | 0 — FIXED_POINT_SCALE | %50 | Double-sign ceza oranı |
| `liveness_slash_ratio_fixed` | 0 — FIXED_POINT_SCALE | %1 | Liveness ihlali ceza oranı |
| `malicious_slash_ratio_fixed` | 0 — FIXED_POINT_SCALE | %100 | Kötü niyetli davranış ceza oranı |

### 1.2 Değişiklik Akışı

1. **Önerge oluşturma:** Herhangi bir validator `ProposalType::ParameterUpdate(key, value)` ile önerge oluşturur.
2. **Oylama dönemi:** Önerge `end_epoch - start_epoch` epoch boyunca açıktır.
3. **Quorum:** `(votes_for + votes_against) * 100 >= total_stake * quorum_pct` (varsayılan %10).
4. **Karar:** `votes_for > votes_against` ise önerge geçer.
5. **Uygulama:** `execute_proposal()` parametreyi `RegistryParams::validate()` sınırları içinde uygular.

### 1.3 Acil Durum Override'ı

- **Yok.** Governance dışında manuel parametre değişikliği mekanizması bulunmamaktadır.
- Acil durumda (ör. kritik zafiyet), yeni bir `ParameterUpdate` önergesi ile süreç hızlandırılabilir.

---

## 2. Slashing Yönetişimi

### 2.1 Otomatik Slashing (Kanıtlı)

| Durum | Kanıt | Ceza Oranı |
|-------|-------|------------|
| Double-sign | İki farklı blok imzası | %50 |
| Liveness ihlali | Ardışık epoch katılım eksikliği (eşik: 10) | %1 |
| Geçersiz imza spam | Eşik aşan geçersiz imza (eşik: 20/epoch) | %100 |

### 2.2 Governance Slashing (V40 — Kanıt Zorunlu)

- `ProposalType::SlashValidator { address, evidence_hash }` önergesi oluşturulur.
- **Ön koşul:** Hedef adresin `registry.slashing_history()`'sında en az bir kayıt bulunmalıdır.
- Quorum ve oylama akışı aynıdır.
- Kanıtsız slash reddedilir (`execute_proposal()` doğrular).

### 2.3 Parametre Değişikliği ile Slashing Devre Dışı Bırakılabilir mi?

- **Teorik olarak evet:** Governance ile slash oranları 0'a çekilebilir.
- **Pratik risk:** Yeterli stake çoğunluğu gerektirir. Bu bilinçli bir tasarım kararıdır — governance = ultimate authority.
- **Koruma:** `params.validate()` alt sınır koymaz (sadece üst sınır = FIXED_POINT_SCALE).

---

## 3. Blok Üretimi ve Konsensüs

### 3.1 PoS VRF Liderlik Seçimi

- Her slot için VRF tabanlı liderlik seçimi.
- Threshold = `validator_stake / total_stake * VRF_BASE_PROB`.
- BLS imzası zorunlu (VRF proof + block signature).

### 3.2 Finality

- BFT tabanlı finality (BLS imza kümesi).
- Quorum: `%67+ stake-weighted imza`.
- Finality Cert zincirde saklanır, geriye dönük değişiklik engellenir.

### 3.3 Epoch Yapısı

- `EPOCH_LENGTH = 100` blok.
- Epoch kapanışında: liveness kontrolü, reward dağıtımı, slashing raporu.
- `MAX_TIMESTAMP_DRIFT_MS = 15,000` (V45).

---

## 4. Bridge Yönetişimi

### 4.1 Relayer Modeli

- **Permissionless:** Stake eden herkes relayer olabilir.
- Minimum stake: `min_relayer_stake` (varsayılan 10,000,000).
- Slash: geçersiz proof %50, expired relay %25.

### 4.2 Asset Kayıt

- `BridgeState::register_asset()` ile yeni asset kaydı.
- Her asset için lock/mint/burn/unlock yaşam döngüsü.
- Replay koruması: `ReplayNonceStore`.

---

## 5. AI Inference Yönetişimi

### 5.1 Model Kayıt

- Permissionless: herkes `AiModelRegister` ile model kaydedebilir.
- Anti-spam: `max_fee >= 1` zorunluluğu.

### 5.2 Verifier Atama

- `RoleId::AI_VERIFIER` (RoleId=6) ile kayıt.
- Fallback: PoS validator'ları (stake ≥ 1000) da verifier olabilir.
- Soft incentive: çoğunluk dışı verifier'lar ödül alamaz ama stake'leri kesilmez.

---

## 6. BNS (Budlum Name Service) Yönetişimi

### 6.1 İsim Kayıt

- Permissionless: herkes `.bud` ismi kaydedebilir.
- Ücret: `base_cost * length_multiplier * duration`.
- Süre dolduğunda isim serbest kalır (yeniden kayıt yapılabilir).

### 6.2 Subdomain

- İsim sahipleri subdomain oluşturabilir.
- Owner-only transfer ve yenileme.

---

## 7. Tokenomics

### 7.1 Sabit Arz

- Toplam: 100,000,000 BUD (6 ondalık).
- Dağıtım: Community 10M, Likidite 10M, Ekosistem 20M, Team 20M, Yakım Rezervi 40M.

### 7.2 Yakım Mekanizmaları

1. **Zamana bağlı yakım:** Yıllık %10 (4M BUD/yıl) yakım rezervinden.
2. **Metabolik yakım:** Her tx fee'sinin %1'i yakılır.

### 7.3 Vesting

- Team: 1 yıl cliff, 4 yıl lineer.
- `spendable_balance = balance - locked_at(epoch)`.

---

## 8. Doküman Güncelleme Politikası

- Bu doküman her phase açılışında güncellenir.
- Parametre değişiklikleri bu dokümanda kaydedilir.
- Acil durum prosedürleri ayrı `docs/EMERGENCY.md`'de tutulur (henüz yok).

---

*Son güncelleme: 2026-07-19, ARENAX denetimi.*
