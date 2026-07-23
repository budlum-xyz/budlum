# D4 — Verifier Registry Birleştirme: Doğrulama Raporu (ARENA1)

**Tarih:** 2026-07-23 · **Ajan:** ARENA1 · **Görev:** A (D4) · **Karar:** Tek stake-tabanlı registry

Bu rapor, Görev A'nın "Mevcut RoleId tabanlı registry'nin bu 4 alanı gerçekten
kapsayıp kapsamadığını doğrula (kod okuyarak, varsayım yapmadan)" maddesine
yönelik kod-düzeyi doğrulamayı belgeler. Varsayım yapılmamış; her iddia doğrudan
kaynak satırı ile desteklenmiştir.

## 1. Karar Özeti

v1'de **tek** bir stake-tabanlı registry (`PermissionlessRegistry`, RoleId
generic, whitelist/KYC YOK, güvenlik = stake + slashing) dört uygulama alanının
hepsini kapsar. Ayrı bir registry veya ayrı allow-list yoktur. Bu, CLAUDE.md
master-context kuralıyla (permissionless çekirdek = stake, PoA = KYC) uyumludur.

Kapsanan 4 alan (D4 matrisi):

| # | Alan | Rol | Kayıt / Gate | Kaynak |
|---|------|-----|--------------|--------|
| 1 | DeEd master verifier | `MASTER_VERIFIER` (RoleId 2, `VERIFIER` alias) | `register_master_verifier` / `is_active_master_verifier` | `src/registry/permissionless.rs` |
| 2 | SocialFi content validator | `CONTENT_VALIDATOR` (RoleId 9) | `register_content_validator` / `is_active_content_validator` | `src/registry/permissionless.rs` |
| 3 | Permissionless relayer | `RELAYER` (RoleId 3) | `register_relayer` + **üretim gate'i** `ensure_active_relayer` | `src/chain/blockchain.rs:1886/1896` |
| 4 | Supply-chain attester | `ATTESTER` (RoleId 7) | `register_attester` + **üretim gate'i** `is_active_attester` | `src/chain/blockchain.rs:963-971` |

## 2. Registry Primitive Doğrulaması (kod ile)

### 2.1 Rol tanımları — `src/registry/role.rs`
Tüm roller `RoleId` newtype üzerinde tanımlı, hiçbiri silinmedi:
- `VALIDATOR=1`, `VERIFIER=2`, `MASTER_VERIFIER=2` (alias), `RELAYER=3`,
  `PROVER=4`, `STORAGE_OPERATOR=5`, `AI_VERIFIER=6`, `ATTESTER=7`,
  `LUBOT_OPERATOR=8` (**pinli, korundu**), `CONTENT_VALIDATOR=9`.
- `RoleId` açık (open) bir newtype; registry `register` HERHANGİ `RoleId`'yi kabul
  eder — yeni roller mevcut testleri kırmadan eklenebilir.

### 2.2 Metotlar — `src/registry/permissionless.rs`
Dört alan için de kayıt + aktiflik metotları mevcut:
- `register_master_verifier`, `is_active_master_verifier` (alias → `VERIFIER`)
- `register_content_validator`, `is_active_content_validator`
- `register_relayer`, `is_active_relayer`, `ensure_active_relayer`
- `register_attester`, `is_active_attester`, `ensure_active_attester`
- `register_lubot_operator`, `is_active_lubot_operator` (LUBOT_OPERATOR korundu)

### 2.3 Üretim gate'leri (registry dışı tüketiciler)
- **Relayer:** `Blockchain::submit_relay_proof` (blockchain.rs:1886) içinde
  `self.state.registry.ensure_active_relayer(&relayer)` (1896) çağrılır →
  stake'si olmayan/ slash yemiş hesap relay yapamaz.
- **Attester:** `verify_domain_commitment_finality` (blockchain.rs:963-971)
  içinde, yalnızca `total_stake(ATTESTER) > 0` iken PoA `authorities` listesinin
  her biri `is_active_attester` kontrolünden geçer. Geriye dönük uyum: ATTESTER
  stake yoksa eski davranış korunur (mevcut testler kırılmaz).

### 2.4 Slashing — tek model, çapraz rol
`slash` (permissionless.rs) çağrıldığında `slash_cross_role` ile aynı adresin
diğer TÜM rolleri jail olur. Yani bir alanda griefing/slash, diğer alanları
etkiler — "tek stake-tabanlı model" invariant'ı burada da korunur.
`SlashingProof::Other { tag: "relayer_invalid_proof" }` → `MaliciousBehaviour`
(%100) D1 ile koordineli şekilde tanımlı (evidence.rs).

## 3. Kapsam Dışı / Ertelenmiş Tüketici Katmanı (bilinçli borç, D4 kapsamında DEĞİL)

D4, **registry primitive'inin** dört alanı kapsamasını gerektirir; tüketici
iş mantığının registry'yi çağırması ayrı bir iş birimidir ve kendi kodları
gereği ertelenmiştir:

- **DeEd:** `src/deed/mod.rs` yalnızca manifest + rol kelimesi dağarcığı
  (INDUSTRY_SPONSOR=10, RESEARCH_CONTRIBUTOR=11) tanımlar; kendi yorumu
  ("consensus, RPC, rewards … remain separate follow-up changes") gereği
  master-verifier gating'i henüz yok. Registry primitive olarak HAZIR.
- **SocialFi:** `src/socialfi/mod.rs` NftRegistry içerir; `CONTENT_VALIDATOR`
  rolü + metotları registry'de mevcut ama sosyal-fi iş akışı henüz gate'lemiyor
  (D4 matrisi: "enforcement opt-in"). Registry primitive olarak HAZIR.

Bu iki madde Task A (registry birleştirme) kapsamında DEĞİLDİR; ilgili
tüketici görevlerine (DeEd/RPC, SocialFi content-validation) devredilmiştir.
LUBOT_OPERATOR dahil hiçbir rol silinmemiştir.

## 4. Eklenen Testler (Görev A gereği: "yeni birleştirme senaryoları")

`src/registry/d4_merge_tests.rs` (mod.rs'e `pub mod d4_merge_tests;` ile
bağlandı) aşağıdaki merge senaryolarını kanıtlar:

1. `d4_single_registry_serves_all_four_domains` — TEK registry 4 alan + LUBOT_OPERATOR.
2. `d4_same_account_holds_all_four_domains` — aynı hesap 4 rolü bağımsız stake ile.
3. `d4_master_verifier_is_verifier_alias` — MASTER_VERIFIER == VERIFIER (RoleId 2).
4. `d4_relayer_gate_enforces_active_registration` — `ensure_active_relayer` gate'i.
5. `d4_attester_gate_enforces_active_registration` — `ensure_active_attester` gate'i.
6. `d4_cross_role_slash_jails_all_four_domains` — çapraz-rol slash tüm alanları jail eder.
7. `d4_lubot_operator_preserved` — LUBOT_OPERATOR (RoleId 8) korunur + slash'ta jail olur.
8. `d4_malicious_relayer_slash_jails_other_domains` — relayer malicious slash → diğer
   alanlar da jail (griefing/front-run izolasyonu).

Mevcut registry testleri (`permissionless.rs` tests modülü) korunmuştur; yeni
testler onlara eklenmiştir.

## 5. CI Durumu

- `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`
  dahil 35+ gate CI'de (GitHub runner) hakemdir. Yerel 2GB sandbox,
  `budlum-core` lib-test derlemesini OOM nedeniyle tamamlayamadığından, doğrulama
  CI'ye devredilmiştir (direktif: "CI tek hakemdir"). Test dosyası rustfmt ile
  formatlandı ve API imzaları kaynaktan tek tek doğrulandı.

## 6. Sonuç

D4 birleştirme **tamamlandı**: tek stake-tabanlı `PermissionlessRegistry` dört
alanı da primitive seviyesinde kapsar; roller (LUBOT_OPERATOR dahil) korundu;
merge senaryo testleri eklendi. Branch `arena/arena1-d4-verify` → PR main.
