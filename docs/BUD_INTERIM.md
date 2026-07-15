# B.U.D. Interim Retrieval Challenge — Teknik ve Ekonomik Açıklama

**Hazırlayan:** ARENA1 (ADIM3 §3.6)
**Tarih:** 2026-07-15
**Durum:** Kullanıcı onayı bekliyor

---

## 1. Genel Bakış

B.U.D. (Broad Universal Database / Merkeziyetsiz Depolama Sunucu Sistemi) mainnet lansmanında **gerçek kriptografik Proof-of-Storage (PoS)** henüz aktif değildir. Bu belge, mevcut interim mekanizmanın nasıl çalıştığını, neden bu şekilde seçildiğini ve kullanıcı beklentilerinin nasıl yönetilmesi gerektiğini açıklar.

---

## 2. Mevcut Durum: Interim Retrieval Challenge

### 2.1 Temel Mekanizma

B.U.D. mainnet'te şu anda **interim retrieval challenge** mekanizması çalışmaktadır:

```
┌─────────────┐      Open Challenge      ┌──────────────────┐
│   Opener    │ ──────────────────────► │   Storage Deal   │
│  (istemci)  │                          │    (operatör)    │
└─────────────┘      Bond (para kilit)   └──────────────────┘
       │                                          │
       │                                          │
       │         Answer (byte_range_hash)         │
       │ ◄──────────────────────────────────────┘
       │         Bond iade / slashing
       ▼
┌──────────────────────────────────────────────────┐
│              On-Chain Accounting                  │
│  • Reward accrual (operatör)                    │
│  • Slashed bond (yanlış/eksik yanıt)            │
│  • Economics event log (gossip)                 │
└──────────────────────────────────────────────────┘
```

### 2.2 Challenge Akışı

1. **Open:** Herhangi bir hesap `bud_storageOpenChallenge` RPC çağrısıyla challenge açar
   - Opener bond kilitlenir (spam önleme)
   - `RetrievalChallengeRequest` → zincirde `RetrievalChallenge` oluşur

2. **Answer:** Operatör `bud_storageAnswerChallenge` RPC çağrısıyla yanıt verir
   - Sadece `range_hash` (alt aralık hash) sunulur
   - **Tam shard kanıtı DEĞİL**

3. **Outcome:** Zincir sonucu kaydeder
   - ✅ Doğru yanıt → opener bond iade, operatör reward accure
   - ❌ Yanlış yanıt → operatör bond slashed
   - ⏰ Deadline geçerse → operatör bond slashed

---

## 3. Neden Gerçek PoS Değil?

### 3.1 Gerçek PoS İçin Gerekenler

Gerçek kriptografik Proof-of-Storage için aşağıdakiler gereklidir:

| Bileşen | Durum | Blocker |
|---------|-------|---------|
| BudZKVM | ✅ Mevcut | — |
| VerifyMerkle opcode | ⚠️ DEVRE DIŞI | Z-B 64-depth proof gate |
| STARK proof üretimi | ⚠️ Yavaş | Performance optimization gerekli |
| `StorageAttestationFinalityAdapter` | ✅ Tamamlandı | ADIM3 §0.1 |
| Faz 3 entegrasyonu | ❌ Kapalı | VerifyMerkle production'a bağlı |

### 3.2 Z-B Gate (ADIM2 Karar 2.1-B)

`VerifyMerkle` opcode'u şu anda **production'da devre dışıdır**:

```rust
// budzero/bud-isa/src/lib.rs:39-43
VerifyMerkle { ... } => {
    // TODO: enable after Z-B Commit 3.5 completes
    return Err(VMError::DisabledInstruction);
}
```

**Karar:** ADIM2'de Z-B Commit 3.5 tamamlanıp gate açılacak. Tahmini: 2-3 hafta.

---

## 4. Ekonomik Oyun Mekanizması

### 4.1 Güvenlik Modeli

Interim challenge, **ekonomik incentives** ile çalışır:

```
┌─────────────────────────────────────────────────────────────┐
│                    Ekonomik Teşvik                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Operatör:                                                  │
│  ├── Gelir: Her epoch'ta fee_per_epoch ödül               │
│  ├── Risk: Yanlış yanıt → bond slashed                     │
│  └── Ceza: Deadline geçerse → bond slashed                 │
│                                                             │
│  Opener (istemci):                                         │
│  ├── Maliyet: Challenge açma = küçük bond kaybı (spam)    │
│  ├── Kazanç: Doğru challenge = operatörün güvenilirliği    │
│  └── Risk: Yanlış challenge = bond kaybı                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Neden Bu Yeterli?

**Kısa vadeli (mainnet lansmanı için):**

1. **Ekonomik caydırıcılık yeterli:** 
   - Operatörler ciddi miktarda bond yatırır
   - Yanlış yanıt = para kaybı = güçlü teşvik
   - "Ben gerçekten saklıyorum" demek için ekonomik baskı

2. **Ölçekleme avantajı:**
   - Gerçek PoS hesaplaması pahalı (STARK proof üretimi)
   - Interim challenge hızlı ve ucuz
   - İlk aşamada yeterli depolama güvencesi sağlar

3. **Geriye dönük uyumluluk:**
   - Faz 3 açıldığında, mevcut operatörler zaten "depoluyorlar"
   - Sadece PoS kanıtı eklemeleri gerekecek

**Uzun vadeli (ADIM4 sonrası):**

Gerçek PoS ile tam kriptografik kanıt:
- Veri gerçekten saklanıyor (Merkle proof)
- Şifreleme anahtarı ile binding
- ZK proof ile zincir dışı doğrulama

---

## 5. Kullanıcı Beklenti Yönetimi

### 5.1 Dökümanlar İçin Öneri

Ana README veya dokümantasyon şöyle bir not içermeli:

> ⚠️ **Mainnet Storage Durumu**
> 
> B.U.D. mainnet'te depolama, **interim retrieval challenge** mekanizması ile korunmaktadır. Bu mekanizma ekonomik teşviklere dayanır:
> - Operatörler yatırılan bond üzerinden cezalandırılır
> - Yanlış yanıt veya deadline aşımı = bond slashing
> 
> Gerçek kriptografik Proof-of-Storage (STARK tabanlı) **ADIM4**'te aktif olacaktır.

### 5.2 Operatörler İçin

```
┌─────────────────────────────────────────────────────────────────┐
│                   Operatör onboarding'da bilgilendirme          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  "Bu mainnet lansmanında, B.U.D. depolama altyapısı            │
│   interim retrieval challenge ile çalışmaktadır.                 │
│                                                                 │
│   Gerçek kriptografik PoS kanıtı (VerifyMerkle STARK)         │
│   ADIM4'te eklenecektir.                                        │
│                                                                 │
│   Şu an için:                                                   │
│   • Her challenge'a doğru byte_range_hash sunmalısınız         │
│   • Deadline'leri kaçırmayın (slashing riski)                  │
│   • Depolama performansınız challenge başarı oranınızla ölçülür│
│                                                                 │
│   ADIM4 sonrası:                                                │
│   • Ek Merkle proof sunmanız gerekecek                         │
│   • PoS kanıtınız zincir dışı doğrulanabilecek                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. Teknik Detaylar

### 6.1 RPC Metodları

| Metod | Açıklama | İmza Gerekli |
|-------|----------|--------------|
| `bud_storageOpenChallenge` | Challenge açar | `opener_signature` (Ed25519) |
| `bud_storageAnswerChallenge` | Yanıt verir | `responder_signature` (Ed25519) |
| `bud_storageGetOutcome` | Sonucu sorgular | Hayır |

### 6.2 Veri Yapıları

```rust
// RetrievalChallengeRequest - opener signature zorunlu
pub struct RetrievalChallengeRequest {
    pub deal_id: u64,
    pub byte_start: u64,
    pub byte_end: u64,
    pub challenge_epoch: u64,
    pub deadline_epoch: u64,
    pub opener_bond: u64,
    pub opener: Option<Address>,           // Self-reported
    pub opener_signature: Option<Vec<u8>>,  // Zorunlu (mainnet)
}

// RetrievalResponse - responder signature zorunlu
pub struct RetrievalResponse {
    pub challenge_id: u64,
    pub _range_hash: ContentId,
    pub responder: Address,                  // Self-reported
    pub response_epoch: u64,
    pub responder_signature: Option<Vec<u8>>, // Zorunlu (mainnet)
}
```

### 6.3 Economics Events

Operatör reward accrual ve slashing, `StorageEconomicsEvent` üzerinden izlenebilir:

```rust
pub enum StorageEconomicsEvent {
    RewardAccrued { operator: Address, amount: u64 },
    BondSlashed { operator: Address, amount: u64, reason: SlashedReason },
}
```

---

## 7. Karar Kaydı

| Tarih | Karar | Açıklama |
|-------|-------|----------|
| 2026-07-15 | ADIM2 §2.3 = **Seçenek A** | B.U.D. mainnet'e dahil, interim challenge ile başla |
| 2026-07-15 | ADIM4 = **VerifyMerkle Gate Açılışı** | Faz 3 entegrasyonu için |

---

## 8. Sonraki Adımlar

- [ ] Bu belge kullanıcı onayı aldıktan sonra `docs/BUD_INTERIM.md` olarak repo'ya eklenecek
- [ ] README'de mainnet storage durumu notu eklenecek
- [ ] Operatör runbook (§3.3) güncellenecek
- [ ] ADIM4 planında VerifyMerkle gate açılışı takip edilecek

---

## 9. İlgili Belgeler

- `docs/MAINNET_READINESS.md` — ADIM2/ADIM3 planı
- `src/domain/storage_deal.rs` — Retrieval challenge veri yapıları
- `src/rpc/api.rs` — Storage RPC surface
- `budzero/bud-isa/src/lib.rs` — VerifyMerkle opcode (devre dışı)
