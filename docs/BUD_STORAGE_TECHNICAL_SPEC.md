# B.U.D. Storage — Teknik Spec (Vision → Implementation)

> **Yazar:** ARENA1 (görev yöneticisi), 2026-07-20.
> **Durum:** Final v1 (Task 11.6) → implementasyon Task 11.10.
> **ADR:** [ADR-002](adr/ADR-002-storage-spec-first.md) + [ADR-003](adr/ADR-003-node-siniflandirma.md)
> **SPEC_REVIEW:** [BUD_STORAGE_TECHNICAL_SPEC_REVIEW.md](spec-review/BUD_STORAGE_TECHNICAL_SPEC_REVIEW.md)
> **INTERFACE_FROZEN:** true
> **Kaynak Vision:** `budlum-xyz/B.U.D./BUD_Merkeziyetsiz_Depolama_Vizyonu.md`.

---

## 0. Interface Freeze (Task 11.6)

Bu spec Task 11.6 sonunda **interface-frozen** kabul edilir. Task 11.10 kodu aşağıdaki trait imzalarını, state machine durumlarını, hata semantiğini ve CI spec-review kapısını değiştiremez; değişiklik gerekiyorsa yeni ADR açılır.

### 0.1 Donmuş storage provider trait

Task 11.10'da `src/storage/provider.rs` içinde aşağıdaki interface açılır. Bu trait on-chain state'i doğrudan değiştirmez; storage backend ve proof üretim/doğrulama adaptörü olarak çalışır.

```rust
pub type DealId = [u8; 32];
pub type ChallengeId = [u8; 32];

pub struct PutReceipt {
    pub content_id: ContentId,
    pub bytes_written: u64,
    pub provider_commitment: Hash32,
}

pub struct StorageProof {
    pub deal_id: DealId,
    pub challenge_id: ChallengeId,
    pub range_hash: Hash32,
    pub merkle_path: Vec<Hash32>,
    pub proof_bytes: Vec<u8>,
}

pub trait StorageProvider {
    fn put(&mut self, manifest: &ContentManifest, bytes: &[u8]) -> Result<PutReceipt, StorageError>;
    fn get(&self, content_id: &ContentId, range: std::ops::Range<u64>) -> Result<Vec<u8>, StorageError>;
    fn prove(&self, deal_id: DealId, challenge: &RetrievalChallenge) -> Result<StorageProof, StorageError>;
    fn challenge(&mut self, deal_id: DealId, challenge: RetrievalChallenge) -> Result<ChallengeId, StorageError>;
    fn settle(&mut self, challenge_id: ChallengeId, proof: StorageProof) -> Result<ChallengeResult, StorageError>;
}
```

**Hata semantiği:** proof üretilemezse fail-closed; `Ok(())` dönen stub yasaktır. Interim `RetrievalChallenge` gerçek Proof-of-Storage değildir ve UI/RPC metinlerinde böyle iddia edilemez.

### 0.2 Deal lifecycle state machine

Donmuş state seti:

```text
Open → Proving → Challenged → Settled
  │       │           │          │
  │       │           ├── Missed ┤
  │       │           └── Slashed┤
  └── Expired ───────────────────┘
```

- **Open:** deal kaydedildi, operator bond kilitli.
- **Proving:** provider initial commitment/proof sundu.
- **Challenged:** permissionless opener challenge açtı; opener bond kilitli.
- **Settled:** geçerli proof veya challenge başarıyla sonuçlandı; bond/reward dağıtıldı.
- **Missed:** deadline geçti, cevap yok; operator slash edilir.
- **Slashed:** geçersiz proof veya malicious evidence; operator bond kesilir.
- **Expired:** deal süresi bitti, bond iade/settle akışı tamamlandı.

Geçersiz geçişler reddedilir; özellikle `Settled/Slashed/Expired` terminaldir.

### 0.3 CI spec-review kapısı

Task 11.6'da `scripts/check-spec-coverage.sh` bu dosyanın `INTERFACE_FROZEN: true` marker'ını ve review kaydını zorunlu tutar. Task 11.10'da aynı script `src/storage/provider.rs` içindeki trait adlarını (`put`, `get`, `prove`, `challenge`, `settle`) spec ile eşleştirecek şekilde genişletilir.

## 1. Mevcut Kod Haritası

| Bileşen | Dosya | Durum | Görev |
|---------|-------|-------|-----|
| ContentId (32-byte hash) | `src/storage/content_id.rs` | ✅ | Görev 2 |
| ContentManifest (shard list + owner) | `src/storage/manifest.rs` | ✅ | Görev 2 |
| StorageDomainParams | `src/domain/storage_params.rs` | ✅ | Görev 1 |
| StorageDeal + DealStatus | `src/domain/storage_deal.rs` | ✅ | Görev 5 |
| RetrievalChallenge/Response/Outcome | `src/domain/storage_deal.rs` | ✅ interim | Görev 5 |
| StorageRegistry (permissionless) | `src/domain/storage_deal.rs` | ✅ | Görev 5 |
| StorageEconomicsParams | `src/domain/storage_deal.rs` | ✅ | Görev 5 |
| Storage RPC uçları | `src/rpc/api.rs` + `server.rs` | ✅ | Görev 5 |
| MerkleTrie (state tree) | `src/storage/merkle_trie.rs` | ✅ 256-bit | Görev 4 |
| Storage pruning | `src/chain/blockchain.rs` | ✅ kısmi | Görev 5 |
| VerifyMerkle | `budzero/bud-vm` / `budzero/bud-proof` | 🔒 production-gated | Görev 3 |
| Real Proof-of-Storage | — | ❌ | Görev 3 |
| DataAsset/AccessGrant | `src/pollen/` | 🟡 gelişiyor | Marketplace |
| BNS .bud | `src/bns/registry.rs` | ✅ iskelet | Görev 6 |

## 2. Görev Haritası (Vision → Kod)

### Görev 1 — Domain Kaydı (✅ Tamam)

`ConsensusKind::StorageAttestation(StorageDomainParams)` ve permissionless `STORAGE_OPERATOR` rolü.

### Görev 2 — Content Addressing (✅ Tamam)

`ContentId`, `ContentManifest`, `ShardRef`; parçalama off-chain, zincir manifest commitment tutar.

### Görev 3 — Proof-of-Storage (🔒 Production-gated)

Mevcut `RetrievalChallenge` interim byte-range mekanizmasıdır; gerçek PoS iddiası yapılmaz. VerifyMerkle production gate açılmadan slashing yalnız deadline/response discipline için kullanılabilir. V111 sınıfı 64-bit/256-bit path uyumsuzluğu çözülmeden "full cryptographic PoS" etiketi yasaktır.

### Görev 4 — Block Header Integration (🟡 Kısmi)

`GlobalBlockHeader.storage_root` ve storage commitment header binding'i Task 11.10/sonrası uygulanır. State root kapsamı spec-review gate ile izlenir.

### Görev 5 — Deal/Challenge Ekonomisi (✅ Temel Tamam)

`StorageDeal`, `RetrievalChallenge`, `ChallengeResult`, permissionless `open_deal/open_challenge`. Whitelist/admin/pause hook'u yoktur.

### Görev 6 — BNS .bud Integration (✅ İskelet)

`BnsRegistry` name → address/content resolution; storage content binding ileride AccessGrant/HPKE ile birleşir.

## 3. Gap Analizi (Vision ↔ Kod)

| Vision Özelliği | Kod Durumu | Gap |
|-----------------|------------|-----|
| Content addressing | ✅ ContentId + Manifest | — |
| Sharding | ✅ ShardRef | off-chain delivery spec gerekli |
| Deal marketplace | ✅ StorageDeal + RPC | Pollen payment/signature atomikliği ayrı |
| Proof-of-Storage | 🔒 Interim | VerifyMerkle + path model |
| Slashing | ✅ missed challenge | mismatched proof semantics sınırlı |
| Pruning | ✅ kısmi | Full/archive split Task 11.10 |
| Storage root in header | ❌ | Header binding |
| Retrieval | ❌ | Off-chain, bu spec dışı |
| Encryption | ❌ | Pollen/HPKE görevı |
| Multi-replica deals | ✅ deals_for_manifest | replica quorum policy ileride |

## 4. Veri Egemenliği Kuralı

Hiçbir kritik fonksiyon Budlum ekibinin servisine bağımlı değildir. `open_deal`, `open_challenge` permissionless; `answer_challenge` yalnız deal operator; whitelist/admin/pause hook'u yoktur. Bu kural CLAUDE.md permissionless ilkesiyle uyumludur.

## 5. Node Sınıflandırmasıyla Etkileşim

ADR-003 uyarınca full node pruning default, archive node full history tutar. Storage proof/challenge kanıtı için finalized checkpoint snapshot'ları full node'da da korunur. Task 11.10 pruning implementasyonu finalized storage commitments'ı silemez.

## 6. Kabul Kriterleri (Task 11.10)

1. `StorageProvider` trait + mock impl derlenir.
2. Deal lifecycle geçersiz geçişleri reddeder.
3. Full node eski pruned state'e erişimi reddeder; archive erişir.
4. Snapshot restore finalized checkpoint'ten başlar.
5. Spec-coverage gate trait imzalarını kontrol eder.
6. Fuzz target proof/challenge input'larında panic üretmez.

## 7. Sıradaki Adımlar

1. VerifyMerkle gate politikası (ARENA3/budzero) ve V111 path uyumu.
2. `src/storage/provider.rs` trait implementation.
3. `GlobalBlockHeader.storage_root` binding.
4. HPKE/AccessGrant hard-enforcement.
5. Operator churn/grace-period politikası.

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
