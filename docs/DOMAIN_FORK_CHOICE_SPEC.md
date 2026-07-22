# Domain Fork-Choice & Lifecycle Spec

> **Yazar:** ARENA1, 2026-07-20.
> **Durum:** Final v1 (Task 11.6) → implementasyon Task 11.8.
> **ADR:** [ADR-007](adr/ADR-007-per-domain-fork-choice.md)
> **SPEC_REVIEW:** [DOMAIN_FORK_CHOICE_SPEC_REVIEW.md](spec-review/DOMAIN_FORK_CHOICE_SPEC_REVIEW.md)
> **INTERFACE_FROZEN:** true

---

## 0. Interface Freeze (Task 11.6)

Bu spec Task 11.6 sonunda **interface-frozen** kabul edilir. Task 11.8 implementasyonu aşağıdaki trait imzasını, domain kural adlarını ve lifecycle state'lerini değiştiremez; değişiklik gerekiyorsa yeni ADR açılır.

### 0.1 Donmuş trait imzası

```rust
pub struct ForkCandidate {
    pub domain_id: u64,
    pub head_hash: Hash32,
    pub parent_hash: Hash32,
    pub height: u64,
    pub cumulative_work: Option<u128>,
    pub justified_checkpoint: Option<Hash32>,
    pub finalized_checkpoint: Option<Hash32>,
    pub proposer: Option<Address>,
    pub votes: Vec<DomainVote>,
    pub qc: Option<QcBlob>,
}

pub struct ResolvedHead {
    pub domain_id: u64,
    pub head_hash: Hash32,
    pub height: u64,
    pub finality: DomainFinalityStatus,
    pub reason: ForkChoiceReason,
}

pub trait ConsensusDomainForkChoice {
    fn fork_choice(&self, candidates: &[ForkCandidate]) -> Result<ResolvedHead, ForkChoiceError>;
}
```

`fork_choice` saf/deterministik olmalıdır; network/RPC çağrısı yapamaz ve state mutate edemez. Tie-breaker her domain için explicit olmalıdır.

### 0.2 Domain lifecycle state'leri

```rust
pub enum DomainLifecycleStatus {
    Proposed,
    Active,
    Paused,
    Draining,
    Retired,
}
```

`Active → Paused → Active`, `Active → Draining → Retired` izinli geçişlerdir. `Retired` terminaldir.

## 1. Fork-Choice Kuralları (Domain-Özel)

### 1.1 PoW Domain — Longest/Most-Work Chain

- **Kural:** En yüksek cumulative work canonical head olur.
- **Tie-breaker:** eşit work halinde lexicographically lowest `head_hash` (deterministik).
- **Reorg:** `MAX_REORG_DEPTH = 100` sınırı; finalized checkpoint sonrası reorg yasak.
- **Finality:** probabilistic (k-deep confirmations) + global finalized checkpoint.
- **Test matrisi:** shallow reorg kabul, deep reorg red, equal-work tie deterministic.

### 1.2 PoS Domain — LMD-GHOST + Finality Checkpoint

- **Kural:** non-finalized adaylar arasında latest-message-driven GHOST; validatorların son oyları stake-weighted olarak uygulanır.
- **Finality:** BLS12-381 quorum cert ile finalized checkpoint immutable.
- **Reorg:** finalized checkpoint'i geriye alan aday red.
- **Tie-breaker:** equal vote weight halinde justified checkpoint yüksekliği, sonra lowest `head_hash`.
- **Test matrisi:** nothing-at-stake double-vote evidence, long-range checkpoint red, stale vote ignored.

### 1.3 BFT Domain — Instant Finality

- **Kural:** geçerli QC / aggregated signature taşıyan candidate finalized head olur.
- **Equivocation:** aynı height'ta iki geçerli QC varsa fault proof açılır; slash/finality invalidation hardening protokolüne göre işlenir.
- **Tie-breaker:** iki geçerli QC eşdeğer olamaz; varsa `ForkChoiceError::ConflictingFinality`.
- **Test matrisi:** valid QC accept, malformed QC reject, conflicting QC evidence.

### 1.4 PoA Domain — Round-Robin Authority

- **Kural:** authority set sıralı round-robin leader schedule izler; slot leader dışındaki proposer ancak explicit skip/timeout evidence ile kabul edilir.
- **Finality:** authority set'in 2/3+ imzası instant finality sağlar.
- **İzolasyon:** PoA membership registry permissionless registry'den ayrı kalır; PoA KYC/approval kuralları PoW/PoS/BFT'ye sızamaz.
- **Tie-breaker:** aynı slotta iki valid block varsa authority equivocation evidence.
- **Test matrisi:** leader đúng block kabul, leader skip with timeout kabul, unauthorized signer red, permissionless registry sızma red.

## 2. Cross-Domain Settlement

- Tüm domain'ler `GlobalBlockHeader` üzerinden settle edilir.
- Her domain finality proof'u `DomainFinalityAdapter` ile doğrulanır.
- Cross-domain mesajlar `CrossDomainMessage` + nonce/replay protection + expiry/verify_id sertleştirmesiyle işlenir.
- Domain fork-choice kararı global settlement'a sadece finalized/accepted head olarak yansır; domain içi fork ayrıntıları global state'i doğrudan mutate edemez.

## 3. Domain Lifecycle

### 3.1 Start

- `bootstrap_domains` config veya governance proposal ile `Proposed` domain kaydı açılır.
- Genesis domain'leri ceremony sırasında `Active` başlar.
- Yeni domain activation için spec + finality adapter + fork-choice impl review zorunludur.

### 3.2 Pause

- Governance proposal + timelock ile `Active → Paused`.
- Paused domain yeni cross-domain mesaj üretemez; pending settlement/read-only query devam eder.
- PoA pause yetkisi yalnız PoA domain içindir; permissionless domain'e PoA admin freeze sızamaz.

### 3.3 Drain / Retire

- `Active → Draining`: yeni deal/message kapalı, mevcut in-flight akışlar settle edilir.
- `Draining → Retired`: pending message/deal yoksa terminal.
- Retired domain yeniden Active yapılamaz; yeni domain ID gerekir.

### 3.4 Upgrade

- Parametre upgrade proposal-driven ve timelock'ludur.
- Fork-choice algoritması değişikliği konsensüs-kritik kabul edilir; yeni ADR + spec-review + migration planı gerekir.
- Aktif deal/bridge mesajı olan domain'lerde upgrade safety window uygulanır.

## 4. Gap Analizi

| Gap | Risk | Task |
|-----|------|-------|
| `ConsensusDomainForkChoice` trait kodda yok | domain-specific fork-choice dağınık kalır | 11.8 |
| PoS LMD-GHOST implementation yok | PoS fork-choice finality-only kalabilir | 11.8 |
| PoA pure round-robin schedule kodu net değil | authority scheduling drift | 11.8/11.18 |
| Domain pause/drain/retire module yok | aktif domain durdurma fon kilidi yaratabilir | 11.8 |
| Cross-domain finality conflict policy sınırlı | conflicting heads settlement riski | 11.8 |

## 5. Kabul Kriterleri (Task 11.8)

1. Her domain impl'i `fork_choice()` methodunu sağlar.
2. PoW reorg, PoS nothing-at-stake/long-range, BFT conflicting QC, PoA leader-skip testleri isim-kilitli olur.
3. Lifecycle geçişleri illegal transition'ları reddeder.
4. Domain pause PoA/permissionless izolasyonunu bozmaz.
5. Fork-choice fuzz target 60s CI quick gate içinde çalışır.

## 6. CI Kapısı

Task 11.6 spec kapısı: `scripts/check-spec-coverage.sh` bu dosyada `INTERFACE_FROZEN: true` marker'ını ve review kaydını zorunlu tutar. Task 11.8 kod kapısı: fork-choice fuzz + domain lifecycle invariant testleri.

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
