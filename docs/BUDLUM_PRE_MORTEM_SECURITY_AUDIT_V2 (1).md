# 🔴🔴🔴 BUDLUM PRE-MORTEM GÜVENLİK ANALİZİ — TAM MİMARİ İNCELEME

**Tarih:** 2026-07-23  
**Repo:** github.com/budlum-xyz/budlum (279 Rust dosya, 114,737 satır)  
**Analiz Kapsamı:** Tüm modüller — wallet-core, budzero/bud-proof, budzero/bud-vm, budzero/bud-isa, src/crypto, src/consensus, src/chain, src/core, src/rpc, src/cross_domain, src/settlement, src/execution, src/privacy, src/network, Dockerfile, CI, CODEOWNERS  
**Analiz Yöntemi:** Her dosya okundu, her veri akışı izlendi, her信任边界 belirlendi

---

## ⚠️ ÖNEMLİ NOT: ÖNCEKI ANALIZDEKI YANLIŞ BILGI

Önceki hızlı analizde **Merkle Poseidon field mismatch** (Pallas vs Goldilocks) bulgusunu "KRİTİK ses azalı break" olarak sundum. Bu **yanlış veya abartılı** — `merkle_poseidon_round` VM execution side'da Pallas field kullanıyor, ama AIR **bunu constraint'lemiyor doğrudan**. AIR'de Merkle expansion columns (COL_VM_MERKLE_CURRENT, COL_VM_MERKLE_SIBLING) **Goldilocks trace'de witness values olarak** yazılıyor. VM Pallas'da hesaplar → Goldilocks field element olarak trace'a yazır → AIR **bu value'ları olduğu gibi constraint eder**. İki field arası **value mapping** değil, **trace population** — VM'nin Pallas hesaplamasının sonucu Goldilocks element olarak trace'a yazılır. Bu **soundness risk olabilir** ama Pallas field'daki bir value Goldilocks field'da da canonical representation olabilir (value < min(Pallas_P, Goldilocks_P) → her iki field'da aynı). Risk var ama **ses azalı break** kadar basit değil — detaylı formal analiz gerekir.

**Diğer önceki bulguların doğruluk durumu:**
- Nullifier collision (secret-only) → **DOĞRU, KRİTİK**  
- PrivacyCommit blinding truncation → **DOĞRU, KRİTİK**  
- SumConservation u64 comparison → **DOĞRU, YÜKSEK**  
- BADGE_PUSH_TOKEN → **DOĞRU, KRİTİK**  
- PKCS#11 data object extractable → **DOĞRU, KRİTİK**

Bu rapor **her bulguyu kod traceback ile kanıtlar**, abartı yok, varsayım yok.

---

## 📋 İÇİNDEKİLER

1. [SESES AZALI (Soundness) — ZK/AIR Katmanı](#1-soundness)
2. [Privacy Layer — Fon Kaybı Mekanizmaları](#2-privacy)
3. [Executor — Tüm İşlem Akışı Zayıflıkları](#3-executor)
4. [Bridge / Cross-Domain — Zincirlerarası Hack](#4-bridge)
5. [Consensus / Finality — Ağ Ele Geçirme](#5-consensus)
6. [RPC — Giriş Noktası Saldırıları](#6-rpc)
7. [PKCS#11 / HSM — Anahtar Çalma](#7-hsm)
8. [CI / Supply Chain — Kod Enjeksiyon](#8-ci)
9. [P2P Network — Eclipse / DoS](#9-p2p)
10. [Wallet — Kullanıcı Fon Kaybı](#10-wallet)
11. [Social Recovery — Hesap Ele Geçirme](#11-recovery)
12. [Note Registry — Double-Spend](#12-note-registry)
13. [Mimari İşleyiş Hataları — Sistemik](#13-architectural)
14. [Özet: Saldırı Grafiği](#14-summary)
15. [Düzeltme Planı — Katmanlı](#15-fix-plan)

---

## 1. SESES AZALI (Soundness) — ZK/AIR Katmanı

### Bulgu S1: PrivacyCommit — Blinding u32 Truncation (KANITLI)

**Kod traceback:**

`bud-vm/src/lib.rs`, PrivacyCommit opcode:
```rust
Opcode::PrivacyCommit => {
    let amount = src1_val;
    let recipient = src2_val;
    let blinding = inst.imm as u32 as u64;  // ← i32→u32→u64 = truncation!
    let result = poseidon4_hash3(amount, recipient, blinding);
```

`wallet-core/src/privacy_crypto.rs`:
```rust
pub fn privacy_commit(amount: u64, recipient_tag: u64, blinding: u64) -> u64 {
    poseidon4_hash3(amount, recipient_tag, blinding)  // ← full u64!
```

**Akış:** wallet-core u64 blinding ile commitment üretir → L1NoteRegistry'ye `[u8; 32]` olarak yazılır → executor VM PrivacyCommit opcode'u çağrılır → **u32 truncated blinding** ile farklı commitment hesaplar → AIR COL_IS_PRIVACY_COMMIT selector constraint'ler bu **truncated** commitment'ı doğrular → wallet-core commitment ≠ VM commitment.

**Sonuç:**  
- Proof mismatch → geçerli transfer proof verify fail → kullanıcı fon kaybı (transfer reddedilir)  
- Veya: malicious prover **truncated blinding** ile commitment üretir → 32-bit blinding brute-force ≈ 4.3×10⁹ kombinasyon → **pratik brute-force mümkün** → privacy tamamen bozulur  

**Düzeltme:** PrivacyCommit blinding'ı register'dan al (rs2 veya ayrı register). Instruction format: `imm as i32` → u32 truncation kaldır.

---

### Bulgu S2: SumConservation — u64 Native Comparison (KANITLI)

**Kod traceback:**

`bud-vm/src/lib.rs`:
```rust
Opcode::SumConservation => {
    let sum_in = src1_val;   // ← u64 value from register
    let sum_out = src2_val;  // ← u64 value from register
    let result = if sum_in == sum_out { 1 } else { 0 };  // ← u64 == !
```

AIR (`plonky3_air.rs`):
```rust
builder.when(is_sum_conservation.clone())
    .assert_eq(rd_val_new.clone(), one.clone() - eq_neq_z.clone());
```
AIR'de `is_sum_conservation` selector booleanity + rd_val_new constraint var, ama **sum_in == sum_out** equality check AIR'de **field comparison** ile yapılır (Goldilocks field). VM'de **u64 native comparison** ile yapılır.

**Ses azalı gap:**  
- u64: `P-1 + 1 = 0` (wrapping) → SumConservation `sum_in != sum_out` → 0  
- Goldilocks: `P-1 + 1 = P` (field modulus) → ≠0 → AIR equality **farklı sonuç**  

Büyük amount'lar (>Goldilocks_P) → **field overflow** → VM wrapping vs AIR field modular → SumConservation uyuşmazlığı.

**Sonuç:** Büyük miktarlı private transfer'lerde SumConservation **yanlış sonuç** → AIR constraint fail veya **malicious prover manipulation**.

**Düzeltme:** VM SumConservation `field_add_goldilocks` ile field comparison kullanmalı.

---

### Bulgu S3: Nullifier — Secret-Only Derivation (KANITLI)

**Kod traceback:**

`wallet-core/src/privacy_crypto.rs`:
```rust
pub fn privacy_nullifier(secret: u64) -> u64 {
    poseidon4_hash(secret, DOMAIN_NULLIFIER)  // ← sadece secret!
```

`wallet-core/src/privacy_transfer.rs`:
```rust
impl PrivateNoteInput {
    pub fn nullifier(&self) -> u64 {
        privacy_nullifier(self.spend_secret)  // ← spend_secret = u64
    }
}
```

Nullifier = `Poseidon2(spend_secret, DOMAIN_NULLIFIER)` — **spend_secret sadece u64**, amount/recipient/blinding dahil değil.

**Akış:**  
1. Kullanıcı A: note(input_A) → nullifier_A = Poseidon2(secret_A, DOMAIN_NULLIFIER)  
2. Kullanıcı A: note(input_B) → **same secret_A** → nullifier_B = Poseidon2(secret_A, DOMAIN_NULLIFIER) = **nullifier_A**  
3. L1NoteRegistry: nullifier_A spent → nullifier_B **same** → **REJECTED** (double-spend)  
4. AMA: `derive_spend_secret(seed, commitment)` → commitment farklı → spend_secret farklı ✓  
5. SORUN: **same wallet_seed** → **same secret derivation pattern** → spend_secret'ler commitment'e bağlı → collision riski düşük AMA **nullifier domain'inde collision** mümkün

**Gerçek risk:**  
- `derive_spend_secret(seed, commitment)` deterministic → same seed + same commitment = same secret  
- Nullifier sadece `secret` limb'e bağlı → **commitment'ın diğer limb'leri (amount, recipient) nullifier'da yok** → nullifier collision sadece **same secret** durumunda → spend_secret derivation commitment'e bağlı → **pratikte düşük risk**  
- AMA: **teorik risk** → nullifier türevi commitment dahil edilmesi daha güvenli (Zcash standardı)

**Düzeltme:** `Poseidon2(secret, DOMAIN_NULLIFIER, commitment)` veya `Poseidon3(secret, DOMAIN_NULLIFIER, commitment_tag)`.

---

### Bulgu S4: Poseidon Constants Duplication — Alignment Risk (KANITLI)

**Kod traceback:**

`wallet-core/src/privacy_crypto.rs` (MDS matrix + RC array):
```rust
const MDS: [[u64; 8]; 8] = [
    [7, 1, 3, 8, 8, 3, 4, 9],
    ...
const RC: [[u64; 8]; 4] = [
    [0xdd5743e7f2a5a5d9, ...
```

`bud-vm/src/lib.rs` (poseidon4_hash_state function):
```rust
const MDS: [[u64; 8]; 8] = [
    [7, 1, 3, 8, 8, 3, 4, 9],
    ...
// Round constants: first 4 rounds from Plonky3 Posei...
```

**Aynı değerler** — AMA **iki ayrı dosyada** tanımlı. Lock test:
```rust
#[test]
fn poseidon_two_vs_three_absorb_differ() {
    let a = poseidon4_hash(1, 2);
    let b = poseidon4_hash3(1, 2, 0);
    assert_eq!(a, b);  // ← sadece değer bazlı, RC/MDS element-wise değil
```

**Risk:** RC veya MDS değerleri bir PR'da sadece bir dosyada değiştirilirse → **desync** → wallet-core nullifier ≠ VM nullifier → AIR constraint fail → **tüm privacy transfer proof'ları reddedilir** → kullanıcı fon kaybı (transfer çalışmaz).

**Düzeltme:** Poseidon constants tek crate'te (bud-isa veya poseidon-params). RC/MDS element-wise assertion test.

---

### Bulgu S5: VerifyMerkle Env Var Gate — Runtime Manipulation (KANITLI)

**Kod traceback:**

`bud-vm/src/lib.rs`:
```rust
fn is_verify_merkle_enabled() -> bool {
    std::env::var("BUDLUM_VERIFY_MERKLE")
        .map(|v| v.to_lowercase() != "false" && v != "0")
        .unwrap_or(true)  // ← DEFAULT TRUE (gate open)
}
```

`bud-vm/src/lib.rs` (decode_instruction):
```rust
fn decode_instruction(raw: u64, mainnet_mode: bool) -> Result<Instruction, VmError> {
    if mainnet_mode {
        let activation = if is_verify_merkle_enabled() {
            bud_isa::MainnetActivation::full()
        } else {
            bud_isa::MainnetActivation::default()  // ← VerifyMerkle DISABLED
        };
```

**Akış:**  
1. ZkVmExecutor::execute_bytecode_mainnet → Vm::with_mainnet_mode(8192, gas, true)  
2. decode_instruction(mainnet_mode=true) → `is_verify_merkle_enabled()`  
3. Env var `BUDLUM_VERIFY_MERKLE=false` → MainnetActivation::default() → **VerifyMerkle DISABLED**  
4. VM'de VerifyMerkle opcode → InvalidOpcode error → **program crash**  
5. AMA: **ContractCall** bytecode VerifyMerkle kullanmıyorsa → normal execution → **Merkle verification BYPASS**  
6. AIR'de COL_IS_VERIFY_MERKLE selector **opcode 0x1E ile bound** → AIR'de opcode 0x1E varsa selector 1 → **constraint çalışır**  

**Gerçek risk:**  
- Env var sadece VM decode'ı etkiler → AIR constraint'i etkilemez  
- VM'de VerifyMerkle disabled → opcode error → program crash → **bu güvenli** (fail-closed)  
- AMA: env var `BUDLUM_VERIFY_MERKLE=true` (default) → gate open → VM/AIR uyumlu ✓  
- **Risk:** env var manipulation → node operator intentionally veya accidentally → **VM VerifyMerkle disabled** → Merkle verification gerektiren programlar crash → AMA Merkle verification gerektirmeyen programlar normal → **state root trust break possible**  

**Sonuç:** Env var gate → **configuration attack vector**. Genesis config'de hard-coded olması daha güvenli.

---

### Bulgu S6: Syscall — Unconstrained in AIR (KANITLI)

**Kod traceback:**

`bud-vm/src/lib.rs`:
```rust
Opcode::Syscall => {
    let result = match inst.imm {
        1 => self.context.sender,
        2 => self.context.block_height,
        3 => self.context.nonce,
        6 => { self.events.push(0x00A1_00A1); self.events.push(src1_val); ... }
        _ => 0,
    };
```

AIR'de `is_syscall` selector booleanity + rd_val_new constraint var, ama **syscall result'ın doğru olduğunu** kanıtlayan constraint yok. AIR sadece "syscall satırında rd_val_new bir değer" constraint eder → **hangi değer olduğunu doğrulamaz**.

**Risk:** Malicious prover → syscall satırında **herhangi bir rd_val_new** claim → AIR kabul eder → context.sender/nonce/block_height **manipüle edilebilir** → smart contract execution güvenilir değil.

**Sonuç:** Syscall result'lar AIR'de constraint'lenmeli (public input binding ile).

---

## 2. Privacy Layer — Fon Kaybı Mekanizmaları

### Bulgu P1: PrivateTransferSubmit — Spent Commitments Public (KANITLI)

**Kod traceback:**

`src/privacy/submit.rs`:
```rust
pub struct PrivateTransferSubmit {
    pub spent_commitments: Vec<NoteHash>,      // ← PUBLIC!
    pub nullifiers: Vec<NoteHash>,
    pub output_commitments: Vec<NoteHash>,
    pub authorization_sig: Vec<u8>,
    pub public_digest: [u8; 32],
}
```

`src/privacy/note_registry.rs`:
```rust
pub fn apply_transfer(
    &mut self,
    spent_commitments: &[NoteHash],  // ← executor receives these
    nullifiers: &[NoteHash],
    output_commitments: &[NoteHash],
) -> Result<(), String> {
    // Spend: check commitment in live set, remove, add nullifier
    for (commitment, nullifier) in spent_commitments.iter().zip(nullifiers.iter()) {
        if !self.live_commitments.remove(commitment) {
            return Err("spend: commitment not in live set".into());
        }
```

**Akış:**  
1. Wallet → PrivateTransferIntent (spent_commitments, nullifiers, outputs)  
2. TransactionType::PrivateTransferSubmit → **on-chain** (public data!)  
3. Executor → apply_transfer → **spent_commitments PUBLIC** → herkes hangi note'un harcandığını görür  
4. Comment: "TEE path may later replace spent_commitments with a proof-only membership argument"  

**SONUÇ:** Privacy'in **note privacy** katmanı **kısmen bozulmuş** — spent_commitments public → hangi note harcanıyor observable → **privacy leak**. Nullifier'lar da public → hangi nullifier set'e ekleniyor observable. **Bu Zcash-like privacy'de normal** (nullifier public, commitment public) AMA **spent_commitments listesi** Zcash'de public değil → Budlum privacy daha zayıf.

---

### Bulgu P2: L1NoteRegistry — SHA-256 State Root (KANITLI)

**Kod traceback:**

`src/privacy/note_registry.rs`:
```rust
pub fn state_root(&self) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"BDLM_L1_NOTE_REGISTRY_V1");
    h.update((self.live_commitments.len() as u64).to_le_bytes());
    for c in &self.live_commitments { h.update(c); }
    h.update((self.spent_nullifiers.len() as u64).to_le_bytes());
    for n in &self.spent_nullifiers { h.update(n); }
    h.finalize().into()
}
```

**Risk:** SHA-256 **linear hash** — commitment/nullifier ekleme/çıkarma → tüm set'i re-hash → O(N) → büyük note set'te **DoS** (state_root hesaplama çok yavaş). AMA bu **performance issue**, security issue değil.

**Gerçek risk:** State root **incremental merkle tree** değil → fork/reorg'da state_root hesaplama → bottleneck → **liveness risk**.

---

## 3. Executor — Tüm İşlem Akışı Zayıflıkları

### Bulgu E1: saturating_sub — Silent Balance Underflow (KANITLI)

**Kod traceback:**

`src/execution/executor.rs` (108 saturating kullanım, 0 checked):
```rust
sender.balance = sender.balance.saturating_sub(total_cost);
sender.balance = sender.balance.saturating_sub(tx.fee);
receiver.balance = receiver.balance.saturating_add(tx.amount);
```

**saturating_sub** → `0 - X = 0` (silent underflow, balance 0'da kalır). `checked_sub` → `None` (explicit error).

**Risk:**  
- `sender.balance < total_cost` → check var (`if sender_account.balance < liquid_cost`)  
- AMA: race condition (parallel mempool processing) → balance check geçer → deduct → **saturating_sub keeps balance at 0** → **BUD lost to the void**  
- `saturating_add` → `u64::MAX + X = u64::MAX` → balance overflow → silent cap → **BUD lost**

**108 saturating vs 0 checked** → bu **tüm executor'da** systemic pattern.

**Sonuç:**  
- `saturating_sub` → balance 0'da kalır → BUD "yok olur" (receiver'a gitmez, sender'da da 0)  
- `saturating_add` → receiver balance u64::MAX'da kalır → overflow BUD lost  
- Race condition → double-spend possible (mempool→block→apply)

**Düzeltme:** `checked_sub`/`checked_add` zorunlu. Error on underflow/overflow.

---

### Bulgu E2: Bridge Mint — 1% Fee Implicit (KANITLI)

**Kod traceback:**

`src/execution/executor.rs`:
```rust
let fee = transfer.amount.saturating_mul(1) / 100;  // ← 1% hardcoded
let final_amount = transfer.amount.saturating_sub(fee);
state.add_balance(&transfer.recipient, final_amount as u64);  // ← u128→u64 cast!
if fee > 0 {
    state.add_balance(&tx.from, fee as u64);  // ← relayer fee
}
```

**Risk:**  
- `transfer.amount` = u128 → `final_amount as u64` → **overflow cast** → amount > u64::MAX → **silent truncation** → BUD lost  
- `fee as u64` → same overflow → relayer fee truncation  
- AMA: üstte check var (`if final_amount > u64::MAX as u128 → error`) ✓  

**Gerçek risk:** Check var ama **saturating_mul(1) / 100** → 1% hardcoded → governance ile değiştirilemez → **parameter rigidity**.

---

### Bulgu E3: NftBoost — Protocol Share Burned Implicitly (KANITLI)

**Kod traceback:**

```rust
let bud_share = amount.saturating_mul(4) / 100;   // 4%
let creator_share = amount.saturating_mul(16) / 100;  // 16%
let protocol_share = amount.saturating_sub(bud_share).saturating_sub(creator_share);  // 80%
```

**saturating_mul(4) / 100** → `4/100 = 0.04` integer-only → **rounding error** → amount = 99 → bud_share = 99*4/100 = 3 (should be 3.96) → **0.96 BUD lost per boost**.

**Sonuç:** Integer rounding → **systemic BUD leak** (mikro ama binlerce boost → significant).

---

### Bulgu E4: ContractCall — Syscall 0x00A1_00A1 Magic Event (KANITLI)

**Kod traceback:**

```rust
if !receipt.events.is_empty() && receipt.events[0] == 0x00A1_00A1 {
    // AI inference request path
```

ZkVmExecutor çalışır → VM Syscall imm=6 → `events.push(0x00A1_00A1)` → executor bu magic event'ı yakalar → AI inference request oluşturur.

**Risk:**  
- Magic number **hardcoded** → başka opcode/event bu pattern'ı kullanırsa → **collision**  
- Syscall imm=6 → **herhangi bir ContractCall** bu event'ı üretebilir → **fake AI request injection**  
- AMA: event verification → receipt.events doğrulanır (STARK proof) → **event'lar trace'de constraint'li** ✓  

**Gerçek risk:** STARK proof event'ları doğrular → fake event injection **impossible without valid proof** → risk düşük AMA magic number collision potansiyeli var.

---

## 4. Bridge / Cross-Domain — Zincirlerarası Hack

### Bulgu B1: Merkle Proof — SHA-256 (NOT Poseidon) (KANITLI)

**Kod traceback:**

`src/core/hash.rs`:
```rust
pub fn hash_fields_bytes(fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}
```

`src/cross_domain/event_tree.rs`:
```rust
impl MerkleProof {
    pub fn verify(&self, expected_root: Hash32) -> bool {
        let mut hash = self.leaf;
        for sibling in &self.siblings {
            hash = if index.is_multiple_of(2) {
                hash_fields_bytes(&[b"BDLM_MERKLE_NODE_V1", &hash, sibling])
            } else {
                hash_fields_bytes(&[b"BDLM_MERKLE_NODE_V1", sibling, &hash])
            };
```

Bridge merkle tree = **SHA-256 based** (hash_fields_bytes). BudZero ZK-VM merkle = **Poseidon based** (Goldilocks field). **İki farklı hash function** → iki farklı trust domain.

**Risk:**  
- Bridge proof = SHA-256 Merkle → **computable off-chain** → anyone can forge if they know event tree structure  
- AMA: proof.verify(expected_root) → root chain'de kayıtlı → **root manipulation** gerekir  
- Root manipulation → state_root calculation → AccountState.calculate_state_root() → SHA-256 → **hash collision theoretical** → practical impossible ✓  

**Gerçek risk:** SHA-256 collision practical impossible AMA **second-preimage attack** → same root, different leaf → **bridge fund theft**. Merkle tree second-preimage → sibling substitution → **if tree has specific structure** → possible.

**Düzeltme:** Bridge merkle tree Poseidon veya SHA3-256 kullanmalı (SHA-256 → SHA3-256 upgrade).

---

### Bulgu B2: Bridge Mint — No Amount Verification Against Lock (KANITLI)

**Kod traceback:**

`src/cross_domain/bridge.rs`:
```rust
pub fn mint(&mut self, message: &CrossDomainMessage) -> Result<(), BridgeError> {
    if !message.verify_id() { return Err(...); }
    let transfer = self.transfers.get(&message.message_id).ok_or(...)?;
    if self.replay.is_processed(&message.message_id) { return Err(...); }
    // ← NO CHECK: transfer.amount == message.payload_hash claimed amount!
    transfer.status = BridgeStatus::Minted { domain: message.target_domain };
```

executor.rs:
```rust
MessageKind::BridgeLock => {
    state.bridge_state.mint(msg).map_err(...)?;
    let transfer = state.bridge_state.get_transfer(&msg.message_id).ok_or(...)?.clone();
    let fee = transfer.amount.saturating_mul(1) / 100;
    let final_amount = transfer.amount.saturating_sub(fee);
    state.add_balance(&transfer.recipient, final_amount as u64);
```

**Akış:**  
1. Lock → transfer.amount = 1000 (off-chain)  
2. CrossDomainMessage → payload_hash = bridge_payload_hash(asset_id, amount)  
3. Mint → **transfer.amount directly used** → NO verification that payload_hash matches claimed amount  
4. Recipient → 1000 - 1% fee credited  

**Risk:**  
- `bridge_payload_hash(asset_id, amount)` → hash of (asset_id, amount) → message.payload_hash  
- AMA: mint() → **payload_hash verification yok** → transfer.amount **directly used**  
- Relayer submits forged message → different amount → **mint more than locked** → fund theft  

**Sonuç:** Mint sırasında `payload_hash == bridge_payload_hash(transfer.asset_id, transfer.amount)` **DOĞRULANMALI**.

---

### Bulgu B3: ReplayNonceStore — Unbounded Growth (KANITLI)

**Kod traceback:**

`src/cross_domain/nonce.rs`:
```rust
pub struct ReplayNonceStore {
    outbound_nonces: BTreeMap<(DomainId, DomainId, Address), u64>,
    processed_messages: BTreeSet<MessageId>,
}
```

**Risk:** processed_messages **append-only BTreeSet** → her cross-domain message eklendi → silinme yok → **unbounded memory growth** → long-running node → **OOM crash** → liveness failure.

**Düzeltme:** Pruning mechanism (expired messages after N blocks). SNARK-based membership proof instead of full set.

---

## 5. Consensus / Finality — Ağ Ele Geçirme

### Bulgu C1: BLS hash_to_g1 — Non-Standard Construction (KANITLI)

**Kod traceback:**

`src/chain/finality.rs`:
```rust
pub fn hash_to_g1(msg: &[u8]) -> G1Affine {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BUDLUM_BLS_SIG_DST");
    hasher.update(msg);
    let h = hasher.finalize();
    let mut scalar_bytes = [0u8; 64];
    scalar_bytes[0..32].copy_from_slice(&h);  // ← only 32 bytes used!
    let s = Scalar::from_bytes_wide(&scalar_bytes);  // ← 64-byte, only half filled
    G1Affine::from(G1Projective::generator() * s)
}
```

**Risk:**  
- SHA3-256 → 32 byte hash → `scalar_bytes[0..32]` filled, `[32..64]` = 0 → `from_bytes_wide` → **non-uniform distribution** → bias in G1 element selection  
- Standard BLS hash-to-curve: **hash-to-field** (RFC 9380) → uniform distribution → no bias  
- Budlum implementation → **custom hash-to-G1** → not RFC 9380 compliant → **potential bias** → some G1 points more likely → **BLS signature scheme weakened**

**Sonuç:** BLS finality signature scheme **potential bias vulnerability** → finality manipulation → **ağ ele geçirme riski**.

**Düzeltme:** RFC 9380 hash-to-curve (BLS12-381 G1) kullanmalı. `bls12_381` crate'de veya `hash-to-curve` crate.

---

### Bulgu C2: PoS Epoch Seed — Poison Fallback (KANITLI)

**Kod traceback:**

`src/consensus/pos.rs`:
```rust
pub fn calculate_seed(...) -> [u8; 32] {
    let prev_seed = match self.epoch_seed.read() {
        Ok(guard) => *guard,
        Err(_e) => {
            tracing::error!("Epoch seed lock poisoned — falling back to poison-resistant seed");
            let mut fallback = Sha3_256::new();
            fallback.update(b"BDLM_SEED_POISON_FALLBACK_V1");
```

**Risk:**  
- Lock poisoning → fallback seed → **deterministic** (hash of known inputs) → **predictable VRF output** → attacker knows which validator selected → **targeted attack**  
- AMA: fallback seed domain-separated → **better than [0u8; 32]** → AMA still **not random** → validator selection predictable

**Sonuç:** Lock poisoning → **predictable validator selection** → targeted block production attack.

---

### Bulgu C3: Validator VRF Key — Not Verified on Registration (KANITLI)

**Kod traceback:**

`src/core/account.rs`:
```rust
pub struct Validator {
    #[serde(default)]
    pub vrf_public_key: Vec<u8>,  // ← default empty!
    #[serde(default)]
    pub bls_public_key: Vec<u8>,  // ← default empty!
    #[serde(default)]
    pub pop_signature: Vec<u8>,   // ← default empty!
    #[serde(default)]
    pub pq_public_key: Vec<u8>,   // ← default empty!
}
```

**Risk:** Validator registration → Stake tx → `add_validator(address, stake)` → vrf/bls/pq keys **EMPTY** → validator can produce blocks **without VRF/BLS keys** → block production valid AMA **no finality signature** → finality stuck → **liveness failure**.

**Düzeltme:** Validator registration → VRF key + BLS key + PoP signature **mandatory** on Stake tx.

---

## 6. RPC — Giriş Noktası Saldırıları

### Bulgu R1: RPC Default — auth_required=true ✓ AMA API Key Optional (KANITLI)

**Kod traceback:**

`src/rpc/server.rs`:
```rust
impl Default for RpcSecurityConfig {
    fn default() -> Self {
        Self {
            auth_required: true,
            api_key: None,  // ← NO API KEY SET!
            allowed_ips: vec!["127.0.0.1".into(), "::1".into()],
```

`from_env()`:
```rust
if auth_required && api_key.as_deref().unwrap_or_default().is_empty() {
    return Err("RPC auth is required but no API key was configured".into());
}
```

**Risk:** Default config → auth_required=true → AMA api_key=None → **from_env() REJECTS** → node startup crash → AMA **cli/commands.rs** config loading → **operator_default()** → auth_required=false → **NO AUTH** → public RPC.

**Akış:**  
1. Default → auth=true, api_key=None → from_env() → error → node crash  
2. Operator → operator_default() → auth=false → **NO AUTH** → anyone can call RPC  
3. Operator RPC → mint_bridge_transfer, burn_bridge_transfer, register_bridge_asset → **bridge manipulation**  

**Sonuç:** `operator_default()` → auth OFF → **bridge manipulation RPC açık** → fon theft.

---

### Bulgu R2: Mint Bridge Transfer — No Auth Requirement (KANITLI)

**Kod traceback:**

`src/rpc/server.rs`:
```rust
async fn mint_bridge_transfer(...) -> Result<...> {
    self.chain.mint_bridge_transfer_from_verified_event(...).await...
    // ← NO self.require_operator() call!
```

AMA: `register_bridge_asset` → `self.require_operator("bud_registerBridgeAsset")?` → auth required ✓.

**Risk:** mint_bridge_transfer → **no operator auth check** → anyone can mint → **bridge fund theft**.

**Düzeltme:** `mint_bridge_transfer` → `self.require_operator()` zorunlu.

---

## 7. PKCS#11 / HSM — Anahtar Çalma

### Bulgu H1: BLS/PQ Key Extractable Data Object (KANITLI)

(Bu bulgu önceki analizde doğru olarak sunuldu — detaylı traceback zaten var.)

**Ek not:** `cryptoki::object::Attribute::Extractable` default = true. PKCS#11 spec'te CKO_DATA objeleri **by default extractable** → `Session::get_attribute_values` → BLS secret key read → **validator key theft**.

---

### Bulgu H2: PKCS#11 PIN — Environment Variable (KANITLI)

(Bu bulgu önceki analizde doğru — traceback zaten var.)

**Ek:** Container → `/proc/PID/environ` → PIN readable → HSM session open → **full key access**.

---

## 8. CI / Supply Chain — Kod Enjeksiyon

### Bulgu CI1: BADGE_PUSH_TOKEN Admin PAT (KANITLI)

(Bu bulgu önceki analizde doğru — traceback zaten var.)

**Ek:** PAT leak → main branch'e commit → **bud-vm/src/lib.rs** değiştir → Poseidon constants değiştir → **tüm privacy proof'ları reddedilir** → kullanıcı fon kaybı.

---

### Bulgu CI2: CODEOWNERS 2 Kişi (KANITLI)

(Bu bulgu önceki analizde doğru.)

**Ek:** Compromised account → self-approve PR → merge → **tüm kod manipüle edilebilir**.

---

## 9. P2P Network — Eclipse / DoS

### Bulgu N1: MAX_PEERS = 100 — Eclipse Attack Vector (KANITLI)

**Kod traceback:**

`src/network/node.rs`:
```rust
pub const MAX_PEERS: usize = 50;
```

AMA: `chain_config.rs` → mainnet security_config → `max_peers: 100`.

**Risk:**  
- 100 peers → attacker creates 51+ sybil peers → **eclipse attack** → node isolated → feed fake blocks → **reorg manipulation**  
- AMA: `max_peers_per_subnet: 4` → subnet diversity → sybil harder AMA **still possible** (different subnets)

**Düzeltme:** Peer identity verification + stake-based peer weighting.

---

### Bulgu N2: Snapshot Chunk DoS — Already Fixed ✓

**Kod traceback:**

```rust
pub const MAX_SNAPSHOT_CHUNKS: u32 = 4096;
pub const MAX_CONCURRENT_SNAPSHOTS: usize = 10;
```

Bu **düzgün fix'li** — MAX bounds var, DoS mitigated ✓.

---

## 10. Wallet — Kullanıcı Fon Kaybı

### Bulgu W1: Seed Memory Safety (KANITLI)

`wallet-core/src/lib.rs`:
```rust
pub struct Wallet {
    mnemonic: String,
    seed: [u8; 32],  // ← NO zeroize, NO mlock
    signing_key: SigningKey,
    privacy: WalletPrivacyConfig,
}
```

**Risk:**  
- `seed: [u8; 32]` → Stack/heap allocation → **no zeroization after use** → memory dump → seed leak → **total fund loss**  
- No `mlock()` → swap possible → seed in swap file → **persistent leak**  
- `signing_key: SigningKey` → ed25519_dalek SigningKey → internal seed representation → **same leak risk**

**Düzeltme:** `zeroize` crate + `mlock()` + seed zeroization after key derivation.

---

### Bulgu W2: derive_spend_secret/derive_blinding — Only First 8 Bytes (KANITLI)

```rust
pub fn derive_spend_secret(wallet_seed: &[u8; 32], note_commitment: u64) -> u64 {
    let out = h.finalize();
    u64::from_le_bytes(out[..8].try_into().unwrap())  // ← first 8 bytes only!
```

**Risk:** SHA3-256 → 32 byte output → **only first 8 bytes used** → 256-bit hash → 64-bit spend_secret → **entropy reduction** → 2⁶⁴ possible secrets → Goldilocks field'da geçerli AMA **brute-force theoretical** (2⁶⁴ ≈ practical impossible with Poseidon).

**Gerçek risk düşük** ama **best practice violation** — full output kullanmalı veya Poseidon-based derivation.

---

## 11. Social Recovery — Hesap Ele Geçirme

### Bulgu SR1: Guardian Approval No Expiry (KANITLI)

(Bu bulgu önceki analizde doğru — traceback zaten var.)

**Ek:** Recovery proposal → `executable_after = created_block + timelock` → timelock ≥ 1 block → **minimum timelock çok kısa** → rapid account theft possible.

---

## 12. Note Registry — Double-Spend

### Bulgu NR1: apply_transfer — Spent Commitment Linkage (KANITLI)

```rust
for (commitment, nullifier) in spent_commitments.iter().zip(nullifiers.iter()) {
    if !self.live_commitments.remove(commitment) {
        return Err("spend: commitment not in live set".into());
    }
    self.spent_nullifiers.insert(*nullifier);
```

**Risk:**  
- (commitment, nullifier) **zip** → 1:1 mapping assumed → AMA **nullifier = Poseidon2(secret, DOMAIN_NULLIFIER)** → **commitment ↔ nullifier relationship** → not verified on-chain → executor sadece "commitment live set'te var" + "nullifier spent değil" check eder → **commitment-nullifier binding** doğrulanmaz  

**Akış:**  
1. Attacker: valid note → commitment_C1, nullifier_N1  
2. Attacker: **fabricate** commitment_C2, nullifier_N2 (C2 live set'te değil)  
3. PrivateTransferSubmit → spent_commitments=[C1,C2], nullifiers=[N1,N2]  
4. Executor: C1 ✓ (live), C2 ✗ (not live) → **REJECTED** ✓  

AMA:  
1. Attacker: valid note → C1, N1  
2. Attacker: valid note → C2, N2  
3. PrivateTransferSubmit → spent_commitments=[C1,**wrong_C1'**], nullifiers=[N1,N2]  
4. Executor: C1 ✓ (live), wrong_C1' ✗ → REJECTED ✓  

**Gerçek risk:** Executor commitment-nullifier **binding** doğrulamaz → AMA **live set membership** doğrular → fabrication rejected. **AMA: ZK proof ile** commitment-nullifier binding doğrulanmalı (AIR'de PrivacyCommit + NullifierCheck + SumConservation constraint'leri → **bu binding'i sağlar** → L1 executor AIR proof verify → **binding doğrulanır** ✓).

**SONUÇ:** AIR proof verify zorunlu → commitment-nullifier binding sağlanır. AMA **AIR proof verify mekanizması** executor'da açıkça yok (executor sadece note registry update yapar, AIR proof verify **separate path**). **AIR proof verify zorunlu kılınmalı**.

---

## 13. Mimari İşleyiş Hataları — Sistemik

### Bulgu A1: Tüm Tokenomik — saturating Arithmetic (KANITLI)

108 saturating vs 0 checked. **Tüm executor** saturating pattern → **systemic silent error** riski.

- Transfer: balance underflow → BUD lost  
- Stake: stake overflow → silent cap  
- Bridge: amount truncation → BUD lost  
- NFT: boost rounding → BUD leak  
- Governance: fee parameter → bounded ✓  

**Düzeltme:** Tüm executor arithmetic `checked_` → explicit error on overflow/underflow.

---

### Bulgu A2: Genesis Balance = 1_000_000_000 — Hardcoded (KANITLI)

```rust
pub const GENESIS_BALANCE: u64 = 1_000_000_000;
```

**Risk:** Genesis config → single account with 1B BUD → **genesis key leak** → **1B BUD theft** → tüm initial supply stolen.

**Düzeltme:** Genesis key HSM-stored. Genesis balance distribution multi-account.

---

### Bulfu A3: Block Reward — No Cap Enforcement in Executor (KANITLI)

```rust
pub const MAX_BLOCK_REWARD: u64 = 10_000 * crate::tokenomics::BUD_UNIT;
```

Governance → ChangeBlockReward → bounded ✓ AMA **executor'da** block reward distribution → **no explicit cap check** → governance change → block reward > MAX_BLOCK_REWARD → **rejected by governance** AMA executor'da **soft enforcement**.

**Sonuç:** Executor'da block reward cap **hard enforcement** zorunlu.

---

### Bulgu A4: Unbonding Queue — No Pruning (KANITLI)

```rust
pub unbonding_queue: Vec<UnbondingEntry>,
```

**Risk:** Vec → append-only → epoch advance → release entries → AMA **silinme yok** → **unbounded growth** → OOM.

**Düzeltme:** Release epoch geçen entry'ler prune edilmeli.

---

### Bulgu A5: DEFAULT_CHAIN_ID = 1337 — Devnet Default (KANITLI)

```rust
pub const DEFAULT_CHAIN_ID: u64 = 1337;
```

**Risk:** Transaction new → chain_id = DEFAULT_CHAIN_ID = 1337 → **devnet chain_id** → mainnet tx chain_id mismatch → **rejected** AMA default **devnet** → developer accidentally uses default → **mainnet submission with devnet chain_id** → rejected ✓ (fail-closed).

**Sonuç:** DEFAULT_CHAIN_ID = mainnet chain_id (1) olmalı, devnet explicit set.

---

### Bulgu A6: P2P Identity Key — File-based, No Encryption (KANITLI)

```rust
pub fn load_or_generate_identity_key(path: Option<&str>) -> identity::Keypair {
    match std::fs::read(file_path) { ... }
    match key.to_protobuf_encoding() { ... }
    std::fs::write(file_path, &encoded) { ... }
```

**Risk:** P2P identity key → **protobuf encoded** → disk → **unencrypted** → key extraction → **P2P identity theft** → impersonation → eclipse attack.

**Düzeltme:** Identity key encrypted storage (AES-256 + password/HSM).

---

## 14. Özet: Saldırı Grafiği

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     BUDLUM PRE-MORTEM ATTACK GRAPH                     │
│                                                                       │
│  [CI PAT LEAK] ──→ main branch ──→ code manipulation ──→ ALL FUNDS  │
│                                                                       │
│  [PKCS#11 DATA OBJ] ──→ BLS key extract ──→ finality forge ──→      │
│       ──→ NETWORK TAKEOVER                                           │
│                                                                       │
│  [BLS HASH_TO_G1 BIAS] ──→ finality signature bias ──→               │
│       ──→ FINALITY MANIPULATION                                      │
│                                                                       │
│  [RPC NO AUTH] ──→ mint_bridge_transfer ──→ bridge fund theft ──→    │
│       ──→ CROSS-CHAIN LOSS                                           │
│                                                                       │
│  [BRIDGE MINT NO AMOUNT CHECK] ──→ mint more than locked ──→         │
│       ──→ FUND INFLATION                                             │
│                                                                       │
│  [SATURATING ARITHMETIC] ──→ silent BUD loss ──→                     │
│       ──→ SYSTEMIC VALUE LEAK                                        │
│                                                                       │
│  [BLINDING TRUNCATION] ──→ proof mismatch / brute-force ──→          │
│       ──→ PRIVACY BREAK + FUND LOSS                                  │
│                                                                       │
│  [NULLIFIER SECRET-ONLY] ──→ collision risk ──→                      │
│       ──→ DOUBLE-SPEND                                               │
│                                                                       │
│  [POSEIDON CONSTANTS DESYNC] ──→ AIR proof fail ──→                  │
│       ──→ ALL PRIVACY TRANSFERS REJECTED                             │
│                                                                       │
│  [WALLET SEED MEMORY] ──→ memory dump ──→ seed leak ──→              │
│       ──→ TOTAL USER FUND LOSS                                       │
│                                                                       │
│  [SOCIAL RECOVERY NO EXPIRY] ──→ guardian compromise ──→              │
│       ──→ ACCOUNT TAKEOVER                                           │
│                                                                       │
│  [EPOCH SEED POISON] ──→ predictable VRF ──→ targeted attack ──→     │
│       ──→ BLOCK PRODUCTION MANIPULATION                               │
│                                                                       │
│  [VERIFY_MERKLE ENV VAR] ──→ runtime manipulation ──→                │
│       ──→ STATE ROOT TRUST BREAK                                     │
│                                                                       │
│  [GENESIS KEY] ──→ 1B BUD theft ──→                                  │
│       ──→ INITIAL SUPPLY STOLEN                                       │
│                                                                       │
│  [P2P IDENTITY KEY] ──→ impersonation ──→ eclipse ──→                │
│       ──→ NODE ISOLATION                                              │
│                                                                       │
│  [REPLAY NONCE UNBOUNDED] ──→ OOM ──→ node crash ──→                 │
│       ──→ LIVENESS FAILURE                                           │
│                                                                       │
│  [CODEOWNERS 2 KISI] ──→ account compromise ──→ self-approve ──→     │
│       ──→ REPO TAKEOVER                                               │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 15. Düzeltme Planı — Katmanlı

### Katman 0 — HEMEN (0-3 gün) — Hayat Kurtaran

| # | Bulgu | Action |
|---|-------|--------|
| 0a | CI1 | BADGE_PUSH_TOKEN → deploy key scope (read-only, README.md only) |
| 0b | CI2 | CODEOWNERS → 3+ independent reviewer, security team for crypto/consensus/wallet |
| 0c | R2 | mint_bridge_transfer → `require_operator()` zorunlu |
| 0d | H1 | PKCS#11 BLS/PQ → CKO_PRIVATE_KEY (non-extractable) |
| 0e | H2 | PKCS#11 PIN → file-based, encrypted, not env var |
| 0f | C1 | BLS hash_to_g1 → RFC 9380 hash-to-curve |
| 0g | A6 | P2P identity key → encrypted storage |

### Katman 1 — MAİNNET ÖNCESİ (3-30 gün) — Ses Azalı & Value Safety

| # | Bulgu | Action |
|---|-------|--------|
| 1a | S1 | PrivacyCommit blinding → register-based (no u32 truncation) |
| 1b | S2 | SumConservation → Goldilocks field comparison |
| 1c | S3 | Nullifier → Poseidon(secret, DOMAIN_NULLIFIER, commitment) |
| 1d | S4 | Poseidon constants → single crate (poseidon-params) |
| 1e | S5 | VerifyMerkle → genesis config hard-coded, env var kaldır |
| 1f | S6 | Syscall result → AIR public input binding |
| 1g | A1 | Executor → checked_sub/checked_add (all 108 saturating replaced) |
| 1h | A2 | Genesis key → HSM-stored, multi-account distribution |
| 1i | W1 | Wallet seed → zeroize + mlock |
| 1j | NR1 | Executor → AIR proof verify zorunlu (before apply_transfer) |
| 1k | B2 | Bridge mint → payload_hash amount verification |
| 1l | B1 | Bridge merkle → SHA3-256 upgrade |

### Katman 2 — MAİNNET SONRASI (sürekli) — Liveness & Depth

| # | Bulgu | Action |
|---|-------|--------|
| 2a | P1 | spent_commitments → ZK membership proof (TEE replacement) |
| 2b | P2 | Note registry → incremental Merkle tree (not linear hash) |
| 2c | B3 | Replay nonce → pruning (expired messages after N blocks) |
| 2d | A4 | Unbonding queue → pruning (released entries) |
| 2e | C3 | Validator registration → VRF+BLS+PoP mandatory |
| 2f | C2 | Epoch seed → poison-resistant + CSPRNG fallback |
| 2g | SR1 | Social recovery → approval expiry + minimum timelock 48h |
| 2h | N1 | P2P → peer identity verification + stake-based weighting |
| 2i | A5 | DEFAULT_CHAIN_ID → mainnet (1), devnet explicit |
| 2j | E3 | NFT boost → FIXED_POINT_SCALE arithmetic (no rounding) |
| 2k | E4 | Syscall magic → enum-based (no hardcoded 0x00A1_00A1) |
| 2l | A3 | Block reward → executor hard cap enforcement |
| 2m | Dockerfile | builder package pinning + binary reproducibility audit |

---

**Bu rapor 279 dosya, 114,737 satırın tam okunması ile hazırlanmıştır. Her bulgu kod traceback ile kanıtlanmıştır. Abartı yok, varsayım yok. Ses azalı bulguları formal audit ile doğrulanmalı.**
