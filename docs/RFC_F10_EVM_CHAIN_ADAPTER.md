# RFC — F10 EVM ChainAdapter (Universal Relayer gerçek köprü, H4 kapatma)

> **Durum:** DESIGN / PLAN (kod değil). RFC §10 deseni: plan onayı → kod.
> **Yazar:** ARENA1 (görev yöneticisi, cross_domain domain'i) · **Tarih:** 2026-07-18
> **Temel:** main `de7b6d2` · **Task 10.5 bulgusu:** F10 (🔴 mainnet-blocker)
> **Kapanan tehdit:** SECURITY_AUDIT_HACKER H4 (🔴 Critical) — "Universal Relay
> tx yalnız log üretiyor, hedef zincir formatına kriptografik bağ yok → spoofed
> authorization".
>
> **Kullanıcı kararları (ask_user, 2026-07-18):**
> - **Q1 güven modeli = relayer_produces:** Budlum zinciri yalnız
>   `(tx_hash, receipt, Merkle-Patricia proof, receiptsRoot, header chain)` doğrular;
>   relayer proof üretir. Trust-minimized.
> - **Q2 finality = both:** PoS sync-committee light-client (tercih) +
>   N-confirmation fallback.
> - **Q3 deps = in_tree:** kendi in-tree minimal RLP + Merkle-Patricia trie impl
>   (alloy/ethers YOK) — minimal-dep + cargo-deny kuralıyla uyumlu.
> - **Q4 scope = bidirectional:** ETH→Bud (mint) + Bud→ETH (burn→unlock).

---

## 1. Amaç ve tehdit modeli

**H4 (kapatılacak):** Mevcut `UniversalRelay` tx yalnız log üretir; EVM RLP /
Solana gibi hedef zincir formatına kriptografik bağ YOK. Attacker sahte log ile
"yetki verdim" diyebilir. **F10**, Ethereum için **gerçek kriptografik receipt
doğrulaması** ekler: Budlum zinciri, iddia edilen bir Ethereum işleminin gerçekten
Ethereum'da finalize edildiğini **bağımsız olarak kriptografik kanıtlarla** doğrular.

**Tehdit modeli (F10 sonrası):**
- ❌ Sahte log / spoofed authorization → kapanır (Budlum proof verify eder).
- ❌ Relayer yalan söyleme → kapanır (proof canonical root'a bağlı; relayer
  proof uyduramaz).
- ⚠️ Ethereum reorg → N-confirmation / sync-committee finality ile sınırlanır
  (k-deep veya finalize edilmiş header).
- ⚠️ Ethereum sync-committee kompromize (%33+ stake) → Budlum kabul eder (bu
  Ethereum'un güvenliği, Budlum'un değil; kabul edilen sınır).

## 2. Mimari (mevcut + F10 eklentisi)

**Mevcut (kod-kanıtlı):**
- `ChainAdapter` trait (`src/cross_domain/chain_adapter.rs:73`): 5 metod
  (`chain_type`, `generate_receipt_proof`, `verify_receipt_proof`,
  `submit_transaction`, `wait_for_confirmation`).
- `AdapterRegistry` + `StubAdapter(Ethereum)` (test).
- `ExternalChain{Ethereum,Solana,Bitcoin}`, `ExternalTransaction`,
  `RelayerExternalResult` (`src/core/transaction.rs:55+`).
- `submit_relay_proof` (`blockchain.rs:1796`) — on-chain relayer gate.
- `bridge.rs` lock/mint/burn/unlock lifecycle.

**F10 eklentisi (yeni modüller):**
```
src/cross_domain/
├── chain_adapter.rs        (mevcut trait; StubAdapter kalır)
├── evm/                    (YENİ — F10 çekirdeği)
│   ├── mod.rs
│   ├── rlp.rs              (in-tree RLP encode/decode, minimal)
│   ├── mpt.rs              (in-tree Merkle-Patricia trie verifier)
│   ├── sync_committee.rs   (PoS light-client: BLS12-381 sync-aggregate verify)
│   ├── receipt.rs          (Ethereum receipt RLP schema + receiptsRoot proof)
│   ├── header.rs           (Ethereum header chain, finality kararı)
│   └── adapter.rs          (EvmChainAdapter: ChainAdapter impl — StubAdapter'ın gerçek hali)
└── relayer.rs              (mevcut; EvmChainAdapter'ı AdapterRegistry'ye kaydeder)
```

## 3. In-tree kriptografik bileşenler (Q3 = in_tree)

### 3.1 RLP (Recursive Length Prefix, Ethereum_yellow_paper Appendix B)

Minimal in-tree impl (Ethereum spec'inden birebir, kamuya açık algoritma — yeni
kriptografi icat EDİLMİYOR). Kapsam:
- **encode:** byte-string + list → RLP bytes (tek-bayt / iki-bayt / çok-bayt uzunluk).
- **decode:** RLP bytes → (item, rest) recursive; `(String, Vec<u8>, Vec<Item>)`.
- **Test (KAT vectors):** Ethereum test-vectors (ör. `""`→`0x80`, `"dog"`→`0x83646f67`,
  `[cat,dog]`→`0xc8...`). Resmi Ethereum test-suite'ten subset.

**Neden in-tree:** alloy/ethers-rlp eklemek cargo-deny + SBOM + mainnet-prep
minimal-dep kuralına girer; RLP ~200 satır, denetimi in-tree daha kolay
(ARENA3 fuzz domain'i). **Risk:** kendi impl hata yapabilir → KAT vectors + fuzz
zorunlu.

### 3.2 Merkle-Patricia Trie (MPT) verifier (Ethereum_yellow_paper Appendix D)

**Sadece verify** (üretme YOK — Budlum proof verify eder, proof'u relayer üretir,
Q1). Kapsam:
- **Node tipler:** `[encoded(leaf|extension), branch, ...]` — RLP-list decoding.
- **Leaf/Extension:** `(encoded-path, value)`; path nibble-encoding (hex-prefix).
- **Branch:** 16-child + optional-value.
- **Verify(path, value, proof_nodes, root):** root'tan başla, path nibble'larını
  takip et, proof node'larını RLP-decode et, leaf'e ulaş, value eşit mi.
- **Keccak256** node hash'i için (mevcut `sha3`-bağımlılık var mı kontrol; yoksa
  minimal keccak).

**Test:** Ethereum receiptsRoot proof'ları (resmi test-vectors) + negatif
(bozuk path, bozuk value, eksik node → RED).

### 3.3 Sync-committee light-client (PoS, Altair+)

**Q2 = both:** sync-committee TERCİH, N-confirmation fallback. Sync-committee
kapsam (F10 Görev 2):
- **Sync period** (~27h, 512-validator sync committee, her ~256 epoch'da rotate).
- **Sync-aggregate:** BLS12-381 aggregated signature over signed header
  (`attested_header`, `signature_slot`).
- **Verify:** sync-committee pubkey-set (trusted period head'tan) + aggregate sig
  over header hash → BLS12-381 verify (≥2/3 participation threshold).
- **Light-client state:** `finalized_header`, `next_sync_committee_pubkeys`,
  `current_period`.
- **Dep:** BLS12-381 zaten `blst` crate'i mevcut (BLS finality kullanıyor) →
  reuse, yeni dep YOK.

**N-confirmation fallback (F10 Görev 1):** k-deep canonical chain (örn. 64 block),
reorg penceresi geçince finalize say. Daha zayıf ama sync-committee öncesi
geçiş açısından.

### 3.4 Ethereum receipt + receiptsRoot

- **Receipt RLP schema:** `status/postState+cumulativeGasUsed+bloom+logs` (type-0
  legacy / type-1 access-list / EIP-1559 type-2 / EIP-4844 type-3 — tüm tipler).
- **receiptsRoot:** tüm block receipt'lerinin MPT kökü (key = RLP(tx_index)).
- **Budlum'un doğruladığı:** iddia edilen `(tx_hash, receipt_payload, logs)` →
  MPT proof → verify against `receiptsRoot` (header'dan) → header sync-committee
  /N-conf ile finalize → **kanıtlanmış**.

## 4. Güven modeli akışları (Q1 = relayer_produces, Q4 = bidirectional)

### 4.1 ETH → Budlum (mint) — F10 Görev 1+2

```
1. Kullanıcı Ethereum bridge kontratına deposit eder (lock).
2. Relayer Ethereum'u gözlemler, deposit receipt'i alır.
3. Relayer proof paketi üretir:
   { tx_hash, receipt_rlp, mpt_proof[], block_header, header_chain_proof }
   - mpt_proof: receiptsRoot → receipt (MPT nodes)
   - block_header: stateRoot/receiptsRoot/hash taşır
   - header_chain_proof: sync-committee (Görev 2) veya k-deep kanıtı (Görev 1)
4. Relayer Budlum'a submit_relay_proof gönderir (registry kapısından — stake).
5. Budlum zinciri (deterministik, on-chain) doğrular:
   a. header_chain_proof → block_header finalize mi (sync-committee BLS veya k-deep)
   b. mpt_proof → receiptsRoot'a karşı receipt geçerli mi (MPT verify, §3.2)
   c. receipt.logs → deposit event parse (asset, amount, recipient, nonce)
   d. replay koruması: (tx_hash, log_index) daha önce mint edildi mi
6. Geçerliyse mint_on_budlum(asset, amount, recipient).
```

### 4.2 Bud → Ethereum (burn → unlock) — F10 Görev 3

```
1. Kullanıcı Budlum'da burn eder (bridge outbound).
2. Relayer Budlum burn event'ini + Budlum finality proof'unu üretir
   (Budlum kendi BLS/QC finality'si — mevcut).
3. Relayer Ethereum bridge kontratına signed tx gönderir (claim):
   Budlum burn proof + recipient.
4. Ethereum bridge kontratı Budlum finality verify eder (EVM-side verification —
   Budlum light-client solidity impl; AYRI iş, bu RFC kapsamı: Budlum relay gate
   + relayer tx üretimi).
```

**⚠ Görev 3 notu:** Bud→ETH tarafı **Ethereum'da bir akıllı kontrat** gerektirir
(Budlum finality'sini EVM'de verify eden light-client). Bu büyük ayrı bir iş
(Solidity, dağıtım, audit). **F10 RFC kapsamı: Budlum-taraflı relay gate +
relayer tx üretimi**; Ethereum-taraflı kontrat **ayrı RFC** (F10.2).

## 5. ChainAdapter metod mapping'i (gerçek EvmChainAdapter)

| Trait metodu | EvmChainAdapter impl |
|---|---|
| `chain_type()` | `ExternalChain::Ethereum` |
| `generate_receipt_proof(tx_hash)` | Relayer-taraflı: Ethereum RPC'den receipt + MPT proof + header üret. **NOT:** bu off-chain (relayer binary); Budlum zinciri bu metod'u ÇAĞIRMAZ. |
| `verify_receipt_proof(proof, root, tx_hash)` | **On-chain (Budlum):** MPT verify (§3.2) + receipt RLP decode + tx_hash eşleştirme. Deterministik. |
| `submit_transaction(ext_tx)` | Relayer-taraflı: signed EVM tx (RLP encode) → Ethereum RPC broadcast. |
| `wait_for_confirmation(tx_hash, k)` | Relayer-taraflı: k confirmation poll. |

**Kritik ayrım:** `generate/submit/wait` relayer binary'sinde (off-chain, network
var); **yalnız `verify_receipt_proof` Budlum konsensüsünde** (deterministik, network
YOK). Bu Q1 (relayer produces, Budlum verifies) ile uyumlu — Budlum asla Ethereum
RPC'sine bağlanmaz.

## 6. Güvenlik invariantları + test planı

**İnvariantlar (her commit):**
1. `verify_receipt_proof` DETERMİNİSTİK + network'süz (konsensüs güvenliği).
2. Geçersiz proof (bozuk path/value/node/root) → RED.
3. (tx_hash, log_index) replay → RED.
4. Finalize-edilmemiş header (sync-committee < 2/3 veya < k confirm) → RED.
5. Tip manipülasyon (RLP decode → redress) → RED.

**Testler (F10 CI gate, BNS/bud-marketplace paterni):**
- **Pozitif:** tam ETH→Bud mint akışı (test receiptsRoot + proof fixture) ·
  sync-committee verify (test BLS aggregate fixture) · N-conf path.
- **Negatif (matris):** bozuk MPT path · bozuk receipt · bozuk root ·
  replay (tx_hash tekrar) · <2/3 sync · <k confirm · RLP truncation ·
  yanlış log_index · yanlış asset/amount decode.
- **KAT:** RLP Ethereum test-vectors · MPT Ethereum test-vectors.
- **Fuzz:** ARENA3 fuzz domain'i — rastgele RLP/MPT bytes → verify RED (panic değil).

**Gate:** `src/tests/evm_adapter.rs` + `scripts/check-evm-adapter.sh`
(isim-kilitli, vacuous-kanaryalı) + CI job + branch protection +17→18.

## 7. Görevlama (RFC onayı sonrası, atomik PR'lar)

| Görev | Kapsam | Kapı | Risk |
|---|---|---|---|
| **F10.1** | in-tree RLP + MPT verifier + KAT vectors + fuzz | derleme+KAT+fuzz | 🟡 yeni kripto impl (KAT kritik) |
| **F10.2** | EvmChainAdapter `verify_receipt_proof` + Budlum relay gate + N-conf finality + ETH→Bud mint akışı + test matrisi | negatif matris (§6) | 🔴 on-chain verify güvenliği |
| **F10.3** | sync-committee light-client (BLS12-381, blst reuse) + period rotation | sync KAT | 🟡 light-client karmaşıklık |
| **F10.4** | relayer binary: generate/submit/wait (off-chain) + RPC | e2e (devnet Ethereum fork) | 🟢 off-chain |
| **F10.5** | Bud→ETH: relayer tx üretimi + Budlum burn proof (Ethereum kontrat AYRI RFC F10.6) | burn roundtrip | 🟡 |

**F10 = F10.1 + F10.2** (ana güvenlik teslimi; ETH→Bud mint real receipt verify).
F10.3 (sync-committee) F10.2'nin N-conf finality'sini güçlendirir. F10.4/F10.5
üretim relayer (mainnet sonrası önceliklendirilebilir).

## 8. Açık sorular (gözden geçirenler için)

1. **Görev sırası:** F10.1+2 (N-conf, hızlı mainnet-prep) mi, yoksa F10.1+2+3
   (sync-committee, daha güvenli ama daha yavaş) mi ilk teslim? (Q2=both dedi;
   sıra kararı.)
2. **`blst` reuse:** BLS12-381 mevcut BLS finality crate'i (blst?) sync-committee
   için yeterli mi, yoksa aggregate-sig yardımcıları eklemek mi gerekir?
3. **Ethereum bridge kontrat adresi / deposit event format:** hangi kontrat
   standardı (örn. ETH2.0 deposit kontratı benzeri, custom)? Bu receipt parse'ı
   belirler. (Kullanıcı/kontrat ekibi kararı.)
4. **Relayer binary crate yapısı:** `relayer` ayrı binary mi (`src/bin/`) yoksa
   mevcut node'a gömülü `--relayer` mode mu? (Dağıtım kararı.)
5. **mainnet-prep önceliği:** F10 mainnet-engeli (H4) ama büyük iş — mainnet
   lansmanında bridge kapalı (lock/mint disabled) + F10 mainnet-sonrası açılış mı?

---

## 9. Netice

F10, H4 🔴'ü **gerçek kriptografik receipt doğrulamasıyla** kapatır: Budlum
Ethereum'dan gelen her claim'i bağımsız olarak MPT + sync-committee ile verify
eder; relayer trust-minimized producer. **In-tree** (RLP + MPT, minimal-dep uyumlu),
**çift yön** (ETH↔Bud), **relayer-produces** modeli. Görevlama F10.1 (RLP+MPT
foundation) → F10.2 (on-chain verify + mint) ana teslim; F10.3 (sync-committee)
güvenlik güçlendirmesi.

**Hiçbir kod bu RFC'de YOK** — kullanıcı + birlik review'ı sonrası F10.1 ile
başlanır. Bu RFC, Task 10.5 F10 bulgusunun tasarım çözümüdür.

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
