# RFC F10.5 — Bud→ETH Solidity Bridge Kontratı (Ethereum-taraflı light-client)

> **Durum:** DESIGN / PLAN (Solidity implementasyonu ayrı iş + audit).
> **Yazar:** ARENA1 (görev yöneticisi, cross_domain domain'i), 2026-07-19.
> **Temel:** main `9ba7955` (F10.1+F10.2+F10.3 ship edildi).
> **Kaynak:** `docs/RFC_F10_EVM_CHAIN_ADAPTER.md` §4.2 (Bud→ETH akışı).

---

## 0. Kapsam ve sınır

F10.5'in iki tarafı:
1. **Budlum-taraflı (ship edildi):** `src/cross_domain/evm/bud_to_eth.rs` — relayer,
   Budlum burn event + finality proof paketler → `BudToEthClaim` payload.
2. **Ethereum-taraflı (bu RFC):** Solidity akıllı kontrat — Budlum finality'sini
   EVM'de verify eden **Budlum light-client** + bridge unlock logic.

**Bu RFC yalnızca Ethereum-taraflı tasarımı kapsar.** Solidity implementasyonu
ayrı repo + harici audit gerektirir (EVM güvenlik farklı paradigm).

---

## 1. Mimari

```
Budlum (burn) → relayer (BudToEthClaim) → Ethereum Bridge.sol → unlock
                                              ↓
                                         BudlumLightClient.sol
                                              ↓
                                         BLS12-381 precompile
                                         + sync-committee verify
```

### Kontratlar

| Kontrat | Sorumluluk |
|---|---|
| `BudlumLightClient.sol` | Budlum finalized header'ları saklar; sync-committee rotation; BLS aggregate verify |
| `BudlumBridge.sol` | lock/mint (ETH→Bud tarafı) + burn/unlock (Bud→ETH); BudlumLightClient'a finality check |
| `BudlumToken.sol` (varsa) | ERC-20 wrapped $BUD; bridge mint/burn yetkisi |

---

## 2. BudlumLightClient.sol — EVM'de Budlum finality

### State

```solidity
struct BudlumHeader {
    uint64 height;
    bytes32 hash;
    bytes32 parentHash;
    bytes32 stateRoot;
    uint64 timestamp;
}

struct SyncCommittee {
    bytes32[] pubkeysRoot;    // 512 BLS pubkey'in Merkle root'u
    uint64 periodStart;
}

BudlumHeader public finalizedHeader;
SyncCommittee public currentCommittee;
SyncCommittee public nextCommittee;
mapping(bytes32 => bool) public processedHeaders;
```

### Fonksiyonlar

- `updateFinalizedHeader(BudlumHeader calldata header, bytes calldata blsAggregate,
  bytes32[] calldata participatingPubkeys)`: sync-committee BLS aggregate verify
  (≥2/3 participation) → finalizedHeader güncelle.
- `verifyFinality(uint64 height, bytes32 hash, bytes calldata proof)`: header'ın
  finalized chain'de olduğunu doğrula (Merkle ancestry proof).

### BLS12-381 EVM precompile

- EIP-2537 (Prague/Cancun'da) BLS12-381 precompile'ları sağlar: `BLS_G1ADD`,
  `BLS_G1MSM`, `BLS_PAIRING`, vb.
- **Risk:** EIP-2537 mainnet activation tarihi belirsiz. Fallback: `blst`
 Solidity wrapper (gaz maliyeti yüksek) veya optimistic finality (challenge window).

---

## 3. BudlumBridge.sol — lock/mint + burn/unlock

### ETH → Bud (F10.2 karşılığı, Ethereum-taraflı)

```solidity
function deposit(uint256 amount, bytes32 budlumRecipient)
    external payable nonReentrant {
    // ERC-20 transferFrom (veya native ETH lock)
    // emit Deposit(msg.sender, amount, budlumRecipient, nonce)
    // Relayer Budlum'da bu event'i gözle → F10.2 verify → mint
}
```

### Bud → ETH (F10.5 — bu RFC'nin ana konusu)

```solidity
function claimUnlock(
    BudlumLightClient.BudlumHeader calldata finalizedHeader,
    bytes calldata finalityProof,      // BLS aggregate + sync-committee bits
    bytes32 message_id,
    bytes32 asset_id,
    uint256 amount,
    address recipient,
    bytes calldata burnEventProof      // Budlum event tree → Budlum root
) external nonReentrant {
    // 1. Finality: BudlumLightClient.verifyFinality(header, proof)
    require(lightClient.isFinalized(finalizedHeader), "not finalized");

    // 2. Burn event proof: Budlum event tree → finalizedHeader.stateRoot
    require(verifyBurnEventProof(message_id, asset_id, amount, recipient,
        finalizedHeader.stateRoot, burnEventProof), "invalid burn proof");

    // 3. Replay protection
    require(!processedClaims[message_id], "already claimed");
    processedClaims[message_id] = true;

    // 4. Unlock (ERC-20 transfer veya native ETH)
    IERC20(budToken).transfer(recipient, amount);
    emit Unlocked(message_id, asset_id, amount, recipient);
}
```

---

## 4. Güvenlik invariantları

1. **Finality zorunlu:** `claimUnlock` Budlum finalized header gerektirir
   (light-client). Budlum'un trust EdILMEZ — proof bağımsız verify.
2. **Replay protection:** `processedClaims[message_id]` mapping; aynı burn
   iki kez unlock edilemez.
3. **Amount cap:** bridge cap (governance parametresi); büyük drain saldırısı sınır.
4. **BLS12-381 subgroup check:** rogue-key attack koruması (precompile seviyesinde).
5. **Challenge window (optimistic fallback):** EIP-2537 yoksa optimistic
   finality + fraud proof window (7 gün); challenger doğru proof sunarsa claim revert.
6. **Pause (governance):** acil durumda bridge pause (multi-sig governance).

---

## 5. Riskler

- **EIP-2537 activation:** BLS precompile mainnet'te yok → gaz maliyeti yüksek
  (blst wrapper) veya optimistic finality (challenge window).
- **Budlum light-client complexity:** sync-committee rotation + Merkle ancestry
  proof Solidity'de karmaşık (gaz maliyeti).
- **Audit:** Solidity kontratı harici audit GEREKTİRİR (Spearbit/Trail of Bits
  seviyesi). EVM güvenlik paradigması Rust'tan farklı.
- **Dağıtım:** immutable kontrat; bug sonrası upgrade proxy gerek (governance).

---

## 6. Uygulama planı

| Faz | Kapsam | Sorumlu | Kapı |
|---|---|---|---|
| F10.5a | `BudToEthClaim` Rust payload (ship edildi, `bud_to_eth.rs`) | ARENA1 ✅ | unit test |
| F10.5b | `BudlumLightClient.sol` iskelet (BLS verify stub) | ARENA1 / Solidity ekibi | foundry test |
| F10.5c | `BudlumBridge.sol` claimUnlock + replay + cap | ARENA1 / Solidity ekibi | foundry test |
| F10.5d | EIP-2537 integration veya optimistic fallback | Solidity uzman | gaz benchmark |
| F10.5e | Harici audit (Spearbit/Trail of Bits) | audit firm | audit raporu |
| F10.5f | Mainnet dağıtım (immutable + governance proxy) | release manager | ceremony |

---

## 7. Kabul kriterleri

- [ ] F10.5a (Rust payload) ship edildi (`bud_to_eth.rs`).
- [ ] F10.5b-c Solidity kontrat foundry test'leri yeşil.
- [ ] F10.5d BLS verify çalışır (EIP-2537 veya optimistic).
- [ ] F10.5e harici audit raporu (CRITICAL/HIGH kapalı).
- [ ] F10.5f mainnet dağıtım + bridge ceremony.

---

## 8. Netice

F10.5 Bud→ETH yönü, Ethereum'da Budlum finality'sini verify eden Solidity
light-client gerektirir. Budlum-taraflı payload (F10.5a) ship edildi; Ethereum-
taraflı kontrat ayrı büyük iş (Solidity + EIP-2537 + audit). Bu RFC, F10
kompletness için Ethereum-taraflı tasarımı dokümante eder; implementasyon
mainnet sonrası (veya kullanıcı emriyle Solidity ekibi).

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
