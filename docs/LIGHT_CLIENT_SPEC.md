# Light Client / SPV Interface Spec

> **Yazar:** ARENA1, 2026-07-20. **Durum:** Erken tasarım.

## 1. Amaç

Tam node çalıştırmadan (storage/state sync olmadan) Budlum zincirini
doğrulayabilen light client. Mobil cüzdanlar, browser extension'lar,
cross-chain relayer'lar için.

## 2. Mimarisi

```
Light Client
  ├── Header Chain (PoW bounded header-chain proof)
  ├── Finality Certificates (BLS12-381 / QC)
  ├── State Proofs (Merkle inclusion proof → state root)
  └── Cross-Domain Proofs (domain finality → Budlum settlement)
```

## 3. Interface

```rust
trait LightClient {
    /// En son finalized header'ı döndür.
    fn finalized_header(&self) -> &BudlumHeader;

    /// Bir header'ın finalized chain'de olduğunu doğrula.
    fn verify_ancestry(&self, header: &BudlumHeader) -> bool;

    /// Bir state claim'ini Merkle proof ile doğrula.
    fn verify_state_proof(
        &self,
        key: &[u8],
        value: &[u8],
        proof: &MerkleProof,
    ) -> bool;

    /// Cross-domain finality doğrula.
    fn verify_domain_finality(
        &self,
        domain_id: DomainId,
        header: &DomainHeader,
        proof: &FinalityProof,
    ) -> bool;
}
```

## 4. Mevcut Altyapı

- **PoW light client:** Bounded header-chain adapter (`src/domain/finality_adapter.rs`)
  - "Not a full light client" (kod yorumunda itiraf) — sınırlı
- **Merkle proof:** `MerkleTrie.proof()` + `MerkleProof.verify()`
- **Finality certs:** `FinalityCert::verify()` (BLS12-381)
- **State root:** `AccountState.calculate_state_root()`

## 5. Gap Analizi

- **Full SPV:** Header sync + state proof query — implemente değil
- **Sync committee:** F10.3 EVM sync-committee benzeri Budlum light client committee
- **ZK light client:** BudZKVM ile "prove the state transition" → trustless
- **Mobile/browser:** Wallet-core ile entegrasyon (BIP39 → light client sync)

## 6. Önerilen Görevlar

1. **Görev 1:** Header-chain sync + state proof query (RPC endpoint)
2. **Görev 2:** Budlum sync-committee (BLS aggregate light client)
3. **Görev 3:** ZK proof of state transition (BudZKVM)

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
