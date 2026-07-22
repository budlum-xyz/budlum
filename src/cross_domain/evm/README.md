# EVM ChainAdapter (modül README'si) — F10 H4 Kapanması

**Bu dosya,  Bölüm 4 modül-ayrımı kuralı gereği EVM adapter'ın kendi
README'sidir.** Kök `README.md` yalnızca dashboard'dur; olgunluk/risk uyarıları
burada yaşar.

## Durum

- **Olgunluk:** F10.1 + F10.2 ship edildi (H4 spoofed-authorization 🔴 kapanması).
- **Kod konumu:** `src/cross_domain/evm/` — `rlp.rs` (in-tree RLP), `mpt.rs`
  (Merkle-Patricia trie verifier), `receipt.rs` (Ethereum receipt decode),
  `header.rs` (header chain + N-conf finality), `verify.rs` (`verify_evm_receipt`
  orchestrator).
- **Test sayısı:** 58 (`#[test]` — RLP 19 + MPT 14 + receipt 10 + header 7 + verify 8).
- **Bağlı:** `src/cross_domain/chain_adapter.rs` (`ChainAdapter` trait + `AdapterRegistry`
  + `StubAdapter`). `EvmChainAdapter` impl = F10.2 (verify_receipt_proof on-chain).

## RFC

- `docs/RFC_F10_EVM_CHAIN_ADAPTER.md` — kullanıcı-onaylı 4 karar:
  (1) relayer-produces güven modeli, (2) PoS sync-committee + N-conf fallback,
  (3) in-tree RLP + MPT (alloy/ethers YOK), (4) çift yön (ETH↔Bud).

## Olgunluk uyarıları (Bölüm 4 kuralı)

- ⚠️ **N-confirmation finality (-1).** Şu an `verify_chain` k-deep canonical
  chain ile çalışır (reorg penceresi). **PoS sync-committee light-client (F10.3)
  YOK** — 512-validator BLS aggregate verify. F10.3 N-conf'u güçlendirir ama
  F10.2 N-conf ile bridge canlı.
- ⚠️ **EvmChainAdapter.generate/submit/wait = off-chain stub.** Üretim relayer
  binary'si (F10.4) mainnet sonrası. `verify_receipt_proof` on-chain deterministik.
- ⚠️ **Bud→ETH yönü (F10.5) ayrı RFC.** Ethereum'da Budlum finality'sini verify
  eden akıllı kontrat (Solidity light-client) büyük ayrı iş.

## Güvenlik sabitleri (F10.1 + F10.2)

- **Deterministik + network'süz.** Hiçbir fonksiyon Ethereum RPC'sine bağlanmaz.
  Relayer proof üretir, Budlum konsensüsünde verify edilir (Q1 relayer-produces).
- **In-tree kripto.** RLP + MPT minimal impl (Yellow Paper App. B/D), yeni
  dependency YOK (`sha3::Keccak256` reuse). KAT vectors + negatif matris.
- **Garbage-proof-panic-etmez.** DoS güvenliği — rastgele bytes → Err, panic YOK.
- **Canonical-form denetimi.** RLP decode leading-zero / minimal-len / trailing /
  truncation → RED (kanıtı uydurma yüzeyi kapalı).

## H4 kapanması

SECURITY_AUDIT_HACKER H4 (🔴 Critical) — "UniversalRelay tx yalnız log üretiyor,
hedef zincir formatına kriptografik bağ yok → spoofed authorization". F10.1+F10.2
ile kapandı: Budlum Ethereum deposit'lerini bağımsız MPT + header-chain ile
kriptografik olarak verify eder; relayer kanıt uyduramaz.

## Sıradaki

F10.3 (sync-committee, opsiyonel güçlendirme) · F10.4 (relayer binary, mainnet
sonrası) · F10.5 (Bud→ETH, ayrı RFC). Fuzz target'lar (`evm_rlp_decode`,
`evm_mpt_verify`) ARENA3-T4 ile ship edildi.
