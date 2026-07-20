# Phase 11.3 — 7 Görev (Devasa Oturum)

> **Yazar:** ARENA1 (görev yöneticisi), 2026-07-20.
> **Kullanıcı emri:** 7 görev, hepsi bu oturumda.

## 1. Read-only RPC endpoint'leri
Mevcut: chainId, blockNumber, getBlock, getBalance, getNonce, getTransaction, gasPrice, estimateGas, syncing, netVersion, netListening.
Eksik: `bud_getStatus` (validator count, finalized height, epoch), `bud_getValidatorSet`, `bud_getDomainInfo`, `bud_getSlashingHistory`.
Plan: api.rs + server.rs'e yeni read-only uçlar ekle (relayer kararından bağımsız).

## 2. CrossDomainMessage sertleştirme
Mevcut: verify_id + nonce var ama submit_cross_domain_message replay store kullanmıyor.
Plan: submit_cross_domain_message içine replay_nonce.mark_processed + verify_id zorunlu + domain-spoofing check (source_domain ≠ target_domain).

## 3. Slashing test matrisi
Mevcut: finality_adversarial + liveness test'leri var ama double-sign/downtime/invalid-attestation ayrı ayrı değil.
Plan: src/tests/slashing_matrix.rs — double_sign_slash, downtime_slash, invalid_attestation_reject, slashing_history_persistence.

## 4. PoA KYC/whitelist modülü
Mevcut: PoaMembershipRegistry (apply/approve/revoke) + kyc_commitment.
Eksik: participant onboarding flow + whitelist enforcement test + PoA↔permissionless izolasyon mührü.
Plan: src/registry/poa_onboarding.rs + test matrisi.

## 5. bud-cli
Mevcut: budzero/bud-cli (BudZKVM compile/run/prove/verify).
Eksik: tx gönderme, state sorgulama, local validator.
Plan: bud-cli'ye `tx send`, `query balance`, `query block`, `validator run` subcommand'ları.

## 6. Domain test suite'leri
Mevcut: liveness, finality, settlement test'leri var.
Eksik: BFT view-change, PoS slashing triggers, PoW difficulty adjustment edge-case'leri.
Plan: src/tests/domain_edge_cases.rs.

## 7. Metrics/observability
Mevcut: AI QoS metrics, latency histogram (Phase 0.37).
Eksik: per-domain Prometheus metrics + structured logging.
Plan: src/observability/domain_metrics.rs.
