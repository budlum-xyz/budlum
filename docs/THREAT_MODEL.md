# Budlum Threat Model v2 (Task 11.20)

**Durum:** Final v2 (Task 11.20) — Task 11.8 → 11.18 azaltmaları CI-gated olarak işlenmiştir
**ADR:** [ADR-010](adr/ADR-010-security-audit-hsm.md)
**Metodoloji:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
**Tehdit sınıflandırması:** 🔴 Kritik / 🟠 Yüksek / 🟡 Orta / 🔵 Düşük
**CI yargıcı:** Her azaltma için GitHub CI yeşil olmalıdır; lokal kontrol yalnızca ön doğrulamadır.

## 1. Sistem Sınırları ve Güven Varlıkları

**Güven varlıkları:**
- Konsensüs katmanı (PoW/PoS/BFT/PoA domain'leri)
- State (ledger, account balances, registry)
- Cross-domain bridge (lock/mint/burn)
- Kullanıcı anahtarları (wallet, validator signing key)
- AI/data layer (Pollen grants, B.U.D. storage)
- p2p ağı (libp2p)

**Güven sınırı:**
- Node operatörleri (validator)
- Relayer (permissionless, staked)
- Kullanıcı (wallet holder)
- Dış zincir (Ethereum bridge)

## 2. Konsensüs Tehditleri

| # | Tehdit | Sınıf | Etki | Mevcut Azaltma | Kalan Risk |
|---|---|---|---|---|---|
| C1 | Nothing-at-stake (PoS — aynı blokta iki imza) | Tampering | 🔴 | SlashingCondition::DoubleSign (slashing_matrix.rs) | QC fault proof (V103) — slash uygulanıyor |
| C2 | Long-range attack (PoS — eski key'lerle geçmiş rewrite) | Tampering | 🔴 | Finality checkpoint + weak-subjectivity | Light client checkpoint sync (ADR-007) |
| C3 | Equivocation (BFT — iki çakışan blok) | Tampering | 🔴 | QcFaultProof::InvalidateFinality + slash | ✅ V103 |
| C4 | 51% hash power (PoW — reorg) | Tampering | 🟠 | Finality checkpoint (finalized block reorg reddi) | — |
| C5 | Validator key theft (imzalama anahtarı çalınma) | Spoofing | 🔴 | HSM policy (ADR-010) | Soft launch'ta software key risk |
| C6 | Validator downtime (liveness fault) | DoS | 🟡 | LivenessTracker + LivenessFault slashing | — |
| C7 | LMD-GHOST fork bomb (PoS — çok fork) | DoS | 🟠 | fork_choice bound + finality | ADR-007 impl |
| C8 | Domain lifecycle abuse (kötü domain start) | EoP | 🟡 | proposal-driven lifecycle (ADR-007) | Governance whitelist |

## 3. Bridge / Cross-Domain Tehditleri

| # | Tehdit | Sınıf | Etki | Mevcut Azaltma | Kalan Risk |
|---|---|---|---|---|---|
| B1 | Forged EVM receipt proof (sahte deposit) | Tampering | 🔴 | EvmChainAdapter Merkle verify (V30) + verify_evm_receipt | ✅ V30 |
| B2 | Replay attack (aynı mesaj tekrar) | Tampering | 🔴 | BridgeState.replay.mark_processed (V24) | ✅ V24 |
| B3 | Domain spoofing (source≠target bypass) | Tampering | 🟠 | submit_cross_domain_message spoof check (Görev 2) | ✅ Görev 2 |
| B4 | Anchor substitution (sahte finalize anchor) | Tampering | 🟠 | bridge_negatives testleri (P0 gap) | ✅ |
| B5 | Inactive relayer submits stale message | DoS | 🟡 | relayer active check (relayer_liveness) | ✅ |
| B6 | Bridge unlock without burn (double-spend) | Tampering | 🔴 | V17 unlock fix + V24 lock | ✅ V17 |

## 4. p2p / Ağ Tehditleri

| # | Tehdit | Sınıf | Etki | Mevcut Azaltma | Kalan Risk |
|---|---|---|---|---|---|
| N1 | Eclipse attack (node kendi peer'larıyla çevrelenme) | DoS/Tampering | 🔴 | /24 subnet bound (H2, ekip 261df88) | ADR-008 full hardening |
| N2 | Sybil (kimlik flooding) | DoS | 🟠 | stake/reputation | ADR-008 reputation |
| N3 | Gossipsub MessageId collision (mesaj çakışma) | Tampering | 🟠 | V114 fix (ekip eb56e72) | ✅ V114 |
| N4 | Peer reputation gaming | Tampering | 🟡 | reputation scoring (ADR-008) | Tuning testi |
| N5 | NAT traversal abuse (relay üzerinden saldırı) | DoS | 🔵 | auto-nat config (ADR-008) | — |

## 5. Wallet / Hesap Tehditleri

| # | Tehdit | Sınıf | Etki | Mevcut Azaltma | Kalan Risk |
|---|---|---|---|---|---|
| W1 | Anahtar kaybı (fon kaybı) | — | 🔴 | Social recovery (ADR-005) | ADR-005 impl |
| W2 | Guardian collusion (recovery saldırısı) | Tampering | 🟠 | Guardian threshold + rotation (ADR-005) | ADR-005 test |
| W3 | Multisig owner compromise | Spoofing | 🟠 | M-of-N threshold (ADR-005) | ADR-005 impl |
| W4 | Seed phrase leak (BIP39) | Info Disclosure | 🔴 | wallet-core + HSM (operatör) | HSM policy (ADR-010) |

## 6. AI / Data (Pollen) Tehditleri

| # | Tehdit | Sınıf | Etki | Mevcut Azaltma | Kalan Risk |
|---|---|---|---|---|---|
| A1 | AI izinsiz veri okuma | Info Disclosure | 🔴 | AI read gate (ai_data_access_denied, A4-1) | ✅ A4-1 |
| A2 | AccessGrant replay (aynı grant tekrar) | Tampering | 🟠 | bounded reads (reads_used < max_reads) | ✅ A4-1 |
| A3 | Grant forge (sahte owner imza) | Tampering | 🔴 | owner_signature validation + sentinel reddi | ✅ A4-1 |
| A4 | DAO decrypt yetkisi gaslighting | EoP | 🔴 | DAO decrypt authority yok (invariant, P12-4) | P12-4 |

## 7. PoA / Regülasyon Tehditleri

| # | Tehdit | Sınıf | Etki | Mevcut Azaltma | Kalan Risk |
|---|---|---|---|---|---|
| P1 | PoA rules permissionless'e sızma | EoP | 🔴 | PoA Isolation (CI Madde 9, 8 test) | ✅ Görev 4 mührü |
| P2 | PoA admin freeze abuse | DoS | 🟠 | admin rotation + audit (ADR-009) | ADR-009 impl |
| P3 | KYC metadata leak (cross-domain) | Info Disclosure | 🟠 | CrossDomainMessage KYC taşımaz (P0 gap test) | ✅ |

## 8. Governance Tehditleri

| # | Tehdit | Sınıf | Etki | Mevcut Azaltma | Kalan Risk |
|---|---|---|---|---|---|
| G1 | Governance whitelist'e permissionless ekleme | EoP | 🔴 | Parametre whitelist invariant (ADR-004) | ADR-004 impl |
| G2 | Vote manipulation (stake transfer) | Tampering | 🟠 | Stake-ağırlıklı vote + snapshot | ADR-004 impl |
| G3 | Timelock bypass (anında parametre değişimi) | Tampering | 🟠 | Timelock zorunlu (ADR-004) | ADR-004 impl |
| G4 | DAO halt rollback (no-rollback ihlali) | Tampering | 🔴 | Constitution no-rollback ilkesi | ✅ (mevcut) |

## 9. Storage Tehditleri

| # | Tehdit | Sınıf | Etki | Mevcut Azaltma | Kalan Risk |
|---|---|---|---|---|---|
| S1 | Forged storage proof (sahte depolama kanıtı) | Tampering | 🔴 | Storage challenge + proof (spec Task 11.6) | ADR-002 impl |
| S2 | Storage node plaintext zorunlu kılma | EoP | 🔴 | Encryption policy (P12-4, DAO dokunamaz) | P12-4 |
| S3 | Pruning ile finalized state kaybı | Tampering | 🟠 | Snapshot retantion (ADR-003) | ADR-003 impl |

## 10. Task 11.20 Mitigation Closure Matrix

| Görev | Kapatılan risk sınıfı | Gerçekleşmiş azaltma | CI kanıtı | Kalan risk |
|---|---|---|---|---|
| 11.6 | Spec drift / audit blind spot | Frozen specs + spec-review checklist | Repo Lint spec coverage | Yeni spec değişiklikleri aynı gate'e bağlanmalı |
| 11.8 | Economy cap / fee-market / fork-choice tampering | Committed supply denominator, EIP-1559 fail-closed migration, domain fork-choice primitives, lifecycle guards | `Economy Invariants`, `Fork-Choice Invariants` | Fee distribution full wiring sonraki ekonomi ADIM'i |
| 11.10 | Storage proof / pruning state loss | Storage provider proof API, lifecycle projection, full/archive pruning policy | `StorageProvider Gate`, `Node Classification` | Production storage incentives için uzun soak |
| 11.12 | Eclipse / rate-limit DoS | /24 profile-driven peer bound, idempotent peer accounting, rate-limit ban threshold | `Network Hardening` | Chaos/fuzz tuning devam etmeli |
| 11.14 | Wallet key loss / multisig compromise | Multisig matrix, social recovery, guardian rotation, recovery proposal digest, binding stubs | `Wallet Core` | UI/mobile production binding generation ayrıca denetlenecek |
| 11.16 | Governance EoP / timelock bypass | Parameter whitelist, activation timelock, vote-weight snapshot | `Governance Invariants` | Governance UX and voter education risk |
| 11.18 | PoA compliance leakage | PoA-only screening/freeze/travel-rule metadata + audit export | `PoA Compliance Isolation` | Regulator oracle integration is off-chain and must be audited separately |
| 11.20 | Audit/HSM operational blind spot | Audit prep index + validator YubiHSM 2 / PKCS#11 key policy | `Audit Prep` | 7-day CI stability window before launch lock |

## 11. Residual Risk Register (mainnet sonrası takip)

**🔴 Kritik:** Bu v2 snapshot itibarıyla pre-Task12 kapsamda CI-gated ve açık kritik kod riski bırakılmaması hedeflenmiştir. Kritik sınıf yeniden açılırsa yeni ADIM kırmızı kabul edilir ve yeni scope durdurulur.

**🟠 Yüksek / operasyonel:**
- R1 — Long-range / checkpoint operations: validator onboarding ve genesis ceremony prosedürleri HSM policy ile birlikte dry-run edilmelidir.
- R2 — Hardware signer rollout: YubiHSM 2 / PKCS#11 cihaz envanteri, PIN custody ve backup quorum bağımsız audit tarafından örneklenmelidir.
- R3 — Network chaos tuning: Eclipse/rate-limit kapıları yeşil olsa da multi-node partition/Byzantine chaos senaryoları mainnet öncesi soak ister.
- R4 — Storage proof economics: Proof verification strict; incentive and slashing parameter calibration uzun devnet gözlemi gerektirir.
- R5 — Wallet UX: wallet-core primitive'leri hazır; kullanıcı-facing recovery/multisig UX sonraki ürün görevında yanlış kullanım riskini azaltmalıdır.
- R6 — PoA oracle/regulator data: On-chain hash kayıtları PoA'ya izole; off-chain oracle doğruluğu ve veri saklama politikası ayrı audit alanıdır.
- R7 — CI stability: Launch lock için tüm required + extended gates en az 7 gün kırmızısız izlenmelidir.

## 12. İlgili

- `docs/SECURITY_AUDIT_HACKER.md` — V17-V7 bulguları (geçmiş tehdit denetimi)
- `SECURITY.md`, `docs/BUG_BOUNTY.md` — sürekli tehdit tespiti
- 10 ADR (`docs/adr/`) — her tehdit için azaltma kararı
- Task 11.6-11.20 yol haritası — azaltmaların implementasyon görevları
