# BUDLUM HARİTASI — tarihsel kırılmalar → Budlum karşılıkları

Bu belge, `github.com/budlum-xyz/budlum` ağacında `1bd9356` (15 Kasım 2026) üzerinde **kodu okuyarak** çıkarıldı. Her satırda dosya yolu var; "var" dediğim şeyin dosyası, "yok" dediğim şeyin yokluğu aranabilir.

## 1. Neden–sonuç zinciri ve Budlum'daki yeri

| # | Tarihsel kırılma | Sahip / belge | Budlum'daki karşılığı | Durum |
|---|---|---|---|---|
| 1 | Kör imza, dijital nakit | Chaum 1982/85 | `src/crypto/` (PQ imza katmanı), `src/privacy/` | Kısmi: mahremiyet ilkelleri var, Chaum tarzı e-cash yok |
| 2 | Hashcash / PoW | Back 1997 | `src/consensus/pow.rs`, `src/consensus/budget.rs` | Var |
| 3 | b-money (defter + kontrat + teminat) | Dai 1998 | `src/consensus/pos.rs`, `src/registry/permissionless.rs` (teminat, slashing, unbonding) | Var |
| 4 | Bit gold / RPOW | Szabo 2005, Finney 2004 | `src/consensus/pow.rs` + `src/chain/finality.rs` | Var (PoW motoru + BLS/PQ kesinlik) |
| 5 | Nakamoto konsensüsü (kanonik sıra) | Nakamoto 2008 | `src/chain/blockchain.rs`, `src/chain/chain_actor.rs`, `src/chain/snapshot.rs` | Var |
| 6 | Script = predicate | Nakamoto 2010 (kodda) | `src/execution/` + `budzero/` (BudZKVM, ISA + STARK) | Var (daha güçlü biçimde: zkVM) |
| 7 | Akıllı kontrat / EVM | Szabo 1996, Buterin 2013/15 | `src/cross_domain/evm/` (RLP, MPT, receipt, header, `verify.rs`), `contracts/` | Var |
| 8 | BFT sınırı (3m+1, FLP) | Lamport 1982, FLP 1985 | `src/consensus/qc.rs` (quorum sertifikası), `src/consensus/filiz.rs`, `src/consensus/block_signature.rs` | Var |
| 9 | Casper / PoS + slashing | Buterin & Zamfir 2014–17 | `src/consensus/pos.rs`, `src/registry/permissionless.rs` (`slash_from_report`, `slash_validator`) | Var |
| 10 | Tendermint / HotStuff / IBC | Buchman 2014, Yin 2019 | **Yok.** `tendermint` aramasında sıfır eşleşme; `src/cross_domain/external/spec.rs` üçüncü taraf adaptör arayüzü sunuyor ama hazır bir Tendermint adaptörü yok | **Eksik** |
| 11 | DAG / PoH / PoSpace | Sompolinsky–Zohar 2013, Yakovenko 2017, Filecoin 2017 | **Yok.** `PoH`/`PoSpace` aramasında sıfır eşleşme | **Eksik** |
| 12 | Bitcoin SPV / header chain | Nakamoto 2008 §8 | `src/domain/finality_adapter.rs`: `PoWHeader`, `PoWHeaderChainFinalityAdapter`, `FinalityProof::PoWHeaderChain` — **jenerik** bounded-PoW başlık zinciri; Bitcoin'e özgü difficulty retarget, 80 baytlık başlık düzeni, confirmation politikası yok | **Kısmi** |
| 13 | Ethereum hafif istemci | Altair 2021 | `src/cross_domain/evm/sync_committee.rs` (512 anahtar, 2/3 eşik, fork domain), `src/cross_domain/evm/verify.rs` | Var (relayer üretir, Budlum BLS doğrular) |
| 14 | Yerel hafif istemci | — | `src/light_client/mod.rs` (BLS `FinalityCert` + PQ `QcBlob`), `src/bin/budlum-light.rs` | Var |
| 15 | Rollup / DA / modüler | Poon–Buterin 2017, WhiteHat/Buterin 2018, EIP-4844 2022 | **Yok.** `rollup` aramasında sıfır eşleşme; `data_availability` yalnız `src/tests/permissionless.rs` içinde geçiyor | **Eksik** |
| 16 | Restaking / paylaşılan güvenlik | EigenLayer 2023 | `src/settlement/shared_security.rs`, `src/settlement/domains.rs` | Kısmi |
| 17 | ZK doğrulama | GMR 1985 → Groth16 2016 | `budzero/` (Plonky3 STARK), `src/crypto/`, `src/prover/` | Var |
| 18 | Global settlement başlığı | — | `src/settlement/global_block.rs`: `GlobalBlockHeader` **V7**, `GLOBAL_HEADER_WINDOW = 64` | Var |
| 19 | Heterojen kesinlik adaptörleri | — | `src/domain/finality_adapter.rs`: `FinalityProof::{PoS, PoA, Bft, Zk, Raw, PoWHeaderChain, PoSPq, PoAPq, BftPq}` + `DomainFinalityAdapter` trait | Var |
| 20 | Üçüncü taraf adaptör sözleşmesi | — | `src/cross_domain/external/{spec,profile,versioning,intake,quorum,prover}.rs` — "boolean değil, kanıt"; bilinmeyen sürüm sert ret | Var |
| 21 | **Ağır nesne toplama (iddia + tek Ana Kanıt)** | BUDLUM AGREGASYON DİREKTİFİ | **Bu turda eklendi:** `src/aggregation/` (PR #188) | **Yeni** |
| 22 | Depolama (B.U.D. 3.0) | — | `src/storage/` (erasure, lrc, msr, column_commitment…), `bud/`, `src/bud/` | Var |

## 2. "Consensus of consensuses" iddiasının bugünkü gerçek durumu

Bugün Budlum, **heterojen kesinlik kanıtlarını doğrulayıp tek bir `GlobalBlockHeader`'a işleyen** bir katman olarak çalışıyor:

```
domain commitment ──► FinalityProof ──► DomainFinalityAdapter::verify_finality
                                             │
                                             ▼
                                   FinalityStatus::{Pending, Finalized, Rejected}
                                             │
                                             ▼
                        GlobalBlockHeader { domain_registry_root, domain_commitment_root,
                                            settlement_finality_root, storage_root, ai_root,
                                            identity_root, external_intake_root, graft_root,
                                            delegation_root, ... }   // V7
```

Eksik olan üç eksen, bu turdaki haritanın ana bulgusu:

1. **Aile kapsamı.** Tendermint/IBC, DAG/PoH/PoSpace ve rollup/DA yok. Bir ağ bu üç aileden birindeyse bugün Budlum'a *domain olarak* giremez; yalnız `external` adaptörü yazarsa girer.
2. **Kanıt taşıma.** Her domain kendi kanıtını blok gövdesinde taşıyor: 1–6 kB PQ imza, ~128 kB STARK. Bu, BUDLUM AGREGASYON DİREKTİFİ'nin çözmek istediği problem ve bu turda çekirdeği yazıldı (`src/aggregation/`).
3. **Ölçek.** 33 workflow, ~60 kapı, `--all` kapı seti; ama tam crate derlemesi bu ortamda yapılamadı (bkz. denetim raporu B-0002). Testnet iddiası bu yüzden CI'ya bağlı.

## 3. Ne var, ne yok (özet tablo)

| Yetenek | Dosya | Durum |
|---|---|---|
| PoW / PoS / PoA / BFT motorları | `src/consensus/{pow,pos,poa,qc}.rs` | Var |
| BLS + PQ hibrit kesinlik | `src/chain/finality.rs`, `src/consensus/qc.rs` | Var |
| Domain kaydı ve soyutlama | `src/domain/{registry,plugin,plugin_registry,sovereign}.rs` | Var |
| Kesinlik adaptörleri (PoS/PoA/BFT/ZK/PoW-header) | `src/domain/finality_adapter.rs` | Var |
| EVM adaptörü + sync committee | `src/cross_domain/evm/*` | Var |
| Üçüncü taraf adaptör sözleşmesi | `src/cross_domain/external/*` | Var |
| Köprü yaşam döngüsü | `src/cross_domain/bridge*.rs` | Var |
| Stake/slashing/unbonding | `src/registry/permissionless.rs` | Var (bkz. B-0003) |
| BudZero zkVM (STARK) | `budzero/` | Var |
| B.U.D. depolama | `src/storage/`, `bud/` | Var |
| **Agregasyon (iddia/çerçeve/Ana Kanıt)** | `src/aggregation/` | **Bu turda eklendi (PR #188)** |
| Tendermint/IBC adaptörü | — | **Yok** |
| DAG/PoH/PoSpace adaptörü | — | **Yok** |
| Bitcoin'e özgü SPV adaptörü | `src/domain/finality_adapter.rs` (jenerik) | **Kısmi** |
| Rollup / DA katmanı | — | **Yok** |
| Restaking ekonomisi | `src/settlement/shared_security.rs` | Kısmi |

## 4. Bu haritanın sınırı

Harita, `main` ağacının `1bd9356` commit'ine aittir. `testnet` (#126, 1249 commit), `garden` (#164, 51 commit) ve `budlum-stack` (#183, 22 commit) dallarında bu satırların bir kısmı değişmiş olabilir; `src/storage/bud3/` yalnızca stack'te var. Bir sonraki turda harita, stack başına (`budlum-stack`) yeniden çıkarılmalıdır.
