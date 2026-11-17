# BUDLUM TASARIMI — eksik konsensüs aileleri için adaptörler ve ortak kanıt modeli

Bu belge tasarımdır, kod değil. Yazılan tek parça `src/aggregation/` (PR #188). Buradaki her adaptör, o parçanın `Claim` modeline oturur; oturmayan tasarım yoktur.

## 0. Ortak kanıt modeli (yazıldı)

Üç seviye:

```
Envelope  (ağır nesne + tx_hash + domain)          → object_id
   │  claim_from_envelope  (bayttan türetilir, ağdan alınmaz)
   ▼
Claim     Sig{scheme,signer,msg_hash} | Prog{program,input,output} | Poly{poly,point,value}
   │  claim_digest(domain, claim)  →  Merkle  →  claims_root
   ▼
ClaimFrame { segments, shape, claims, proof }      →  fold_shape  →  master_pi
   │  frame_hash(master_pi, params_hash, H(proof))
   ▼
Blok başlığı: frame_hash                            →  tek Ana Kanıt doğrulanır
```

Bağlayıcılık üç yerde: `domain` her iddia özetinde; `params_hash` her çerçeve özetinde; `adapter_binding` her kesinlik iddiasında. Bir kanıt başka domain'de, başka parametre setinde veya başka adaptör sürümünde yeniden kullanılamaz. Bu üç bağ, **çapraz domain güvenliğinin tamamıdır**; geri kalanı kanıt sisteminin işi.

## 1. Bitcoin (SPV + header chain)

**Bugün:** `FinalityProof::PoWHeaderChain { headers: Vec<PoWHeader> }` + `PoWHeaderChainFinalityAdapter`. `PoWHeader` alanları: `height, parent_hash, state_root, tx_root, event_root, timestamp_ms, nonce, difficulty_bits`. Jenerik; Bitcoin'in *kurallarını* içermiyor.

**Tasarım:**
1. `bitcoin_headers` programı (BudZKVM AIR): `(prev_hash, version, merkle_root, time, bits, nonce)` → `block_hash` ve `bits == expected_bits(height)` retarget kontrolü. Program özeti `Claim::Prog { program_hash: BTC_HEADER_PROGRAM, input_hash: H(header_bytes), output_hash: block_hash }`.
2. Derinlik politikası adaptör parametresi olur, kod olmaz: `confirmation_depth` (6 varsayılan), `max_reorg_bits`. Politika `adapter_binding` içinde taşınır → aynı başlık zinciri farklı politika ile farklı iddia üretir.
3. SPV kanıtı ayrı bir `Prog` iddiası: `(tx_hash, merkle_branch, block_header)` → `output = H(tx) ∈ merkle_root`. Böylece "işlem zincirde" iddiası, "en ağır zincir" iddiasından bağımsız doğrulanır.
4. **Yapılmaması gereken:** `difficulty_bits`'i adaptörün "kabul ettiği aralık" olarak `PoWDomainParameters` içinden okumak (bugünkü yol). Bitcoin'de zorluk, *zincirin kendi kuralıdır*; parametre değil.

## 2. Ethereum (sync committee)

**Bugün:** `src/cross_domain/evm/sync_committee.rs`. 512 anahtar, 2/3 eşik, `BLS_SIG_BLS12381G2_...` suite'i, fork domain'i, `FastAggregateVerify`. Dosyanın kendi notu: relayer üretir, Budlum doğrular; committee state'i **finalized beacon state'e henüz bağlı değil**.

**Tasarım:** Kanıtlanacak geçişi `Prog` iddiasına çevir: `(beacon_header, sync_aggregate, committee, finality_branch)` → `output = execution_state_root`. Böylece (a) committee rotasyonu `finality_branch` ile bağlanır, (b) iddia, `ClaimFrame` içinde öbür domainlerinkiyle aynı Ana Kanıt'a girer. Bugünkü "BLS doğrula + state'i ver" adımı, "state'i kanıtla" adımına yükselir.

## 3. Tendermint / CometBFT / IBC (yok)

**Neden gerekli:** Cosmos ekosistemi, bugün Budlum'a giremeyen en büyük tek aile.

**Tasarım (üç iddia):**
1. `tendermint_commit`: `Prog` iddiası — `(chain_id, height, app_hash, validator_set_hash, commit_sigs, voting_power)` → `output = H(chain_id || height || app_hash)`. Kural: imzalı voting power ≥ 2/3 **ve** `validator_set_hash` bir önceki iddiadaki setin ardılı (set değişimi kanıtlanır).
2. `ibc_client_update`: `(client_state, header, consensus_state)` → yeni `consensus_state`; `Prog` iddiası. IBC zaten bu şekle sahiptir; yapılacak olan onu BudZKVM programı olarak yazmak.
3. `ibc_packet_commitment`: `(packet, proof, root)` → `output = H(packet)` ∈ `root`.

**Kritik ayrıntı:** Tendermint'te kesinlik *sonlu* ve geri döndürülemez; ama Budlum'un gördüğü set değişimi, Budlum'un *kendi* kaydettiği son setle zincirlenmelidir. `adapter_binding(adapter="tendermint-commit-v1", evidence_version="v1")` + `last_height` monotonluğu zorunlu; aksi hâlde eski bir commit yeniden sunulur (replay).

## 4. DAG / PoH / PoSpace (yok)

**DAG (Sompolinsky–Zohar türü):** Kesinlik "en ağır alt DAG"dır. İddia: `Prog { program: DAG_FINALITY, input: H(tips), output: confirmed_set_root }` ve parametre olarak `confirmation_weight`. Bu ailede kesinlik *ölçülebilir bir ağırlıktır*, "finalized" bayrağı değil; bu yüzden `FinalityStatus::Finalized` yerine yeni bir `FinalizedWeight { w, threshold }` durumu gerekir. Bugünkü enum bunu ifade edemiyor: **tasarım boşluğu.**

**PoH (Solana):** Kesinlik iki katmanlı: (a) PoH zinciri doğrulanabilir gecikme zinciridir, `Prog` iddiası olur; (b) gerçek kesinlik, stake ağırlıklı oylamadır (TowerBFT), yani `tendermint_commit` şeklinin bir varyantı. PoH tek başına kesinlik değildir; adaptör bunu ayrı ayrı iddia etmeli, birleştirmemeli.

**PoSpace (Filecoin):** Depolama kanıtı + tip setleri + EC finality. Üç iddia: `seal_proof` (Prog), `tipset_weight` (Prog), `ec_finality` (derinlik politikası). Budlum'un `StorageAttestation` domainiyle karıştırılmamalı: orası B.U.D. kanıtı, burası yabancı bir ağın uzay kanıtı.

## 5. Rollup / DA (yok)

**Neden gerekli:** Web3'ün 2018 sonrası bütün ölçekleme hattı burada. Bir rollup, Budlum için "L2" değil, **kendi kesinliğini üreten bir domain**dir.

**Tasarım:** `Prog` iddiası — `(batch, prev_state_root, new_state_root, proof)`:
- ZK rollup: `proof` bir geçerlilik kanıtıdır; `output = new_state_root`.
- Optimistic rollup: `proof` boştur; iddia, **itiraz penceresi** parametresiyle gelir. Bu, `FinalityStatus::Pending { required_depth, observed_depth }` durumunun zaman karşılığını gerektirir → adaptöre `challenge_window_blocks` parametresi.
- DA: veri erişilebilirliği bir *iddia* değil, bir *yayın taahhüdüdür*: `H(batch_data)` Budlum'da saklanmıyorsa, `Prog` iddiası yalnız "veriyi gördüm" demez; "verinin kökü şu" der. Veri yoksa optimistic iddia doğrulanamaz → fail-closed: **veri taahhüdü yoksa kesinlik yok**.

## 6. Stake / slashing ekonomisi (mevcut yapı üstüne)

Bugün: `PermissionlessRegistry::slash_from_report` (validator/relayer/verifier/storage rolleri), `MIN_REGISTRATION_STAKE = 1_000`, `Network::min_stake()`.

Genişleme üç kural ister:

1. **Kanıt maliyeti < teminat.** Bir adaptör yanlış kesinlik iddia ederse, slash edilen teminat o iddianın açtığı zararı karşılamalı. Formül: `bond ≥ value_at_risk × (1 + itiraz_maliyeti_oranı)`. Bugün bu bağ *yok*; teminat sabit.
2. **İtiraz penceresi = kanıt üretim süresi × 2.** Optimistic ailelerde pencere, `prove_tick` + `prove_merge` süresinin iki katından kısa olamaz; aksi hâlde itiraz edecek düğüm kanıtı yetiştiremez.
3. **Çapraz domain kesintisi.** Bir domain'in kesinlik iddiası çürütülürse, slash o domain'in *relayer bond*'una gider; domain'in kendi iç stake'ine Budlum dokunamaz (egemenlik ilkesi). Bu, `src/settlement/shared_security.rs` ile birleştirilecek tek noktadır.

## 7. Neden bu sıra

| Öncelik | İş | Gerekçe |
|---|---|---|
| 1 | `src/aggregation/` (yazıldı) | Her ailenin kanıtı aynı çerçeveye girmek zorunda; bu olmadan yeni adaptör eklemek blok boyutunu büyütür |
| 2 | Tendermint/IBC adaptörü | En büyük tek ekosistem boşluğu; şablon net (2/3 commit + set değişimi) |
| 3 | Bitcoin SPV adaptörü (retarget + derinlik) | Jenerik PoW adaptörü var; fark küçük, kazanç yüksek |
| 4 | `FinalityStatus`'a ağırlık/süre varyantları | DAG ve optimistic rollup, bugünkü enum'a *ifade edilemediği için* giremiyor |
| 5 | Rollup/DA adaptörü | En yüksek etki, en yüksek belirsizlik |
| 6 | PoH/PoSpace | Niş; ama aynı `Prog` şablonu |
