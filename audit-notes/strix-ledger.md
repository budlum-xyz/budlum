# Strix bulgu defteri

Bu dosya açık PR'lar üzerindeki Strix bulgularını, mevcut ucu (aa3529c)
üzerinde teker teker incelenmiş halde yazar. Her bulgu için konum,
önem, ne oldu, neden önemli, çözüm ve durum yazılır.

Uc: `aa3529c` (`budlum-stack`). Önceki kayıtlar `13ae9a55`, `dc90927` ve
`eb5504f` uclarına aittir.

## Özet

- PR #126 (testnet): 8 HIGH, 22 MEDIUM, 10 LOW.
- PR #164 (garden): 2 HIGH, 7 MEDIUM, 3 LOW.
- HIGH bulguların 7 tanesi uçta kod ile çözülmüş. 1 tanesi (Garden 1015)
  Garden'ın güven modeline göre açıklanmış; bu dosya o gerekçeyi yazar.

## PR #126 HIGH

### B-0001 · SVM mint ve hesap ezmesi · `src/execution/coordinator/svm_ee.rs`

- **Önem:** HIGH (CWE-862).
- **Ne:** `SplMintTo` çağrıyı yetkisiz araca kredi yazıyordu.
- **Uçtaki durum:** `SplMintTo` artık mint kaydının `authority` alanını
  okur ve `caller_pk` ile karşılaştırır; uyuşmazsa `Revert` döner.
  `SplInitializeMint` mint adresini `caller_pk`'ten türetir. ATA oluşturma
  var olan hesabı "associated token account already exists" diye reddeder.
- **Durum:** kod ile çözüldü.

### B-0002 · EVM bellek genişlemesi ölçülmezdi · `src/execution/coordinator/evm_ee.rs`

- **Önem:** HIGH.
- **Ne:** Bir işlem düşük maliyetle süreci abort edebilirdi.
- **Uçtaki durum:** `MAX_EVM_MEMORY_BYTES` sabiti ve
  `memory_expansion_gas` karesel ücreti uygulanmış.
- **Durum:** kod ile çözüldü.

### B-0003 · Android sabit token · `mobile/android/.../KeystoreKeyVault.kt`

- **Önem:** HIGH (CWE-306).
- **Ne:** Sahip harcama kapısı sabit bir dizgeyle karşılanıyordu.
- **Uçtaki durum:** `requireOwnerSpendAuthorization` her çağrıda
  `SecurityException` fırlatır; parametre `@Suppress("UNUSED_PARAMETER")`
  ile işaretsiz kalır.
- **Durum:** kod ile çözüldü.

### B-0004 · Move varlık sınıfı · `contracts/object-layer/move/sources/settlement_endpoint.move`

- **Önem:** HIGH.
- **Ne:** Depozito kapısının varlık sınıfı bağlanmamış.
- **Uçtaki durum:** `deposit_fa` ve `deposit_token` `abort E_NOT_OPEN`
  döndürür; yani bu uçta açık değil. SVM tarafında ATA ve mint yetkisi
  B-0001'de kapatılmış.
- **Durum:** kod ile kapandı (kapı kapalı).

### B-0005 · Seat eşiği ile finalize · `src/chain/finality.rs:1014`

- **Önem:** HIGH (CWE-863).
- **Ne:** Koltuk eşiği, asgari paya sahip bir koalisyonun tek başına
  finalize etmesine izin verebilirdi.
- **Uçtaki durum:** `check_prevote_quorum` ve `check_precommit_quorum`
  hem `quorum_seats()` hem `quorum_stake()` şart koşar. Stake eşiği
  silinmemiş. `try_produce_cert` ve `verify_with_committee` de aynı iki
  koşulu kullanır.
- **Durum:** kod ile çözüldü.

### B-0006 · `seat_participation` sahteciliği · `src/validators/committee.rs:141`

- **Önem:** HIGH (CWE-345).
- **Ne:** Önereni, katılım kaydını belgelenmemiş şekilde değiştirebilirdi.
- **Uçtaki durum:** `SeatParticipation::verify_against_signers` var ve
  `last_seat_participation` yalnızca bu doğrulamadan geçer. Arsiv
  yinelemesi (`derive_seat_table_for_checkpoint`) bir QC blob'u varsa
  kaydı blob'un doğrulanmış imzacılarından yeniden üretir; eşle blob yok
  ve anlık görüntüde anahtar yoksa kaydı kullanır. Yani bir anlık
  görüntüde anahtar olduğu sürece eş blob zorunludur.
- **Durum:** kod ile çözüldü.

### B-0007 · EVM `CALL` değer operandı · `src/execution/coordinator/evm_ee.rs`

- **Önem:** MEDIUM.
- **Uçtaki durum:** `CALL` değer operandını açıyor ve `CALLVALUE`
  üretiyor; işlem içinde değer transferi uygulanmış.
- **Durum:** kod ile çözüldü (tam içerik MEDIUM defterinde).

### B-0008 · Android sabit operatör anahtarı · `mobile/android/.../MainActivity.kt`

- **Önem:** MEDIUM.
- **Uçtaki durum:** operatör anahtarı artık sabit tohumdan değil, cihaz
  içinde üretilen bir tohumdan geliyor.
- **Durum:** kod ile çözüldü.

## PR #164 HIGH

### B-0009 · Garden yokluk raporu · `src/garden/state.rs:471`

- **Önem:** HIGH.
- **Ne:** Tek bir üye, kanıtsız bir yokluk raporuyla Garden'ı sonsuza
  dek durdurabiliyordu.
- **Uçtaki durum:** `apply_tx` bir `Suspend` yalnızca blok liderinden kabul
  eder (`leader != Some(&sender)` ise `Revert`). `check_tx` aynı kurala
  uyar, yani böyle bir rapor havuza giremez. `assemble` de yabancı raporları
  atar.
- **Durum:** kod ile çözüldü.

### B-0010 · Garden eşiği bloktan türetiliyor · `src/garden/state.rs:1015`

- **Önem:** HIGH.
- **Ne:** Bir blok, onu yargılayan küme seçebiliyordu.
- **Uçtaki durum (gerekçe):** Garden, ev sahibi (host) güven köklü bir
  odadır. Ev sahibi zaten `Leave` ile odayı dondurur (Frozen), üyeleri
  tek başına kabul eder ve odayı emekliye ayırır. Bir lider artı ev sahibi
  bir üyeyi çıkarabilse de, ev sahibi tek başına zaten aynı ve daha fazla
  güce sahiptir; bu yüzden saldırı yeni bir güç kazandırmaz. Kalan risk,
  göreve büyük oda tanımınde yer alan güven sayısıdır ve bu bir kod
  güvenliği sorunu değil bir güven modelidir.
- **Kanıt:** `src/garden/state.rs` içinde ev sahibi tek başına donma ve
  emeklilik yolunun varlığı; `electorate` fonksiyonunun rapor hedefini
  çıkarması.
- **Durum:** açıklanmış (kod değişikliği yok). Bir sonraki adım: bu
  güven modelini `docs/` altında yazılı hale getirmek.

## MEDIUM ve LOW

22 MEDIUM ve 10 LOW bulgu şu an için defterde tutuluyor. Öncelik sırası:
önce bu dosyanın alta kalanındaki üç konu (PoSpace+VDF, restaking ölçüsü,
çok-yükseklikli ışık istemcisi), sonra MEDIUM'lar.

---

# Üçüncü tur: uç `027296e`

Bu bölüm, `aa3529c`'dan sonra uça gelen 11 commit'in doğrulamasını yazar.
Uç: `027296e` (`budlum-stack`).

## B-0012 · Dört yeni adaptörün hiçbirine giriş yolu yok

- **Yer:** `src/cross_domain/external/{based_preconf,ton_catchain,mina_recursive,stellar_fba}.rs`
- **Önem:** MEDIUM.
- **Ne:** Dört yeni `ExternalFinalityAdapter` implementasyonu (~4600 satır)
  eklendi. Hiçbirinin `AdapterSpec`'e karşılık gelen bir variantı yok,
  `IntakeState`'te pin haritası yok, `core/transaction.rs` ve
  `settlement/universal_finality.rs` içinde eşleme yok. Modül ve domain
  tag olarak duruyorlar; `mod.rs` dışında tek bir referansları yok.
- **Neden önemli:** Bir adaptör, bir konsensüs alanının
  (`ConsensusDomain`) kaydını yapmak için bir `AdapterSpec` variantı
  üretmelidir. Bu dördü, kütüphane kodu olarak doğru olabilir ama ağın
  giriş kapısından geçemez. Eleştiri, "adaptör var" demekle "giriş kapısı
  var" demek aynı şey mi, sorusuna cehipsiz.
- **Kanıt:** `grep -rn AdapterSpec:: src/ | grep -v intake.rs` içinde
  tam 7 variant. Dört yeni adaptör adının `mod.rs` dışında referansı yok.
- **Durum:** açık. Öneri: ya bu dördünü `AdapterSpec`'e (en sona tag 7-10)
  eklemek ve pin + giriş kapısını yazmak, ya da bu commit'i madde olarak
  bölmek. Bir adaptörü "bildirmek" için bir test yeterli.

## B-0013 · `BeaconBinding::period` kullanılmayan bir sınıf üye

- **Yer:** `src/cross_domain/evm/sync_committee.rs:671`
- **Önem:** LOW (CI kırması).
- **Ne:** `period()` yalnızca testler içinde çağrılıyor. `cargo check --lib`
  bir `dead_code` uyarısı veriyor. CI kapısı `-D warnings` olduğu için
  lib hedefinde bu uyarı kırmaya işaret.
- **Kanıt:** `grep -rn "\.period()" src/` içinde dört test çağrısı; test
  dışı çağrı yok. `cargo check --lib --all-targets` çıktısı 1 uyarı.
- **Durum:** açık. Öneri: `#[cfg(test)]` kapsamına almak ya da
  üretim yolundaki üç komite dönüşümünde kullanmak.

## B-0014 · Kesilen (slashed) bir prover rejemede kendini yedekleyemiyor

- **Yer:** `src/cross_domain/external/registry.rs:719` (`bond_prover`),
  `src/cross_domain/external/external_tx.rs` (`BondProver` kapısı).
- **Önem:** MEDIUM.
- **Ne:** `bond_prover` yalnızca **yeni** bir prover kapısıdır: önce
  `bond_atoms < required` olup olmadığına bakılır, sonra
  `provers.contains_key(&prover)` → `ProverAlreadyBonded`. Kayıt
  sırasında poster zaten prover olarak eklenir (`register`, satır 285).
   Bir kesilen prover için iki engel bir araya gelir: kendi çağrısı
  `ProverAlreadyBonded` ile reddedilir, üstelik tutar da **tabanın
  tamamına** göre ölçülür, eksiğe göre değil.
- **Neden önemli:** `readmit`, canlı toplamın (`live_total`) tabanın
  altında olmasında ancak önceden kesilmiş bir domaine bir **ikinci**
  prover taban kadar sermaye koyduğunda mümkündür. Bu ekonomik olarak
  savunulabilir; savunulamaz olan, ucun kendi testinin bunu yapamayacağını
  söylemesidir.
- **Kanıt:** `register_seeds_crqc_isolation_and_readmit_blocks_isolated_or_underbonded`
  ucutta kırmızıydı: `Intake("the posted bond 1000 is below the required
  100000")`. Test 1_000 posting ediyordu; taban
  `conservative_economics(1_000_000)` için `1_000_000 * 1/10 = 100_000`.
- **Durum:** test, gerçek kapı kurallarıyla hizaya getirildi (kendi
  prover'ının `ProverAlreadyBonded` ile reddedilmesi; ikinci bir prover
  taban koyduğunda readmit geçmesi). `external_tx` 18/0. Eksik **top-up
  kapısı** tasarım önerisi olarak açık: `bond_prover` tutarı eksikliğe
  göre ölçüp mevcut kaydı güncellediğinde kesilen prover tek başına
  yedekleyebilir; ekonomik etkisi bir karar gerektirir.

## B-0015 · `cargo fmt --check` ucun kırmızı

- **Yer:** `src/core/governance.rs`, `src/cross_domain/external/intake.rs`,
  `src/cross_domain/external/tendermint.rs` (12 fark).
- **Önem:** LOW (CI kırması).
- **Ne:** Uç, rustfmt 1.97.1 ile biçimli değil. `cargo fmt --check` bu üç
  dosyada 12 fark veriyor. CI'in `fmt` işi kırmızı.
- **Kanıt:** `git stash` ile dışarıda bırakıp `cargo fmt --check` koşmak üç
  dosyayı da buluyor (yani benim değişikliğimle açılmış değil).
- **Durum:** `cargo fmt` ile 12 fakın tamamı biçimlendirildi; beraberinde
  gelen iki dosya (governance.rs, intake.rs) bu sebeple değişikliğe
  girdi. Semantik değişikliği yok.

## B-0016 · `evm_ee` işaret (pointer) testi artık var olmayan bir kapıya
giden kurulumuyu soruyor

- **Yer:** `src/execution/coordinator/evm_ee.rs`, test
  `delegatecall_and_callcode_into_precompiles_or_pointer_tokens_revert`.
- **Önem:** MEDIUM (CI kırması).
- **Ne:** Test, işaret (pointer) bytecode'u `EvmEe::execute(Deploy)` ile
  kuruyor. `validate_deploy` artık `is_pointer_bytecode_prefixed` olan
  kodu `InvalidCode` ile reddediyor ("system pointer bytecode prefix is
  reserved for uel/assets"). Test bu yüzden `deploy()` yardımcısının
  `assert_eq!(res.status, Success)` satırında patlıyordu; test adının
  sorduğu DELEGATECALL/CALLCODE reddi hiç sormuyordu.
- **Neden önemli:** Reddin nedeni, testin iddiasından bağımsız bir
  değişiklik; test sabit bir saldırı senaryosunu çalıştırmıyor.
- **Kanıt:** test tek başına kırmızı: `left: InvalidCode, right: Success`
  (`evm_ee.rs:3222`). Aynı değişiklik `conformance_tests` içinde
  `forged_or_misplaced_pointer_bytecode_is_refused` ile bilinçli ve
  belgelenmiş.
- **Durum:** test, işareti artık gerçek kurulum kapısıyla yerleştiriyor
  (`NS_EVM_CODE`/`NS_EVM_ACCOUNT`) ve ham `Deploy` kapısının reddettiğini
  ayrıca kilitliyor. `execution::coordinator::evm_ee` 8/0.

## B-0012 (genişletme) · Beşinci yetim adaptör: `pospace_vdf`

- **Yer:** `src/cross_domain/external/pospace_vdf.rs` (1319 satır),
  `mod.rs:95,145-148`.
- **Ne:** Uç `d8d3f01` PoSpace + VDF adaptörünü ekledi ("GOREV-13,
  GOREV-21"). `PoSpaceVdfAdapter` `mod.rs` içinden `pub use` ediliyor ama
  `mod.rs` dışında **tek bir referansı yok**; `AdapterSpec`'e variant yok,
  pin haritası yok, `core/transaction.rs` / `settlement/universal_finality.rs`
  eşlemesi yok. Önceki dört yetimle aynı örüntü.
- **Not:** Bu, `07-konsens-us-tarihi.md`'deki "eksik üç şey"den birinin
  **kodunun yazıldığı** ancak **giriş kapısının bağlanmadığı** anlamına
  gelir. Adaptör kütüphane olarak doğru olabilir; ağın kayıt kapısından
  geçemez.
- **Durum:** açık. Öneri: `AdapterSpec`'e en sona bir variant (tag 7) ve
  `pinned_pospace_anchors` + giriş kapısı. Bu dördü + bu biri için tek bir
  serbest değişken (campaign) olarak yapılması iyi olur.

## B-0017 · Uç `d8d3f01` clippy kapısını yeniden kırmızı yapmış

- **Yer:** dört dosya, dört lint.
- **Ne:** `d8d3f01` (~5300 satır yeni kod: PoSpace+VDF adaptörü, ULP-1,
  ışık istemcisi) clippy kapısını yeniden kırmızı yapmış:
  1. `src/cross_domain/external/pospace_vdf.rs:1002` — `mine_valid_block`
     9 argüman (`too_many_arguments`).
  2. `src/settlement/shared_security.rs:1540` — `.get(&val_a).is_none()`
     (`unnecessary_get_then_check`).
  3. `src/tests/bitcoin_spv.rs:721` — `assert!(MAX_STARK_BATCH_HEADERS >= 6)`
     (`assertions_on_constants`).
  4. `src/light_client/mod.rs:2338` — `vec![...]` tek öğeli dizi
     (`useless_vec`).
- **Neden önemli:** Kapı her seferinde yeniden kırmızı oluyor; bu, kapıın
  ucu gerçekten koruyamadığının kanıtı.
- **Durum:** dördü de düzeltildi. `cargo clippy --no-default-features
  --features "pq-ml-dsa wallet-ml-dsa" --all-targets -- -D warnings` temiz.
