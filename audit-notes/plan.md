# Plan

Bu dosya `BUDLUM_DENETIM_DIREKTIFI` Asama 0 ciktisidir. Plan bir kontrol listesidir.
Her satir bir is birimidir. Is bitince isaretlenir, Asama 11 te turnu basinda
isaretler kaldirilir.

## 1. Acik PR listesi (canli, 13-11-2026)

| PR | Baslik | Kaynak dal | Hedef dal | Head SHA | Mergeable | Durum |
|----|--------|------------|-----------|----------|-----------|-------|
| #126 | testnet | `testnet` | `testnet-quantum` | `8b5592af` | true | blocked |
| #110 | Testnet and Quantum | `testnet-quantum` | `main` | `55ec2f7b` | true | blocked |

Yigin: `testnet` -> `testnet-quantum` -> `main`. Iki PR ayni yiginin iki
halkasidir. #126'ya atilan her commit #110'a tasinir.

Yigin disinda baska acik PR yok. Bu calisma icin acilan yeni PR yigina girmez
(direktif bolum 7.1).

## 2. Isletim sistemleri

| Sistem | Surum | Edinme yolu | Durum |
|--------|-------|-------------|-------|
| Ubuntu | 24.04 LTS | konteyner | sirada |
| Debian | 12 | konteyner | sirada |
| Fedora | 41 | konteyner | sirada |
| Arch Linux | rolling | konteyner | sirada |
| Alpine | 3.21 | konteyner | sirada |
| macOS | 14 | VM | sirada |
| Windows | 11 (WSL2) | VM | sirada |

Ubuntu zorunlu maddelerden biridir. Her sistem icin bir bulgu dosyasi:
`audit-notes/findings/<sistem>.md`.

## 3. Denetlenecek dizinler ve moduller

Kapsam `main` dalidir (340 kaynak dosya). `testnet` dalinda ayni agac 568
dosyaya cikar, cunku yiginin alt halkalari tum testnet isini tasir.

### 3.1 Konsensus

- [ ] `src/consensus/` (7 dosya): PoW, PoS, BFT, izole PoA
- [ ] `src/chain/` (8 dosya): blok, finality, handoff, snapshot
- [ ] `src/validators/` (main'de yok, testnet'te var): komite, PoP
- [ ] Alanlar arasi sizinti: her modulun durum yazma yuzeyi

### 3.2 Settlement primitifleri

- [ ] `src/cross_domain/` (32 dosya): DomainFinalityAdapter, GlobalBlockHeader,
      ReplayNonceStore, CrossDomainMessage, BridgeState, DomainStatus
- [ ] `BDLM_DOMAIN_COMMITMENT_V1` hash etiketi tutarliligi
- [ ] `src/settlement/` (testnet'te): domains, graft, shared_security

### 3.3 BudZero ve BudZKVM

- [ ] `budzero/` (pul_air, trace matrisi, AIR kisitlari, opcode davranisi)
- [ ] `VerifyMerkle` 64 derinlik uretimde kapali mi
- [ ] `src/execution/` (4 dosya) ve `execution/` isci crate'leri

### 3.4 Cuzdan cekirdegi

- [ ] `crates/wallet-core/`: anahtar yonetimi, imzalama, RPC istemcisi
- [ ] BIP39 + SLIP-0010 ed25519 turetimi
- [ ] Adres = Ed25519 genel anahtarinin SHA3-256 ozeti
- [ ] PoA akisinin izinsiz akistan izolasyonu

### 3.5 Depolama

- [ ] `src/storage/` ve `src/storage/bud3/`: icerik adresleme,
      Reed-Solomon, shard yerlestirme, sifreleme
- [ ] `src/domain/` (15 dosya): storage_deal, storage_tx
- [ ] Baglanti (wiring) durumu

### 3.6 Ekosistem modulleri

- [ ] `src/ai/` (8 dosya)
- [ ] `src/lubot/` (main'de yok ise atlanir, gerekce yazilir)
- [ ] `src/pollen/` (4 dosya)
- [ ] `src/socialfi/`
- [ ] `src/bns/` (3 dosya ve testnet'te 5)
- [ ] `src/budlumxyz/` (2 dosya)

### 3.7 CI ve tedarik zinciri

- [ ] `.github/workflows/`: izinler, secret kullanimi, aksiyon surumleri
- [ ] `BADGE_PUSH_TOKEN` riski
- [ ] `supply-chain/`, `osv-scanner.toml`, `cargo-vet`

### 3.8 Diger

- [ ] `src/core/` (14 dosya), `src/crypto/` (7), `src/network/` (10)
- [ ] `src/rpc/` (4), `src/registry/` (14), `src/relayer/` (3)
- [ ] `src/mempool/`, `src/light_client/`, `src/privacy/`, `src/sharding/`
- [ ] `src/account_abstraction/`, `src/deed/`, `src/prover/`, `src/sdk/`
- [ ] `xtask/` (gate'ler), `ops/`, `contracts/`, `fuzz/`, `kani/`
- [ ] `Cargo.toml`, `clippy.toml`, `rust-toolchain.toml`, `build.rs`

## 4. Asama sirasi

- [ ] Asama 0: plan, dal, klasor, PR
- [ ] Asama 1: durum tespiti, PR diff okumasi
- [ ] Asama 2: Strix bulgularinin toplanmasi, defter
- [ ] Asama 3: bulgularin cozulmesi (56 kayit)
- [ ] Asama 4: cozum bildirimi, yorumlarin silinmesi
- [ ] Asama 5: Strix onayi
- [ ] Asama 6: merge kapilari
- [ ] Asama 7: merge
- [ ] Asama 8: kapsamli denetim (bu plandaki her dizin)
- [ ] Asama 9: her isletim sisteminde calistirma
- [ ] Asama 10: testnet maddelerinin insasi
- [ ] Asama 11: tekrar

## 5. Olcum

Her turda su sayilar `audit-notes/report.md` dosyasina yazilir:

- Acik Strix bulgusu sayisi (hedef 0)
- Acik kendi bulgum sayisi (hedef 0)
- Planda isaretsiz dizin sayisi
- Yesil CI kosusu sayisi (kanit: SHA + run numarasi)
