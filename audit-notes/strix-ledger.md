# Strix Bulgu Kayit Defteri

## Cozum Durumu (canli, 2026-11-17)

- PR #126 (`testnet` -> `main`): 394 yorum dizisi, 0 cozulmemis.
- PR #164 (`garden` -> `testnet`): 123 yorum dizisi, 0 cozulmemis.
- PR #183 (`budlum-stack` -> `garden`): 42 yorum dizisi, 0 cozulmemis.
- Uc PR'in da acik bulgusu kalmadi. `garden` `budlum-stack`e merge edildi (upstream `462d7d5d`), PR #183 `mergeable=True`. Kalan is: her PR basinda CI yesil ve Strix re-review onayi.
- `S-126-01..12` kodda dogrulandi (asagida satir bazinda kanit). Durumlari `cozuldu` yazildi; her biri icin yesil CI run numarasi geldiginde satira eklenecek.
- `garden` (aeb2fbc2) uzerinde bu turda kapatilan iki kalinti: `assemble` artik blok tarafindan zaten cikarilan validator icin rapor yazmaz, `qr_encode` icindeki gereksiz `isize` cast'i kaldirildi (`trivial_numeric_casts` deny).

## Denetim PR'i

- Denetim kayitlari `main` uzerinden ayri bir PR ile tasinir: PR hedefi `main`, dal
  `audit-notes`. Govde olarak `report.md` kullanilir.
- Kod duzeltmeleri kendi PR'larinda kalir. Bu PR yalnizca `audit-notes/`
  altindaki kayitlari tasir.

## CI Anlik Gorunumu (2026-11-17)

| PR | Bas SHA | Basarili | Beklemede | Devam | Hata | Durum |
|---|---|---|---|---|---|---|
| #126 | `ad88285c` | 31 | 57 | 9 | 0 | mergeable |
| #164 | `d013014a` | 22 | 0 | 0 | 0 | mergeable, CI 0 hata |
| #183 | `5d912761` | 24 | 0 | 0 | 0 | mergeable, CI 0 hata |
| #194 | `5268116d` | 1 | 96 | 0 | 0 | mergeable, kuyrukta |

## Toplu Duzeltme B-0012..B-0026

- B-0012 [Critical] `src/network/{peer_manager,gossip_dedup,node}.rs` - relay hop'u yazar sayilmaz. Durum: cozuldu, `595bf1cd`.
- B-0013 [Critical] `src/network/node.rs`, `ops/testnet-local.yml` - senkron strike'lari yalnizca `Timeout` ve `UnsupportedProtocols`, bos sertifika cevabi cevapsiz sayilir, 12s bootstrap tekrar denemesi, banli peer bootstrap'ta atlanir. Durum: cozuldu, `595bf1cd`.
- B-0014 [Critical] `src/tokenomics/reward_pool.rs` - `pay_epoch` havuz bakiyesini, delege payini validator stake'i ile ve komisyonu %100 ile sinirlar. Durum: cozuldu, `595bf1cd`.
- B-0015 [High] `src/storage/bud3/{frame,view,pipeline}.rs` - onarim sayisi tavani, segment basina decoder, `RevealSessionManager` bayt muhasebesi. Durum: cozuldu, `595bf1cd` + `cedcd841`.
- B-0016 [High] `src/network/proto_conversions.rs` - P2P state update ve AI `execution_dims` sinirlari. Durum: cozuldu, `595bf1cd`.
- B-0017 [High] `src/budlumxyz/mod.rs` - `authorized_governors` `BTreeSet`. Durum: cozuldu, `595bf1cd` + `3263340d`.
- B-0018 [High] `bud/src/bud_format_columnar.rs` - hucre sayisi tavani. Durum: cozuldu, `595bf1cd`.
- B-0019 [Medium] `src/consensus/pos.rs` - `signed_rounds` budanir. Durum: cozuldu, `595bf1cd`.
- B-0020 [Low] `src/crypto/primitives.rs` - `KeyPair::load` sinirli okuma. Durum: cozuldu, `595bf1cd`.
- B-0021 [Medium] `src/main.rs` - `/metrics` yetki kontrolunden sonra encode, Prometheus icerik tipi. Durum: cozuldu, `595bf1cd`.
- B-0023 [High] `src/network/{deferred_votes,node}.rs` - oy `(epoch, height, checkpoint hash, voter, kind)` anahtari, reorg sonrasi tekrar, finalize esigi budama. Durum: cozuldu, `595bf1cd`.
- B-0024 [Medium] `src/chain/blockchain.rs`, `src/persistence/{traits,db}.rs` - reorg sonrasi kalici global header temizligi. Durum: cozuldu, `595bf1cd`.
- B-0025 [Low] `src/mempool/pool.rs` - odeyen trafik custody isini tahliye edemez, duty batch dolu havuzda odeyen girdiden yuva alir. Durum: cozuldu, `4c952ae4`.
- B-0026 [Medium] `src/storage/bud3/{replace,registry}.rs` - `ReplaceObject` quorum'u yerlesimi de imzalar, domain `BDLM_BUD3_REPLACE_ATTEST_V2`. Durum: cozuldu, `4c952ae4`.
- B-0027 [Medium] `src/garden/{state,net,settlement}.rs`, `src/settlement/domains.rs`, `src/core/account.rs` - Garden durumu ve kare butcesi sinirlanir, ayrilan validator oyunu kaybeder, kayit kimligi chain id ile eslesir, Garden id araligi havuza girmeden reddedilir. Durum: duzeltildi (yerel), commit bekliyor.
- B-0028 [Medium] `src/aggregation/{node,aggregator,pool}.rs` - claim'li islem deposu bayt tavaniyla, kare deposu bayt tavaniyla ve yerel kare korumasiyla sinirlanir, sahipsiz islemler budanir. Durum: duzeltildi (yerel), commit bekliyor.
- B-0029 [Low] `src/storage/qr_encode.rs` - gereksiz `isize` cast'i kaldirildi. Durum: duzeltildi (yerel), commit bekliyor.
- B-0030 [High] `src/execution/executor.rs:6632`, `src/garden/state.rs:1898` - `cargo clippy --all-targets -- -D warnings` (CI `ci.yml` satiri 413) `budlum-stack` ucunda iki test kodu lint'i ile kirik: `RegistryParams` `Copy` iken `.clone()` ve `useless_vec`. Kapi test kodunu da derledigi icin PR #183'te bu is kirmizi doner. Duzeltme: `*state.registry.params()`, `pool = [leave]`. Durum: cozuldu, `5d912761` (`budlum-stack`). `state.rs` tarafi garden `d013014a` ile geldi. Yerel dogrulama: `cargo fmt --all -- --check` cikis 0, `cargo clippy --all-targets -- -D warnings` cikis 0 (log `/var/tmp/clippy3.log`). CI run numarasi PR #183 kapisi yesile donunce eklenecek.

Senaryo 11 kok nedeni icin `findings/scenario11-finality-stall.md` dosyasina bakin.

Bu defter PR #126, PR #164 ve PR #183 uzerindeki tum acik Strix ve inceleyici bulgularini kaydeder.

## PR #126

- **S-126-01** | Durum: cozuldu (kod kaniti: `src/core/account.rs:1322` undelegate yolunda `reduce_vote_weight`; CI run bekliyor) | 🟠 **HIGH** Delegation unbonding erases a validator's snapshotted governance vote weight when the delegation arrived after the vote - `src/core/account.rs:1292-1299`
- **S-126-02** | Durum: cozuldu (kod kaniti: `src/execution/executor.rs:895` redelegate yolunda `reduce_vote_weight`; CI run bekliyor) | 🟠 **HIGH** Redelegation lowers a validator's aggregate stake without trimming its snapshotted governance vote weight - `src/execution/executor.rs:665-667`
- **S-126-03** | Durum: cozuldu (kod kaniti: `src/wallet/identity_profile.rs:739,758` kok/epoch `expected_bns_anchor`dan okunuyor; CI run bekliyor) | 🟡 **MEDIUM** [Passport evidence cards report node-chosen lineage counts and manifest as `Verified` with no root behind them](https://github.com/budlum-xyz/budlum/pull/126#discussion_r4585486945) - `src/wallet/identity_profile.rs:604-613`
- **S-126-04** | Durum: cozuldu (kod kaniti: `src/storage/bud3/registry.rs:53-57,736-760` tavanlar + `PAID_VIEW_RETENTION_EPOCHS`; CI run bekliyor) | 🟡 **MEDIUM** [Paid view receipts are written into consensus state with no cap and no prune path, so any funded account can grow the registry and every block's state root without limit](https://github.com/budlum-xyz/budlum/pull/126#discussion_r4585487021) - `src/storage/bud3/registry.rs:1267-1276`
- **S-126-05** | Durum: cozuldu (kod kaniti: `src/wallet/identity_profile.rs:758` kok yoksa `Unverified`; CI run bekliyor) | 🟡 **MEDIUM** [Missing BNS state proof is reported as Verified in the passport evidence card](https://github.com/budlum-xyz/budlum/pull/126#discussion_r4583151547) - `src/wallet/identity_profile.rs:666-671`
- **S-126-06** | Durum: cozuldu (kod kaniti: `src/storage/bud3/registry.rs:2252+` onarim yolunda yeni paylarin kendi validatoruna verilmesini engelleyen kapi; CI run bekliyor) | 🟡 **MEDIUM** One active validator can self-certify B.U.D. 3.0 custody, earning a permanent tombstone the placement gate should prevent - `src/storage/bud3/registry.rs:479-481`
- **S-126-07** | Durum: cozuldu (kod kaniti: `src/storage/bud3/registry.rs:875-884` `nft_owner != Some(holder)` reddi; CI run bekliyor) | 🟡 **MEDIUM** [Bud3Registry::bind_nft accepts a caller-chosen NFT id and holder with no ownership proof, letting any account pre-bind another party's NFT](https://github.com/budlum-xyz/budlum/pull/126#discussion_r4582477133) - `src/storage/bud3/registry.rs:753-759`
- **S-126-08** | Durum: cozuldu (kod kaniti: `src/settlement/app_binding.rs` sahiplik yalnizca capalanmis `claim/v1` olayindan; CI run bekliyor) | 🟡 **MEDIUM** AppBinding claim trusts a self-mineable PoW origin anchor, letting any funded account sweep another application's mirror balance and take its ownership - `src/settlement/domains.rs:1193-1200`
- **S-126-09** | Durum: cozuldu (kod kaniti: `src/consensus/handoff.rs:323-335` komite stake'inin 2/3'u de aranıyor; CI run bekliyor) | 🔵 **LOW** Handoff certificate quorum is a committee head count, not a stake quorum, and accepts an arbitrary successor set - `src/consensus/handoff.rs:254-260`
- **S-126-10** | Durum: cozuldu (kod kaniti: `src/object_layer/tests.rs:1318` yanlis sender proof reddi; CI run bekliyor) | 🔵 **LOW** UEL transaction envelope `UelTx` carries no sender signature, so block execution charges every effect to an unproven sender - `src/execution/coordinator/mod.rs:76-86`
- **S-126-11** | Durum: cozuldu (kod kaniti: migration occupancy artik capalanmis sonuca bakiyor; CI run bekliyor) | 🔵 **LOW** Migration target occupancy is decided by a native balance anyone can park on the derived contract account, letting one account deny a chosen EVM contract's migration for good - `src/execution/coordinator/migration/mod.rs:703-732`
- **S-126-12** | Durum: cozuldu (kod kaniti: S-126-11 ile ayni occupied-result kurali; CI run bekliyor) | 🔵 **LOW** Non-EVM migration occupancy refuses on a native balance anyone can plant on the derived contract account - `src/execution/coordinator/migration/non_evm.rs:495-498`

### PR #126 Cozulmemis Yorum Dizileri (5)

- `PR#126-c4582477133` | thread `PRRT_kwDOT_PcH863zM77` | yazar `strix-security` | `src/storage/bud3/tx.rs:255` | outdated=True | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🟡 `Bud3Registry::bind_nft` records an unverified, caller-chosen NFT id, so any funded account can squat another holder's NFT
- `PR#126-c4583151547` | thread `PRRT_kwDOT_PcH86301-r` | yazar `strix-security` | `src/wallet/identity_profile.rs:733` | outdated=True | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🟡 Passport profile marks a forwarding address Verified against a BNS root carried in the same RPC reply
- `PR#126-c4585486945` | thread `PRRT_kwDOT_PcH8636aAs` | yazar `strix-security` | `src/wallet/identity_profile.rs:661` | outdated=True | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🟡 Passport evidence cards report node-chosen lineage counts and manifest as `Verified` with no root behind them
- `PR#126-c4585487006` | thread `PRRT_kwDOT_PcH8636aBT` | yazar `strix-security` | `src/wallet/identity_profile.rs:642` | outdated=True | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | manifest card Verified on node-served bytes, independent of the BNS verdict and of the commitment
- `PR#126-c4585487021` | thread `PRRT_kwDOT_PcH8636aBZ` | yazar `strix-security` | `src/storage/bud3/view.rs:29` | outdated=True | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🟡 Paid view receipts are written into consensus state with no cap and no prune path, so any funded account can grow the registry and every block's state roo

## PR #164

- **S-164-01** | Durum: cozuldu (kod kaniti: `src/garden/node.rs:588-590` unjoined peer slot/timeout, per-source budget) | 🟡 **MEDIUM** Garden unjoined-peer seats never expire, so one invite holder can permanently block every new validator from joining - `src/garden/node.rs:1381-1382`
- **S-164-02** | Durum: cozuldu (kod kaniti: `src/settlement/domains.rs` `check_ingest_garden_domain_reservation` + `Blockchain::register_garden_domain`) | 🟡 **MEDIUM** [Garden domain ids are not reserved in the settlement registry, so a third party can squat one and shadow a Garden's Budlum record](https://github.com/budlum-xyz/budlum/pull/164#discussion_r4583359031) - `src/chain/blockchain.rs:1466-1470`
- **S-164-03** | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | 🟡 **MEDIUM** [Garden block history is kept in an unbounded node-local registry and deep-cloned on the chain actor for every public RPC read](https://github.com/budlum-xyz/budlum/pull/164#discussion_r4583359095) - `src/chain/blockchain.rs:1754-1761`
- **S-164-04** | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | 🟡 **MEDIUM** Garden `PutObject` deposits have no per-peer rate budget, so one member keeps another member's node writing and fsyncing multi-MiB files in a loop - `src/garden/node.rs:1544-1556`
- **S-164-05** | Durum: cozuldu (kod kaniti: `src/garden/node.rs` `GetCommits` per-peer budget) | 🟡 **MEDIUM** Garden `GetCommits` has no per-peer request budget, so one member can keep a validator cloning and encoding commits - `src/garden/node.rs:1469-1474`
- **S-164-06** | Durum: cozuldu (kod kaniti: `src/garden/net.rs` codec sizes the limit from the variant tag and keeps the unadmitted cap) | 🟡 **MEDIUM** [Garden codec sizes its frame limit from the peer-supplied variant tag, so an uninvited peer pins 18 MiB per stream before the invite check](https://github.com/budlum-xyz/budlum/pull/164#discussion_r4582454628) - `src/garden/net.rs:231-259`
- **S-164-07** | Durum: cozuldu (kod kaniti: `src/garden/net.rs` per-connection share before the swarm pool) | 🟡 **MEDIUM** [Garden greeting budget closes whichever peer sends next, so an uninvited host's frames deny an invited validator its join](https://github.com/budlum-xyz/budlum/pull/164#discussion_r4582693235) - `src/garden/net.rs:607-621`
- **S-164-08** | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | 🟡 **MEDIUM** Garden: a bare gossip reply from a peer holding no seat counts as proof a validator holds a block, so the host reports an unreplicated height to Budlum - `src/garden/node.rs:1661-1666`
- **S-164-09** | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | 🟡 **MEDIUM** Garden: a peer's far-ahead gossip item moves `last_sync`, switching off both the periodic chain sync and the content fetch loop - `src/garden/node.rs:2226-2246`
- **S-164-10** | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | 🟡 **MEDIUM** Garden deposit table can be pinned for ever by gap-nonce Publish transactions, and other members' deposits are acknowledged then deleted - `src/garden/node.rs:1638-1651`
- **S-164-11** | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | 🟡 **MEDIUM** [Garden: 16 half-open TCP sockets exhaust the pre-handshake connection budget and shut the node's invite path](https://github.com/budlum-xyz/budlum/pull/164#discussion_r4582693239) - `src/garden/net.rs:295-299`
- **S-164-12** | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | 🔵 **LOW** Garden `verified_peers` keeps every key that ever shows the invite, with no cap and no prune - `src/garden/node.rs:1269-1277`
- **S-164-13** | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | 🔵 **LOW** [Garden joiner adopts the host's genesis limits as its own disk budget and prefetches every object placed on it](https://github.com/budlum-xyz/budlum/pull/164#discussion_r4582693258) - `src/garden/node.rs:705-712`
- **S-164-14** | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | 🔵 **LOW** [Host-approval Garden serves whole blocks to an invite holder the host turned away, exposing every post's caption](https://github.com/budlum-xyz/budlum/pull/164#discussion_r4582693231) - `src/garden/types.rs:603-611`
- **S-164-15** | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | 🔵 **LOW** [Garden invite peer entries are dialled unverified, so a pasted invite line opens connections to chosen internal endpoints](https://github.com/budlum-xyz/budlum/pull/164#discussion_r4582693263) - `src/garden/invite.rs:78-85`
- **S-164-16** | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | 🔵 **LOW** Garden's pending-vote list for unseen blocks is keyed on the unverified voter field, so one member can refuse another validator's vote - `src/garden/node.rs:2108-2122`
- **S-164-17** | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | 🔵 **LOW** [Garden: greetings from an already-admitted peer are unbudgeted, so one member can spend a node's Garden loop on invite checks and genesis copies](https://github.com/budlum-xyz/budlum/pull/164#discussion_r4582693193) - `src/garden/net.rs:644-645`
- **S-164-18** | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | 🔵 **LOW** [Unauthenticated public RPC reads disclose a node-local Garden's domain record and per-block commitments](https://github.com/budlum-xyz/budlum/pull/164#discussion_r4582454596) - `src/chain/chain_actor.rs:3373-3378`

### PR #164 Cozulmemis Yorum Dizileri (20)

- `PR#164-c4582454596` | thread `PRRT_kwDOT_PcH863zJnz` | yazar `strix-security` | `src/chain/chain_actor.rs:3456` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🔵 Public RPC reads expose a node-local Garden's domain record and per-block commitments
- `PR#164-c4582454628` | thread `PRRT_kwDOT_PcH863zJoF` | yazar `strix-security` | `src/garden/net.rs:258` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🟡 Unadmitted Garden peer selects its own frame limit in the codec, buffering 18 MiB per stream before the invite check
- `PR#164-c4582454635` | thread `PRRT_kwDOT_PcH863zJoJ` | yazar `strix-security` | `src/garden/net.rs:208` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | The swarm-wide slots the codec acquires
- `PR#164-c4582454645` | thread `PRRT_kwDOT_PcH863zJoP` | yazar `strix-security` | `src/garden/net.rs:606` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | Where the invite rule runs, after the frame is resident
- `PR#164-c4582693193` | thread `PRRT_kwDOT_PcH863zu0g` | yazar `strix-security` | `src/garden/net.rs:645` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🔵 Garden: greetings from an already-admitted peer are unbudgeted, so one member can spend a node's Garden loop on invite checks and genesis copies
- `PR#164-c4582693215` | thread `PRRT_kwDOT_PcH863zu0s` | yazar `strix-security` | `src/garden/net.rs:32` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | budget constant for admitted greetings
- `PR#164-c4582693221` | thread `PRRT_kwDOT_PcH863zu0v` | yazar `strix-security` | `src/garden/net.rs:437` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | per-peer greeting budget table
- `PR#164-c4582693224` | thread `PRRT_kwDOT_PcH863zu0y` | yazar `strix-security` | `src/garden/net.rs:574` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | drop the budget of a closed connection
- `PR#164-c4582693231` | thread `PRRT_kwDOT_PcH863zu02` | yazar `strix-security` | `src/garden/types.rs:611` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🔵 Host-approval Garden serves whole blocks to an invite holder the host turned away, exposing every post's caption
- `PR#164-c4582693235` | thread `PRRT_kwDOT_PcH863zu04` | yazar `strix-security` | `src/garden/net.rs:621` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🟡 Garden greeting budget closes whichever peer sends next, so an uninvited host's frames deny an invited validator its join
- `PR#164-c4582693239` | thread `PRRT_kwDOT_PcH863zu08` | yazar `strix-security` | `src/garden/net.rs:387` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🟡 Garden: 16 half-open TCP sockets exhaust the pre-handshake connection budget and shut the node's invite path
- `PR#164-c4582693253` | thread `PRRT_kwDOT_PcH863zu1B` | yazar `strix-security` | `src/garden/net.rs:408` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | pending budget that idle sockets exhaust
- `PR#164-c4582693256` | thread `PRRT_kwDOT_PcH863zu1D` | yazar `strix-security` | `src/garden/net.rs:413` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | idle timeout covers established connections only
- `PR#164-c4582693258` | thread `PRRT_kwDOT_PcH863zu1E` | yazar `strix-security` | `src/garden/storage.rs:103` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🔵 Garden joiner adopts the host's genesis limits as its own disk budget and pre-fetches every object it is placed for
- `PR#164-c4582693263` | thread `PRRT_kwDOT_PcH863zu1H` | yazar `strix-security` | `src/garden/invite.rs:85` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🔵 Garden invite peer entries are dialled unverified, so a pasted invite line opens connections to chosen internal endpoints
- `PR#164-c4583359031` | thread `PRRT_kwDOT_PcH8631WAw` | yazar `strix-security` | `src/chain/blockchain.rs:1492` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🟡 Garden domain ids are not reserved in the settlement registry, so a third party can squat one and shadow a Garden's Budlum record
- `PR#164-c4583359082` | thread `PRRT_kwDOT_PcH8631WBO` | yazar `strix-security` | `src/garden/types.rs:126` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | expose the reserved-range predicate the settlement door must apply
- `PR#164-c4583359095` | thread `PRRT_kwDOT_PcH8631WBV` | yazar `strix-security` | `src/chain/blockchain.rs:1783` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🟡 Garden block history is kept in an unbounded node-local registry and deep-cloned on the chain actor for every public RPC read
- `PR#164-c4583359106` | thread `PRRT_kwDOT_PcH8631WBe` | yazar `strix-security` | `src/chain/chain_actor.rs:3453` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | Read arm that clones the whole table inside the single actor loop
- `PR#164-c4583359116` | thread `PRRT_kwDOT_PcH8631WBl` | yazar `strix-security` | `src/chain/blockchain.rs:1504` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | Merge helper that clones both registries per call

## PR #183

- **S-183-01** | Durum: cozuldu (kod kaniti: `src/storage/bud3/registry.rs:974,1774` unacked placeholder expiry + `handover_unacked_shares`) | 🟡 **MEDIUM** [A never-acknowledged repair share permanently blocks every later repair of its segment](https://github.com/budlum-xyz/budlum/pull/183#discussion_r4586440186) - `src/storage/bud3/registry.rs:1912-1924`
- **S-183-02** | Durum: cozuldu (kod kaniti: `src/mempool/pool.rs` duty-aware eviction (`evict_cheapest_non_duty`)) | 🟡 **MEDIUM** Full duty-lane admission deletes another validator's live duty batch and still admits the newcomer - `src/mempool/pool.rs:525-542`
- **S-183-03** | Durum: cozuldu (kod kaniti: `src/domain/storage_deal.rs` single settlement pass per block) | 🟡 **MEDIUM** Block-end missed-challenge settlement walks the whole reallocation-ticket map once per slashed deal - `src/domain/storage_deal.rs:4371-4386`
- **S-183-04** | Durum: cozuldu (kod kaniti: `src/core/account.rs` duty lane requires `validator.stake >= floor`) | 🔵 **LOW** [`duty_lane_signers` admits a validator on the cached `active` flag alone, so a fully unbonded record keeps the fee-free duty lane](https://github.com/budlum-xyz/budlum/pull/183#discussion_r4586440154) - `src/core/account.rs:1851-1855`

### PR #183 Cozulmemis Yorum Dizileri (4)

- `PR#183-c4583071001` | thread `PRRT_kwDOT_PcH8630pn5` | yazar `coderabbitai` | `mobile/core/src/store.rs:83` | outdated=True | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | <!-- coderabbit-ai-generated:v1 -->
- `PR#183-c4586440154` | thread `PRRT_kwDOT_PcH8638qwX` | yazar `strix-security` | `src/core/account.rs:1863` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🔵 Duty-lane signer set trusts `Validator.active` instead of a bond, so a validator with no stake keeps the zero-fee lane
- `PR#183-c4586440186` | thread `PRRT_kwDOT_PcH8638qwm` | yazar `strix-security` | `src/storage/bud3/registry.rs:1900` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | ### 🟡 A single unacknowledged repair share permanently blocks every later repair of its segment
- `PR#183-c4586440198` | thread `PRRT_kwDOT_PcH8638qwv` | yazar `strix-security` | `src/execution/executor.rs:4199` | outdated=False | Durum: thread kapandi (Strix: 0 acik, 2026-11-17), kod dogrulamasi bekliyor | changed RecordRepair call site that reaches the refusal

## PR #194 (budlum-consensus-of-consensuses -> budlum-stack)

- **STRX-194-01** | Durum: cozuldu (kod kaniti: `src/domain/types.rs:77-85` discriminants: AiInference=5, Dag=6, Poh=7, Pospace=8; `3c891b5d`) | 🔴 **CRITICAL** Bincode discriminant index shift on `ConsensusKind` enum breaks binary consensus encoding compatibility across nodes.
- **STRX-194-02** | Durum: cozuldu (kod kaniti: `src/domain/plugin.rs:415-424` parent list deduplicated & sorted canonically; `3c891b5d`) | 🟠 **HIGH** DAG multi-parent commitment extraction allows malleable root hashing by permuting parent order.
- **STRX-194-03** | Durum: cozuldu (kod kaniti: `src/consensus/poh.rs:188-212` bounded verification ticks and fail-closed state transition checks; `3c891b5d`) | 🟠 **HIGH** PoH tick sequence verification without rate bounding risks single-core validator thread starvation during reorgs.
- **STRX-194-04** | Durum: cozuldu (kod kaniti: `src/consensus/pospace.rs:240-265` domain commitment explicitly binds global header root and epoch challenge; `3c891b5d`) | 🟠 **HIGH** PoSpace plot challenge replay vulnerability across epochs when plot proofs omit canonical block header binding.
- **STRX-194-05** | Durum: cozuldu (kod kaniti: `src/domain/plugin.rs:442-455` and `src/consensus/zk_verifier.rs` explicit ZkSnark/ZkStark validation, Raw mode rejected with `UntrustedProofMode`; `cfc1fc7` + `3c891b5d`) | 🔴 **CRITICAL** Acceptance of `Raw` proof mode bypasses ZK light client verification, allowing forged domain state transitions.
- **STRX-194-06** | Durum: cozuldu (kod kaniti: `xtask/gates/src/gates/zkvm_refuses_untrusted_proofs.rs` gate enforces proof verification keys; `cfc1fc7`) | 🟡 **MEDIUM** Adapter proof validation must fail-closed on unpinned or missing verification keys.


