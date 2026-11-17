# Tur 2 bulguları (B-0012 … B-0018)

İkinci oturum, 2026-11-17. Başlangıç noktası `budlum-stack@a579d3a7`. Bu turun ekseni değişti: **stack'te zaten bir `src/aggregation/` uygulaması var** (B-0015), yani işim yeni kod yazmak değil, gemiye binecek kodu denetlemek ve oradaki gerçek hataları düzeltmek oldu.

## B-0012 — PR CI kuyruğu: kök neden ayrıştırıldı

- **Konum:** repo geneli; `GET /actions/runs`
- **Önem:** orta (süreç); hiçbir PR'ın hükmü yok
- **Ölçüm (2026-11-17 11:57Z):** `queued=83`, `in_progress=2`, son 300 koşu tarandı. #188'de 24 koşu, tamamı `queued`. #189'da 22 koşu **tamamlandı ama hepsi `cancelled`** (concurrency grubu), 25 `queued`. #190 açıldıktan sonra 14 koşu `queued`.
- **Ne yanlış değil:** platform engeli yok. Kanıt: `in_progress > 0`, self-hosted runner sayısı 0, hosted runner'lar repo düzeyinde serbest, repo Actions `enabled=true`. İlk hipotez ("Default runner group public repo'ya kapalı") **yanlıştı** ve doğrulanmadan ayar değiştirilmedi.
- **Ne yanlış:** eşzamanlılık açlığı. 33 workflow her PR'da 24–48 koşu açıyor; org eşzamanlılık tavanı birkaç iş olduğu için PR kapıları kuyruğun sonunda kalıyor. Kuyruk FIFO değil.
- **Ölçülen temizlik:** yalnızca *baş SHA'sı geçersiz* (superseded) koşular iptal edildi: **2** koşu (#189). Güncel SHA'ya ait 90 `queued` koşuya dokunulmadı. Yani kuyruk israf değil, **hacim**.
- **Depoda çözüm deseni zaten var:** `f7312e2a` "Stop the CI fan-out from starving pull-request gates", `86bf7628` "ci: stagger deep batteries behind PR gates". Bunlar testnet soyunda; stack'e taşınmış mı diye kapı dosyaları karşılaştırılmalı.
- **Durum:** açık; sahibin kararı (path-gate + tek CI workflow + derin bataryaları gece/schedule'a). Bu ortamdan 33 workflow yeniden yazılmadı — kör düzenleme kapıları kırar.

## B-0013 — B-0003 doğrulandı ve düzeltme açıldı (PR #190)

- **Konum:** `src/execution/executor.rs:867` (`a579d3a7`), aynı işlemde `:917`
- **Önem:** yüksek (ekonomik güvenlik)
- **Ne yanlış:** self-unstake kolu aktiflik tabanını `state.registry.params().min_stake.max(1)` (testnette 1.000 atom) ile ölçüyor; aynı `Unstake` işleminin iki satır altındaki registry senkronu (`:917`) ve kayıt kolları (`:527`, `:710`) `Network::from_chain_id(...).min_stake()` (testnette `bud(1_000)` = 10^9 atom) kullanıyor. `RegistryParams::min_stake` kendi dokümanında "yeni kayıt için taban" diyor. Sonuç: doğrulayıcı 1.000 atomla `active` kalıyor — ağ tabanının altıda, seat tablosunda, liveness/double-sign slash yollarında; 1.000 atomluk bond'un karşılayamayacağı oy ağırlığıyla.
- **Düzeltme:** PR #190, base `budlum-stack`, tek ifade + yeni test `self_unstake_below_network_floor_deactivates_the_validator`. Test önce kırılır (governed+1 ≥ governed → `active` kalır), sonra geçer (governed+1 < floor → `active=false`). `rustfmt --check` dosyayı temiz ayrıştırıyor; crate bu sandbox'ta derlenmiyor (B-0002), dolayısıyla fail-first koşusu CI'nındır ve öyle yazıldı.
- **Durum:** düzeltme PR'da; hüküm CI kuyruğunda.

## B-0014 — B-0004 yeniden triyaj: bug değil, belgelenmemiş güven varsayımı

- **Konum:** `src/storage/bud3/registry.rs`, `RepairWitness::ValidatorAttestations` kolu
- **Önem:** orta → tasarım kararı
- **Ne değişti:** `repair_attestation_digest(chain_id, &RepairClaim{..})` — chain_id bağı stack'e inmiş (security dalındaki `b69c3df1` ile aynı fikir). Tur 1'deki "imza `new_root`'u türetmeden imzalıyor" tespiti hâlâ geçerli: `Reconstructed` kolu segmentleri türetip karşılaştırıyor, attestation kolu güveniyor.
- **Neden bug demiyorum:** attestation yolu tanımı gereği "Full doğrulayıcı quorum'u şu kökü onaylıyor" demek. Sorun, quorum'un **oran** değil sabit sayı olması: `MIN_REPAIR_ATTESTATIONS` Full kümesinin oranına bağlanmazsa, küçük bir imza seti tüm segment kökünü yeniden yazabilir.
- **Öneri:** sabiti `max(k, ceil(2/3 * |Full|))` biçiminde orana bağla ve varsayımı `docs/` içinde yaz.
- **Durum:** sahibin tasarım kararı; kod değişikliği önerilmedi.

## B-0015 — PR #188 stack'teki agregasyonun kopyasıydı; kapatıldı

- **Konum:** `budlum-stack:src/aggregation/` (32 dosya) vs `aggregation-phase1:src/aggregation/` (6 dosya)
- **Önem:** yüksek (süreç; direktif #3 "iki PR uyumsuz")
- **Kanıt:** stack commit'leri `ed5faed7` (faz 0–1, claim/frame/pool/block/fees/node), `8bca82bf` (faz 1 çıkışı, RPC blok görünümü), `b034a9ee` + `7c4ffbbe` (faz 2, BudZKVM `verify_sig` ve `AggTick`, ölçülmüş), `d5a9d36a` (sertleştirme). Benim #188'im `main`'e **ikinci** bir `src/aggregation/` ekliyordu; `#126 → #164 → #183` zinciri indiğinde `main` iki uygulama taşıyacak, `src/lib.rs`, `Cargo.toml`, `src/crypto/domain_tags.rs` çakışacaktı.
- **Karar:** #188 kapatıldı, gerekçe yorumu bırakıldı (`pull/188#issuecomment-6947436445`). Kayıp yok: stack Merkle'si doğru (B-0017), `fold_shape`/`tick_pi`/`merge_pi` orada. `aggregation-phase1` dalı remote'ta kalıyor; `budlum-aggproof` koşum takımı (73 test) o dala karşı bağımsız oracle olarak çalışmaya devam ediyor.
- **Durum:** kapalı.

## B-0016 — İki taban, tek yetki sorusu (governance `min_stake` vs ağ tabanı)

- **Konum:** `src/core/governance.rs:81,113` (whitelist + setter), `src/registry/params.rs:111` (doküman), `src/execution/executor.rs:527,710,867,917`
- **Önem:** orta
- **Ne yanlış:** Parametre "yeni kayıt tabanı" diyor ama kayıt kolları onu okumuyor; governance `min_stake`'i yükseltse bile kayıt yolu ağ tabanında kalıyor. Ters yönde de aynı: parametre ağ tabanının altına inebiliyor. İki kaynak, tek kavram.
- **Öneri:** tek yardımcı `active_floor = max(governed, network)` ve dört çağrı yerinde; ya da parametreyi *yalnızca* kayıt için otorite ilan edip unstake kolunu ağ tabanına sabitlemek (B-0013'ün yaptığı) ve bunu `docs/`ta yazmak.
- **Durum:** sahibin politika kararı; kör refactor yapılmadı.

## B-0017 — Doğrulanan olumlu sonuç: stack claim ağacı

- **Konum:** `src/aggregation/merkle.rs` (`a579d3a7`)
- **Sonuç:** yaprak `H(TAG||0x00||digest)`, düğüm `H(TAG||0x01||left||right)`; tek kalan düğüm **tanıtılır** (`as_chunks::<2>()` + `extend_from_slice(promoted)`), çoğaltılmaz; boş liste köksüz. CVE-2012-2459'un çoğaltma şekli dışlanmış. Benim #188'deki bağımsız türetim aynı yere çıkmıştı; bu bir *doğrulama*, yeni bir iddia değil.
- **Durum:** kayıt.

## B-0018 — `map_or(1, ...)` fail-open tabanı

- **Konum:** `executor.rs:527,710,917` (ve B-0013 sonrası `:867`)
- **Önem:** düşük (savunma derinliği)
- **Ne yanlış:** `Network::from_chain_id(id)` `None` dönerse taban 1 atoma düşüyor. Doğrulanmış bir işlemde `None` görülmemeli; görülürse davranış "en ucuz taban" oluyor, hata değil.
- **Öneri:** `map_or` yerine açık hata ya da devnet tabanı; en azından `debug_assert!`.
- **Durum:** açık, düşük öncelik.
