# BUDLUM SINIRI — "nihai sistem" iddiasının kanıtlanan ve açık kalan kısmı

Bu belge kötü haber belgesidir. Amacı, satılabilir cümleyi ölçülebilir cümleden ayırmak.

## 1. Kanıtlanabilen (bugün, bu repoda)

| İddia | Kanıt | Nerede |
|---|---|---|
| Agregasyon kuralları deterministik | 73 test; aynı girdi → aynı bayt; saat/RNG/dosya okunmuyor | `src/aggregation/tests.rs`, PR #188 |
| İddia ağdan alınmıyor, bayttan türetiliyor | `claim_from_envelope` + `ClaimMismatch` testi | `backend.rs`, `claim_derivation_is_the_only_constructor_the_backend_accepts` |
| Domain ayrımı çapraz replay'i kesiyor | aynı çerçeve başka domain ctx'inde `RootMismatch` | `verify_rejects_a_frame_from_another_domain` |
| Parametre seti kanıta bağlı | `params_hash` → `frame_hash`; her consensus alanı test edildi | `params_hash_changes_with_every_consensus_field` |
| Şekil (shape) sahtelenemiyor | tüketilmemiş segment, eksik segment, merge underflow, bilinmeyen op, boş şekil reddediliyor | `fold_shape_*` (8 test) |
| Merkle'de yaprak çoğaltma (CVE-2012-2459 sınıfı) yok | tek yaprak tanıtılır, kopyalanmaz | `claims_root_promotes_an_odd_leaf_instead_of_duplicating_it` |
| Referans backend üretim profiline giremez | kaynak kapısı: `#[cfg(any(test, feature="native-agg-backend"))]` + default feature kontrolü | `the_reference_backend_is_gated_out_of_the_production_profile` |
| Üretim yolunda panic yok | `.unwrap(`/`.expect(`/`panic!` taraması | `production_sources_have_no_unwrap_expect_or_panic` |
| Etiketler envanterde | reponun **gerçek** `domain-tags` kapısı: "Domain tag inventory OK (422 tags)" | `xtask/gates` 1bd9356 |
| Biçim/lint | `rustfmt --check`, `clippy --all-targets -D warnings` (1.97.1) temiz | yerel, harness |
| Yönetici anahtarı yok | yeni kodda admin/pause/whitelist yolu yok; `NATIVE_BACKEND` dışında yan etki yok | `src/aggregation/*` |

## 2. Açık araştırma (iddia edilemez)

1. **Kanıt sistemi yok.** Yayınlanan backend `NativeBackend`: kanıt baytları nesnelerin kendisi. Yani *kanıt* küçültme iddiası **doğrulanmadı**. Faz 2 (AggTick) ve Faz 3 (AggMerge + StarkBackend) yazılmadan "zincir ağır nesne saklamıyor" cümlesi kurulamaz.
2. **Özyineleme yok.** BudZKVM'in BudZKVM kanıtını doğrulayan bir programı (`verify_vm_proof`) yok; varsa da bu turda doğrulanmadı. Özyineleme olmadan Ana Kanıt, 1024 iddiayı tek kanıta indirmez.
3. **Ses sağlamlığı (soundness) bağımsız denetlenmedi.** `NativeBackend::verify_proof` hiçbir kriptografik bağ kurmaz (kasıtlı, kapılı). Bu backend'e dayanan hiçbir güvenlik iddiası yapılamaz.
4. **Ücret kalibrasyonu yok.** `claim_fee_per_byte = 64` direktiften alınan başlangıç değeri; ölçülmüş bir maliyet değil. Direktifin kendi şartı: "Bir iddianın ücreti, o iddianın kanıt maliyetini aşar" → ölçüm yapılmadan sağlanmış sayılamaz.
5. **Adaptörler güvenilen koddur.** `src/cross_domain/external/spec.rs` "boolean değil kanıt" diyor ama adaptörün kendisi Budlum kodu; hatalı bir adaptör, yanlış kesinliği *geçerli kanıt* gibi sunar. Adaptörler için bağımsız denetim/formal doğrulama yok.
6. **Aile kapsamı.** Tendermint/IBC, DAG/PoH/PoSpace, rollup/DA adaptörü yok (bkz. `BUDLUM-HARITA.md` §3). "Bütün ağlar domain olarak kayıt olur" cümlesi bugün **yanlıştır**; doğrusu "PoW, PoS, PoA, BFT, ZK ve `external` adaptörü yazılmış ağlar".
7. **`FinalityStatus` ifade gücü.** Ağırlık tabanlı (DAG) ve süre tabanlı (optimistic rollup) kesinlik bugünkü enum'a sığmıyor; `Pending{required_depth, observed_depth}` yalnız derinlik ifade eder.
8. **Ekonomi.** Teminat sabit (`MIN_REGISTRATION_STAKE = 1_000`); "kanıt maliyeti < teminat" bağı kurulmadı (bkz. tasarım §6, denetim B-0003).
9. **Ölçek kanıtı yok.** `benches/` var, ama bu turda hiçbir benchmark çalıştırılamadı (B-0002). "1000 iddialık blok" hedefi ölçülmedi.
10. **Determinizm, farklı mimarilerde sınanmadı.** `determinism.yml` ve `diverse-double-compiling.yml` var; ama bu turda hiçbir runner çalışmadı.
11. **Testnet hazır değil.** `THE_BUDLUM_DIREKTIF` §1.3 on madde sayıyor; bu turda kanıtlanabilen madde sayısı sıfır (hepsi uçtan uca ağ provası ister).
12. **"Nihai sistem" iddiası.** Tarihsel olarak her katman bir öncekinin çözemediği bir şeyi çözdü; Budlum'un çözdüğü şey *heterojen kesinliğin doğrulanması*. "Tarihin vardığı son nokta" bir mühendislik iddiası değil, bir konumlandırmadır. Ölçülebilir hâli şudur: **"Bir ağın kesinliğini, o ağın kurallarını yeniden uygulamadan, tek bir başlıkta doğrulanabilir kılmak."** Budlum bunu PoW/PoS/PoA/BFT/ZK için yapıyor; geri kalan aileler için yol var, kanıt yok.

## 3. Her açık maddeyi kapatan kanıt

| # | Kapanış kanıtı |
|---|---|
| 1 | `AggTick` AIR + 256 imzalık tik kanıtı; `proof.len() <= max_proof_bytes`; bozuk imza kanıt üretimini durduruyor |
| 2 | `verify_vm_proof` programı + 1024 iddialık blok tek Ana Kanıt |
| 3 | Bağımsız denetim raporu (Strix + insan) + fuzz hedefleri `ClaimFrame`/`Envelope` |
| 4 | Ölçüm tablosu: kanıt süresi/boyutu ↔ ücret; `benches/agg_baseline` |
| 5 | Adaptör başına negatif test seti (yanlış validator seti, eski height, yanlış chain_id) + kani/loom |
| 6 | Üç adaptör (Tendermint/IBC, Bitcoin SPV, rollup) + `FinalityStatus` genişletmesi |
| 7 | `FinalityStatus::FinalizedWeight` + `FinalizedAfter { window }` |
| 8 | Teminat formülü + simülasyon |
| 9 | CI'da yeşil `benchmark.yml` çıktısı |
| 10 | `determinism.yml` + `diverse-double-compiling.yml` yeşil run |
| 11 | TLG maddelerinin her biri için test adı + gece provası |
| 12 | Yalnızca yukarıdakiler kapandığında, ölçülmüş hâliyle |

## 4. Tek cümlelik sınır

**Bugün Budlum, heterojen kesinlik kanıtlarını doğrulayan ve tek başlıkta birleştiren çalışan bir katmandır; "konsensüslerin konsensüsü"nün kanıt-üreten hâli değildir: toplama kuralları yazıldı ve test edildi, toplama *kanıtı* henüz yok.**
