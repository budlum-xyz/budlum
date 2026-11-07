# Work packages register

Source: `THE_BUDLUM_DIREKTIF.md` section 15.7 (the binding table). Package IDs in the repo and on GitHub use `WP-NN` (section 15.3 rule 1). `İP-NN` and `WP-NN` name the same package.

Status is measured from the repository state at the time of writing. Open PR references are matched by `WP-NN` in the PR title or branch name. A PR that names several packages is counted for each of them.

`main` is at `20140e8`. This branch is `arena/d9464f95-budlum`.

| WP | Title | Lane | Layer | TLG | Depends on | Milestone | Open PRs (referencing) | Status |
|---|---|---|---|---|---|---|---|---|
| WP-01 | Canlı doğrulama: çekirdek | A | T-Açılış | Evet | Yok | M0 | #123, #124, #125, #129, #131, #137, #138 | Open PR(s) exist; not merged to `main`. |
| WP-02 | Canlı doğrulama: depolama | B | T-Açılış | Evet | Yok | M0 | #117, #141 | Open PR(s) exist; not merged to `main`. |
| WP-03 | Canlı doğrulama: yürütme, BudZero, domainler, gizlilik, AI | C | T-Açılış | Evet | Yok | M0 | #129 | Open PR(s) exist; not merged to `main`. |
| WP-04 | Canlı doğrulama: istemciler, işletim, CI, belgeler ve birleşik durum | D | T-Açılış | Evet | Yok | M0 | #75, #77, #96, #118, #129, #139 | Open PR(s) exist; not merged to `main`. |
| WP-05 | Kavram adı haritası ve sayaç kapısı | D | T-Açılış | Evet | İP-04 | M1 | #24, #120, #122, #126, #127, #135 | Concept map and count baseline committed on this branch (İP-05 items 1, 4, 5 in part). Rust gate not yet written. |
| WP-06 | Kalıcılık ve durum kurtarma taşıması | B | T-Açılış | Evet | İP-02 | M1 | #60, #84 | Open PR(s) exist; not merged to `main`. |
| WP-07 | Eski depolama sistemlerinin kaldırılması | B | T-Açılış | Evet | İP-06 | M1 | #69, #71, #104 | Open PR(s) exist; not merged to `main`. |
| WP-08 | Doğrulayıcı sınıfları ve tek kayıt | A | T-Açılış | Evet | İP-01 | M1 | #40 | Open PR(s) exist; not merged to `main`. |
| WP-09 | Yürütme ortamı arayüzü | C | T-Açılış | Evet | İP-03 | M1 | #36, #38, #54, #64, #80 | Open PR(s) exist; not merged to `main`. |
| WP-10 | B.U.D. 3.0 iskeleti ve ortak tipler | B | T-Açılış | Evet | İP-07 | M2 | #56 | Open PR(s) exist; not merged to `main`. |
| WP-11 | Mobil çekirdek ve hafif istemci | D | T-Açılış | Evet | İP-10, İP-12, İP-13, İP-15, İP-20 | M4 | #44, #82, #85, #88, #91 | Open PR(s) exist; not merged to `main`. |
| WP-12 | Kurul tabanlı kesinlik, Anında Koltuk Devri, konsensüs sertleştirme | A | T-Açılış | Evet | İP-08 | M2 | #81 | Open PR(s) exist; not merged to `main`. |
| WP-13 | Varlık protokolü ve askıya alma | A | T-Açılış | Evet | İP-12 | M3 | #45, #70 | Open PR(s) exist; not merged to `main`. |
| WP-14 | Anında Görev Devri ve felaket kipi | A | T-Açılış | Evet | İP-12, İP-13, İP-20, İP-21 | M4 | none | Not started on `main`. |
| WP-15 | Ağ: NAT geçişi ve P2P sertleştirme | A | T-Açılış | Evet | İP-01 | M2 | #48 | Open PR(s) exist; not merged to `main`. |
| WP-16 | Genesis, tören aracı ve ekonomi | A | T-Açılış | Evet | İP-08 | M3 | #34, #37, #39, #52 | Open PR(s) exist; not merged to `main`. |
| WP-17 | Durum geçişi ve zincir sertleştirme | A | T-Açılış | Evet | İP-01, İP-06 | M2 | #62, #66, #67, #133, #134, #142, #143, #144 | Open PR(s) exist; not merged to `main`. |
| WP-18 | Segmentasyon ve RFC 6330 fountain kodu | B | T-Açılış | Evet | İP-10 | M3 | #47 | Open PR(s) exist; not merged to `main`. |
| WP-19 | BOF-1 nesne biçimi, QR sunumu ve video taahhüdü | B | T-Açılış | Evet | İP-10, İP-24 | M3 | #45, #55 | Open PR(s) exist; not merged to `main`. |
| WP-20 | Sınıf duyarlı yerleşim, saklama kanıtı ve onarım | B | T-Açılış | Evet | İP-08, İP-18 | M3 | #13, #59 | Open PR(s) exist; not merged to `main`. |
| WP-21 | Yükleme, görüntüleme, `StorageTx` v3 ve RPC | B | T-Açılış | Evet | İP-18, İP-19, İP-20 | M3 | #57, #105 | Open PR(s) exist; not merged to `main`. |
| WP-22 | Tekilleştirme, başvuru, silme, mühürlü içerik ve izinler | B | T-Açılış | Evet | İP-21 | M3 | #45 | Open PR(s) exist; not merged to `main`. |
| WP-23 | Bağımlı modüllerin B.U.D. 3.0 geçişi | B | T-Açılış | Evet | İP-22 | M4 | #36 | Open PR(s) exist; not merged to `main`. |
| WP-24 | A0 kodek kayıt defteri ve erişim katmanı | B | T-Açılış | Evet | İP-10 | M3 | #65 | Open PR(s) exist; not merged to `main`. |
| WP-25 | Depolama ücreti, Saklama Vakfı ve saklama ödülleri | B | T-Açılış | Evet | İP-16, İP-21 | M4 | #40, #45 | Open PR(s) exist; not merged to `main`. |
| WP-26 | Yürütme Koordinatörü ve EE işçileri | C | T-Açılış | Evet | İP-07, İP-09 | M2 | #24, #36 | Open PR(s) exist; not merged to `main`. |
| WP-27 | EVM yürütme ortamı ve yabancı zarf | C | T-Açılış | Evet | İP-26 | M3 | #78 | Open PR(s) exist; not merged to `main`. |
| WP-28 | Ethereum JSON-RPC ağ geçidi | C | T-Açılış | Evet | İP-27 | M4 | #56, #72, #75, #76 | Open PR(s) exist; not merged to `main`. |
| WP-29 | WASM (CosmWasm ABI) ve Cosmos RPC alt kümesi | C | T-Açılış | Evet | İP-26 | M3 | none | Not started on `main`. |
| WP-30 | Evrensel Çağrı ve Evrensel Varlık Kaydı | C | T-Açılış | Evet | İP-27, İP-29 | M4 | none | Not started on `main`. |
| WP-31 | SVM ve Solana RPC alt kümesi | C | T-Açılış | Evet | İP-26 | M4 | #51, #83 | Open PR(s) exist; not merged to `main`. |
| WP-32 | Move (Aptos) ve Aptos REST alt kümesi | C | T-Açılış | Evet | İP-26 | M4 | #89 | Open PR(s) exist; not merged to `main`. |
| WP-33 | BudZero yürütme ortamı ve BudZero sağlamlık | C | T-Açılış | Evet | İP-26 | M3 | #24 | Open PR(s) exist; not merged to `main`. |
| WP-34 | Göç Kiti | C | T-Açılış | Hayır (Beta) | İP-28 | Koşul değil | #46, #61 | Open PR(s) exist; not merged to `main`. |
| WP-35 | Uygunluk, gaz kalibrasyonu ve çapraz mimari | C | T-Açılış | Evet | İP-27, İP-29, İP-31, İP-32, İP-33 | M4 | #24, #36, #79 | Open PR(s) exist; not merged to `main`. |
| WP-36 | Android doğrulayıcı uygulaması | D | T-Açılış | Evet | İP-11 | M4 | #92, #97 | Open PR(s) exist; not merged to `main`. |
| WP-37 | Mobil cihaz matrisi ve saha testi | D | T-Açılış | Evet | İP-36 | M4 | #92 | Open PR(s) exist; not merged to `main`. |
| WP-38 | iOS fırsatçı uygulaması | D | T-Açılış | Hayır (Beta) | İP-11 | Koşul değil | #100 | Open PR(s) exist; not merged to `main`. |
| WP-39 | Cüzdan çekirdeği ve CLI | D | T-Açılış | Evet | İP-08, İP-21, İP-27 | M4 | #132, #135 | Open PR(s) exist; not merged to `main`. |
| WP-40 | Gezgin ve dizinleyici | D | T-Açılış | Evet | İP-21, İP-26 | M4 | #73 | Open PR(s) exist; not merged to `main`. |
| WP-41 | Musluk ve işletim | D | T-Açılış | Evet | İP-16 | M4 | #34, #52, #58, #59 | Open PR(s) exist; not merged to `main`. |
| WP-42 | CI, kapılar ve tedarik zinciri | D | T-Açılış | Evet | İP-04 | M2 | #24, #29, #30, #42, #63, #74, #75, #93, #95, #96, #98, #101, #103, #104, #106, #107, #109, #116, #119, #120, #121, #122, #129, #130, #132, #135, #136, #139 | Open PR(s) exist; not merged to `main`. |
| WP-43 | Belgeler, README ve TLG raporu | D | T-Açılış | Evet | İP-46, İP-47, İP-48 | M6 | #51, #139 | Open PR(s) exist; not merged to `main`. |
| WP-44 | Domainler, köprü, uzlaşma ve sözleşmeler | A | T-Açılış | Evet | İP-01 | M4 | #14 | Open PR(s) exist; not merged to `main`. |
| WP-45 | Gizlilik, AI ve hesap soyutlama: testnet sınırı | B | T-Açılış | Evet | İP-22 | M4 | #44, #49, #128 | Open PR(s) exist; not merged to `main`. |
| WP-46 | Tören provası, prova ağı ve ölçümler | D | T-Açılış | Evet | M4 | M5 | #92, #99, #102 | Open PR(s) exist; not merged to `main`. |
| WP-47 | Bağımsız inceleme 1: çekirdek ve depolama | Çapraz (C veya D) | T-Açılış | Evet | M4 | M5 | #56 | Open PR(s) exist; not merged to `main`. |
| WP-48 | Bağımsız inceleme 2: yürütme, mobil ve istemciler | Çapraz (A veya B) | T-Açılış | Evet | M4 | M5 | #36, #43, #100 | Open PR(s) exist; not merged to `main`. |
| WP-49 | Evrensel Nesne Katmanı | A | T-Genişleme | Hayır | M7, İP-30, İP-44 |  | none | Not started on `main`. |
| WP-50 | Move (Sui lehçesi) yürütme ortamı | C | T-Genişleme | Hayır | İP-35 |  | none | Not started on `main`. |
| WP-51 | Cairo yürütme ortamı | C | T-Genişleme | Hayır | İP-35 |  | none | Not started on `main`. |
| WP-52 | SVM ve Move işaretçileri | C | T-Genişleme | Hayır | İP-30, İP-31, İP-32 |  | none | Not started on `main`. |
| WP-53 | NEAR WASM, PolkaVM, TVM, UTXO betiği, Plutus | C | T-Genişleme | Hayır | İP-35 |  | none | Not started on `main`. |
| WP-54 | Paylaşılan sıkıştırma bağlamı, ek kodekler, gizli tekilleştirme | B | T-Genişleme | Hayır | İP-22, İP-24 (gizli tekilleştirme kısmı ayrıca İP-56) |  | none | Not started on `main`. |
| WP-55 | Canlı yayın | B | T-Genişleme | Hayır | İP-21 |  | #86 | Open PR(s) exist; not merged to `main`. |
| WP-56 | BudZero gizlilik çekirdeği, yüklem kanıtları, rıza ve PTP-1 | B | T-Genişleme | Hayır | İP-22, İP-33 |  | none | Not started on `main`. |
| WP-57 | AI Doğrulama Katmanı | A | T-Genişleme | Hayır | İP-45, İP-56 |  | none | Not started on `main`. |
| WP-58 | F-Droid ve yeniden üretilebilir Android derlemesi | D | T-Genişleme | Hayır | İP-36 |  | none | Not started on `main`. |
| WP-59 | Paralel yürütme | C | T-Genişleme | Hayır | İP-35 |  | none | Not started on `main`. |
| WP-60 | BudZero özyineleme, RV32, ön derlemeler, domain kesinlik kanıtı, blok toplu kanıtı | C | T-Genişleme | Hayır | İP-56 |  | none | Not started on `main`. |
| WP-61 | RPC ve kriptografi sertleştirme | D | T-Açılış | Evet | İP-01 | M2 | #34, #41, #53 | Open PR(s) exist; not merged to `main`. |
| WP-62 | Evrensel Nesne Katmanı: CosmWasm ve Cosmos SDK ailesi | A | T-Genişleme | Hayır | İP-49, İP-29 |  | none | Not started on `main`. |
| WP-63 | Evrensel Nesne Katmanı: SVM ailesi | A | T-Genişleme | Hayır | İP-49, İP-31 |  | none | Not started on `main`. |
| WP-64 | Evrensel Nesne Katmanı: Move ailesi | A | T-Genişleme | Hayır | İP-49, İP-32 |  | #137 | Open PR(s) exist; not merged to `main`. |

## Counts

- Packages in directive table: 64
- Packages with an open PR referencing them: 48
- Packages with no open PR: 16
- Packages with work on this branch: 1

Package issues (GitHub Issues) are not used. Issues are disabled in this repository, so this file is the register.

No milestone (section 15.6) is reached on `main` by this register.
