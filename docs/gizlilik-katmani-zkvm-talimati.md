# GİZLİLİK KATMANI — zkVM Private Witness Tasarımı

*Budlum / BudZKVM (Plonky3) — Arena'ya yönelik mimari talimat*

- **Durum:** Vizyon / mimari karar dokümanı. Kod yok, opcode yazımı başlamadı.
- **Bağımlılık:** BudZKVM (Plonky3 STARK), PoA/kurumsal domain (BDDK/KYC katılım bankacılığı pilotu).
- **Tarih:** 22 Temmuz 2026.

---

## 1. Neden Bu Doküman Var

Mevcut BudZKVM/Lubot doğrulama tasarımı **bütünlük (integrity)** kanıtlıyor: "hesaplama doğru yapıldı." **Mahremiyet (confidentiality)** — kimin, ne kadar, kime transfer yaptığının gizlenmesi — otomatik gelmiyor, ayrı bir tasarım gerektiriyor. Bu doküman bu ayrımı ve gereken yeni alt-sistemi netleştiriyor.

## 2. Temel Ayrım: Bütünlük vs Mahremiyet

- zkVM/STARK, bir hesaplamanın iddia edildiği gibi doğru çalıştırıldığını kanıtlar — **veriyi gizlemez**.
- Lubot akışında operatör, geçerli bir Pollen `AccessGrant`'a sahipse B.U.D.'dan **düz-metin veriyi okur**, hesaplamayı yapar, sonra STARK proof üretir. Proof kimseden veri gizlemiyor — operatör veriyi zaten görmüştü. Proof sadece verifier'ın tüm hesaplamayı yeniden yapmadan "doğru yapıldı" diyebilmesini sağlıyor.
- "Operatör bile veriyi görmesin" isteniyorsa (execution-time confidentiality), bu **TEE, FHE veya MPC** gerektirir — STARK bunu vermez ve şu an mimaride yok. Ayrı bir araştırma hattı (bkz. Bölüm 10, madde 5).

## 3. Public/Private Input Mekaniği (STARK Genel)

- Devre/opcode tasarımcısı, execution trace'in her sütununu (register/bellek konumu) **elle** iki kategoriden birine atar:
  - **Public input:** proof ile birlikte paylaşılır, verifier bilinen bir değerle karşılaştırır (örn. `final_state_root`).
  - **Private witness:** yalnızca constraint'leri sağlamak için trace'e girer, proof'ta hiç görünmez.
- Bu atama **otomatik değildir** — "gizle" diye çevrilen bir bayrak yok. Hangi değerin public/private olacağı devre yazılırken kodlanır.
- Mevcut `ExecutionPublicInputs` (`program_hash`, `initial_state_root`, `final_state_root`, `gas`, `exit_code`, `trace_len`, `event_digest`) genel-amaçlı yürütme kanıtlama için tasarlandı, mahremiyet için değil. Bu haliyle transfer miktarı/taraf bilgisi state root'un bir parçası olarak **açık kalır**.

## 4. Gizli Transfer İçin Gereken Yeni Alt-Sistem

Üç bileşen gerekiyor:

1. **Commitment** — miktar + alıcı + `blinding_factor` bir hash'e gömülür; zincire yalnızca bu hash yazılır.
2. **Nullifier** — harcanan commitment'ı işaretleyen tek-kullanımlık değer; hangi commitment'ın harcandığını açıklamadan çifte-harcamayı önler.
3. **Korunum (sum-conservation) constraint'i** — "girdilerin toplamı = çıktıların toplamı" miktarlara bakmadan kanıtlanır. Bunun için commitment şemasının **homomorfik** olması gerekir.

## 5. Kriptografik Primitive Seçimi — Field-Native Hash Şart

- Zcash-tarzı sistemler eliptik eğri tabanlı Pedersen commitment (Jubjub) + Groth16 kullanır.
- Biz Plonky3/STARK kullanıyoruz — belirli bir sonlu cisim (Goldilocks/Mersenne) üzerinde çalışıyor; eliptik eğri aritmetiği bu cisimle native uyumlu değil, devre içinde pahalıya patlar.
- **Talimat:** Pedersen/eliptik-eğri DEĞİL, STARK-dostu field-native hash (**Poseidon** veya **Rescue**) kullanılacak. Poseidon vs Rescue seçimi mevcut Plonky3 yığınıyla uyumluluk testi yapılmadan kesinleştirilmeyecek (bkz. Bölüm 10, madde 1).

## 6. Gereken Somut İş

| Katman | Değişiklik |
|---|---|
| `bud-isa` | Yeni opcode ailesi: commit, nullifier-check, sum-conservation |
| `bud-vm` / `bud-proof` | Yeni constraint seti (yukarıdaki opcode'lar için) |
| `bud-state` | Yeni "note/UTXO" veri modeli — **mevcut account-model'in yanına eklenecek, onu değiştirmeden** |
| Primitive seçimi | Poseidon veya Rescue — Bölüm 5 kapanmadan opcode yazımına başlanmayacak |

## 7. İzolasyon Kuralı — NFT ve B.U.D. Verisi Bu Katmandan Etkilenmeyecek

- `NftRegistry` / `ContentId` ve `Pollen AccessGrant` / `StorageRegistry`, commitment/nullifier opcode'larını **çağırmaz** — ayrı state alanlarında yaşarlar.
- **Talimat:** Gizlilik katmanı yalnızca transfer opcode ailesini kapsayacak şekilde izole edilecek. NFT/B.U.D. state'i ile paylaşılan commitment şeması **kullanılmayacak**.
- Lubot'un B.U.D. okuma mekanizması (Pollen grant tabanlı) zaten "kim okuyabilir" sorusunu çözüyor — bu şifreleme değil, yetkilendirmedir. Bu katmana dokunulmayacak, DAO diskalifikasyonu ve kullanıcı-gizleme akışları (grant iptali/daraltma) olduğu gibi kalacak.

## 8. Regülatör Erişimi — View-Key / Selective Disclosure

- Düzenleyicilerin (BDDK gibi) istediği genelde tam opaklık değil, **"kamudan gizli, yetkiliye açık"** modeldir.
- Zcash-tarzı selective disclosure deseni: işlem sahibi kendi `view key`'ini yetkili bir tarafa verip geçmiş işlemleri açabilir — işlem kamuya kapalı kalırken.
- **Talimat:** PoA/katılım bankacılığı pilotu için view-key mekanizması ayrı netleştirilecek: kim üretiyor, kim saklıyor, hangi koşulda ibraz ediliyor.

## 9. Kapsam ve Öncelik

- Bu bir vizyon/mimari dokümandır — henüz kod yok.
- Öncelik PoA/kurumsal domain (BDDK/KYC) ile ilişkili; permissionless tarafta acil değil.
- Mevcut B.U.D./Lubot/NFT sistemlerine dokunmadan, ayrı bir opcode ailesi olarak eklenecek.

## 10. Açık Sorular

1. **Poseidon mu Rescue mu?** — hangi field-native hash, mevcut Plonky3 yığınıyla uyumluluk testiyle netleşecek.
2. **Note/UTXO modeli** mevcut account-model ile nasıl bir arada yaşayacak — hibrit mi, tamamen paralel mi?
3. **View-key mekanizması** — üretim, saklama, ibraz koşulları netleşmemiş.
4. **Zamanlama** — bu katman mainnet launch'a dahil mi, yoksa mevcut direct-testnet stratejisinden sonraki bir gorev mı?
5. **Execution-time confidentiality** (operatör bile veri görmesin) ayrı bir istekse, TEE/FHE/MPC entegrasyonu ayrı bir araştırma hattı olarak mı açılacak?

## 11. Sonraki Adım

Bu doküman koda dökülmeden önce: (a) hash primitive seçimi, (b) note-model tasarımı, (c) view-key mekanizması netleşmeli. Bunlar netleşmeden Arena'ya bu kapsamda görev verilmeyecek.

---

*Bu doküman 22 Temmuz 2026 tarihli bir mimari tartışmaya dayanır; Bölüm 10'daki açık sorular çözüldükçe güncellenmeli.*
