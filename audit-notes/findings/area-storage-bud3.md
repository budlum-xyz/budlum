# Denetim Bulguları: Depolama (Area Storage B.U.D. 3.0)

Denetlenen Konumlar: `src/storage/bud3/` (`registry.rs`, `frame.rs`, `view.rs`, `pipeline.rs`, `replace.rs`, `tx.rs`), `bud/src/`.

## 1. Kapsam ve İnceleme Metodolojisi

B.U.D. 3.0 dağıtık depolama motoru:
- İçerik adresleme ve parçalama (FastCDC),
- Reed-Solomon silme kodlaması (erasure coding) ve parça yerleşimi,
- Saklama kanıtları (custody proofs), onarım döngüleri (repair rounds),
- Ücretli görüntüleme (paid view) makbuzları ve durum şişmesi (state bloat) koruması.

## 2. Bulgular

### B-STRG-01: Ücretli Görüntüleme Makbuzlarının Durum Şişmesi Yaratması
- **Önem**: Orta (Medium)
- **Dosya**: `src/storage/bud3/registry.rs:53-57, 736-760, 1267-1276`
- **Açıklama**: Paid view makbuzları budama (pruning) yolu olmaksızın blok durum köküne yazılıyordu; fonlanmış herhangi bir hesap kayıt defterini sınırsız büyütebiliyordu.
- **Kök Neden**: Saklama süresi ve azami makbuz tavanının tanımlanmamış olması.
- **Çözüm**: `PAID_VIEW_RETENTION_EPOCHS` sabitlendi ve azami tavan aşıldığında eski makbuzlar konsensüs durumundan deterministik olarak budandı.
- **Durum**: Çözüldü (`ad88285c`).

### B-STRG-02: Tek Doğrulayıcının B.U.D. 3.0 Saklamasını Kendi Başına Onaylaması
- **Önem**: Orta (Medium)
- **Dosya**: `src/storage/bud3/registry.rs:479-481, 2252+`
- **Açıklama**: Aktif bir doğrulayıcı kendi shard'ı için saklama kanıtını tek başına onaylayıp yerleşim kurallarını ihlal edebiliyordu.
- **Kök Neden**: Onarım yolunda yeni payların aynı doğrulayıcı kümesine verilmesini engelleyen kısıtın gevşek olması.
- **Çözüm**: Shard yerleşiminde doğrulayıcının kendi kendine atama yapması engellendi; en az k-farklı bağımsız doğrulayıcı şart koşuldu.
- **Durum**: Çözüldü (`ad88285c`).

### B-STRG-03: Onaysız Onarım Payının Segmenti Kalıcı Olarak Kilitlemesi
- **Önem**: Orta (Medium)
- **Dosya**: `src/storage/bud3/registry.rs:1900-1924`
- **Açıklama**: Hiçbir zaman kabul edilmeyen (unacked) bir onarım payı placeholder olarak kaldığında segmentin sonraki tüm onarımlarını kalıcı olarak engelliyordu.
- **Kök Neden**: Zaman aşımı mekanizmasının ve handover mekanizmasının eksikliği.
- **Çözüm**: `unacked placeholder expiry` ve `handover_unacked_shares` eklendi; zaman aşımına uğrayan onarım talepleri temizlenip yeniden havuza aktarıldı.
- **Durum**: Çözüldü (`5d912761`).

### B-STRG-04: Bud3Registry::bind_nft Yetkisiz NFT Sahipliği Bağlama
- **Önem**: Orta (Medium)
- **Dosya**: `src/storage/bud3/registry.rs:753-759, 875-884`
- **Açıklama**: Sahiplik kanıtı aramaksızın çağrıcının belirttiği NFT kimliği kaydedilebiliyordu.
- **Kök Neden**: `nft_owner != Some(holder)` kontrolünün eksikliği.
- **Çözüm**: NFT bağlama işleminde `nft_owner == Some(holder)` doğrulandı; uyuşmazlık durumunda işlem anında reddedildi.
- **Durum**: Çözüldü (`ad88285c`).
