# Denetim Bulguları: Settlement Primitifleri (Area Settlement)

Denetlenen Konumlar: `src/settlement/` (`domains.rs`, `app_binding.rs`, `mod.rs`), `src/core/account.rs`, `src/chain/blockchain.rs`.

## 1. Kapsam ve İnceleme Metodolojisi

Settlement katmanı Budlum'un evrensel uzlaşma omurgasını oluşturur:
- `DomainFinalityAdapter`: Dış ve iç konsensüs alanlarının kesinleşme çıktılarının doğrulanması,
- `GlobalBlockHeader`: Tüm alt alanların durum köklerini birleştiren küresel blok başlığı,
- `ReplayNonceStore`: Alanlar arası mesaj tekrarı (replay) koruması,
- `CrossDomainMessage`: `BDLM_DOMAIN_COMMITMENT_V1` hash etiketiyle korunan mesaj yapısı,
- `DomainStatus`: `Active`, `Frozen`, `Retired` durum geçiş makineleri.

## 2. Bulgular

### B-SETTL-01: AppBinding PoW Anchor Manipülasyonu
- **Önem**: Orta (Medium)
- **Dosya**: `src/settlement/domains.rs:1193-1200`, `src/settlement/app_binding.rs`
- **Açıklama**: AppBinding talebi kendi kendine kazılabilen (self-mineable) zayıf PoW köklerine güveniyordu, bu da başka bir uygulamanın ayna bakiyesinin devralınmasına imkan veriyordu.
- **Kök Neden**: Çapa olayının yalnızca zincir üzerinde kesinleşmiş `claim/v1` kaydı ile doğrulanmaması.
- **Çözüm**: Sahiplik doğrulaması kesinleşmiş L1 çapa olayına bağlandı (`app_binding.rs`).
- **Durum**: Çözüldü (`ad88285c`).

### B-SETTL-02: Replay Nonce Çakışması ve Domain Ayrımı
- **Önem**: Yüksek (High)
- **Dosya**: `src/settlement/domains.rs:450-480`
- **Açıklama**: Farklı domainler aynı nonce değerini kullandığında küresel nonce tablosunda yarış durumu (race condition) ve mesaj düşmesi riski vardı.
- **Kök Neden**: Nonce anahtarının yalnızca `u64` tutulup `(DomainId, SourceAccount, Nonce)` şeklinde bileşik indekslenmemesi.
- **Çözüm**: `ReplayNonceStore` anahtarı `(DomainId, AccountAddress, u64)` olarak güncellendi ve `BDLM_DOMAIN_COMMITMENT_V1` prefix zorunlu kılındı.
- **Durum**: Çözüldü (`ad88285c`).

### B-SETTL-03: Garden Domain Kimlik Alanı Rezervasyonu Eksikliği
- **Önem**: Orta (Medium)
- **Dosya**: `src/chain/blockchain.rs:1466-1470`, `src/settlement/domains.rs`
- **Açıklama**: Garden domain kimlikleri settlement kayıt defterinde rezerve edilmediği için üçüncü bir taraf bu ID'yi önceden alıp bir Garden'ın Budlum kaydını gölgeleyebiliyordu.
- **Kök Neden**: `check_ingest_garden_domain_reservation` filtresinin mempool kabulünde çalıştırılmaması.
- **Çözüm**: Settlement kapısında Garden için ayrılmış ID aralığı korundu ve yetkisiz kayıt denemeleri anında reddedildi.
- **Durum**: Çözüldü (`d013014a`).

### B-SETTL-04: Frozen ve Retired Domain Durum Geçişinde Bakiye Kaçağı
- **Önem**: Yüksek (High)
- **Dosya**: `src/settlement/domains.rs:820-845`
- **Açıklama**: Bir domain `Frozen` durumuna alındığında bekleyen çıkış (exit) taleplerinin durum dondurma işlemi tamamlanmadan çekilebilmesi.
- **Kök Neden**: Çıkış kuyruğunun domain durumunu atomik olarak kilitlememesi.
- **Çözüm**: Durum `Frozen` olduğunda tüm para çekme ve çıkış akışları kilitlenir; yalnızca L1 yönetişim veya kanıtlanmış ZK dolandırıcılık kanıtı (fraud proof) ile çözülür.
- **Durum**: Çözüldü (`5d912761`).
