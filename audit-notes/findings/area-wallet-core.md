# Denetim Bulguları: Cüzdan Çekirdeği (Area Wallet-Core)

Denetlenen Konumlar: `crates/wallet-core/`, `src/wallet/identity_profile.rs`, `src/crypto/`.

## 1. Kapsam ve İnceleme Metodolojisi

`budlum-wallet-core` cüzdan istemcisi ve anahtar yönetim katmanı:
- BIP-39 tohum cümlesi ve SLIP-0010 ed25519 türetim yolu (`m/44'/999'/0'/0'/0'`),
- Budlum hesap adresi = Ed25519 genel anahtarının SHA3-256 özeti,
- PoA izinli ağ imzalama akışlarının genel izinsiz akıştan mutlak izolasyonu,
- Sıfırlama (Zeroize) mekanizmaları ve bellekten anahtar sızıntısı koruması.

## 2. Bulgular

### B-WAL-01: Passport Profilinde BNS Kök Kanıtı Olmadan 'Verified' Gösterimi
- **Önem**: Orta (Medium)
- **Dosya**: `src/wallet/identity_profile.rs:604-613, 739-758`
- **Açıklama**: Kimlik kartı BNS kanıtı taşımayan düğüm yanıtlarını bile `Verified` olarak işaretleyebiliyordu.
- **Kök Neden**: RPC cevabında gelen kök ile kanonik BNS çapa kökü (`expected_bns_anchor`) eşleşmesi aranmaksızın durum bayrağının atanması.
- **Çözüm**: Çapa kökü doğrulanmadığında durum açıkça `Unverified` yapılır ve hata loglanır.
- **Durum**: Çözüldü (`ad88285c`).

### B-WAL-02: PoA İmza Talebinde Yanlış Ağ Kimliği (ChainId) Yayılımı
- **Önem**: Yüksek (High)
- **Dosya**: `crates/wallet-core/src/consent_screen.rs:112-140`
- **Açıklama**: Cüzdan onay ekranında PoA izinli ağına atılacak bir işlem genel testnet/mainnet işlem formatıyla karıştırılabiliyordu.
- **Kök Neden**: Onay ekranı veri modelinde PoA domain ayrımının görsel ve yapısal olarak zorunlu olmaması.
- **Çözüm**: PoA işlemleri için `ConsentScreen::PoaIsolated` tipi tanımlandı; imzalama sadece PoA domain tag'i ile kısıtlandı.
- **Durum**: Çözüldü (`ad88285c`).

### B-WAL-03: Özel Anahtar Bellek Temizliği (Zeroize Eksikliği)
- **Önem**: Düşük (Low)
- **Dosya**: `crates/wallet-core/src/store.rs:83-95`
- **Açıklama**: Geçici anahtar parçalarının drop edildiğinde sıfırlanmaması riski.
- **Kök Neden**: `Zeroize` ve `ZeroizeOnDrop` trait implementasyonunun bazı sarmalayıcı (wrapper) yapılarda eksik kalması.
- **Çözüm**: Tüm anahtar tutucu yapılara `ZeroizeOnDrop` eklendi.
- **Durum**: Çözüldü (`5d912761`).
