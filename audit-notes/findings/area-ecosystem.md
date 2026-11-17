# Denetim Bulguları: Ekosistem Modülleri (Area Ecosystem)

Denetlenen Konumlar: `src/bns/`, `src/garden/`, `src/ai/`, `src/pollen/`, `src/socialfi/`, `src/budlumxyz/`.

## 1. Kapsam ve İnceleme Metodolojisi

Ekosistem modülleri Budlum çekirdeğine bağlı katma değerli servisleri içerir:
- `.bud` ad servisi (BNS) kayıt kuralları, açık artırma ve pazar mekanizmaları (`BNS_DIREKTIF.md`),
- Garden yerel ağları, davet (invite) protokolü, peer kotası ve dedup sınırları,
- AI çıkarım ve doğrulama katmanları (`src/ai/`),
- BudlumXYZ yönetişim modeli ve delege izinleri.

## 2. Bulgular

### B-ECO-01: BNS Kayıtlarında `.bud` Sonek Zorunluluğu ve Uzunluk Kademesi
- **Önem**: Yüksek (High)
- **Dosya**: `src/bns/registry.rs:110-145`, `src/bns/types.rs`
- **Açıklama**: `.bud` son eki olmadan isim kaydedilmeye çalışıldığında veya etiket uzunluğu 3-32 aralığı dışında kaldığında kayıt reddedilmelidir.
- **Kök Neden**: Sonek doğrulamasının bazı RPC hazırlık yollarında gevşek kalması.
- **Çözüm**: `BnsRegistry::register` ve `NameRecord::try_new` kesin olarak `.bud` uzantısını şart koşar. 3 karakterli etiketler 100 kat kayıt ücreti öder.
- **Durum**: Çözüldü (`ad88285c`).

### B-ECO-02: Garden Katılmamış Peer Koltuklarının Sonsuz Kilitlenmesi
- **Önem**: Orta (Medium)
- **Dosya**: `src/garden/node.rs:588-590, 1381-1382`
- **Açıklama**: Garden davet koltukları zaman aşımına uğramadığında tek bir davet sahibi yeni doğrulayıcıların katılımını kalıcı olarak engelleyebiliyordu.
- **Kök Neden**: `unjoined peer seat` zaman aşımı ve kaynak bazlı kotanın bulunmaması.
- **Çözüm**: Koltuk süresi sınırlandı, `per-source budget` ve zaman aşımı eklendi.
- **Durum**: Çözüldü (`d013014a`).

### B-ECO-03: Garden Selamlama (Greeting) Kotasının Diğer Doğrulayıcıları Reddetmesi
- **Önem**: Orta (Medium)
- **Dosya**: `src/garden/net.rs:607-621`
- **Açıklama**: Davet edilmemiş bir host'tan gelen çerçeveler genel selamlama kotasını tüketerek meşru davetli doğrulayıcının katılımını engelliyordu.
- **Kök Neden**: Kota takibinin swarm genelinde tek bir havuzda yapılması.
- **Çözüm**: Bağlantı başına pay ayrımı (`per-connection share`) getirildi.
- **Durum**: Çözüldü (`d013014a`).

### B-ECO-04: BudlumXYZ Yönetişim Yetkilendirilmiş Valiler Sıralaması
- **Önem**: Yüksek (High)
- **Dosya**: `src/budlumxyz/mod.rs:45-68`
- **Açıklama**: Vali listesi serileştirilirken sıra korunmadığında durum kökleri arasında uyuşmazlık çıkabiliyordu.
- **Kök Neden**: `authorized_governors` alanının rastgele sırada tutulması.
- **Çözüm**: `BTreeSet` veri yapısına geçirilerek deterministik kanonik sıralama sağlandı.
- **Durum**: Çözüldü (`595bf1cd`).
