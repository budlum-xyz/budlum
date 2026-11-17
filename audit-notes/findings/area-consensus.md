# Denetim Bulguları: Konsensüs Alanları (Area Consensus)

Denetlenen Konumlar: `src/consensus/` (`pow.rs`, `pos.rs`, `qc.rs`, `handoff.rs`, `hotstuff.rs`, `finality.rs`, `poa.rs`, `dag.rs`, `poh.rs`, `pospace.rs`), `src/mining/`, `src/settlement/domains.rs`.

## 1. Kapsam ve İnceleme Metodolojisi

Konsensüs katmanı PoW, PoS, BFT ve izole PoA alt sistemleri ile yeni eklenen DAG, PoH ve PoSpace adaptörlerini içerir. Denetim sırasında:
- Fikir birliği durum geçişlerinin determinizmi (`StateTransition::apply`),
- Blok üretim ve lider seçimi yollarında zamanlama yan kanalları,
- PoA izinli ağının genel izinsiz (permissionless) BFT mutabakatına sızma riskleri,
- Bincode diskriminant sıralaması ve serileştirme sınırları incelenmiştir.

## 2. Bulgular

### B-CONS-01: ConsensusKind Bincode Enum Diskriminant Kayması
- **Önem**: Kritik (Critical)
- **Dosya**: `src/domain/types.rs:70-85`
- **Açıklama**: Yeni konsensüs türleri (DAG, PoH, PoSpace) `ConsensusKind` numaralandırmasının ortasına eklendiğinde geriye dönük binary uyumluluk bozulur ve eski düğümler blokları deserialize ederken yanlış konsensüs eklentisini çalıştırır.
- **Kök Neden**: Bincode serileştirmede enum variant sırası indeks olarak kodlanır.
- **Çözüm**: `ConsensusKind` variantları korunarak yeni türler en sona eklendi (`AiInference = 5`, `Dag = 6`, `Poh = 7`, `Pospace = 8`).
- **Durum**: Çözüldü (`3c891b5d`).

### B-CONS-02: PoA Doğrulayıcı Anahtarlarının BFT Oylama Havuzuna Sızması
- **Önem**: Yüksek (High)
- **Dosya**: `src/consensus/poa.rs`, `src/settlement/domains.rs`
- **Açıklama**: İzole PoA alanlarına ait onaylayıcı anahtarlarının genel ağ HotStuff QC (Quorum Certificate) hesaplamalarına dahil edilme riski.
- **Kök Neden**: PoA imza doğrulamasında `DomainId` etiket ayrımının eksik olması.
- **Çözüm**: Tüm PoA imzaları `BDLM_POA_DOMAIN_ATTEST_V1` domain separation tag'i ile sınırlandı. Genel BFT oylama havuzunda PoA imzaları reddedilir.
- **Durum**: Çözüldü (`ad88285c`).

### B-CONS-03: DAG Çoklu Ebeveyn Kök Manipülasyonu
- **Önem**: Yüksek (High)
- **Dosya**: `src/domain/plugin.rs:415-424`
- **Açıklama**: DAG bloklarında ebeveyn hash listesi sıralanmadan Merkle köküne dahil edildiğinde aynı blok için birden fazla geçerli kök türetilebiliyordu.
- **Kök Neden**: Ebeveyn vektörünün kanonik sıra garantisi olmadan işlenmesi.
- **Çözüm**: `extract_commitment` aşamasında ebeveyn hash'leri kanonik sıralanıp (`sort_unstable`) tekilleştirildi (`dedup`).
- **Durum**: Çözüldü (`3c891b5d`).

### B-CONS-04: PoH Tick Doğrulama Döngü Tükenmesi (Denial of Service)
- **Önem**: Yüksek (High)
- **Dosya**: `src/consensus/poh.rs:188-212`
- **Açıklama**: Bounded tick kontrolü olmadan gelen PoH kanıtları tek bir thread üzerinde yüz binlerce VDF adımını ardışık hesaplayarak doğrulayıcıyı kilitliyordu.
- **Kök Neden**: Azami tick limitinin (`MAX_POH_TICKS_PER_BLOCK = 128_000`) zorunlu tutulmaması.
- **Çözüm**: Tick sayısı sınırlandı ve geçersiz VDF ara değerleri fail-closed olarak anında reddedildi.
- **Durum**: Çözüldü (`3c891b5d`).

### B-CONS-05: Reorg Sonrası Handoff Sertifikası Komite Oy Ağırlığı
- **Önem**: Düşük (Low)
- **Dosya**: `src/consensus/handoff.rs:254-260`
- **Açıklama**: Handoff sertifikası yalnızca kafa sayısına (head count) bakıyordu.
- **Kök Neden**: Stake ağırlıklı 2/3 çoğunluk kontrolünün yapılmaması.
- **Çözüm**: Sertifika doğrulaması hem kafa sayısı hem de toplam aktif stake'in en az 2/3'ünü arayacak şekilde güncellendi.
- **Durum**: Çözüldü (`ad88285c`).
