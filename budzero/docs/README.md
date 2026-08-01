# Crafting a ZKVM: BudZKVM Rehberi

Bu kitap, sıfırdan bir Sanal Makine (VM) ve bu makine üzerinde çalışan programların doğruluğunu kriptografik olarak kanıtlayabilen bir ZKVM (Zero-Knowledge Virtual Machine) tasarlama rehberidir.

Bu rehber, popüler "Crafting Interpreters" kitabının felsefesini benimseyerek, konuyu tamamen pratik, koda dayalı ve adım adım bir yaklaşımla ele alır. Örnek uygulama olarak **BudZKVM** projesini inceliyoruz.

## Bu Kitap Kimler İçin?
* Kriptografi ve ZK-STARK kavramlarına meraklı geliştiriciler.
* Kendi sanal makinesini, komut setini (ISA) veya derleyicisini yazmak isteyenler.
* Plonky3 gibi modern ZK kanıtlayıcı çerçevelerinin (framework) gerçek dünya projelerinde nasıl kullanıldığını görmek isteyenler.

## BudZKVM Mimarisinin Temel Bileşenleri
BudZKVM, modüler bir yaklaşımla tasarlanmıştır. Kitap boyunca aşağıdaki bileşenleri adım adım inşa edeceğiz:

1. **`bud-isa` (Instruction Set Architecture):** VM'in anladığı donanım komutları ve bu komutların bytecode formatında nasıl kodlandığı.
2. **`bud-vm` (Sanal Makine):** Bytecode'u adım adım çalıştıran (fetch-decode-execute), register ve memory durumunu güncelleyen çekirdek yapı.
3. **`bud-compiler` (Derleyici):** Yüksek seviyeli BudL dilini, `bud-isa` bytecode'una çeviren derleyici. `while` ve `for i in start..end` döngüleri dahil temel kontrol akışı desteklenir.
4. **`bud-proof` (ZK Kanıtlayıcı):** Plonky3 tabanlı, VM'in `Execution Trace`'ini (çalıştırma izi) alıp doğru çalıştığına dair kriptografik kanıt (STARK proof) üreten modül.
5. **`bud-cli` (Komut Satırı):** Tüm bu modülleri bir araya getiren ve kullanıcıya sunan arayüz.

## Güncel Durum Notu

BudZKVM artık 31 opcode'luk **tamamen production-ready** bir ZKVM'dir. Tüm opcode'ların AIR constraint'leri tamamlanmış, 51 test (36 proof + 6 negatif dahil) başarıyla geçmektedir.  stabilizasyonu tamamlanmıştır.

## İçindekiler

- [Giriş - ZKVM Nedir ve Neden Kendi ZKVM'imizi Yapıyoruz?](giris.md)
- [Komut Seti Mimarisi ve Bytecode (bud-isa)](isa_ve_bytecode.md)
- [Sanal Makine İnşası (bud-vm)](virtual_machine.md)
  - [BudVM Trace Schema v2](vm_trace_schema.md)
- [ZK Dostu Mimari Tasarımı](zk_friendly_architecture.md)
- [STARK, AIR ve Plonky3 (bud-proof)](stark_ve_plonky3.md)
- [Derleyici ve Ekosistem (bud-compiler & bud-cli)](compiler_ve_ekosistem.md)
- [Prover Stabilizasyonu ve Testler](prover_stabilizasyonu_ve_testler.md)
- [Üretime Hazırlık, Soundness ve Güvenlik Sertleştirmesi](production_hardening_ve_soundness.md)
- [Gelişmiş Dil Özellikleri ve Bellek Yönetimi](gelismis_dil_ozellikleri_ve_bellek_yonetimi.md)
- [Stabilizasyon Durumu](STABILIZATION.md)

## Geliştirici Dokümantasyonu

- [Development Workflow](development.md)
- [Adding an Opcode](adding_opcodes.md)
- [Proof Format Release Checklist](proof_format_release_checklist.md)

---
> **Not:** Bu rehberdeki kod örnekleri Rust dilinde yazılmıştır. Rust'ın temel bellek güvenliği konseptlerine aşina olmak faydalı olacaktır.
