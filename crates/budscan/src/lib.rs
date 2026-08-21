//! Budscan: Budlum'un merkeziyetsiz tarayici cekirdegi.
//!
//! # Ne yapar
//!
//! Kullanici adres cubuguna `ayaz.bud` yazar. Tarayici sunu yapar:
//!
//! 1. Yazilani siniflandirir ([`query`]): ad mi, adres mi, NFT mi, sema mi.
//! 2. Ad kuralindan gecirir ([`name_rule`]).
//! 3. Adi cozer: `.bud` ise BNS'ten ([`bns_proof`]), `.eth` ise ENS'ten
//!    ([`ens`]).
//! 4. Cozumun gosterdigi icerigi getirir ([`fetch`]).
//! 5. **Getirdigi baytlarin istenen baytlar oldugunu dogrular.**
//! 6. Dogrulanmis baytlari Gecko'ya bir sayfa olarak verir ([`resolve`]).
//!
//! Besinci adim bu tarayicinin var olma sebebi. Bugunku web'de tarayici,
//! sunucunun gonderdigi baytlarin dogru baytlar oldugunu bilmez; TLS yalniz
//! **kimin** gonderdigini soyler, **neyin** gonderildigini degil. Icerik
//! adresli bir agda bu farkli: `manifest_id` baytlarin hash'idir, yani
//! dogrulama bir karsilastirmadir.
//!
//! # Motor yazilmaz, yamalanir
//!
//! Bir tarayici motoru uc seydir: bir HTML/CSS duzenleyici, bir JavaScript
//! motoru ve bir sanal alan. Ucu de onlarca yilin isi ve ucu de saldiri
//! yuzeyinin tamami. Kendi motorunu yazan bir web3 tarayicisi, cozmeye
//! calistigi problemin yanina bir de tarayici guvenligi problemi ekler.
//!
//! Budscan motor yazmaz: Gecko'yu yamalar. Bu crate o yamalarin **arkasindaki
//! karar mercii**dir; `browser/` altindaki yama katmani `bud://` protokol
//! isleyicisini ve adres cubugu gostergesini ekler ve butun kararlari buraya
//! sorar.
//!
//! # Kabuk yok
//!
//! Yama araclari da dahil hicbir sey kabuk degil. Sebep gecmiste iki kez
//! olculdu: yanlis yazilmis bir degisken kabukta hata degil bos dizgidir, yani
//! bir kontrol hicbir seyi inceleyip OK diyebilir. Yama araclari
//! [`patchset`] icinde, Rust olarak duruyor.
//!
//! # Neyin dogrulanmadigi da yazilidir
//!
//! Bu crate'in bir kismi, **yapilamayanin** kaydidir:
//!
//! * BNS cozumu bugun isim basina kanitlanamiyor, cunku
//!   `BnsRegistry::root()` butun defteri tek bir SHA-256 akisina yaziyor
//!   ([`bns_proof`]).
//! * Baslik kesinligi tarayicida dogrulanmiyor; yedi `DomainFinalityAdapter`
//!   bicimi var ve hicbiri istemci tarafinda uygulanmadi
//!   ([`light_client`]).
//! * IPFS `dag-pb` coklu blok icerik dogrulanmiyor ([`cid`]).
//! * IPNS ve Swarm icin getirici yok ([`resolve`]).
//!
//! Bunlarin hicbiri sessizce `dogrulandi` diye etiketlenmiyor; hepsi
//! [`evidence::Strength`] uzerinden asagi bir guce dusuyor.

pub mod arweave;
pub mod bns_proof;
pub mod cid;
pub mod content_id;
pub mod ens;
pub mod evidence;
pub mod evm_audit;
pub mod fetch;
pub mod light_client;
pub mod name_rule;
pub mod patchset;
pub mod punycode;
pub mod query;
pub mod resolve;
pub mod search;

pub use content_id::ContentId;
pub use evidence::{Claim, Evidence, Strength};
pub use name_rule::{check_name, NameRejection};
pub use query::{classify, Query};
pub use resolve::Page;

/// Bu crate'in surumu; rozetlerde ve yama basliklarinda kullanilir.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
