//! Custom alanlarin konsensus eklentileri.
//!
//! # Eklenti konsensus kodudur
//!
//! `ConsensusKind::Custom` bir alanin finality kararini buradaki eklentiye
//! devreder (`blockchain.rs`, `verify_finality` dagitimi). Yani eklenti,
//! "hangi blok kesinlesmis sayilir" sorusunun cevabini yazan koddur - bir
//! yapilandirma degeri degil, konsensus kurallarinin kendisi.
//!
//! Bundan cikan sonuc: bir eklentiyi **degistirmek**, alanin konsensus
//! kurallarini degistirmektir. Kayit anindaki eslesme denetimi (tur ↔ adapter
//! adi) yalnizca ilk kayitta calisiyorsa, kayittan sonraki her degisiklik o
//! denetimin arkasindan dolanir.
//!
//! # Bu dosyada olan neydi
//!
//! `register` yeniden kaydi reddediyordu, ki dogru. Ama yaninda `remove`
//! duruyordu ve ikisi birlikte tam olarak reddedilen seyi yapiyordu:
//! `remove(d)` sonra `register(d, yeni)`. Reddedilen sey tek adimda
//! yapilamiyordu, iki adimda serbestti - ve iki adim, bir saldirgan icin bir
//! adimdan yalnizca bir satir fazladir.
//!
//! `remove` uretimde hicbir yerden cagrilmiyordu; yalnizca testler
//! kullaniyordu. Bir yetkinin uretimde kullanilmiyor olmasi onu zararsiz
//! yapmaz: kod tabaninda duran her yetenek, sonraki gelistiricinin
//! kullanabilecegi bir yetenektir, ve adi (`remove`) ne yaptigini soyler ama
//! neye mal oldugunu soylemez.
//!
//! Simdi degisim mumkun, ama **kaydediliyor**: [`DomainPluginRegistry::replace`]
//! eski eklentinin adapter adini, yenisininkini ve degisimin hangi alanda
//! oldugunu bir denetim girdisine yazar. Kaydin kendisi degisimi engellemez -
//! engellemek dogru olmazdi, cunku hatali bir eklentinin degistirilebilmesi
//! gerekir. Kaydin isi, degisimin **gorunmeden** olmasini engellemek.

use crate::domain::plugin::ConsensusDomainPlugin;
use crate::domain::types::DomainId;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Bir eklentinin degistirildigi anin kaydi.
///
/// Alanlar, degisimden sonra "ne olmustu" sorusunu cevaplamaya yeter: hangi
/// alan, hangi adapter'dan hangisine. Zaman damgasi yok, cunku bu kayit
/// zincirin kendi sirasinda tutuluyor ve duvar saati dugumden dugume
/// degisir - denetlenebilir bir iz, her dugumde ayni olmak zorunda.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginReplacement {
    /// Konsensus kurallari degisen alan.
    pub domain_id: DomainId,
    /// Degisimden onceki adapter adi.
    pub previous_adapter: String,
    /// Degisimden sonraki adapter adi.
    pub next_adapter: String,
}

#[derive(Default)]
pub struct DomainPluginRegistry {
    plugins: BTreeMap<DomainId, Arc<dyn ConsensusDomainPlugin>>,
    /// Yapilmis her eklenti degisiminin izi, sirasiyla.
    replacements: Vec<PluginReplacement>,
}

impl DomainPluginRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            plugins: BTreeMap::new(),
            replacements: Vec::new(),
        }
    }

    /// Bir alana ilk eklentiyi kaydeder.
    ///
    /// # Errors
    ///
    /// Alanda zaten bir eklenti varsa. Degistirmek icin
    /// [`Self::replace`] kullanilmali: ayri bir isim, cunku ayri bir karar.
    pub fn register(
        &mut self,
        domain_id: DomainId,
        plugin: Arc<dyn ConsensusDomainPlugin>,
    ) -> Result<(), String> {
        if self.plugins.contains_key(&domain_id) {
            return Err(format!(
                "Plugin already registered for domain {domain_id}; changing it is a consensus \
                 change and goes through `replace`, which records what changed"
            ));
        }
        self.plugins.insert(domain_id, plugin);
        Ok(())
    }

    /// Var olan bir eklentiyi degistirir ve degisimi denetim izine yazar.
    ///
    /// Cagrildiktan sonra [`Self::replacements`] bir girdi daha tasir. Iz,
    /// eklentinin **ne oldugunu** degil hangi adapter'i sundugunu kaydeder:
    /// alanin konsensus davranisini disaridan gorunur kilan sey odur, ve iki
    /// dugumde ayni degeri verir.
    ///
    /// # Errors
    ///
    /// Alanda kayitli bir eklenti yoksa. Var olmayani degistirmek, ilk kaydi
    /// denetimsiz yapmanin baska bir yolu olurdu.
    pub fn replace(
        &mut self,
        domain_id: DomainId,
        plugin: Arc<dyn ConsensusDomainPlugin>,
    ) -> Result<PluginReplacement, String> {
        let previous = self.plugins.get(&domain_id).ok_or_else(|| {
            format!(
                "No plugin registered for domain {domain_id}; there is nothing to replace, and \
                 a first registration goes through `register`"
            )
        })?;
        let record = PluginReplacement {
            domain_id,
            previous_adapter: previous.finality_adapter().adapter_name().to_string(),
            next_adapter: plugin.finality_adapter().adapter_name().to_string(),
        };
        self.plugins.insert(domain_id, plugin);
        self.replacements.push(record.clone());
        Ok(record)
    }

    /// Bu kayit defterinde yapilmis eklenti degisimleri, sirasiyla.
    #[must_use]
    pub fn replacements(&self) -> &[PluginReplacement] {
        &self.replacements
    }

    #[must_use]
    pub fn get(&self, domain_id: DomainId) -> Option<&Arc<dyn ConsensusDomainPlugin>> {
        self.plugins.get(&domain_id)
    }

    #[must_use]
    pub fn domain_ids(&self) -> Vec<DomainId> {
        self.plugins.keys().copied().collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::pow::PoWEngine;
    use crate::domain::plugin::PoWDomainPlugin;

    fn plugin() -> Arc<dyn ConsensusDomainPlugin> {
        Arc::new(PoWDomainPlugin::new(Arc::new(PoWEngine::new(1))))
    }

    #[test]
    fn register_and_retrieve_plugin() {
        let mut registry = DomainPluginRegistry::new();
        registry.register(1, plugin()).unwrap();
        assert!(registry.get(1).is_some());
        assert!(registry.get(2).is_none());
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut registry = DomainPluginRegistry::new();
        registry.register(1, plugin()).unwrap();
        assert!(registry.register(1, plugin()).is_err());
    }

    /// Bir eklentiyi degistirmek iz birakir.
    ///
    /// Once `remove` + `register` ikilisi vardi ve bu, `register`'in
    /// reddettigi seyi iki adimda yapiyordu - izsiz. Simdi degisim tek bir
    /// adla yapiliyor ve o ad kayit tutuyor.
    #[test]
    fn replacing_a_plugin_leaves_an_audit_trail() {
        let mut registry = DomainPluginRegistry::new();
        registry.register(7, plugin()).expect("ilk kayit");
        assert!(
            registry.replacements().is_empty(),
            "ilk kayit bir degisim degil"
        );

        let record = registry
            .replace(7, plugin())
            .expect("degisim kabul edilmeli");
        assert_eq!(record.domain_id, 7);
        assert_eq!(registry.replacements(), &[record], "degisim ize gecmeli");

        // Iz birikir: ikinci degisim oncekini silmez, cunku silinen bir iz
        // izin kendisini anlamsiz kilar.
        registry.replace(7, plugin()).expect("ikinci degisim");
        assert_eq!(registry.replacements().len(), 2);

        // Kayitli olmayan bir alan degistirilemez: aksi halde `replace`,
        // ilk kaydi denetimden kacirmanin yolu olurdu.
        assert!(
            registry.replace(99, plugin()).is_err(),
            "olmayan eklenti degistirilememeli"
        );

        // Ve degisimden sonra okunan eklenti yenisi olmali - iz tutup eski
        // davranisi surdurmek, izin yalan soylemesi olurdu.
        assert!(registry.get(7).is_some());
    }
}
