//! Sovereign Domain Kit primitives.
//!
//! The kit helps CBDC, public-sector, enterprise PoA and consortium domains
//! Describe lifecycle and compliance evidence without leaking private KYC data
//! Or merging PoA rules into the permissionless core registry.
//!
//! # Nereden cagriliyor
//!
//! `SovereignDomainRegistry::register_template_for_domain`, sablonu
//! `ConsensusDomainRegistry` icindeki gercek alanla karsilastirir: uzlasma
//! turu ve operator eslesmeli. Once oyle degildi - sablonun kendi icinde
//! tutarli olmasi yeterliydi, dolayisiyla bir alani gercekte oldugundan
//! baska turlu anlatan bir denetim belgesi uretilebiliyordu.

use crate::core::address::Address;
use crate::domain::{ConsensusKind, DomainId, DomainStatus, Hash32};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_AUDIT_EXPORT_SPAN_BLOCKS: u64 = 1_000_000;
pub const MAX_SOVEREIGN_DOMAIN_TEMPLATES: usize = 1_024;

fn nonzero_hash(value: &Hash32) -> bool {
    *value != [0u8; 32]
}

fn validate_label(field: &str, value: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && !value.contains("..")
        && !value.contains('/')
        && !value.bytes().any(|b| b == 0 || b.is_ascii_control());
    if valid {
        Ok(())
    } else {
        Err(format!("{field} invalid"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SovereignDomainClass {
    Cbdc,
    PublicSector,
    EnterprisePoa,
    Consortium,
    Custom(String),
}

impl SovereignDomainClass {
    pub fn validate(&self) -> Result<(), String> {
        if let SovereignDomainClass::Custom(label) = self {
            validate_label("SovereignDomainClass::Custom", label)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainLifecycleState {
    Draft,
    Active,
    Frozen,
    Retired,
}

impl DomainLifecycleState {
    pub fn can_transition_to(&self, next: &Self) -> bool {
        match (self, next) {
            (Self::Draft, Self::Active | Self::Frozen | Self::Retired) => true,
            (Self::Active, Self::Frozen | Self::Retired) => true,
            (Self::Frozen, Self::Active | Self::Retired) => true,
            (Self::Retired, _) => false,
            (current, next) if current == next => true,
            _ => false,
        }
    }

    fn tag(&self) -> u8 {
        match self {
            Self::Draft => 1,
            Self::Active => 2,
            Self::Frozen => 3,
            Self::Retired => 4,
        }
    }
}

impl From<DomainStatus> for DomainLifecycleState {
    fn from(status: DomainStatus) -> Self {
        match status {
            DomainStatus::Active => Self::Active,
            DomainStatus::Frozen => Self::Frozen,
            DomainStatus::Retired => Self::Retired,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceEvidence {
    pub policy_hash: Hash32,
    pub authority_set_hash: Hash32,
    pub jurisdiction_hash: Hash32,
    pub audit_commitment: Hash32,
}

impl ComplianceEvidence {
    pub fn validate(&self) -> Result<(), String> {
        if !nonzero_hash(&self.policy_hash) {
            return Err("ComplianceEvidence policy_hash cannot be zero".into());
        }
        if !nonzero_hash(&self.authority_set_hash) {
            return Err("ComplianceEvidence authority_set_hash cannot be zero".into());
        }
        if !nonzero_hash(&self.jurisdiction_hash) {
            return Err("ComplianceEvidence jurisdiction_hash cannot be zero".into());
        }
        if !nonzero_hash(&self.audit_commitment) {
            return Err("ComplianceEvidence audit_commitment cannot be zero".into());
        }
        Ok(())
    }

    /// Domain-separated root over public commitments only. No KYC/person data
    /// Is carried here; private compliance data remains off-chain.
    pub fn root(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_SOVEREIGN_COMPLIANCE_EVIDENCE_V1");
        hasher.update(self.policy_hash);
        hasher.update(self.authority_set_hash);
        hasher.update(self.jurisdiction_hash);
        hasher.update(self.audit_commitment);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovereignDomainTemplate {
    pub template_id: Hash32,
    pub domain_id: DomainId,
    pub class: SovereignDomainClass,
    pub consensus_kind: ConsensusKind,
    pub operator: Address,
    pub requires_kyc: bool,
    pub compliance: ComplianceEvidence,
    pub lifecycle: DomainLifecycleState,
}

impl SovereignDomainTemplate {
    pub fn new(
        domain_id: DomainId,
        class: SovereignDomainClass,
        consensus_kind: ConsensusKind,
        operator: Address,
        requires_kyc: bool,
        compliance: ComplianceEvidence,
        lifecycle: DomainLifecycleState,
    ) -> Self {
        let mut template = Self {
            template_id: [0u8; 32],
            domain_id,
            class,
            consensus_kind,
            operator,
            requires_kyc,
            compliance,
            lifecycle,
        };
        template.template_id = template.calculate_id();
        template
    }

    pub fn calculate_id(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_SOVEREIGN_DOMAIN_TEMPLATE_V1");
        hasher.update(self.domain_id.to_le_bytes());
        hasher.update(format!("{:?}", self.class).as_bytes());
        hasher.update(self.consensus_kind.as_bytes());
        hasher.update(self.operator.as_bytes());
        hasher.update([u8::from(self.requires_kyc)]);
        hasher.update(self.compliance.root());
        hasher.update([self.lifecycle.tag()]);
        hasher.finalize().into()
    }

    pub fn verify_id(&self) -> bool {
        self.template_id == self.calculate_id()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.domain_id == 0 {
            return Err("SovereignDomainTemplate domain_id must be non-zero".into());
        }
        self.class.validate()?;
        self.compliance.validate()?;
        if self.operator == Address::zero() {
            return Err("SovereignDomainTemplate operator cannot be zero".into());
        }
        if !self.verify_id() {
            return Err("SovereignDomainTemplate template_id mismatch".into());
        }
        if matches!(self.consensus_kind, ConsensusKind::PoA) && !self.requires_kyc {
            return Err("PoA sovereign domains must explicitly require KYC".into());
        }
        if !matches!(self.consensus_kind, ConsensusKind::PoA) && self.requires_kyc {
            return Err("KYC requirement must not leak into permissionless non-PoA domains".into());
        }
        if matches!(self.class, SovereignDomainClass::EnterprisePoa)
            && !matches!(self.consensus_kind, ConsensusKind::PoA)
        {
            return Err("EnterprisePoa sovereign class must use PoA consensus".into());
        }
        Ok(())
    }

    pub fn transition_to(&mut self, next: DomainLifecycleState) -> Result<(), String> {
        if !self.lifecycle.can_transition_to(&next) {
            return Err("SovereignDomainTemplate lifecycle transition invalid".into());
        }
        self.lifecycle = next;
        self.template_id = self.calculate_id();
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditExportBundle {
    pub template_id: Hash32,
    pub from_height: u64,
    pub to_height: u64,
    pub global_header_root: Hash32,
    pub commitment_root: Hash32,
    pub compliance_root: Hash32,
}

impl AuditExportBundle {
    pub fn validate_against_template(
        &self,
        template: &SovereignDomainTemplate,
    ) -> Result<(), String> {
        template.validate()?;
        if self.template_id != template.template_id {
            return Err("AuditExportBundle template mismatch".into());
        }
        if self.from_height > self.to_height {
            return Err("AuditExportBundle height range invalid".into());
        }
        if self.to_height.saturating_sub(self.from_height) > MAX_AUDIT_EXPORT_SPAN_BLOCKS {
            return Err("AuditExportBundle height range too large".into());
        }
        if !nonzero_hash(&self.global_header_root)
            || !nonzero_hash(&self.commitment_root)
            || !nonzero_hash(&self.compliance_root)
        {
            return Err("AuditExportBundle roots cannot be zero".into());
        }
        if self.compliance_root != template.compliance.root() {
            return Err("AuditExportBundle compliance root mismatch".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SovereignDomainRegistry {
    pub templates: BTreeMap<DomainId, SovereignDomainTemplate>,
}

impl SovereignDomainRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Şablonu, adlandırdığı gerçek uzlaşma alanına bağlayarak kaydet.
    ///
    /// # Neden ayrı bir giriş
    ///
    /// [`register_template`](Self::register_template) şablonun **kendi
    /// içinde** tutarlı olduğunu doğrular: PoA ise KYC ister, kimliği
    /// alanlarından yeniden hesaplanır. Ama `domain_id`'nin gerçekte hangi
    /// alanı gösterdiğine bakmaz. Bu, şablonun taşıdığı iki iddiayı
    /// denetimsiz bırakıyordu.
    ///
    /// Bir şablon `domain_id = 7` için `PoA` ve `requires_kyc = true`
    /// diyebilirdi; 7 numaralı alan `PoS` olarak kayıtlıysa, denetime sunulan
    /// belge "bu alan izinli ve KYC'li" derken zincir izinsiz çalışmaya devam
    /// ederdi. İkisi de kendi içinde geçerli, birlikte yalan. `operator` için
    /// de aynısı geçerli: şablonun işaret ettiği operatör, alanın gerçek
    /// operatörü olmalı, yoksa başkasının alanı adına denetim belgesi
    /// yazılabilirdi.
    ///
    /// # Errors
    ///
    /// Alan kayıtlı değilse, uzlaşma türü şablonunkiyle uyuşmuyorsa ya da
    /// operatör farklıysa hata döner. Ayrıca
    /// [`register_template`](Self::register_template)'in her hatası.
    pub fn register_template_for_domain(
        &mut self,
        template: SovereignDomainTemplate,
        domains: &crate::domain::registry::ConsensusDomainRegistry,
    ) -> Result<(), String> {
        let domain = domains.get(template.domain_id).ok_or_else(|| {
            format!(
                "SovereignDomainTemplate names domain {} which is not registered",
                template.domain_id
            )
        })?;
        if domain.kind != template.consensus_kind {
            return Err(format!(
                "SovereignDomainTemplate claims {:?} for domain {} but it is registered as {:?}",
                template.consensus_kind, template.domain_id, domain.kind
            ));
        }
        if domain.operator != Some(template.operator) {
            return Err(format!(
                "SovereignDomainTemplate operator does not match the operator of domain {}",
                template.domain_id
            ));
        }
        self.register_template(template)
    }

    pub fn register_template(&mut self, template: SovereignDomainTemplate) -> Result<(), String> {
        template.validate()?;
        if self.templates.len() >= MAX_SOVEREIGN_DOMAIN_TEMPLATES
            && !self.templates.contains_key(&template.domain_id)
        {
            return Err("SovereignDomainRegistry template limit exceeded".into());
        }
        if self.templates.contains_key(&template.domain_id) {
            return Err("SovereignDomainRegistry domain already registered".into());
        }
        self.templates.insert(template.domain_id, template);
        Ok(())
    }

    /// Denetim dışa aktarımını, iddia ettiği kayıtlı şablona karşı doğrula.
    ///
    /// Paket `template_id` taşır ama bu tek başına bir şey söylemez: kimlik
    /// paketin kendi içinden gelir, kayıt defterinden değil. Bağlamadan
    /// önce, uydurma bir `template_id` ile üretilmiş bir paket kendi
    /// tutarlılık denetiminden geçebilirdi. Burada kimlik önce kayıtta
    /// aranır; bulunamazsa paket reddedilir.
    ///
    /// # Errors
    ///
    /// Hiçbir kayıtlı şablon bu kimliği taşımıyorsa, ya da
    /// [`AuditExportBundle::validate_against_template`] hata döndürürse.
    pub fn validate_audit_export(&self, bundle: &AuditExportBundle) -> Result<(), String> {
        let template = self
            .templates
            .values()
            .find(|template| template.template_id == bundle.template_id)
            .ok_or_else(|| {
                "AuditExportBundle names a template that is not registered".to_string()
            })?;
        bundle.validate_against_template(template)
    }

    pub fn transition_lifecycle(
        &mut self,
        domain_id: DomainId,
        next: DomainLifecycleState,
    ) -> Result<(), String> {
        let template = self
            .templates
            .get_mut(&domain_id)
            .ok_or_else(|| "SovereignDomainRegistry domain not found".to_string())?;
        template.transition_to(next)
    }

    pub fn root(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_SOVEREIGN_DOMAIN_REGISTRY_V1");
        for (domain_id, template) in &self.templates {
            hasher.update(domain_id.to_le_bytes());
            hasher.update(template.template_id);
            hasher.update(template.compliance.root());
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    fn evidence() -> ComplianceEvidence {
        ComplianceEvidence {
            policy_hash: [1u8; 32],
            authority_set_hash: [2u8; 32],
            jurisdiction_hash: [3u8; 32],
            audit_commitment: [4u8; 32],
        }
    }

    fn domain_registry_with(
        id: DomainId,
        kind: ConsensusKind,
        adapter: &str,
    ) -> (crate::domain::registry::ConsensusDomainRegistry, Address) {
        let domain =
            crate::domain::plugin::default_domain(id, kind, 4000 + u64::from(id), adapter, 0);
        let operator = domain.operator.expect("varsayilan alan operator tasir");
        let mut domains = crate::domain::registry::ConsensusDomainRegistry::new();
        domains.register(domain).expect("alan kaydi");
        (domains, operator)
    }

    fn template_for(
        id: DomainId,
        kind: ConsensusKind,
        operator: Address,
        requires_kyc: bool,
    ) -> SovereignDomainTemplate {
        SovereignDomainTemplate::new(
            id,
            SovereignDomainClass::Cbdc,
            kind,
            operator,
            requires_kyc,
            evidence(),
            DomainLifecycleState::Draft,
        )
    }

    /// Alanla eşleşen şablon kaydedilebilmeli.
    #[test]
    fn a_template_matching_its_domain_registers() {
        let (domains, operator) =
            domain_registry_with(7, ConsensusKind::PoA, "poa-authority-quorum");
        let mut sovereign = SovereignDomainRegistry::new();
        sovereign
            .register_template_for_domain(
                template_for(7, ConsensusKind::PoA, operator, true),
                &domains,
            )
            .expect("tur ve operator eslesiyor");
        assert!(sovereign.templates.contains_key(&7));
    }

    /// PoS olarak kayıtlı bir alanı PoA gösteren şablon reddedilmeli.
    ///
    /// Şablon kendi içinde geçerlidir (PoA + KYC), alan da geçerlidir; ikisi
    /// birlikte yalan söyler. Bağlama olmadan, denetime "bu alan izinli ve
    /// KYC'li" diyen bir belge üretilebilirdi.
    #[test]
    fn a_template_claiming_the_wrong_consensus_kind_is_refused() {
        let (domains, operator) = domain_registry_with(8, ConsensusKind::PoS, "pos-qc-finality");
        let mut sovereign = SovereignDomainRegistry::new();
        let err = sovereign
            .register_template_for_domain(
                template_for(8, ConsensusKind::PoA, operator, true),
                &domains,
            )
            .expect_err("tur uyusmazligi reddedilmeli");
        assert!(err.contains("registered as"), "{err}");
        assert!(sovereign.templates.is_empty());
    }

    /// Başkasının alanı adına şablon yazılamamalı.
    #[test]
    fn a_template_naming_a_foreign_operator_is_refused() {
        let (domains, _operator) =
            domain_registry_with(9, ConsensusKind::PoA, "poa-authority-quorum");
        let mut sovereign = SovereignDomainRegistry::new();
        let err = sovereign
            .register_template_for_domain(
                template_for(9, ConsensusKind::PoA, addr(200), true),
                &domains,
            )
            .expect_err("yabanci operator reddedilmeli");
        assert!(err.contains("operator"), "{err}");
    }

    /// Kayıtlı olmayan bir alan için şablon yazılamamalı.
    #[test]
    fn a_template_naming_an_unregistered_domain_is_refused() {
        let domains = crate::domain::registry::ConsensusDomainRegistry::new();
        let mut sovereign = SovereignDomainRegistry::new();
        let err = sovereign
            .register_template_for_domain(
                template_for(11, ConsensusKind::PoA, addr(9), true),
                &domains,
            )
            .expect_err("kayitsiz alan reddedilmeli");
        assert!(err.contains("not registered"), "{err}");
    }

    #[test]
    fn poa_template_requires_kyc_and_keeps_only_hashes() {
        let template = SovereignDomainTemplate::new(
            7,
            SovereignDomainClass::Cbdc,
            ConsensusKind::PoA,
            addr(9),
            true,
            evidence(),
            DomainLifecycleState::Draft,
        );
        assert!(template.validate().is_ok());
        let json = serde_json::to_string(&template).unwrap();
        assert!(!json.contains("passport"));
        assert!(!json.contains("national_id"));
        assert!(!json.contains("kyc_document"));
    }

    #[test]
    fn non_poa_template_rejects_kyc_leakage() {
        let template = SovereignDomainTemplate::new(
            8,
            SovereignDomainClass::Consortium,
            ConsensusKind::PoS,
            addr(9),
            true,
            evidence(),
            DomainLifecycleState::Draft,
        );
        assert!(template.validate().unwrap_err().contains("non-PoA"));
    }

    #[test]
    fn audit_bundle_binds_template_and_compliance_root() {
        let template = SovereignDomainTemplate::new(
            7,
            SovereignDomainClass::EnterprisePoa,
            ConsensusKind::PoA,
            addr(9),
            true,
            evidence(),
            DomainLifecycleState::Active,
        );
        let bundle = AuditExportBundle {
            template_id: template.template_id,
            from_height: 10,
            to_height: 20,
            global_header_root: [5u8; 32],
            commitment_root: [6u8; 32],
            compliance_root: template.compliance.root(),
        };
        assert!(bundle.validate_against_template(&template).is_ok());
    }

    #[test]
    fn compliance_evidence_rejects_zero_hashes() {
        let mut evidence = evidence();
        evidence.policy_hash = [0u8; 32];
        assert!(evidence.validate().unwrap_err().contains("policy_hash"));
    }

    #[test]
    fn custom_class_rejects_path_like_label() {
        let template = SovereignDomainTemplate::new(
            9,
            SovereignDomainClass::Custom("../bad".into()),
            ConsensusKind::PoA,
            addr(9),
            true,
            evidence(),
            DomainLifecycleState::Draft,
        );
        assert!(template.validate().unwrap_err().contains("Custom"));
    }

    #[test]
    fn enterprise_poa_class_cannot_use_permissionless_consensus() {
        let template = SovereignDomainTemplate::new(
            9,
            SovereignDomainClass::EnterprisePoa,
            ConsensusKind::PoS,
            addr(9),
            false,
            evidence(),
            DomainLifecycleState::Draft,
        );
        assert!(template.validate().unwrap_err().contains("EnterprisePoa"));
    }

    #[test]
    fn lifecycle_transition_rejects_retired_reactivation() {
        let mut template = SovereignDomainTemplate::new(
            7,
            SovereignDomainClass::EnterprisePoa,
            ConsensusKind::PoA,
            addr(9),
            true,
            evidence(),
            DomainLifecycleState::Active,
        );
        template
            .transition_to(DomainLifecycleState::Retired)
            .unwrap();
        assert!(template
            .transition_to(DomainLifecycleState::Active)
            .unwrap_err()
            .contains("transition"));
    }

    #[test]
    fn registry_root_changes_when_lifecycle_transitions() {
        let template = SovereignDomainTemplate::new(
            7,
            SovereignDomainClass::EnterprisePoa,
            ConsensusKind::PoA,
            addr(9),
            true,
            evidence(),
            DomainLifecycleState::Draft,
        );
        let mut registry = SovereignDomainRegistry::new();
        registry.register_template(template).unwrap();
        let before = registry.root();
        registry
            .transition_lifecycle(7, DomainLifecycleState::Active)
            .unwrap();
        assert_ne!(before, registry.root());
    }

    #[test]
    fn audit_bundle_rejects_zero_roots_and_huge_ranges() {
        let template = SovereignDomainTemplate::new(
            7,
            SovereignDomainClass::EnterprisePoa,
            ConsensusKind::PoA,
            addr(9),
            true,
            evidence(),
            DomainLifecycleState::Active,
        );
        let zero_root_bundle = AuditExportBundle {
            template_id: template.template_id,
            from_height: 10,
            to_height: 20,
            global_header_root: [0u8; 32],
            commitment_root: [6u8; 32],
            compliance_root: template.compliance.root(),
        };
        assert!(zero_root_bundle
            .validate_against_template(&template)
            .unwrap_err()
            .contains("roots"));

        let huge = AuditExportBundle {
            template_id: template.template_id,
            from_height: 0,
            to_height: MAX_AUDIT_EXPORT_SPAN_BLOCKS + 1,
            global_header_root: [5u8; 32],
            commitment_root: [6u8; 32],
            compliance_root: template.compliance.root(),
        };
        assert!(huge
            .validate_against_template(&template)
            .unwrap_err()
            .contains("too large"));
    }
}
