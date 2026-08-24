//! Consensus plugins for custom domains.
//!
//! # A plugin is consensus code
//!
//! `ConsensusKind::Custom` delegates a domain's finality decision to the plugin
//! registered here, through the `verify_finality` dispatch in `blockchain.rs`.
//! So a plugin is the code that writes the answer to "which block counts as
//! final": not a configuration value, but the consensus rules themselves.
//!
//! What follows from that: **changing** a plugin is changing the domain's
//! consensus rules. If the match check performed at registration time, between
//! the kind and the adapter name, only runs on the first registration, then
//! every change after that registration walks around behind the check.
//!
//! # What was happening in this file
//!
//! `register` refused a re-registration, which is right. But `remove` sat next
//! to it, and together the two did exactly the thing that was refused:
//! `remove(d)` followed by `register(d, new)`. What was refused could not be
//! done in one step but was free in two, and two steps are only one line more
//! than one step for an attacker.
//!
//! `remove` was called from nowhere in production; only the tests used it. A
//! capability not being used in production does not make it harmless: every
//! capability standing in the code base is a capability the next developer can
//! use, and its name, `remove`, says what it does but not what it costs.
//!
//! Change is now possible, but it is **recorded**:
//! [`DomainPluginRegistry::replace`] writes the old plugin's adapter name, the
//! new one's, and the domain the change happened in, into an audit entry. The
//! record itself does not prevent the change; preventing it would be wrong,
//! because a faulty plugin has to be replaceable. The record's job is to
//! prevent the change from happening **unseen**.

use crate::domain::plugin::ConsensusDomainPlugin;
use crate::domain::types::DomainId;
use std::collections::BTreeMap;
use std::sync::Arc;

/// The record of the moment a plugin was replaced.
///
/// The fields are enough to answer "what happened" after a change: which
/// domain, from which adapter to which. There is no timestamp, because this
/// record is kept in the chain's own order and a wall clock differs from node
/// to node; an auditable trail has to be identical on every node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginReplacement {
    /// The domain whose consensus rules changed.
    pub domain_id: DomainId,
    /// The adapter name before the change.
    pub previous_adapter: String,
    /// The adapter name after the change.
    pub next_adapter: String,
}

#[derive(Default)]
pub struct DomainPluginRegistry {
    plugins: BTreeMap<DomainId, Arc<dyn ConsensusDomainPlugin>>,
    /// The trail of every plugin change made, in order.
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

    /// Registers the first plugin for a domain.
    ///
    /// # Errors
    ///
    /// If the domain already has a plugin. Changing it goes through
    /// [`Self::replace`]: a separate name, because it is a separate decision.
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

    /// Replaces an existing plugin and writes the change into the audit trail.
    ///
    /// After the call, [`Self::replacements`] carries one more entry. The trail
    /// records not **what** the plugin is but which adapter it offers: that is
    /// what makes the domain's consensus behaviour visible from the outside, and
    /// it gives the same value on two nodes.
    ///
    /// # Errors
    ///
    /// If the domain has no plugin registered. Replacing something that does not
    /// exist would be another way of making the first registration without
    /// audit.
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

    /// The plugin changes made in this registry, in order.
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

    /// Replacing a plugin leaves a trail.
    ///
    /// There used to be a `remove` and `register` pair, which did in two steps
    /// what `register` refused, and left no trail. Now the change goes by a
    /// single name, and that name keeps a record.
    #[test]
    fn replacing_a_plugin_leaves_an_audit_trail() {
        let mut registry = DomainPluginRegistry::new();
        registry
            .register(7, plugin())
            .expect("the first registration");
        assert!(
            registry.replacements().is_empty(),
            "a first registration is not a change"
        );

        let record = registry
            .replace(7, plugin())
            .expect("the change must be accepted");
        assert_eq!(record.domain_id, 7);
        assert_eq!(
            registry.replacements(),
            &[record],
            "the change must reach the trail"
        );

        // The trail accumulates: a second change does not erase the first,
        // because an erased trail makes the trail itself meaningless.
        registry.replace(7, plugin()).expect("the second change");
        assert_eq!(registry.replacements().len(), 2);

        // A domain that is not registered cannot be replaced; otherwise `replace`
        // would be the way to keep the first registration out of the audit.
        assert!(
            registry.replace(99, plugin()).is_err(),
            "a plugin that does not exist must not be replaceable"
        );

        // And after the change, the plugin read back must be the new one; keeping
        // a trail while continuing the old behaviour would make the trail lie.
        assert!(registry.get(7).is_some());
    }
}
