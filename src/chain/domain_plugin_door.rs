//! WIRING: unwired - the domain-block intake door.
//!
//! The plugin registry was built so a node that accepts domain blocks for a
//! local domain validates them through that domain's own registered consensus
//! engine and extracts the commitment through the plugin, whose finality
//! adapter is the one the settlement layer names in the domain record.
//!
//! Nothing in this tree accepts a domain block yet: the relayer submits
//! *commitments* (`settlement::domains::accept_verified_commitment`), not
//! blocks, so the two doors below have no production caller and the block path
//! that will call them lands with the domain-block intake slice. They live in
//! their own module rather than on `Blockchain` so the wiring state is a fact a
//! reviewer reads here, not an assumption made because the methods happen to
//! sit next to the ones that are called.

use crate::chain::blockchain::Blockchain;
use crate::core::block::Block;
use crate::domain::types::{DomainCommitment, DomainId};

/// Resolve the node-local plugin registered for `domain_id`.
///
/// This is the door every plugin-backed operation goes through, and it is
/// fail-closed end to end: the domain must exist (node-local Garden domains
/// first, then canonical in-block domains, the same precedence the RPC views
/// use), a plugin must be registered for it, and the plugin's kind must be the
/// domain's kind. A node that never registered a plugin gets a refusal that
/// names the domain, not a silently permissive default and never a built-in
/// substitution.
///
/// # Errors
///
/// The refusal naming what is missing or mismatched.
pub fn domain_plugin_for(
    chain: &Blockchain,
    domain_id: DomainId,
) -> Result<std::sync::Arc<dyn crate::domain::ConsensusDomainPlugin>, String> {
    let domain = chain
        .consensus_domains_with_garden()
        .into_iter()
        .find(|d| d.id == domain_id)
        .ok_or_else(|| format!("Unknown consensus domain {domain_id}"))?;
    let plugin = chain.plugin_registry.get(domain_id).ok_or_else(|| {
        format!(
            "Domain {domain_id} has no plugin registered in the plugin registry; \
             refusing to run the plugin door for it"
        )
    })?;
    if plugin.kind() != domain.kind {
        return Err(format!(
            "Domain {domain_id} is registered as {:?} but its plugin is a {:?} plugin; \
             refusing to cross-wire them",
            domain.kind,
            plugin.kind()
        ));
    }
    Ok(std::sync::Arc::clone(plugin))
}

/// Validate a domain block through the registered plugin and extract its
/// commitment.
///
/// `domain_chain` is the history of THE DOMAIN'S chain, supplied by the caller
/// that holds it; the context state is this node's settled state. Fail-closed
/// ordering: the domain and plugin must resolve first, the plugin's finality
/// adapter must be the one the domain record commits to, and only then does the
/// block itself get validated. A mismatch at any step is a refusal, never a
/// fallback onto a built-in adapter.
///
/// # Errors
///
/// The refusal from [`domain_plugin_for`], the adapter mismatch, or the
/// plugin's validation/extraction refusal.
///
/// Convenience: kept for the domain-block intake slice; the module header
/// records why no production path calls it yet.
pub fn validate_domain_block_with_plugin(
    chain: &Blockchain,
    domain_id: DomainId,
    block: &Block,
    domain_chain: &[Block],
    sequence: u64,
) -> Result<DomainCommitment, String> {
    let domain = chain
        .consensus_domains_with_garden()
        .into_iter()
        .find(|d| d.id == domain_id)
        .ok_or_else(|| format!("Unknown consensus domain {domain_id}"))?;
    let plugin = domain_plugin_for(chain, domain_id)?;
    let plugin_adapter = plugin.finality_adapter().adapter_name();
    if plugin_adapter != domain.finality_adapter {
        return Err(format!(
            "Domain {domain_id} names finality adapter '{}', but its registered plugin \
             verifies with '{plugin_adapter}'; refusing to emit a commitment under \
             mismatched finality",
            domain.finality_adapter
        ));
    }
    let ctx = crate::domain::DomainContext {
        domain: &domain,
        chain: domain_chain,
        state: &chain.state,
        sequence,
    };
    plugin
        .validate_domain_block(block, ctx.clone())
        .map_err(|e| format!("domain {domain_id} block refused by the registered plugin: {e}"))?;
    plugin
        .extract_commitment(block, ctx)
        .map_err(|e| format!("domain {domain_id} commitment refused by the registered plugin: {e}"))
}
