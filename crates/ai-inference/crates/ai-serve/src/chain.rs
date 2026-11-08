//! The fail-closed budlum node RPC boundary.
//!
//! On-chain operations (model registration, the operator bond, and DataMarket
//! grant checks) go through this interface. The skeleton has no real HTTP
//! client: until a connection is established no chain query counts as
//! successful, and permission rules are not copied into this crate.

use ai_core::dataset::{SourceError, SourceKind, SourceRef};
use ai_core::model::Hash32;

/// Chain RPC errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    /// No node connection was established - fail-closed.
    NotConnected,
    /// The response is not in the expected shape.
    MalformedResponse(String),
}

/// The chain query interface. A DataMarket lookup binds the exact grant, asset,
/// content digest, and consumer together; an asset-only query cannot
/// authorise a caller's chosen grant reference or content bytes.
pub trait ChainClient {
    /// Is this exact DataMarket grant active for this asset, content, and consumer now?
    ///
    /// Implementations must return `true` only when the named grant is active,
    /// belongs to `asset_id`, resolves to `content_id`, and authorises
    /// `consumer`. Checking whether any grant exists for the asset is not
    /// sufficient.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError`] when the node cannot answer or the response is malformed.
    fn data_market_grant_active(
        &self,
        grant_id: &Hash32,
        asset_id: &Hash32,
        content_id: &Hash32,
        consumer: &Hash32,
    ) -> Result<bool, RpcError>;
    /// Is the model registered on chain?
    ///
    /// # Errors
    ///
    /// Returns [`RpcError`] when the node cannot answer or the response is malformed.
    fn model_registered(&self, model_id: &Hash32) -> Result<bool, RpcError>;
    /// The operator's compute-bond amount.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError`] when the node cannot answer or the response is malformed.
    fn operator_bond(&self, operator: &Hash32) -> Result<u64, RpcError>;
}

/// Why a DataMarket input could not be authorised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantAuthorizationError {
    /// The source is malformed or does not identify its exact grant.
    InvalidSource(SourceError),
    /// This entry point is only for DataMarket-backed input.
    WrongSourceKind { found: SourceKind },
    /// The chain did not confirm the grant query.
    Chain(RpcError),
    /// The chain reports no active grant for the complete `(grant, asset,
    /// content, consumer)` tuple.
    InactiveGrant {
        /// The grant reference supplied by the source.
        grant_id: Hash32,
        /// The asset identity supplied by the source.
        asset_id: Hash32,
        /// The content reference supplied by the source.
        content_id: Hash32,
    },
}

/// A short-lived capability created only after the chain confirms an exact
/// DataMarket grant. Callers should obtain one immediately before reading the
/// input and must not cache it across requests or epochs.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizedDataMarketInput {
    grant_id: Hash32,
    asset_id: Hash32,
    content_id: Hash32,
    consumer: Hash32,
}

impl AuthorizedDataMarketInput {
    /// The grant the node confirmed.
    #[must_use]
    pub const fn grant_id(&self) -> &Hash32 {
        &self.grant_id
    }

    /// The asset the node confirmed against that grant.
    #[must_use]
    pub const fn asset_id(&self) -> &Hash32 {
        &self.asset_id
    }

    /// The content the node confirmed against that grant and asset.
    #[must_use]
    pub const fn content_id(&self) -> &Hash32 {
        &self.content_id
    }

    /// The consumer for whom the node confirmed access.
    #[must_use]
    pub const fn consumer(&self) -> &Hash32 {
        &self.consumer
    }
}

/// Query the chain for the exact grant named by a DataMarket source.
///
/// `SourceRef::grant_epochs_remaining` is only a local shape/early-rejection
/// hint. The node query is authoritative and must be repeated for each input
/// access; it verifies that this exact grant names this exact asset, that the
/// asset resolves to this content digest, and that this consumer still has
/// access. A positive caller-supplied epoch count cannot keep a revoked or
/// expired grant alive.
///
/// # Errors
///
/// Returns [`GrantAuthorizationError`] for a malformed source, a non-DataMarket
/// source, an RPC failure, or a grant that is not active for the exact tuple.
fn authorize_data_market_input<C: ChainClient>(
    chain: &C,
    source: &SourceRef,
    consumer: &Hash32,
) -> Result<AuthorizedDataMarketInput, GrantAuthorizationError> {
    source
        .validate()
        .map_err(GrantAuthorizationError::InvalidSource)?;
    if source.kind != SourceKind::DataMarketGrant {
        return Err(GrantAuthorizationError::WrongSourceKind { found: source.kind });
    }
    let Some(grant_id) = source.grant_id else {
        // `validate` rejects this first; keep this branch fail-closed if that
        // validation ever changes.
        return Err(GrantAuthorizationError::InvalidSource(
            SourceError::MissingGrantId,
        ));
    };
    let Some(asset_id) = source.asset_id else {
        // `validate` rejects this first; keep this branch fail-closed if that
        // validation ever changes.
        return Err(GrantAuthorizationError::InvalidSource(
            SourceError::MissingAssetId,
        ));
    };
    let active = chain
        .data_market_grant_active(&grant_id, &asset_id, &source.content_id, consumer)
        .map_err(GrantAuthorizationError::Chain)?;
    if !active {
        return Err(GrantAuthorizationError::InactiveGrant {
            grant_id,
            asset_id,
            content_id: source.content_id,
        });
    }
    Ok(AuthorizedDataMarketInput {
        grant_id,
        asset_id,
        content_id: source.content_id,
        consumer: *consumer,
    })
}

/// Run an input read only after the chain authorizes its exact DataMarket grant.
///
/// This keeps the permission query adjacent to the read operation. The
/// callback is never called for an invalid, inactive, revoked, expired, or
/// unconfirmed grant.
///
/// # Errors
///
/// Returns [`GrantAuthorizationError`] without calling `read` when the source
/// is invalid or the chain does not confirm the exact tuple.
pub fn with_authorized_data_market_input<C, R>(
    chain: &C,
    source: &SourceRef,
    consumer: &Hash32,
    read: impl FnOnce(&AuthorizedDataMarketInput) -> R,
) -> Result<R, GrantAuthorizationError>
where
    C: ChainClient,
{
    let authorization = authorize_data_market_input(chain, source, consumer)?;
    Ok(read(&authorization))
}

/// The skeleton state: no connection. Every query returns `NotConnected`.
#[derive(Debug, Default)]
pub struct NotConnected;

impl ChainClient for NotConnected {
    fn data_market_grant_active(
        &self,
        _grant_id: &Hash32,
        _asset_id: &Hash32,
        _content_id: &Hash32,
        _consumer: &Hash32,
    ) -> Result<bool, RpcError> {
        Err(RpcError::NotConnected)
    }

    fn model_registered(&self, _m: &Hash32) -> Result<bool, RpcError> {
        Err(RpcError::NotConnected)
    }

    fn operator_bond(&self, _o: &Hash32) -> Result<u64, RpcError> {
        Err(RpcError::NotConnected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct GrantRecord {
        asset_id: Hash32,
        content_id: Hash32,
        consumer: Hash32,
        expires_at_epoch: u64,
    }

    struct TestChain {
        grants: BTreeMap<Hash32, GrantRecord>,
        current_epoch: u64,
    }

    impl ChainClient for TestChain {
        fn data_market_grant_active(
            &self,
            grant_id: &Hash32,
            asset_id: &Hash32,
            content_id: &Hash32,
            consumer: &Hash32,
        ) -> Result<bool, RpcError> {
            Ok(self.grants.get(grant_id).is_some_and(|grant| {
                grant.asset_id == *asset_id
                    && grant.content_id == *content_id
                    && grant.consumer == *consumer
                    && self.current_epoch < grant.expires_at_epoch
            }))
        }

        fn model_registered(&self, _model_id: &Hash32) -> Result<bool, RpcError> {
            Ok(true)
        }

        fn operator_bond(&self, _operator: &Hash32) -> Result<u64, RpcError> {
            Ok(1)
        }
    }

    fn active_test_chain(
        grant_id: Hash32,
        asset_id: Hash32,
        content_id: Hash32,
        consumer: Hash32,
    ) -> TestChain {
        TestChain {
            grants: BTreeMap::from([(
                grant_id,
                GrantRecord {
                    asset_id,
                    content_id,
                    consumer,
                    expires_at_epoch: 12,
                },
            )]),
            current_epoch: 7,
        }
    }

    #[test]
    fn skeleton_chain_is_fail_closed() {
        let chain = NotConnected;
        assert_eq!(
            chain.data_market_grant_active(&[3; 32], &[8; 32], &[1; 32], &[2; 32]),
            Err(RpcError::NotConnected)
        );
        assert_eq!(
            chain.model_registered(&[1; 32]),
            Err(RpcError::NotConnected)
        );
        assert_eq!(chain.operator_bond(&[1; 32]), Err(RpcError::NotConnected));
        assert_eq!(
            authorize_data_market_input(
                &chain,
                &SourceRef::data_market_grant([8; 32], [3; 32], [1; 32], 2),
                &[2; 32]
            ),
            Err(GrantAuthorizationError::Chain(RpcError::NotConnected))
        );
    }

    #[test]
    fn active_grant_authorizes_only_its_exact_asset_and_consumer() {
        let grant_id = [3; 32];
        let asset_id = [8; 32];
        let content_id = [1; 32];
        let consumer = [2; 32];
        let chain = active_test_chain(grant_id, asset_id, content_id, consumer);
        let source = SourceRef::data_market_grant(asset_id, grant_id, content_id, 5);
        let authorized = authorize_data_market_input(&chain, &source, &consumer)
            .expect("the exact active grant is confirmed by the chain");
        assert_eq!(authorized.grant_id(), &grant_id);
        assert_eq!(authorized.asset_id(), &asset_id);
        assert_eq!(authorized.content_id(), &content_id);
        assert_eq!(authorized.consumer(), &consumer);
    }

    #[test]
    fn input_read_callback_runs_only_after_exact_grant_authorization() {
        use std::cell::Cell;

        let grant_id = [3; 32];
        let asset_id = [8; 32];
        let content_id = [1; 32];
        let consumer = [2; 32];
        let chain = active_test_chain(grant_id, asset_id, content_id, consumer);
        let reads = Cell::new(0);
        let source = SourceRef::data_market_grant(asset_id, grant_id, content_id, 5);
        let result = with_authorized_data_market_input(&chain, &source, &consumer, |authorized| {
            reads.set(reads.get() + 1);
            (*authorized.asset_id(), *authorized.content_id())
        })
        .expect("the exact active grant is authorized");
        assert_eq!(result, (asset_id, content_id));
        assert_eq!(reads.get(), 1);

        let wrong_asset = SourceRef::data_market_grant([5; 32], grant_id, content_id, 5);
        assert!(
            with_authorized_data_market_input(&chain, &wrong_asset, &consumer, |_| {
                reads.set(reads.get() + 1);
            })
            .is_err()
        );
        assert_eq!(reads.get(), 1, "a rejected grant never reaches the reader");

        let disconnected = NotConnected;
        assert!(
            with_authorized_data_market_input(&disconnected, &source, &consumer, |_| {
                reads.set(reads.get() + 1);
            })
            .is_err()
        );
        assert_eq!(reads.get(), 1, "an RPC failure never reaches the reader");
    }

    #[test]
    fn another_grant_asset_consumer_or_epoch_is_not_authorized() {
        let grant_id = [3; 32];
        let asset_id = [8; 32];
        let content_id = [1; 32];
        let consumer = [2; 32];
        let chain = active_test_chain(grant_id, asset_id, content_id, consumer);

        let wrong_grant = SourceRef::data_market_grant(asset_id, [4; 32], content_id, 5);
        assert!(matches!(
            authorize_data_market_input(&chain, &wrong_grant, &consumer),
            Err(GrantAuthorizationError::InactiveGrant { .. })
        ));

        let wrong_asset = SourceRef::data_market_grant([5; 32], grant_id, content_id, 5);
        assert!(matches!(
            authorize_data_market_input(&chain, &wrong_asset, &consumer),
            Err(GrantAuthorizationError::InactiveGrant { .. })
        ));

        let wrong_content = SourceRef::data_market_grant(asset_id, grant_id, [7; 32], 5);
        assert!(matches!(
            authorize_data_market_input(&chain, &wrong_content, &consumer),
            Err(GrantAuthorizationError::InactiveGrant { .. })
        ));

        let wrong_consumer = [6; 32];
        let source = SourceRef::data_market_grant(asset_id, grant_id, content_id, 5);
        assert!(matches!(
            authorize_data_market_input(&chain, &source, &wrong_consumer),
            Err(GrantAuthorizationError::InactiveGrant { .. })
        ));

        let mut expired = active_test_chain(grant_id, asset_id, content_id, consumer);
        expired.current_epoch = 12;
        assert!(matches!(
            authorize_data_market_input(&expired, &source, &consumer),
            Err(GrantAuthorizationError::InactiveGrant { .. })
        ));
    }

    #[test]
    fn malformed_or_non_data_market_sources_are_refused() {
        let chain = active_test_chain([3; 32], [8; 32], [1; 32], [2; 32]);
        let mut missing_asset = SourceRef::data_market_grant([8; 32], [3; 32], [1; 32], 5);
        missing_asset.asset_id = None;
        assert_eq!(
            authorize_data_market_input(&chain, &missing_asset, &[2; 32]),
            Err(GrantAuthorizationError::InvalidSource(
                SourceError::MissingAssetId
            ))
        );
        let mut missing_id = SourceRef::data_market_grant([8; 32], [3; 32], [1; 32], 5);
        missing_id.grant_id = None;
        assert_eq!(
            authorize_data_market_input(&chain, &missing_id, &[2; 32]),
            Err(GrantAuthorizationError::InvalidSource(
                SourceError::MissingGrantId
            ))
        );
        assert_eq!(
            authorize_data_market_input(&chain, &SourceRef::storage_deal([1; 32]), &[2; 32]),
            Err(GrantAuthorizationError::WrongSourceKind {
                found: SourceKind::StorageDeal
            })
        );
    }
}
