//! A draft of the budlum node RPC connection.
//!
//! On-chain operations (model registration, the operator bond, a Pollen grant
//! query) go through the budlum node RPC. The skeleton has no real HTTP
//! client; the `NotConnected` state is **fail-closed**: until a connection is
//! established no chain query counts as successful, and a second copy of the
//! permission rules is NOT WRITTEN here (the K3 decision).

use agent_core::model::Hash32;

/// Chain RPC errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    /// No node connection was established - fail-closed.
    NotConnected,
    /// The response is not in the expected shape.
    MalformedResponse(String),
}

/// The chain query interface. The real client (based on ureq or reqwest) is
/// added in the production phase; the signatures do not change.
pub trait ChainClient {
    /// Is the Pollen grant currently active for this consumer?
    fn pollen_grant_active(&self, content_id: &Hash32, consumer: &Hash32)
        -> Result<bool, RpcError>;
    /// Is the model registered on chain?
    fn model_registered(&self, model_id: &Hash32) -> Result<bool, RpcError>;
    /// The operator's compute-bond amount.
    fn operator_bond(&self, operator: &Hash32) -> Result<u64, RpcError>;
}

/// The skeleton state: no connection. Every query returns `NotConnected`.
#[derive(Debug, Default)]
pub struct NotConnected;

impl ChainClient for NotConnected {
    fn pollen_grant_active(&self, _c: &Hash32, _u: &Hash32) -> Result<bool, RpcError> {
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

    #[test]
    fn skeleton_chain_is_fail_closed() {
        let chain = NotConnected;
        assert_eq!(
            chain.pollen_grant_active(&[1; 32], &[2; 32]),
            Err(RpcError::NotConnected)
        );
        assert_eq!(
            chain.model_registered(&[1; 32]),
            Err(RpcError::NotConnected)
        );
        assert_eq!(chain.operator_bond(&[1; 32]), Err(RpcError::NotConnected));
    }
}
