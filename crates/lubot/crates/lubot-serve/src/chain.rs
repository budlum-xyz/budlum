//! budlum düğüm RPC bağlantı taslağı.
//!
//! Zincir üstü işlemler (model kaydı, operator bond, Pollen grant sorgusu)
//! budlum düğüm RPC'si üzerinden yapılır. İskelette gerçek HTTP istemcisi
//! yoktur; `NotConnected` durumu **fail-closed**'dur: bağlantı kurulana
//! kadar hiçbir zincir sorgusu başarılı sayılmaz - izin kurallarının
//! ikinci kopyası burada YAZILMAZ (K3 kararı).

use lubot_core::model::Hash32;

/// Zincir RPC hataları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    /// Düğüm bağlantısı kurulmadı - fail-closed.
    NotConnected,
    /// Yanıt beklenen biçimde değil.
    MalformedResponse(String),
}

/// Zincir sorgu arayüzü. Gerçek istemci (ureq/reqwest tabanlı) üretim
/// fazında eklenir; imzalar değişmez.
pub trait ChainClient {
    /// Pollen grant'i bu tüketici için şu an aktif mi?
    fn pollen_grant_active(&self, content_id: &Hash32, consumer: &Hash32)
        -> Result<bool, RpcError>;
    /// Model zincir üstünde kayıtlı mı?
    fn model_registered(&self, model_id: &Hash32) -> Result<bool, RpcError>;
    /// Operator compute-bond miktarı.
    fn operator_bond(&self, operator: &Hash32) -> Result<u64, RpcError>;
}

/// İskelet durumu: bağlantı yok. Her sorgu `NotConnected` döner.
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
