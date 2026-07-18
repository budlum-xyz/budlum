use crate::consensus::pos::SlashingEvidence;
use crate::core::address::Address;
use crate::core::block::{Block, BlockHeader};
use crate::core::transaction::{Transaction, TransactionType};
use crate::network::protocol::NetworkMessage;

#[allow(clippy::all)]
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/budlum.network.rs"));
}

/// Phase 0.32: serialize a network payload, keeping the empty-bytes fallback for
/// behavioral compatibility but LOGGING the error so it is no longer silent.
/// The receiver rejects an empty/invalid payload, so this degrades visibly
/// rather than corrupting state.
fn serialize_payload_or_log<T: serde::Serialize>(what: &str, value: &T) -> Vec<u8> {
    match serde_json::to_vec(value) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("Failed to serialize {} for network payload: {}", what, e);
            Vec::new()
        }
    }
}

impl From<&Transaction> for pb::ProtoTransaction {
    fn from(tx: &Transaction) -> Self {
        let (tx_type_i32, type_payload) = match &tx.tx_type {
            TransactionType::Transfer => (pb::ProtoTransactionType::Transfer as i32, None),
            TransactionType::Stake => (pb::ProtoTransactionType::Stake as i32, None),
            TransactionType::Unstake => (pb::ProtoTransactionType::Unstake as i32, None),
            TransactionType::Vote => (pb::ProtoTransactionType::Vote as i32, None),
            TransactionType::ContractCall => (pb::ProtoTransactionType::ContractCall as i32, None),
            TransactionType::BnsRegister => (pb::ProtoTransactionType::BnsRegister as i32, None),
            TransactionType::BnsSetContent => {
                (pb::ProtoTransactionType::BnsSetContent as i32, None)
            }
            TransactionType::BnsRegisterSubdomain => {
                (pb::ProtoTransactionType::BnsRegisterSubdomain as i32, None)
            }
            TransactionType::BnsSetStorage => {
                (pb::ProtoTransactionType::BnsSetStorage as i32, None)
            }
            TransactionType::NftMint => (pb::ProtoTransactionType::NftMint as i32, None),
            TransactionType::NftTransfer => (pb::ProtoTransactionType::NftTransfer as i32, None),
            TransactionType::NftBurn => (pb::ProtoTransactionType::NftBurn as i32, None),
            TransactionType::NftBoost { nft_id, amount } => (
                pb::ProtoTransactionType::NftBoost as i32,
                Some(pb::proto_transaction::TypePayload::NftBoost(
                    pb::ProtoNftBoost {
                        nft_id: *nft_id,
                        amount: *amount,
                    },
                )),
            ),
            TransactionType::NftUpdateLight { nft_id, delta_mcd } => (
                pb::ProtoTransactionType::NftUpdateLight as i32,
                Some(pb::proto_transaction::TypePayload::NftUpdateLight(
                    pb::ProtoNftUpdateLight {
                        nft_id: *nft_id,
                        delta_mcd: *delta_mcd,
                    },
                )),
            ),
            TransactionType::NftTag { nft_id, tag } => (
                pb::ProtoTransactionType::NftTag as i32,
                Some(pb::proto_transaction::TypePayload::NftTag(
                    pb::ProtoNftTag {
                        nft_id: *nft_id,
                        tag: tag.clone(),
                    },
                )),
            ),
            TransactionType::UniversalRelay(ext_tx) => (
                pb::ProtoTransactionType::UniversalRelay as i32,
                Some(pb::proto_transaction::TypePayload::UniversalRelay(
                    convert_ext_tx_to_proto(ext_tx),
                )),
            ),
            TransactionType::RelayerResult(res) => (
                pb::ProtoTransactionType::RelayerResult as i32,
                Some(pb::proto_transaction::TypePayload::RelayerResult(
                    convert_relayer_result_to_proto(res),
                )),
            ),
            TransactionType::AiOfferData { cid, price } => (
                pb::ProtoTransactionType::AiOfferData as i32,
                Some(pb::proto_transaction::TypePayload::AiOfferData(
                    pb::ProtoAiOfferData {
                        cid: cid.0.to_vec(),
                        price: *price,
                    },
                )),
            ),
            TransactionType::AiPurchaseData { offer_id } => (
                pb::ProtoTransactionType::AiPurchaseData as i32,
                Some(pb::proto_transaction::TypePayload::AiPurchaseData(
                    pb::ProtoAiPurchaseData {
                        offer_id: *offer_id,
                    },
                )),
            ),
            TransactionType::HubRegisterApp {
                name,
                category,
                website_url,
                manifest_id,
            } => (
                pb::ProtoTransactionType::HubRegisterApp as i32,
                Some(pb::proto_transaction::TypePayload::HubRegisterApp(
                    pb::ProtoHubRegisterApp {
                        name: name.clone(),
                        category: convert_app_category_to_proto(category) as i32,
                        website_url: website_url.clone(),
                        manifest_id: manifest_id.map(|m| m.0.to_vec()).unwrap_or_default(),
                    },
                )),
            ),
            TransactionType::AiModelRegister(spec) => (
                pb::ProtoTransactionType::AiModelRegister as i32,
                Some(pb::proto_transaction::TypePayload::AiModelRegister(
                    pb::ProtoAiModelRegister {
                        model_id: spec.model_id.0.to_vec(),
                        model_hash: spec.model_hash.to_vec(),
                        owner: spec.owner.to_string(),
                        min_verifier_count: spec.min_verifier_count,
                        agreement_threshold: spec.agreement_threshold,
                        max_input_ref_bytes: spec.max_input_ref_bytes,
                        max_output_ref_bytes: spec.max_output_ref_bytes,
                        request_deadline_blocks: spec.request_deadline_blocks,
                        result_deadline_blocks: spec.result_deadline_blocks,
                        version: spec.version,
                        active: spec.active,
                    },
                )),
            ),
            TransactionType::AiInferenceRequest(req) => (
                pb::ProtoTransactionType::AiInferenceRequest as i32,
                Some(pb::proto_transaction::TypePayload::AiInferenceRequest(
                    pb::ProtoAiInferenceRequest {
                        request_id: req.request_id.0.to_vec(),
                        requester: req.requester.to_string(),
                        model_id: req.model_id.0.to_vec(),
                        input_commitment: req.input_commitment.to_vec(),
                        input_ref: req.input_ref.as_slice().to_vec(),
                        max_fee: req.max_fee,
                        callback: req
                            .callback
                            .map(|addr| addr.to_string())
                            .unwrap_or_default(),
                        submitted_at_block: req.submitted_at_block,
                        deadline_block: req.deadline_block,
                    },
                )),
            ),
            TransactionType::AiInferenceResult(res) => (
                pb::ProtoTransactionType::AiInferenceResult as i32,
                Some(pb::proto_transaction::TypePayload::AiInferenceResult(
                    pb::ProtoAiInferenceResult {
                        request_id: res.request_id.0.to_vec(),
                        verifier: res.verifier.to_string(),
                        output_commitment: res.output_commitment.to_vec(),
                        output_ref: res.output_ref.as_slice().to_vec(),
                        result_nonce: res.result_nonce,
                        signature: res.signature.clone(),
                        submitted_at_block: res.submitted_at_block,
                    },
                )),
            ),
            TransactionType::AiFeeReclaim(request_id) => (
                pb::ProtoTransactionType::AiFeeReclaim as i32,
                Some(pb::proto_transaction::TypePayload::AiFeeReclaim(
                    pb::ProtoAiFeeReclaim {
                        request_id: request_id.0.to_vec(),
                    },
                )),
            ),
            TransactionType::AiModelDeactivate(model_id) => (
                pb::ProtoTransactionType::AiModelDeactivate as i32,
                Some(pb::proto_transaction::TypePayload::AiModelDeactivate(
                    pb::ProtoAiModelDeactivate {
                        model_id: model_id.0.to_vec(),
                    },
                )),
            ),
            TransactionType::AiModelReactivate(model_id) => (
                pb::ProtoTransactionType::AiModelReactivate as i32,
                Some(pb::proto_transaction::TypePayload::AiModelReactivate(
                    pb::ProtoAiModelDeactivate {
                        model_id: model_id.0.to_vec(),
                    },
                )),
            ),
            TransactionType::AiRequestCancel(request_id) => (
                pb::ProtoTransactionType::AiRequestCancel as i32,
                Some(pb::proto_transaction::TypePayload::AiRequestCancel(
                    pb::ProtoAiFeeReclaim {
                        request_id: request_id.0.to_vec(),
                    },
                )),
            ),
        };

        pb::ProtoTransaction {
            from: tx.from.to_string(),
            to: tx.to.to_string(),
            amount: tx.amount,
            fee: tx.fee,
            nonce: tx.nonce,
            data: tx.data.clone(),
            timestamp: tx.timestamp.to_string(),
            hash: tx.hash.clone(),
            signature: tx.signature.clone().unwrap_or_default(),
            chain_id: tx.chain_id,
            signature_version: tx.signature_version,
            tx_type: tx_type_i32,
            wire_version: 2,
            type_payload,
        }
    }
}

fn convert_ext_tx_to_proto(
    ext: &crate::core::transaction::ExternalTransaction,
) -> pb::ProtoUniversalRelay {
    let (chain_type, custom_id) = match ext.chain {
        crate::core::transaction::ExternalChain::Ethereum => {
            (pb::proto_external_chain::ChainType::Ethereum as i32, 0)
        }
        crate::core::transaction::ExternalChain::Solana => {
            (pb::proto_external_chain::ChainType::Solana as i32, 0)
        }
        crate::core::transaction::ExternalChain::Bitcoin => {
            (pb::proto_external_chain::ChainType::Bitcoin as i32, 0)
        }
        crate::core::transaction::ExternalChain::Avalanche => {
            (pb::proto_external_chain::ChainType::Avalanche as i32, 0)
        }
        crate::core::transaction::ExternalChain::Polygon => {
            (pb::proto_external_chain::ChainType::Polygon as i32, 0)
        }
        crate::core::transaction::ExternalChain::Arbitrum => {
            (pb::proto_external_chain::ChainType::Arbitrum as i32, 0)
        }
        crate::core::transaction::ExternalChain::Optimism => {
            (pb::proto_external_chain::ChainType::Optimism as i32, 0)
        }
        crate::core::transaction::ExternalChain::Custom(id) => {
            (pb::proto_external_chain::ChainType::Custom as i32, id)
        }
    };
    pb::ProtoUniversalRelay {
        chain: Some(pb::ProtoExternalChain {
            chain_type,
            custom_id,
        }),
        target_address: ext.target_address.clone(),
        payload: ext.payload.clone(),
        external_nonce: ext.external_nonce,
    }
}

fn convert_proto_to_ext_tx(
    proto: &pb::ProtoUniversalRelay,
) -> Result<crate::core::transaction::ExternalTransaction, String> {
    let chain_proto = proto.chain.as_ref().ok_or("Missing external chain")?;
    let chain = match pb::proto_external_chain::ChainType::try_from(chain_proto.chain_type) {
        Ok(pb::proto_external_chain::ChainType::Ethereum) => {
            crate::core::transaction::ExternalChain::Ethereum
        }
        Ok(pb::proto_external_chain::ChainType::Solana) => {
            crate::core::transaction::ExternalChain::Solana
        }
        Ok(pb::proto_external_chain::ChainType::Bitcoin) => {
            crate::core::transaction::ExternalChain::Bitcoin
        }
        Ok(pb::proto_external_chain::ChainType::Avalanche) => {
            crate::core::transaction::ExternalChain::Avalanche
        }
        Ok(pb::proto_external_chain::ChainType::Polygon) => {
            crate::core::transaction::ExternalChain::Polygon
        }
        Ok(pb::proto_external_chain::ChainType::Arbitrum) => {
            crate::core::transaction::ExternalChain::Arbitrum
        }
        Ok(pb::proto_external_chain::ChainType::Optimism) => {
            crate::core::transaction::ExternalChain::Optimism
        }
        Ok(pb::proto_external_chain::ChainType::Custom) => {
            crate::core::transaction::ExternalChain::Custom(chain_proto.custom_id)
        }
        Err(_) => return Err("Invalid external chain type".into()),
    };
    Ok(crate::core::transaction::ExternalTransaction {
        chain,
        target_address: proto.target_address.clone(),
        payload: proto.payload.clone(),
        external_nonce: proto.external_nonce,
    })
}

fn convert_app_category_to_proto(
    cat: &crate::hub::types::AppCategory,
) -> pb::proto_hub_register_app::AppCategoryProto {
    match cat {
        crate::hub::types::AppCategory::SocialFi => {
            pb::proto_hub_register_app::AppCategoryProto::SocialFi
        }
        crate::hub::types::AppCategory::DeFi => pb::proto_hub_register_app::AppCategoryProto::DeFi,
        crate::hub::types::AppCategory::Storage => {
            pb::proto_hub_register_app::AppCategoryProto::Storage
        }
        crate::hub::types::AppCategory::Gaming => {
            pb::proto_hub_register_app::AppCategoryProto::Gaming
        }
        crate::hub::types::AppCategory::Infrastructure => {
            pb::proto_hub_register_app::AppCategoryProto::Infrastructure
        }
        crate::hub::types::AppCategory::Other => {
            pb::proto_hub_register_app::AppCategoryProto::Other
        }
    }
}

fn convert_proto_to_app_category(cat_i32: i32) -> Result<crate::hub::types::AppCategory, String> {
    match pb::proto_hub_register_app::AppCategoryProto::try_from(cat_i32) {
        Ok(pb::proto_hub_register_app::AppCategoryProto::SocialFi) => {
            Ok(crate::hub::types::AppCategory::SocialFi)
        }
        Ok(pb::proto_hub_register_app::AppCategoryProto::DeFi) => {
            Ok(crate::hub::types::AppCategory::DeFi)
        }
        Ok(pb::proto_hub_register_app::AppCategoryProto::Storage) => {
            Ok(crate::hub::types::AppCategory::Storage)
        }
        Ok(pb::proto_hub_register_app::AppCategoryProto::Gaming) => {
            Ok(crate::hub::types::AppCategory::Gaming)
        }
        Ok(pb::proto_hub_register_app::AppCategoryProto::Infrastructure) => {
            Ok(crate::hub::types::AppCategory::Infrastructure)
        }
        Ok(pb::proto_hub_register_app::AppCategoryProto::Other) => {
            Ok(crate::hub::types::AppCategory::Other)
        }
        Err(_) => Err("Invalid AppCategoryProto value".into()),
    }
}

fn convert_relayer_result_to_proto(
    res: &crate::core::transaction::RelayerExternalResult,
) -> pb::ProtoRelayerResult {
    let (chain_type, custom_id) = match res.chain {
        crate::core::transaction::ExternalChain::Ethereum => {
            (pb::proto_external_chain::ChainType::Ethereum as i32, 0)
        }
        crate::core::transaction::ExternalChain::Solana => {
            (pb::proto_external_chain::ChainType::Solana as i32, 0)
        }
        crate::core::transaction::ExternalChain::Bitcoin => {
            (pb::proto_external_chain::ChainType::Bitcoin as i32, 0)
        }
        crate::core::transaction::ExternalChain::Avalanche => {
            (pb::proto_external_chain::ChainType::Avalanche as i32, 0)
        }
        crate::core::transaction::ExternalChain::Polygon => {
            (pb::proto_external_chain::ChainType::Polygon as i32, 0)
        }
        crate::core::transaction::ExternalChain::Arbitrum => {
            (pb::proto_external_chain::ChainType::Arbitrum as i32, 0)
        }
        crate::core::transaction::ExternalChain::Optimism => {
            (pb::proto_external_chain::ChainType::Optimism as i32, 0)
        }
        crate::core::transaction::ExternalChain::Custom(id) => {
            (pb::proto_external_chain::ChainType::Custom as i32, id)
        }
    };
    let proto_chain = pb::ProtoExternalChain {
        chain_type,
        custom_id,
    };
    let proto_msg = res.message.as_ref().map(|msg| {
        let kind = match &msg.kind {
            crate::cross_domain::message::MessageKind::BridgeLock => pb::ProtoMessageKind {
                kind_type: pb::proto_message_kind::KindType::BridgeLock as i32,
                custom_bytes: Vec::new(),
            },
            crate::cross_domain::message::MessageKind::BridgeMint => pb::ProtoMessageKind {
                kind_type: pb::proto_message_kind::KindType::BridgeMint as i32,
                custom_bytes: Vec::new(),
            },
            crate::cross_domain::message::MessageKind::BridgeBurn => pb::ProtoMessageKind {
                kind_type: pb::proto_message_kind::KindType::BridgeBurn as i32,
                custom_bytes: Vec::new(),
            },
            crate::cross_domain::message::MessageKind::BridgeUnlock => pb::ProtoMessageKind {
                kind_type: pb::proto_message_kind::KindType::BridgeUnlock as i32,
                custom_bytes: Vec::new(),
            },
            crate::cross_domain::message::MessageKind::Custom(b) => pb::ProtoMessageKind {
                kind_type: pb::proto_message_kind::KindType::Custom as i32,
                custom_bytes: b.clone(),
            },
        };
        pb::ProtoCrossDomainMessagePayload {
            message_id: hex::encode(msg.message_id),
            correlation_id: msg.correlation_id.map(hex::encode).unwrap_or_default(),
            source_domain: format!("{}", msg.source_domain),
            target_domain: format!("{}", msg.target_domain),
            source_height: msg.source_height,
            event_index: msg.event_index,
            nonce: msg.nonce,
            sender: msg.sender.to_string(),
            recipient: msg.recipient.to_string(),
            payload_hash: hex::encode(msg.payload_hash),
            kind: Some(kind),
            expiry_height: msg.expiry_height,
        }
    });

    pb::ProtoRelayerResult {
        chain: Some(proto_chain),
        tx_hash: res.tx_hash.clone(),
        success: res.success,
        message: proto_msg,
        receipt_proof: res.receipt_proof.clone(),
        external_state_root: res.external_state_root.to_vec(),
    }
}

fn convert_proto_to_relayer_result(
    proto: &pb::ProtoRelayerResult,
) -> Result<crate::core::transaction::RelayerExternalResult, String> {
    let chain_proto = proto
        .chain
        .as_ref()
        .ok_or("Missing external chain in RelayerResult")?;
    let chain = match pb::proto_external_chain::ChainType::try_from(chain_proto.chain_type) {
        Ok(pb::proto_external_chain::ChainType::Ethereum) => {
            crate::core::transaction::ExternalChain::Ethereum
        }
        Ok(pb::proto_external_chain::ChainType::Solana) => {
            crate::core::transaction::ExternalChain::Solana
        }
        Ok(pb::proto_external_chain::ChainType::Bitcoin) => {
            crate::core::transaction::ExternalChain::Bitcoin
        }
        Ok(pb::proto_external_chain::ChainType::Avalanche) => {
            crate::core::transaction::ExternalChain::Avalanche
        }
        Ok(pb::proto_external_chain::ChainType::Polygon) => {
            crate::core::transaction::ExternalChain::Polygon
        }
        Ok(pb::proto_external_chain::ChainType::Arbitrum) => {
            crate::core::transaction::ExternalChain::Arbitrum
        }
        Ok(pb::proto_external_chain::ChainType::Optimism) => {
            crate::core::transaction::ExternalChain::Optimism
        }
        Ok(pb::proto_external_chain::ChainType::Custom) => {
            crate::core::transaction::ExternalChain::Custom(chain_proto.custom_id)
        }
        Err(_) => return Err("Invalid external chain type".into()),
    };

    let message = if let Some(ref p_msg) = proto.message {
        let msg_id_bytes =
            hex::decode(&p_msg.message_id).map_err(|e| format!("Invalid message_id hex: {e}"))?;
        let mut message_id = [0u8; 32];
        if msg_id_bytes.len() != 32 {
            return Err("message_id must be 32 bytes".into());
        }
        message_id.copy_from_slice(&msg_id_bytes);

        let correlation_id = if p_msg.correlation_id.is_empty() {
            None
        } else {
            let corr_bytes = hex::decode(&p_msg.correlation_id)
                .map_err(|e| format!("Invalid correlation_id hex: {e}"))?;
            if corr_bytes.len() != 32 {
                return Err("correlation_id must be 32 bytes".into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&corr_bytes);
            Some(arr)
        };

        let src_dom = p_msg
            .source_domain
            .parse::<u32>()
            .map_err(|e| format!("Invalid source_domain: {e}"))?;
        let tgt_dom = p_msg
            .target_domain
            .parse::<u32>()
            .map_err(|e| format!("Invalid target_domain: {e}"))?;

        let payload_hash_bytes = hex::decode(&p_msg.payload_hash)
            .map_err(|e| format!("Invalid payload_hash hex: {e}"))?;
        let mut payload_hash = [0u8; 32];
        if payload_hash_bytes.len() != 32 {
            return Err("payload_hash must be 32 bytes".into());
        }
        payload_hash.copy_from_slice(&payload_hash_bytes);

        let p_kind = p_msg.kind.as_ref().ok_or("Missing message kind")?;
        let kind = match pb::proto_message_kind::KindType::try_from(p_kind.kind_type) {
            Ok(pb::proto_message_kind::KindType::BridgeLock) => {
                crate::cross_domain::message::MessageKind::BridgeLock
            }
            Ok(pb::proto_message_kind::KindType::BridgeMint) => {
                crate::cross_domain::message::MessageKind::BridgeMint
            }
            Ok(pb::proto_message_kind::KindType::BridgeBurn) => {
                crate::cross_domain::message::MessageKind::BridgeBurn
            }
            Ok(pb::proto_message_kind::KindType::BridgeUnlock) => {
                crate::cross_domain::message::MessageKind::BridgeUnlock
            }
            Ok(pb::proto_message_kind::KindType::Custom) => {
                crate::cross_domain::message::MessageKind::Custom(p_kind.custom_bytes.clone())
            }
            Err(_) => return Err("Invalid cross domain message kind".into()),
        };

        Some(crate::cross_domain::message::CrossDomainMessage {
            message_id,
            correlation_id,
            source_domain: src_dom,
            target_domain: tgt_dom,
            source_height: p_msg.source_height,
            event_index: p_msg.event_index,
            nonce: p_msg.nonce,
            sender: Address::from_hex(&p_msg.sender)
                .map_err(|e| format!("Invalid message sender: {e}"))?,
            recipient: Address::from_hex(&p_msg.recipient)
                .map_err(|e| format!("Invalid message recipient: {e}"))?,
            payload_hash,
            kind,
            expiry_height: p_msg.expiry_height,
        })
    } else {
        None
    };

    let mut external_state_root = [0u8; 32];
    if proto.external_state_root.len() != 32 {
        return Err("external_state_root must be 32 bytes".into());
    }
    external_state_root.copy_from_slice(&proto.external_state_root);

    Ok(crate::core::transaction::RelayerExternalResult {
        chain,
        tx_hash: proto.tx_hash.clone(),
        success: proto.success,
        message,
        receipt_proof: proto.receipt_proof.clone(),
        external_state_root,
    })
}

impl TryFrom<pb::ProtoTransaction> for Transaction {
    type Error = String;
    fn try_from(proto: pb::ProtoTransaction) -> Result<Self, Self::Error> {
        let timestamp = proto
            .timestamp
            .parse::<u128>()
            .map_err(|e| format!("Invalid block timestamp string: {e}"))?;
        let signature = if proto.signature.is_empty() {
            None
        } else {
            Some(proto.signature)
        };
        let tx_type_proto = pb::ProtoTransactionType::try_from(proto.tx_type)
            .map_err(|_| "Invalid transaction type in proto payload")?;

        let tx_type = match tx_type_proto {
            pb::ProtoTransactionType::Transfer => TransactionType::Transfer,
            pb::ProtoTransactionType::Stake => TransactionType::Stake,
            pb::ProtoTransactionType::Unstake => TransactionType::Unstake,
            pb::ProtoTransactionType::Vote => TransactionType::Vote,
            pb::ProtoTransactionType::ContractCall => TransactionType::ContractCall,
            pb::ProtoTransactionType::BnsRegister => TransactionType::BnsRegister,
            pb::ProtoTransactionType::BnsSetContent => TransactionType::BnsSetContent,
            pb::ProtoTransactionType::BnsRegisterSubdomain => TransactionType::BnsRegisterSubdomain,
            pb::ProtoTransactionType::BnsSetStorage => TransactionType::BnsSetStorage,
            pb::ProtoTransactionType::NftMint => TransactionType::NftMint,
            pb::ProtoTransactionType::NftTransfer => TransactionType::NftTransfer,
            pb::ProtoTransactionType::NftBurn => TransactionType::NftBurn,
            pb::ProtoTransactionType::NftBoost => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::NftBoost(p)) => p,
                    _ => return Err("Missing or mismatched NftBoost payload".into()),
                };
                TransactionType::NftBoost {
                    nft_id: payload.nft_id,
                    amount: payload.amount,
                }
            }
            pb::ProtoTransactionType::NftUpdateLight => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::NftUpdateLight(p)) => p,
                    _ => return Err("Missing or mismatched NftUpdateLight payload".into()),
                };
                TransactionType::NftUpdateLight {
                    nft_id: payload.nft_id,
                    delta_mcd: payload.delta_mcd,
                }
            }
            pb::ProtoTransactionType::NftTag => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::NftTag(p)) => p,
                    _ => return Err("Missing or mismatched NftTag payload".into()),
                };
                TransactionType::NftTag {
                    nft_id: payload.nft_id,
                    tag: payload.tag,
                }
            }
            pb::ProtoTransactionType::UniversalRelay => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::UniversalRelay(p)) => p,
                    _ => return Err("Missing or mismatched UniversalRelay payload".into()),
                };
                TransactionType::UniversalRelay(convert_proto_to_ext_tx(&payload)?)
            }
            pb::ProtoTransactionType::RelayerResult => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::RelayerResult(p)) => p,
                    _ => return Err("Missing or mismatched RelayerResult payload".into()),
                };
                TransactionType::RelayerResult(convert_proto_to_relayer_result(&payload)?)
            }
            pb::ProtoTransactionType::AiOfferData => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::AiOfferData(p)) => p,
                    _ => return Err("Missing or mismatched AiOfferData payload".into()),
                };
                let mut cid_bytes = [0u8; 32];
                if payload.cid.len() != 32 {
                    return Err("AiOfferData cid must be 32 bytes".into());
                }
                cid_bytes.copy_from_slice(&payload.cid);
                TransactionType::AiOfferData {
                    cid: crate::storage::content_id::ContentId(cid_bytes),
                    price: payload.price,
                }
            }
            pb::ProtoTransactionType::AiPurchaseData => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::AiPurchaseData(p)) => p,
                    _ => return Err("Missing or mismatched AiPurchaseData payload".into()),
                };
                TransactionType::AiPurchaseData {
                    offer_id: payload.offer_id,
                }
            }
            pb::ProtoTransactionType::HubRegisterApp => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::HubRegisterApp(p)) => p,
                    _ => return Err("Missing or mismatched HubRegisterApp payload".into()),
                };
                let manifest_id = if payload.manifest_id.is_empty() {
                    None
                } else {
                    if payload.manifest_id.len() != 32 {
                        return Err("HubRegisterApp manifest_id must be 32 bytes".into());
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&payload.manifest_id);
                    Some(crate::storage::content_id::ContentId(arr))
                };
                TransactionType::HubRegisterApp {
                    name: payload.name,
                    category: convert_proto_to_app_category(payload.category)?,
                    website_url: payload.website_url,
                    manifest_id,
                }
            }
            pb::ProtoTransactionType::AiModelRegister => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::AiModelRegister(p)) => p,
                    _ => return Err("Missing or mismatched AiModelRegister payload".into()),
                };
                if payload.model_id.len() != 32 || payload.model_hash.len() != 32 {
                    return Err("AiModelRegister model_id and model_hash must be 32 bytes".into());
                }
                let mut mid = [0u8; 32];
                mid.copy_from_slice(&payload.model_id);
                let mut mhash = [0u8; 32];
                mhash.copy_from_slice(&payload.model_hash);
                TransactionType::AiModelRegister(crate::ai::types::AiModelSpec {
                    model_id: crate::ai::types::AiModelId(mid),
                    model_hash: mhash,
                    owner: Address::from_hex(&payload.owner)
                        .map_err(|e| format!("Invalid owner address: {e}"))?,
                    min_verifier_count: payload.min_verifier_count,
                    agreement_threshold: payload.agreement_threshold,
                    max_input_ref_bytes: payload.max_input_ref_bytes,
                    max_output_ref_bytes: payload.max_output_ref_bytes,
                    request_deadline_blocks: payload.request_deadline_blocks,
                    result_deadline_blocks: payload.result_deadline_blocks,
                    version: payload.version,
                    active: payload.active,
                })
            }
            pb::ProtoTransactionType::AiInferenceRequest => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::AiInferenceRequest(p)) => p,
                    _ => return Err("Missing or mismatched AiInferenceRequest payload".into()),
                };
                if payload.request_id.len() != 32
                    || payload.model_id.len() != 32
                    || payload.input_commitment.len() != 32
                {
                    return Err("AiInferenceRequest ids and commitment must be 32 bytes".into());
                }
                let mut rid = [0u8; 32];
                rid.copy_from_slice(&payload.request_id);
                let mut mid = [0u8; 32];
                mid.copy_from_slice(&payload.model_id);
                let mut icom = [0u8; 32];
                icom.copy_from_slice(&payload.input_commitment);
                let callback = if payload.callback.is_empty() {
                    None
                } else {
                    Some(
                        Address::from_hex(&payload.callback)
                            .map_err(|e| format!("Invalid callback address: {e}"))?,
                    )
                };
                TransactionType::AiInferenceRequest(crate::ai::types::AiInferenceRequest {
                    request_id: crate::ai::types::AiRequestId(rid),
                    requester: Address::from_hex(&payload.requester)
                        .map_err(|e| format!("Invalid requester address: {e}"))?,
                    model_id: crate::ai::types::AiModelId(mid),
                    input_commitment: icom,
                    input_ref: crate::ai::types::BoundedBytes::try_new(payload.input_ref)?,
                    max_fee: payload.max_fee,
                    callback,
                    submitted_at_block: payload.submitted_at_block,
                    deadline_block: payload.deadline_block,
                })
            }
            pb::ProtoTransactionType::AiInferenceResult => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::AiInferenceResult(p)) => p,
                    _ => return Err("Missing or mismatched AiInferenceResult payload".into()),
                };
                if payload.request_id.len() != 32 || payload.output_commitment.len() != 32 {
                    return Err(
                        "AiInferenceResult request_id and output_commitment must be 32 bytes"
                            .into(),
                    );
                }
                let mut rid = [0u8; 32];
                rid.copy_from_slice(&payload.request_id);
                let mut ocom = [0u8; 32];
                ocom.copy_from_slice(&payload.output_commitment);
                TransactionType::AiInferenceResult(crate::ai::types::AiInferenceResult {
                    request_id: crate::ai::types::AiRequestId(rid),
                    verifier: Address::from_hex(&payload.verifier)
                        .map_err(|e| format!("Invalid verifier address: {e}"))?,
                    output_commitment: ocom,
                    output_ref: crate::ai::types::BoundedBytes::try_new(payload.output_ref)?,
                    result_nonce: payload.result_nonce,
                    signature: payload.signature,
                    submitted_at_block: payload.submitted_at_block,
                })
            }
            pb::ProtoTransactionType::AiFeeReclaim => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::AiFeeReclaim(p)) => p,
                    _ => return Err("Missing or mismatched AiFeeReclaim payload".into()),
                };
                if payload.request_id.len() != 32 {
                    return Err("AiFeeReclaim request_id must be 32 bytes".into());
                }
                let mut rid = [0u8; 32];
                rid.copy_from_slice(&payload.request_id);
                TransactionType::AiFeeReclaim(crate::ai::types::AiRequestId(rid))
            }
            pb::ProtoTransactionType::AiModelDeactivate => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::AiModelDeactivate(p)) => p,
                    _ => return Err("Missing or mismatched AiModelDeactivate payload".into()),
                };
                if payload.model_id.len() != 32 {
                    return Err("AiModelDeactivate model_id must be 32 bytes".into());
                }
                let mut mid = [0u8; 32];
                mid.copy_from_slice(&payload.model_id);
                TransactionType::AiModelDeactivate(crate::ai::types::AiModelId(mid))
            }
            pb::ProtoTransactionType::AiModelReactivate => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::AiModelReactivate(p)) => p,
                    _ => return Err("Missing or mismatched AiModelReactivate payload".into()),
                };
                if payload.model_id.len() != 32 {
                    return Err("AiModelReactivate model_id must be 32 bytes".into());
                }
                let mut mid = [0u8; 32];
                mid.copy_from_slice(&payload.model_id);
                TransactionType::AiModelReactivate(crate::ai::types::AiModelId(mid))
            }
            pb::ProtoTransactionType::AiRequestCancel => {
                let payload = match proto.type_payload {
                    Some(pb::proto_transaction::TypePayload::AiRequestCancel(p)) => p,
                    _ => return Err("Missing or mismatched AiRequestCancel payload".into()),
                };
                if payload.request_id.len() != 32 {
                    return Err("AiRequestCancel request_id must be 32 bytes".into());
                }
                let mut rid = [0u8; 32];
                rid.copy_from_slice(&payload.request_id);
                TransactionType::AiRequestCancel(crate::ai::types::AiRequestId(rid))
            }
        };

        Ok(Transaction {
            from: Address::from_hex(&proto.from)
                .map_err(|e| format!("Invalid from address: {e}"))?,
            to: Address::from_hex(&proto.to).map_err(|e| format!("Invalid to address: {e}"))?,
            amount: proto.amount,
            fee: proto.fee,
            nonce: proto.nonce,
            data: proto.data,
            timestamp,
            hash: proto.hash,
            signature,
            chain_id: proto.chain_id,
            signature_version: proto.signature_version,
            tx_type,
        })
    }
}

impl From<&SlashingEvidence> for pb::ProtoSlashingEvidence {
    fn from(ev: &SlashingEvidence) -> Self {
        pb::ProtoSlashingEvidence {
            header1: Some(pb::ProtoBlockHeader::from(&ev.header1)),
            header2: Some(pb::ProtoBlockHeader::from(&ev.header2)),
            signature1: ev.signature1.clone(),
            signature2: ev.signature2.clone(),
        }
    }
}

impl TryFrom<pb::ProtoSlashingEvidence> for SlashingEvidence {
    type Error = String;
    fn try_from(proto: pb::ProtoSlashingEvidence) -> Result<Self, Self::Error> {
        let header1 = proto.header1.ok_or("Missing header1 in proto evidence")?;
        let header2 = proto.header2.ok_or("Missing header2 in proto evidence")?;
        Ok(SlashingEvidence {
            header1: BlockHeader::try_from(header1)?,
            header2: BlockHeader::try_from(header2)?,
            signature1: proto.signature1,
            signature2: proto.signature2,
        })
    }
}

impl From<&BlockHeader> for pb::ProtoBlockHeader {
    fn from(header: &BlockHeader) -> Self {
        pb::ProtoBlockHeader {
            index: header.index,
            timestamp: header.timestamp.to_string(),
            previous_hash: header.previous_hash.clone(),
            hash: header.hash.clone(),
            producer: header.producer.map(|p| p.to_string()).unwrap_or_default(),
            chain_id: header.chain_id,
            state_root: header.state_root.clone(),
            tx_root: header.tx_root.clone(),
            slashing_evidence: header
                .slashing_evidence
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(pb::ProtoSlashingEvidence::from)
                .collect(),
            nonce: header.nonce,
            epoch: header.epoch,
            slot: header.slot,
            vrf_output: header.vrf_output.clone(),
            vrf_proof: header.vrf_proof.clone(),
            validator_set_hash: header.validator_set_hash.clone(),
        }
    }
}

impl TryFrom<pb::ProtoBlockHeader> for BlockHeader {
    type Error = String;
    fn try_from(proto: pb::ProtoBlockHeader) -> Result<Self, Self::Error> {
        let timestamp = proto
            .timestamp
            .parse::<u128>()
            .map_err(|e| format!("Invalid block header timestamp string: {e}"))?;
        let producer = if proto.producer.is_empty() {
            None
        } else {
            Some(
                Address::from_hex(&proto.producer)
                    .map_err(|e| format!("Invalid producer address: {e}"))?,
            )
        };
        let mut evidence = Vec::new();
        for ev in proto.slashing_evidence {
            evidence.push(SlashingEvidence::try_from(ev)?);
        }
        let slashing_evidence = if evidence.is_empty() {
            None
        } else {
            Some(evidence)
        };
        Ok(BlockHeader {
            index: proto.index,
            timestamp,
            previous_hash: proto.previous_hash,
            hash: proto.hash,
            producer,
            chain_id: proto.chain_id,
            state_root: proto.state_root,
            tx_root: proto.tx_root,
            slashing_evidence,
            nonce: proto.nonce,
            epoch: proto.epoch,
            slot: proto.slot,
            vrf_output: proto.vrf_output,
            vrf_proof: proto.vrf_proof,
            validator_set_hash: proto.validator_set_hash,
            storage_root: None,
        })
    }
}

impl From<&Block> for pb::ProtoBlock {
    fn from(block: &Block) -> Self {
        pb::ProtoBlock {
            index: block.index,
            timestamp: block.timestamp.to_string(),
            previous_hash: block.previous_hash.clone(),
            hash: block.hash.clone(),
            transactions: block
                .transactions
                .iter()
                .map(pb::ProtoTransaction::from)
                .collect(),
            nonce: block.nonce,
            producer: block.producer.map(|p| p.to_string()).unwrap_or_default(),
            signature: block.signature.clone().unwrap_or_default(),
            chain_id: block.chain_id,
            slashing_evidence: block
                .slashing_evidence
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(pb::ProtoSlashingEvidence::from)
                .collect(),
            state_root: block.state_root.clone(),
            tx_root: block.tx_root.clone(),
            epoch: block.epoch,
            slot: block.slot,
            vrf_output: block.vrf_output.clone(),
            vrf_proof: block.vrf_proof.clone(),
            validator_set_hash: block.validator_set_hash.clone(),
        }
    }
}

impl TryFrom<pb::ProtoBlock> for Block {
    type Error = String;
    fn try_from(proto: pb::ProtoBlock) -> Result<Self, Self::Error> {
        let timestamp = proto
            .timestamp
            .parse::<u128>()
            .map_err(|e| format!("Invalid block timestamp string: {e}"))?;
        let producer = if proto.producer.is_empty() {
            None
        } else {
            Some(
                Address::from_hex(&proto.producer)
                    .map_err(|e| format!("Invalid producer address: {e}"))?,
            )
        };
        let signature = if proto.signature.is_empty() {
            None
        } else {
            Some(proto.signature)
        };

        let mut evidence = Vec::new();
        for ev in proto.slashing_evidence {
            evidence.push(SlashingEvidence::try_from(ev)?);
        }
        let slashing_evidence = if evidence.is_empty() {
            None
        } else {
            Some(evidence)
        };

        let mut transactions = Vec::new();
        for t in proto.transactions {
            transactions.push(Transaction::try_from(t)?);
        }

        Ok(Block {
            index: proto.index,
            timestamp,
            previous_hash: proto.previous_hash,
            hash: proto.hash,
            transactions,
            nonce: proto.nonce,
            producer,
            signature,
            chain_id: proto.chain_id,
            slashing_evidence,
            state_root: proto.state_root,
            tx_root: proto.tx_root,
            epoch: proto.epoch,
            slot: proto.slot,
            vrf_output: proto.vrf_output,
            vrf_proof: proto.vrf_proof,
            validator_set_hash: proto.validator_set_hash,
            storage_root: None,
        })
    }
}

impl From<&NetworkMessage> for pb::ProtoNetworkMessage {
    fn from(msg: &NetworkMessage) -> Self {
        let payload = match msg {
            NetworkMessage::Handshake {
                version_major,
                version_minor,
                chain_id,
                best_height,
                validator_set_hash,
                supported_schemes,
            } => pb::proto_network_message::Payload::Handshake(pb::ProtoHandshake {
                version_major: *version_major,
                version_minor: *version_minor,
                chain_id: *chain_id,
                best_height: *best_height,
                validator_set_hash: validator_set_hash.clone(),
                supported_schemes: supported_schemes.clone(),
            }),
            NetworkMessage::HandshakeAck {
                version_major,
                version_minor,
                chain_id,
                best_height,
                validator_set_hash,
                supported_schemes,
            } => pb::proto_network_message::Payload::HandshakeAck(pb::ProtoHandshakeAck {
                version_major: *version_major,
                version_minor: *version_minor,
                chain_id: *chain_id,
                best_height: *best_height,
                validator_set_hash: validator_set_hash.clone(),
                supported_schemes: supported_schemes.clone(),
            }),
            NetworkMessage::Block(block) => {
                pb::proto_network_message::Payload::Block(pb::ProtoBlock::from(block))
            }
            NetworkMessage::Transaction(tx) => {
                pb::proto_network_message::Payload::Transaction(pb::ProtoTransaction::from(tx))
            }
            NetworkMessage::GetHeaders { locator, limit } => {
                pb::proto_network_message::Payload::GetHeaders(pb::ProtoGetHeaders {
                    locator: locator.clone(),
                    limit: *limit,
                })
            }
            NetworkMessage::Headers(headers) => {
                pb::proto_network_message::Payload::Headers(pb::ProtoHeaders {
                    headers: headers.iter().map(pb::ProtoBlockHeader::from).collect(),
                })
            }
            NetworkMessage::GetBlocksRange { from, to } => {
                pb::proto_network_message::Payload::GetBlocksRange(pb::ProtoGetBlocksRange {
                    from_index: *from,
                    to_index: *to,
                })
            }
            NetworkMessage::Blocks(blocks) => {
                pb::proto_network_message::Payload::Blocks(pb::ProtoBlocks {
                    blocks: blocks.iter().map(pb::ProtoBlock::from).collect(),
                })
            }
            NetworkMessage::GetBlocksByHeight {
                from_height,
                to_height,
            } => {
                pb::proto_network_message::Payload::GetBlocksByHeight(pb::ProtoGetBlocksByHeight {
                    from_height: *from_height,
                    to_height: *to_height,
                })
            }
            NetworkMessage::BlocksByHeight(blocks) => {
                pb::proto_network_message::Payload::BlocksByHeight(pb::ProtoBlocksByHeight {
                    blocks: blocks.iter().map(pb::ProtoBlock::from).collect(),
                })
            }
            NetworkMessage::StateSnapshotResponse {
                height,
                state_root,
                ok,
            } => pb::proto_network_message::Payload::StateSnapshotResponse(
                pb::ProtoStateSnapshotResponse {
                    height: *height,
                    state_root: state_root.clone(),
                    ok: *ok,
                },
            ),
            NetworkMessage::NewTip { height, hash } => {
                pb::proto_network_message::Payload::NewTip(pb::ProtoNewTip {
                    height: *height,
                    hash: hash.clone(),
                })
            }
            NetworkMessage::GetStateSnapshot { height } => {
                pb::proto_network_message::Payload::GetStateSnapshot(pb::ProtoGetStateSnapshot {
                    height: *height,
                })
            }
            NetworkMessage::SnapshotChunk {
                height,
                index,
                total,
                data,
                session_id,
            } => pb::proto_network_message::Payload::SnapshotChunk(pb::ProtoSnapshotChunk {
                height: *height,
                index: *index,
                total: *total,
                data: data.clone(),
                session_id: *session_id,
            }),
            NetworkMessage::Prevote {
                epoch,
                checkpoint_height,
                checkpoint_hash,
                voter_id,
                sig_bls,
            } => pb::proto_network_message::Payload::Prevote(pb::ProtoPrevote {
                epoch: *epoch,
                checkpoint_height: *checkpoint_height,
                checkpoint_hash: checkpoint_hash.clone(),
                voter_id: voter_id.clone(),
                sig_bls: sig_bls.clone(),
            }),
            NetworkMessage::Precommit {
                epoch,
                checkpoint_height,
                checkpoint_hash,
                voter_id,
                sig_bls,
            } => pb::proto_network_message::Payload::Precommit(pb::ProtoPrecommit {
                epoch: *epoch,
                checkpoint_height: *checkpoint_height,
                checkpoint_hash: checkpoint_hash.clone(),
                voter_id: voter_id.clone(),
                sig_bls: sig_bls.clone(),
            }),
            NetworkMessage::FinalityCert {
                epoch,
                checkpoint_height,
                checkpoint_hash,
                agg_sig_bls,
                bitmap,
                set_hash,
            } => pb::proto_network_message::Payload::FinalityCert(pb::ProtoFinalityCert {
                epoch: *epoch,
                checkpoint_height: *checkpoint_height,
                checkpoint_hash: checkpoint_hash.clone(),
                agg_sig_bls: agg_sig_bls.clone(),
                bitmap: bitmap.clone(),
                set_hash: set_hash.clone(),
            }),
            NetworkMessage::GetQcBlob {
                epoch,
                checkpoint_height,
            } => pb::proto_network_message::Payload::GetQcBlob(pb::ProtoGetQcBlob {
                epoch: *epoch,
                checkpoint_height: *checkpoint_height,
            }),
            NetworkMessage::QcBlobResponse {
                epoch,
                checkpoint_height,
                checkpoint_hash,
                blob_data,
                found,
            } => pb::proto_network_message::Payload::QcBlobResponse(pb::ProtoQcBlobResponse {
                epoch: *epoch,
                checkpoint_height: *checkpoint_height,
                checkpoint_hash: checkpoint_hash.clone(),
                blob_data: blob_data.clone(),
                found: *found,
            }),
            NetworkMessage::QcFaultProof { proof_data } => {
                pb::proto_network_message::Payload::QcFaultProof(pb::ProtoQcFaultProof {
                    proof_data: proof_data.clone(),
                })
            }
            NetworkMessage::DomainCommitment(commitment) => {
                pb::proto_network_message::Payload::DomainCommitment(pb::ProtoDomainCommitment {
                    data: serialize_payload_or_log("DomainCommitment", commitment),
                })
            }
            NetworkMessage::VerifiedDomainCommitment(payload) => {
                pb::proto_network_message::Payload::VerifiedDomainCommitment(
                    pb::ProtoVerifiedDomainCommitment {
                        data: serialize_payload_or_log("VerifiedDomainCommitment", payload),
                    },
                )
            }
            NetworkMessage::SlashingEvidence(evidence) => {
                pb::proto_network_message::Payload::SlashingEvidence(
                    pb::ProtoSlashingEvidence::from(evidence),
                )
            }
            NetworkMessage::GlobalHeader(header) => {
                pb::proto_network_message::Payload::GlobalHeader(pb::ProtoGlobalHeader {
                    data: serialize_payload_or_log("GlobalHeader", header),
                })
            }
            NetworkMessage::CrossDomainMessage(msg) => {
                pb::proto_network_message::Payload::CrossDomainMessage(
                    pb::ProtoCrossDomainMessage {
                        data: serialize_payload_or_log("CrossDomainMessage", msg),
                    },
                )
            }
        };

        pb::ProtoNetworkMessage {
            payload: Some(payload),
        }
    }
}

impl TryFrom<pb::ProtoNetworkMessage> for NetworkMessage {
    type Error = String;
    fn try_from(proto: pb::ProtoNetworkMessage) -> Result<Self, Self::Error> {
        let payload = proto
            .payload
            .ok_or("Empty payload in ProtoNetworkMessage")?;
        match payload {
            pb::proto_network_message::Payload::Handshake(h) => Ok(NetworkMessage::Handshake {
                version_major: h.version_major,
                version_minor: h.version_minor,
                chain_id: h.chain_id,
                best_height: h.best_height,
                validator_set_hash: h.validator_set_hash,
                supported_schemes: h.supported_schemes,
            }),
            pb::proto_network_message::Payload::HandshakeAck(h) => {
                Ok(NetworkMessage::HandshakeAck {
                    version_major: h.version_major,
                    version_minor: h.version_minor,
                    chain_id: h.chain_id,
                    best_height: h.best_height,
                    validator_set_hash: h.validator_set_hash,
                    supported_schemes: h.supported_schemes,
                })
            }
            pb::proto_network_message::Payload::Block(b) => {
                Ok(NetworkMessage::Block(Block::try_from(b)?))
            }
            pb::proto_network_message::Payload::Transaction(t) => {
                Ok(NetworkMessage::Transaction(Transaction::try_from(t)?))
            }
            pb::proto_network_message::Payload::GetHeaders(h) => Ok(NetworkMessage::GetHeaders {
                locator: h.locator,
                limit: h.limit,
            }),
            pb::proto_network_message::Payload::Headers(h) => {
                let mut headers = Vec::new();
                for header in h.headers {
                    headers.push(BlockHeader::try_from(header)?);
                }
                Ok(NetworkMessage::Headers(headers))
            }
            pb::proto_network_message::Payload::GetBlocksRange(r) => {
                Ok(NetworkMessage::GetBlocksRange {
                    from: r.from_index,
                    to: r.to_index,
                })
            }
            pb::proto_network_message::Payload::Blocks(b) => {
                let mut blocks = Vec::new();
                for block in b.blocks {
                    blocks.push(Block::try_from(block)?);
                }
                Ok(NetworkMessage::Blocks(blocks))
            }
            pb::proto_network_message::Payload::GetBlocksByHeight(r) => {
                Ok(NetworkMessage::GetBlocksByHeight {
                    from_height: r.from_height,
                    to_height: r.to_height,
                })
            }
            pb::proto_network_message::Payload::BlocksByHeight(b) => {
                let mut blocks = Vec::new();
                for block in b.blocks {
                    blocks.push(Block::try_from(block)?);
                }
                Ok(NetworkMessage::BlocksByHeight(blocks))
            }
            pb::proto_network_message::Payload::StateSnapshotResponse(r) => {
                Ok(NetworkMessage::StateSnapshotResponse {
                    height: r.height,
                    state_root: r.state_root,
                    ok: r.ok,
                })
            }
            pb::proto_network_message::Payload::NewTip(t) => Ok(NetworkMessage::NewTip {
                height: t.height,
                hash: t.hash,
            }),
            pb::proto_network_message::Payload::GetStateSnapshot(s) => {
                Ok(NetworkMessage::GetStateSnapshot { height: s.height })
            }
            pb::proto_network_message::Payload::SnapshotChunk(c) => {
                Ok(NetworkMessage::SnapshotChunk {
                    height: c.height,
                    index: c.index,
                    total: c.total,
                    data: c.data,
                    session_id: c.session_id,
                })
            }
            pb::proto_network_message::Payload::Prevote(v) => Ok(NetworkMessage::Prevote {
                epoch: v.epoch,
                checkpoint_height: v.checkpoint_height,
                checkpoint_hash: v.checkpoint_hash,
                voter_id: v.voter_id,
                sig_bls: v.sig_bls,
            }),
            pb::proto_network_message::Payload::Precommit(v) => Ok(NetworkMessage::Precommit {
                epoch: v.epoch,
                checkpoint_height: v.checkpoint_height,
                checkpoint_hash: v.checkpoint_hash,
                voter_id: v.voter_id,
                sig_bls: v.sig_bls,
            }),
            pb::proto_network_message::Payload::FinalityCert(f) => {
                Ok(NetworkMessage::FinalityCert {
                    epoch: f.epoch,
                    checkpoint_height: f.checkpoint_height,
                    checkpoint_hash: f.checkpoint_hash,
                    agg_sig_bls: f.agg_sig_bls,
                    bitmap: f.bitmap,
                    set_hash: f.set_hash,
                })
            }
            pb::proto_network_message::Payload::GetQcBlob(q) => Ok(NetworkMessage::GetQcBlob {
                epoch: q.epoch,
                checkpoint_height: q.checkpoint_height,
            }),
            pb::proto_network_message::Payload::QcBlobResponse(q) => {
                Ok(NetworkMessage::QcBlobResponse {
                    epoch: q.epoch,
                    checkpoint_height: q.checkpoint_height,
                    checkpoint_hash: q.checkpoint_hash,
                    blob_data: q.blob_data,
                    found: q.found,
                })
            }
            pb::proto_network_message::Payload::QcFaultProof(p) => {
                Ok(NetworkMessage::QcFaultProof {
                    proof_data: p.proof_data,
                })
            }
            pb::proto_network_message::Payload::DomainCommitment(c) => {
                let commitment = serde_json::from_slice(&c.data)
                    .map_err(|e| format!("Invalid domain commitment payload: {e}"))?;
                Ok(NetworkMessage::DomainCommitment(commitment))
            }
            pb::proto_network_message::Payload::VerifiedDomainCommitment(c) => {
                let payload = serde_json::from_slice(&c.data)
                    .map_err(|e| format!("Invalid verified domain commitment payload: {e}"))?;
                Ok(NetworkMessage::VerifiedDomainCommitment(payload))
            }
            pb::proto_network_message::Payload::SlashingEvidence(e) => Ok(
                NetworkMessage::SlashingEvidence(SlashingEvidence::try_from(e)?),
            ),
            pb::proto_network_message::Payload::GlobalHeader(h) => {
                let header = serde_json::from_slice(&h.data)
                    .map_err(|e| format!("Invalid global header payload: {e}"))?;
                Ok(NetworkMessage::GlobalHeader(header))
            }
            pb::proto_network_message::Payload::CrossDomainMessage(m) => {
                let msg = serde_json::from_slice(&m.data)
                    .map_err(|e| format!("Invalid cross domain message payload: {e}"))?;
                Ok(NetworkMessage::CrossDomainMessage(msg))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::KeyPair;

    #[test]
    fn test_transaction_proto_conversion() {
        let keypair = KeyPair::generate().unwrap();
        let from = Address::from(keypair.public_key_bytes());
        let mut tx = Transaction::new_with_fee(from, Address::zero(), 100, 1, 42, vec![1, 2, 3, 4]);
        tx.sign(&keypair);

        let proto_tx = pb::ProtoTransaction::from(&tx);

        let decoded_tx =
            Transaction::try_from(proto_tx).expect("Failed to decode proto transaction");

        assert_eq!(tx, decoded_tx);
    }

    #[test]
    fn test_all_23_transaction_types_lossless_roundtrip() {
        let kp = KeyPair::generate().unwrap();
        let from = Address::from(kp.public_key_bytes());
        let to =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();

        let test_cases = vec![
            TransactionType::Transfer,
            TransactionType::Stake,
            TransactionType::Unstake,
            TransactionType::Vote,
            TransactionType::ContractCall,
            TransactionType::BnsRegister,
            TransactionType::BnsSetContent,
            TransactionType::BnsRegisterSubdomain,
            TransactionType::BnsSetStorage,
            TransactionType::NftMint,
            TransactionType::NftTransfer,
            TransactionType::NftBurn,
            TransactionType::NftBoost {
                nft_id: 42,
                amount: 1000,
            },
            TransactionType::NftUpdateLight {
                nft_id: 42,
                delta_mcd: -15,
            },
            TransactionType::NftTag {
                nft_id: 42,
                tag: "legendary".into(),
            },
            TransactionType::UniversalRelay(crate::core::transaction::ExternalTransaction {
                chain: crate::core::transaction::ExternalChain::Ethereum,
                target_address: "0xabc".into(),
                payload: vec![1, 2, 3],
                external_nonce: 99,
            }),
            TransactionType::RelayerResult(crate::core::transaction::RelayerExternalResult {
                chain: crate::core::transaction::ExternalChain::Solana,
                tx_hash: "hash123".into(),
                success: true,
                message: None,
                receipt_proof: vec![9, 9, 9],
                external_state_root: [5u8; 32],
            }),
            TransactionType::AiOfferData {
                cid: crate::storage::content_id::ContentId([7u8; 32]),
                price: 500,
            },
            TransactionType::AiPurchaseData { offer_id: 888 },
            TransactionType::HubRegisterApp {
                name: "BudApp".into(),
                category: crate::hub::types::AppCategory::DeFi,
                website_url: "https://budlum.ai".into(),
                manifest_id: Some(crate::storage::content_id::ContentId([8u8; 32])),
            },
            TransactionType::AiModelRegister(crate::ai::types::AiModelSpec {
                model_id: crate::ai::types::AiModelId([1u8; 32]),
                model_hash: [2u8; 32],
                owner: from,
                min_verifier_count: 3,
                agreement_threshold: 2,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
            }),
            TransactionType::AiInferenceRequest(crate::ai::types::AiInferenceRequest {
                request_id: crate::ai::types::AiRequestId([3u8; 32]),
                requester: from,
                model_id: crate::ai::types::AiModelId([1u8; 32]),
                input_commitment: [4u8; 32],
                input_ref: crate::ai::types::BoundedBytes::try_new(vec![10, 20, 30]).unwrap(),
                max_fee: 50,
                callback: Some(to),
                submitted_at_block: 10,
                deadline_block: 110,
            }),
            TransactionType::AiInferenceResult(crate::ai::types::AiInferenceResult {
                request_id: crate::ai::types::AiRequestId([3u8; 32]),
                verifier: from,
                output_commitment: [5u8; 32],
                output_ref: crate::ai::types::BoundedBytes::try_new(vec![40, 50, 60]).unwrap(),
                result_nonce: 1,
                signature: vec![7, 7, 7],
                submitted_at_block: 15,
            }),
        ];

        for tx_type in test_cases {
            let mut tx = Transaction::new_with_chain_id(
                from,
                to,
                100,
                10,
                1,
                vec![1],
                1337,
                tx_type.clone(),
            );
            tx.sign(&kp);

            let proto_tx = pb::ProtoTransaction::from(&tx);
            let decoded_tx = Transaction::try_from(proto_tx.clone())
                .unwrap_or_else(|e| panic!("Failed to decode {:?}: {}", tx_type, e));

            assert_eq!(tx, decoded_tx, "Mismatch on roundtrip for {:?}", tx_type);
            assert_eq!(tx.hash, decoded_tx.hash);
        }
    }

    #[test]
    fn test_p0_fail_closed_unknown_or_corrupt_payload() {
        let mut proto = pb::ProtoTransaction {
            from: "0000000000000000000000000000000000000000000000000000000000000001".into(),
            to: "0000000000000000000000000000000000000000000000000000000000000002".into(),
            amount: 10,
            fee: 1,
            nonce: 0,
            data: vec![],
            timestamp: "1000".into(),
            hash: "abc".into(),
            signature: vec![],
            chain_id: 1337,
            signature_version: crate::core::transaction::SIGNATURE_VERSION_V4,
            tx_type: pb::ProtoTransactionType::NftBoost as i32,
            wire_version: 2,
            type_payload: None, // Missing payload for NftBoost!
        };

        assert!(Transaction::try_from(proto.clone()).is_err());

        proto.tx_type = 999; // Unknown transaction type tag
        assert!(Transaction::try_from(proto).is_err());
    }

    #[test]
    fn test_block_proto_conversion() {
        let keypair = KeyPair::generate().unwrap();
        let from = Address::from(keypair.public_key_bytes());
        let mut tx = Transaction::new(from, Address::zero(), 50, vec![]);
        tx.sign(&keypair);

        let mut block = Block::new(10, "PREV_HASH".to_string(), vec![tx]);
        block.state_root = "STATE_ROOT".to_string();
        block.tx_root = "TX_ROOT".to_string();
        block.producer = Some(from);
        block.sign(&keypair);

        let proto_block = pb::ProtoBlock::from(&block);

        let decoded_block = Block::try_from(proto_block).expect("Failed to decode proto block");

        assert_eq!(block, decoded_block);
    }

    #[test]
    fn test_network_message_block_conversion() {
        let block = Block::new(1, "PREV".to_string(), vec![]);
        let msg = NetworkMessage::Block(block);

        let proto_msg = pb::ProtoNetworkMessage::from(&msg);

        let decoded_msg =
            NetworkMessage::try_from(proto_msg).expect("Failed to decode NetworkMessage");

        if let (NetworkMessage::Block(orig_b), NetworkMessage::Block(dec_b)) = (&msg, &decoded_msg)
        {
            assert_eq!(orig_b, dec_b);
        } else {
            panic!("Decoded message is not a Block");
        }
    }

    #[test]
    fn test_qc_fault_proof_message_conversion() {
        let proof_data = br#"{"version":1}"#.to_vec();
        let msg = NetworkMessage::QcFaultProof {
            proof_data: proof_data.clone(),
        };

        let proto_msg = pb::ProtoNetworkMessage::from(&msg);
        let decoded_msg =
            NetworkMessage::try_from(proto_msg).expect("Failed to decode QcFaultProof message");

        match decoded_msg {
            NetworkMessage::QcFaultProof {
                proof_data: decoded,
            } => {
                assert_eq!(decoded, proof_data);
            }
            _ => panic!("Expected QcFaultProof message"),
        }
    }

    #[test]
    fn test_domain_commitment_message_conversion() {
        let commitment = crate::domain::DomainCommitment {
            domain_id: 1,
            domain_height: 42,
            domain_block_hash: [1u8; 32],
            parent_domain_block_hash: [2u8; 32],
            state_root: [3u8; 32],
            tx_root: [4u8; 32],
            event_root: [5u8; 32],
            finality_proof_hash: [6u8; 32],
            consensus_kind: crate::domain::ConsensusKind::PoW,
            validator_set_hash: [7u8; 32],
            timestamp_ms: 123,
            sequence: 9,
            producer: None,
            state_updates: std::collections::BTreeMap::new(),
        };
        let msg = NetworkMessage::DomainCommitment(commitment.clone());
        let proto_msg = pb::ProtoNetworkMessage::from(&msg);
        let decoded_msg =
            NetworkMessage::try_from(proto_msg).expect("Failed to decode DomainCommitment");

        match decoded_msg {
            NetworkMessage::DomainCommitment(decoded) => assert_eq!(decoded, commitment),
            _ => panic!("Expected DomainCommitment message"),
        }
    }

    #[test]
    fn test_verified_domain_commitment_message_conversion() {
        let commitment = crate::domain::DomainCommitment {
            domain_id: 1,
            domain_height: 42,
            domain_block_hash: [1u8; 32],
            parent_domain_block_hash: [2u8; 32],
            state_root: [3u8; 32],
            tx_root: [4u8; 32],
            event_root: [5u8; 32],
            finality_proof_hash: crate::domain::hash_finality_proof(
                &crate::domain::FinalityProof::PoW {
                    confirmations: 64,
                    total_work_hint: 1000,
                    declared_head_hash: [0u8; 32],
                    declared_cumulative_work: 1000,
                },
            ),
            consensus_kind: crate::domain::ConsensusKind::PoW,
            validator_set_hash: [7u8; 32],
            timestamp_ms: 123,
            sequence: 9,
            producer: None,
            state_updates: std::collections::BTreeMap::new(),
        };
        let payload = crate::domain::VerifiedDomainCommitment {
            commitment: commitment.clone(),
            proof: crate::domain::FinalityProof::PoW {
                confirmations: 64,
                total_work_hint: 1000,
                declared_head_hash: [0u8; 32],
                declared_cumulative_work: 1000,
            },
        };
        let msg = NetworkMessage::VerifiedDomainCommitment(payload);
        let proto_msg = pb::ProtoNetworkMessage::from(&msg);
        let decoded_msg =
            NetworkMessage::try_from(proto_msg).expect("Failed to decode VerifiedDomainCommitment");

        match decoded_msg {
            NetworkMessage::VerifiedDomainCommitment(decoded) => {
                assert_eq!(decoded.commitment, commitment);
                match decoded.proof {
                    crate::domain::FinalityProof::PoW {
                        confirmations,
                        total_work_hint,
                        ..
                    } => {
                        assert_eq!(confirmations, 64);
                        assert_eq!(total_work_hint, 1000);
                    }
                    _ => panic!("Expected PoW finality proof"),
                }
            }
            _ => panic!("Expected VerifiedDomainCommitment message"),
        }
    }

    #[test]
    fn test_global_header_message_conversion() {
        let header = crate::settlement::GlobalBlockHeader {
            version: 1,
            global_height: 7,
            previous_global_hash: [1u8; 32],
            chain_id: 1337,
            timestamp_ms: 456,
            domain_registry_root: [2u8; 32],
            domain_commitment_root: [3u8; 32],
            message_root: [4u8; 32],
            bridge_state_root: [5u8; 32],
            replay_nonce_root: [6u8; 32],
            proposer: None,
            settlement_finality_root: [7u8; 32],
            storage_root: None,
        };
        let msg = NetworkMessage::GlobalHeader(header.clone());
        let proto_msg = pb::ProtoNetworkMessage::from(&msg);
        let decoded_msg =
            NetworkMessage::try_from(proto_msg).expect("Failed to decode GlobalHeader");

        match decoded_msg {
            NetworkMessage::GlobalHeader(decoded) => assert_eq!(decoded, header),
            _ => panic!("Expected GlobalHeader message"),
        }
    }

    #[test]
    fn test_cross_domain_message_conversion() {
        let msg_inner = crate::cross_domain::CrossDomainMessage::new(
            crate::cross_domain::message::CrossDomainMessageParams {
                source_domain: 1,
                target_domain: 2,
                source_height: 10,
                event_index: 0,
                nonce: 42,
                sender: crate::core::address::Address::zero(),
                recipient: crate::core::address::Address::zero(),
                payload_hash: [9u8; 32],
                kind: crate::cross_domain::MessageKind::BridgeLock,
                expiry_height: 100,
            },
        );
        let msg = NetworkMessage::CrossDomainMessage(msg_inner.clone());
        let proto_msg = pb::ProtoNetworkMessage::from(&msg);
        let decoded_msg =
            NetworkMessage::try_from(proto_msg).expect("Failed to decode CrossDomainMessage");

        match decoded_msg {
            NetworkMessage::CrossDomainMessage(decoded) => assert_eq!(decoded, msg_inner),
            _ => panic!("Expected CrossDomainMessage"),
        }
    }
}
