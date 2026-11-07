//! B.U.D. 3.0 CLI command builders and handlers (`bud storage *`, `bud validator *`,
//! `bud alias show`, `bud faucet request`, and network base-fee default resolution;
//! Section 6.22, Section 7.3, WP-39, DOC-GAP-08).
//! exposed for CLI binary subcommands, wallet SDK scripts, and integration tests.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::address::Address;
use crate::storage::bud3::content_gateway::{Bud3ContentGateway, GatewayError, GatewayResponse};
use crate::storage::bud3::delete::GrantRevocationAuth;
use crate::storage::bud3::grants::{build_grant_row, GrantRow};
use crate::storage::bud3::keys::{seal_key_package_xwing, ObjectKeyPackage, XWingPublicKey};
use crate::storage::bud3::limits::{Bud3Limits, Profile};
use crate::storage::bud3::placement::{Class, Share};
use crate::storage::bud3::registry::{Bud3Registry, NftId, ObjectKey, RegistryError};
use crate::storage::bud3::tx::StorageTxV3;
use crate::storage::bud3::upload::{FinishedUpload, UploadError, UploadSessionManager};

/// Domain tag deriving deterministic cross-environment account aliases (`bud alias show`).
pub const DOMAIN_CLI_ALIAS: &[u8] = b"BDLM_BUD3_CLI_ALIAS_V1";

/// Domain tag hashing faucet proof-of-work challenges (`bud faucet request`).
pub const DOMAIN_CLI_FAUCET_POW: &[u8] = b"BDLM_BUD3_CLI_FAUCET_POW_V1";

/// Minimum Full-class validator stake in base BUD atoms (`10_000 BUD`, `1 BUD = 10^6`).
pub const FULL_VALIDATOR_MIN_STAKE_ATOMS: u64 = 10_000_000_000;

/// Minimum Mobile-class validator stake in base BUD atoms (`100 BUD`, `1 BUD = 10^6`).
pub const MOBILE_VALIDATOR_MIN_STAKE_ATOMS: u64 = 100_000_000;

/// Minimum Mobile custody quota (`1 GiB`).
pub const MOBILE_MIN_CUSTODY_QUOTA_BYTES: u64 = 1 << 30;

/// Errors returned by B.U.D. 3.0 CLI command handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliBud3Error {
    /// `--signing-chain-id` was missing or zero.
    MissingSigningChainId,
    /// Network `base_fee` was zero or unavailable (`DOC-GAP-08`).
    UnavailableNetworkBaseFee,
    /// Streaming upload session error.
    Upload(UploadError),
    /// Content gateway / reveal session error.
    Gateway(GatewayError),
    /// On-chain B.U.D. 3.0 registry error.
    Registry(RegistryError),
    /// Grant building or X-Wing sealing error.
    Grant(String),
    /// Invalid validator registration parameters.
    InvalidValidatorRegistration(&'static str),
    /// Proof-of-work search exhausted `max_attempts` without meeting `difficulty_bits`.
    PowExhausted,
}

impl std::fmt::Display for CliBud3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSigningChainId => {
                f.write_str("`--signing-chain-id` must be explicitly set and non-zero")
            }
            Self::UnavailableNetworkBaseFee => {
                f.write_str("network base_fee must be queried and non-zero when --fee is omitted")
            }
            Self::Upload(e) => write!(f, "cli upload error: {e}"),
            Self::Gateway(e) => write!(f, "cli view error: {e}"),
            Self::Registry(e) => write!(f, "cli registry error: {e:?}"),
            Self::Grant(msg) => write!(f, "cli grant error: {msg}"),
            Self::InvalidValidatorRegistration(msg) => {
                write!(f, "invalid validator command: {msg}")
            }
            Self::PowExhausted => f.write_str("faucet PoW search exhausted max_attempts"),
        }
    }
}

impl std::error::Error for CliBud3Error {}

/// Resolve the transaction fee for a CLI invocation (`DOC-GAP-08`).
/// exposed for `bud` CLI transaction builders.
///
/// Requires a non-zero `signing_chain_id`, uses `explicit_fee` when provided,
/// and otherwise reads `network_base_fee` from the connected node.
///
/// # Errors
///
/// Returns [`CliBud3Error`] if `signing_chain_id == 0` or the fee is zero.
pub fn resolve_cli_fee_default(
    signing_chain_id: u64,
    explicit_fee: Option<u64>,
    network_base_fee: Option<u64>,
) -> Result<u64, CliBud3Error> {
    if signing_chain_id == 0 {
        return Err(CliBud3Error::MissingSigningChainId);
    }
    match explicit_fee {
        Some(f) if f > 0 => Ok(f),
        Some(_) => Err(CliBud3Error::UnavailableNetworkBaseFee),
        None => match network_base_fee {
            Some(base) if base > 0 => Ok(base),
            _ => Err(CliBud3Error::UnavailableNetworkBaseFee),
        },
    }
}

/// Stream-upload content via `UploadSessionManager` (`bud storage upload`) and
/// construct the ready-to-sign [`StorageTxV3::RegisterObject`] transaction.
/// exposed for `bud storage upload` CLI command.
///
/// # Errors
///
/// Returns [`CliBud3Error`] if `signing_chain_id == 0` or the upload session fails.
#[allow(clippy::too_many_arguments)]
pub fn cli_storage_upload(
    sessions: &mut UploadSessionManager,
    uploader: [u8; 32],
    signing_chain_id: u64,
    payload: &[u8],
    chunk_size: usize,
    profile: Profile,
    limits: &Bud3Limits,
    shares: Vec<(u64, Share)>,
    lifetime_epochs: u64,
    now_secs: u64,
) -> Result<(FinishedUpload, StorageTxV3), CliBud3Error> {
    if signing_chain_id == 0 {
        return Err(CliBud3Error::MissingSigningChainId);
    }
    let step = chunk_size.max(1);
    let sid = sessions
        .open_session(uploader, payload.len() as u64, false, profile, limits, now_secs)
        .map_err(CliBud3Error::Upload)?;

    let mut offset = 0usize;
    while offset < payload.len() {
        let end = offset.saturating_add(step).min(payload.len());
        if let Some(slice) = payload.get(offset..end) {
            sessions
                .append_chunk(sid, slice, now_secs)
                .map_err(CliBud3Error::Upload)?;
        }
        offset = end;
    }

    let finished = sessions
        .finish_public(sid, limits)
        .map_err(CliBud3Error::Upload)?;
    let tx = StorageTxV3::RegisterObject {
        record: finished.record.clone(),
        shares,
        lifetime_epochs,
    };
    Ok((finished, tx))
}

/// Retrieve and verify content via `Bud3ContentGateway` (`bud storage view`).
/// exposed for `bud storage view` CLI command.
///
/// # Errors
///
/// Returns [`CliBud3Error::Gateway`] if view authorization or symbol recovery fails.
pub fn cli_storage_view(
    bud3: &Bud3Registry,
    gateway: &mut Bud3ContentGateway,
    object_commitment: &ObjectKey,
    nft_id: Option<NftId>,
    grant_tag: Option<[u8; 32]>,
    paid_fallback_bud: Option<u64>,
    current_height: u64,
) -> Result<GatewayResponse, CliBud3Error> {
    if nft_id.is_some() || grant_tag.is_some() {
        return gateway
            .get_object(bud3, object_commitment, nft_id, grant_tag, current_height)
            .map_err(CliBud3Error::Gateway);
    }
    if let Some(paid) = paid_fallback_bud {
        return gateway
            .get_public_paid(bud3, object_commitment, paid)
            .map_err(CliBud3Error::Gateway);
    }
    gateway
        .get_object(bud3, object_commitment, None, None, current_height)
        .map_err(CliBud3Error::Gateway)
}

/// Build a `bud storage renew`, `burn`, `grant`, or `revoke` transaction.
/// exposed for `bud storage` lifecycle CLI commands.
#[must_use]
pub fn cli_storage_renew(object: ObjectKey, extra_epochs: u64) -> StorageTxV3 {
    StorageTxV3::RenewObject {
        object,
        extra_epochs,
    }
}

/// Build a `bud storage burn` transaction (`BurnReference` or `SocialDelete`).
/// exposed for `bud storage burn` CLI command.
#[must_use]
pub fn cli_storage_burn(nft: NftId, grant_revocations: Vec<GrantRevocationAuth>) -> StorageTxV3 {
    if grant_revocations.is_empty() {
        StorageTxV3::BurnReference { nft }
    } else {
        StorageTxV3::SocialDelete {
            nft,
            grant_revocations,
        }
    }
}

/// Build an unlinkable `bud storage grant` (`StorageTxV3::IssueViewGrant`).
/// exposed for `bud storage grant` CLI command.
///
/// # Errors
///
/// Returns [`CliBud3Error::Grant`] if X-Wing sealing or grant validation fails.
pub fn cli_storage_grant(
    nft_id: &NftId,
    grant_nonce: &[u8; 32],
    one_time_public_key: Vec<u8>,
    key_package: &ObjectKeyPackage,
    grantee_xwing_pk: &XWingPublicKey,
    seal_seed: &[u8; 64],
    expires_at_height: u64,
    current_height: u64,
) -> Result<(GrantRow, StorageTxV3), CliBud3Error> {
    let capsule = seal_key_package_xwing(key_package, grantee_xwing_pk, seal_seed)
        .map_err(|e| CliBud3Error::Grant(e.to_string()))?;
    let row = build_grant_row(
        nft_id,
        grant_nonce,
        one_time_public_key,
        capsule.to_bytes(),
        expires_at_height,
        current_height,
    )
    .map_err(|e| CliBud3Error::Grant(e.to_string()))?;
    Ok((row.clone(), StorageTxV3::IssueViewGrant { row }))
}

/// Build a `bud storage revoke` transaction (`StorageTxV3::RevokeViewGrant`).
/// exposed for `bud storage revoke` CLI command.
#[must_use]
pub fn cli_storage_revoke(grant_tag: [u8; 32], one_time_signature: Vec<u8>) -> StorageTxV3 {
    StorageTxV3::RevokeViewGrant {
        grant_tag,
        one_time_signature,
    }
}

/// Validated `bud validator register --class full|mobile` descriptor (Section 7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorRegisterSpec {
    pub validator: Address,
    pub class: Class,
    pub stake_atoms: u64,
    pub custody_quota_bytes: u64,
    pub signing_chain_id: u64,
}

/// Validate `bud validator register --class full|mobile` arguments.
/// exposed for `bud validator register` CLI command.
///
/// # Errors
///
/// Returns [`CliBud3Error`] if stake floor, Mobile custody quota, or chain id fails.
pub fn cli_validator_register(
    validator: Address,
    class_flag: &str,
    stake_atoms: u64,
    custody_quota_bytes: u64,
    signing_chain_id: u64,
) -> Result<ValidatorRegisterSpec, CliBud3Error> {
    if signing_chain_id == 0 {
        return Err(CliBud3Error::MissingSigningChainId);
    }
    if validator == Address::zero() {
        return Err(CliBud3Error::InvalidValidatorRegistration(
            "validator address cannot be zero",
        ));
    }
    let class = match class_flag.trim().to_ascii_lowercase().as_str() {
        "full" => {
            if stake_atoms < FULL_VALIDATOR_MIN_STAKE_ATOMS {
                return Err(CliBud3Error::InvalidValidatorRegistration(
                    "Full validator requires >= 10_000 BUD stake",
                ));
            }
            Class::Full
        }
        "mobile" => {
            if stake_atoms < MOBILE_VALIDATOR_MIN_STAKE_ATOMS {
                return Err(CliBud3Error::InvalidValidatorRegistration(
                    "Mobile validator requires >= 100 BUD stake",
                ));
            }
            if custody_quota_bytes < MOBILE_MIN_CUSTODY_QUOTA_BYTES {
                return Err(CliBud3Error::InvalidValidatorRegistration(
                    "Mobile validator requires >= 1 GiB custody quota",
                ));
            }
            Class::Mobile
        }
        _ => {
            return Err(CliBud3Error::InvalidValidatorRegistration(
                "unknown --class flag; expected `full` or `mobile`",
            ))
        }
    };

    Ok(ValidatorRegisterSpec {
        validator,
        class,
        stake_atoms,
        custody_quota_bytes,
        signing_chain_id,
    })
}

/// Cross-environment alias projection (`bud alias show <address>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountAliases {
    pub native: Address,
    pub evm_address: [u8; 20],
    pub wasm_address: [u8; 32],
    pub svm_address: [u8; 32],
    pub move_address: [u8; 32],
}

/// Compute deterministic per-environment aliases for a native `Address`.
/// exposed for `bud alias show` CLI command.
#[must_use]
pub fn cli_alias_show(address: Address) -> AccountAliases {
    let derive = |env_label: &[u8]| -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN_CLI_ALIAS);
        h.update(env_label);
        h.update(address.as_bytes());
        h.finalize().into()
    };
    let evm_full = derive(b"evm");
    let mut evm_address = [0u8; 20];
    if let Some(tail) = evm_full.get(12..32) {
        evm_address.copy_from_slice(tail);
    }
    AccountAliases {
        native: address,
        evm_address,
        wasm_address: derive(b"wasm"),
        svm_address: derive(b"svm"),
        move_address: derive(b"move"),
    }
}

/// Count leading zero bits in a 32-byte digest.
fn leading_zero_bits(digest: &[u8; 32]) -> u32 {
    let mut total = 0u32;
    for &b in digest {
        if b == 0 {
            total = total.saturating_add(8);
        } else {
            total = total.saturating_add(b.leading_zeros());
            break;
        }
    }
    total
}

/// Solve the faucet proof-of-work challenge (`bud faucet request --address <addr>`).
/// exposed for `bud faucet request` CLI command.
///
/// # Errors
///
/// Returns [`CliBud3Error::PowExhausted`] if no nonce in `0..max_attempts` meets
/// `difficulty_bits`.
pub fn solve_faucet_pow(
    address: &Address,
    challenge_seed: &[u8; 32],
    difficulty_bits: u32,
    max_attempts: u64,
) -> Result<(u64, [u8; 32]), CliBud3Error> {
    for nonce in 0..max_attempts {
        let mut h = Sha256::new();
        h.update(DOMAIN_CLI_FAUCET_POW);
        h.update(challenge_seed);
        h.update(address.as_bytes());
        h.update(nonce.to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();
        if leading_zero_bits(&digest) >= difficulty_bits {
            return Ok((nonce, digest));
        }
    }
    Err(CliBud3Error::PowExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::bud3::tx::apply as apply_bud3_tx;

    const P: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 1024,
        fps: 10,
        k_max: 64,
    };

    #[test]
    fn cli_storage_upload_view_round_trip() {
        let mut sessions = UploadSessionManager::new();
        let mut bud3 = Bud3Registry::new();
        let mut gateway = Bud3ContentGateway::new();

        let uploader = [0x42; 32];
        let payload = b"bud cli streaming upload and view round trip".repeat(60);
        let shares = vec![(
            0,
            Share {
                validator: [7u8; 32],
                class: Class::Full,
                first_esi: 0,
                symbol_count: 8,
            },
        )];

        let (finished, tx) = cli_storage_upload(
            &mut sessions,
            uploader,
            45261,
            &payload,
            512,
            P,
            &Bud3Limits::default(),
            shares,
            20,
            100,
        )
        .unwrap();

        let key = finished.record.commitment;
        let nft_id = [0x88; 32];
        apply_bud3_tx(&mut bud3, uploader, tx, 1, 10, 10_000).unwrap();
        bud3.bind_nft(nft_id, key).unwrap();
        gateway
            .stage_object(&finished.record, &finished.object_bytes)
            .unwrap();

        let viewed =
            cli_storage_view(&bud3, &mut gateway, &key, Some(nft_id), None, None, 10).unwrap();
        assert_eq!(viewed.body, payload);
        assert_eq!(viewed.content_id, finished.record.content_id);
    }

    #[test]
    fn cli_validator_register_mobile_class() {
        let addr = Address::from([0x19; 32]);
        assert!(cli_validator_register(addr, "mobile", 50_000_000, 1 << 30, 45261).is_err());
        assert!(cli_validator_register(addr, "mobile", 100_000_000, 512, 45261).is_err());

        let ok = cli_validator_register(addr, "mobile", 100_000_000, 2 << 30, 45261).unwrap();
        assert_eq!(ok.class, Class::Mobile);

        let full = cli_validator_register(addr, "full", FULL_VALIDATOR_MIN_STAKE_ATOMS, 0, 45261)
            .unwrap();
        assert_eq!(full.class, Class::Full);
    }

    #[test]
    fn cli_fee_default_reads_network_base_fee() {
        assert_eq!(
            resolve_cli_fee_default(0, Some(10), Some(5)),
            Err(CliBud3Error::MissingSigningChainId)
        );
        assert_eq!(
            resolve_cli_fee_default(45261, None, None),
            Err(CliBud3Error::UnavailableNetworkBaseFee)
        );
        assert_eq!(resolve_cli_fee_default(45261, None, Some(17)).unwrap(), 17);
        assert_eq!(
            resolve_cli_fee_default(45261, Some(25), Some(17)).unwrap(),
            25
        );
    }

    #[test]
    fn cli_alias_and_faucet_pow_work() {
        let addr = Address::from([0x77; 32]);
        let a1 = cli_alias_show(addr);
        let a2 = cli_alias_show(addr);
        assert_eq!(a1, a2);
        assert_ne!(a1.evm_address, [0u8; 20]);
        assert_ne!(a1.wasm_address, a1.svm_address);

        let (nonce, digest) = solve_faucet_pow(&addr, &[0xAB; 32], 8, 100_000).unwrap();
        assert!(leading_zero_bits(&digest) >= 8);
        let _ = nonce;
    }
}
