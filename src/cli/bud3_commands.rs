//! B.U.D. 3.0 CLI command builders and handlers (`bud storage *`, `bud validator *`,
//! `bud alias show`, `bud faucet request`, and network base-fee default resolution;
//! Section 6.22, Section 7.3).
//! exposed for CLI binary subcommands, wallet SDK scripts, and integration tests.

use serde::{Deserialize, Serialize};

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::storage::bud3::content_gateway::{Bud3ContentGateway, ContentGatewayError};
use crate::storage::bud3::content_id::ContentKey;
use crate::storage::bud3::content_ref::{ContentRef, ContentRefError};
use crate::storage::bud3::delete::GrantShredAuth;
use crate::storage::bud3::grants::{build_grant_row, compute_grant_tag, GrantBud3Error, GrantRow};
use crate::storage::bud3::keys::{seal_key_package, KeyPkgBud3Error};
use crate::storage::bud3::limits::Profile;
use crate::storage::bud3::placement::{Candidate, Class, PlacementRow};
use crate::storage::bud3::registry::{Bud3Registry, NftId, ObjectKey, RegistryError};
use crate::storage::bud3::tx::StorageTxV3;
use crate::storage::bud3::upload::{FinishedUploadSession, UploadError, UploadSessionManager};
use crate::storage::bud3::view::{
    view_from_network, NetworkSymbolSource, PaidViewReceipt, ViewBud3Error,
};

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
    /// Network `base_fee` was zero or unavailable.
    UnavailableNetworkBaseFee,
    /// Streaming upload session error.
    Upload(UploadError),
    /// Content gateway error.
    Gateway(ContentGatewayError),
    /// Network view reconstruction error.
    View(ViewBud3Error),
    /// Invalid `ContentRef`.
    InvalidContentRef(ContentRefError),
    /// On-chain B.U.D. 3.0 registry error.
    Registry(RegistryError),
    /// X-Wing sealing error.
    KeyPackage(KeyPkgBud3Error),
    /// Grant row validation error.
    Grant(GrantBud3Error),
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
            Self::Upload(e) => write!(f, "cli upload error: {e:?}"),
            Self::Gateway(e) => write!(f, "cli gateway error: {e:?}"),
            Self::View(e) => write!(f, "cli view error: {e:?}"),
            Self::InvalidContentRef(e) => write!(f, "cli ContentRef error: {e:?}"),
            Self::Registry(e) => write!(f, "cli registry error: {e:?}"),
            Self::KeyPackage(e) => write!(f, "cli key-package error: {e:?}"),
            Self::Grant(e) => write!(f, "cli grant error: {e:?}"),
            Self::InvalidValidatorRegistration(msg) => {
                write!(f, "invalid validator command: {msg}")
            }
            Self::PowExhausted => f.write_str("faucet PoW search exhausted max_attempts"),
        }
    }
}

impl std::error::Error for CliBud3Error {}

/// Resolve the transaction fee for a CLI invocation.
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

/// Parameters controlling a streaming `bud storage upload` CLI session.
#[derive(Debug, Clone, Copy)]
pub struct CliUploadParams {
    pub uploader: [u8; 32],
    pub signing_chain_id: u64,
    pub chunk_size: usize,
    pub profile: Profile,
    pub lifetime_epochs: u64,
    pub now_secs: u64,
}

/// Stream-upload content via `UploadSessionManager` (`bud storage upload`) and
/// construct the ready-to-sign [`StorageTxV3::RegisterObject`] transaction.
/// exposed for `bud storage upload` CLI command.
///
/// # Errors
///
/// Returns [`CliBud3Error`] if `signing_chain_id == 0` or the upload session fails.
pub fn cli_storage_upload(
    sessions: &mut UploadSessionManager,
    bud3: &Bud3Registry,
    params: &CliUploadParams,
    payload: &[u8],
    row: &PlacementRow,
    candidates: &[Candidate],
) -> Result<FinishedUploadSession, CliBud3Error> {
    if params.signing_chain_id == 0 {
        return Err(CliBud3Error::MissingSigningChainId);
    }
    let step = params.chunk_size.max(1);
    let sid = sessions
        .open_session(
            (params.uploader, [0u8; 16]),
            payload.len() as u64,
            0,
            params.lifetime_epochs,
            false,
            params.now_secs,
        )
        .map_err(CliBud3Error::Upload)?;

    for chunk in payload.chunks(step) {
        sessions
            .append_chunk(sid, chunk, params.now_secs)
            .map_err(CliBud3Error::Upload)?;
    }

    sessions
        .finish_session(
            sid,
            &params.profile,
            row,
            candidates,
            bud3,
            params.now_secs,
        )
        .map_err(CliBud3Error::Upload)
}

/// Retrieve and verify content via `Bud3ContentGateway` / `bud3::view` (`bud storage view`).
/// exposed for `bud storage view` CLI command.
///
/// # Errors
///
/// Returns [`CliBud3Error`] if view authorization or symbol recovery fails.
pub fn cli_storage_view<N: NetworkSymbolSource>(
    bud3: &Bud3Registry,
    network: &N,
    object_commitment: &ObjectKey,
    nft_id: Option<NftId>,
    content_key: Option<&ContentKey>,
    paid_receipt: Option<&PaidViewReceipt>,
) -> Result<Vec<u8>, CliBud3Error> {
    let entry = bud3
        .object(object_commitment)
        .ok_or(CliBud3Error::Registry(RegistryError::UnknownObject))?;
    let cref = ContentRef::new(entry.record.content_id, *object_commitment, nft_id)
        .map_err(CliBud3Error::InvalidContentRef)?;

    if let Some(receipt) = paid_receipt {
        return Bud3ContentGateway::serve_paid_public_fallback(bud3, &cref, receipt, network)
            .map_err(CliBud3Error::Gateway);
    }

    let _bundle = Bud3ContentGateway::fetch_symbol_bundle(bud3, &cref, network)
        .map_err(CliBud3Error::Gateway)?;
    view_from_network(bud3, object_commitment, content_key, network).map_err(CliBud3Error::View)
}

/// Build a `bud storage renew` transaction (`StorageTxV3::RenewObject`).
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
pub fn cli_storage_burn(nft: NftId, grant_shreds: Vec<GrantShredAuth>) -> StorageTxV3 {
    if grant_shreds.is_empty() {
        StorageTxV3::BurnReference { nft }
    } else {
        StorageTxV3::SocialDelete { nft, grant_shreds }
    }
}

/// Parameters used to seal and build an unlinkable `bud storage grant` row.
pub struct CliGrantRequest<'a> {
    pub nft_id: NftId,
    pub grant_nonce: [u8; 32],
    pub one_time_pk: Vec<u8>,
    pub object: ObjectKey,
    pub content_key: &'a ContentKey,
    pub grantee_hpke_public: &'a [u8],
}

/// Build an unlinkable `bud storage grant` (`StorageTxV3::IssueViewGrant`).
/// exposed for `bud storage grant` CLI command.
///
/// # Errors
///
/// Returns [`CliBud3Error`] if X-Wing sealing or grant validation fails.
pub fn cli_storage_grant(
    req: CliGrantRequest<'_>,
    expires_at_epoch: u64,
    current_epoch: u64,
) -> Result<(GrantRow, StorageTxV3), CliBud3Error> {
    let tag = compute_grant_tag(&req.nft_id, &req.grant_nonce);
    let sealed = seal_key_package(
        req.grantee_hpke_public,
        &tag,
        &req.object,
        req.content_key,
    )
    .map_err(CliBud3Error::KeyPackage)?;
    let row = build_grant_row(
        &req.nft_id,
        &req.grant_nonce,
        req.one_time_pk,
        sealed,
        expires_at_epoch,
        current_epoch,
    )
    .map_err(CliBud3Error::Grant)?;
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
        hash_fields_bytes(&[DOMAIN_CLI_ALIAS, env_label, address.as_bytes()])
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
        let digest = hash_fields_bytes(&[
            DOMAIN_CLI_FAUCET_POW,
            challenge_seed,
            address.as_bytes(),
            &nonce.to_le_bytes(),
        ]);
        if leading_zero_bits(&digest) >= difficulty_bits {
            return Ok((nonce, digest));
        }
    }
    Err(CliBud3Error::PowExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::bud3::limits::Bud3Limits;
    use crate::storage::bud3::tx::apply as apply_bud3_tx;
    use crate::storage::bud3::view::MemorySymbolNetwork;

    const P: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };

    #[test]
    fn cli_storage_upload_view_round_trip() {
        let mut sessions = UploadSessionManager::new(Bud3Limits::default());
        let mut bud3 = Bud3Registry::default();

        let uploader = [0x42; 32];
        let payload = b"bud cli streaming upload and view round trip".repeat(8);
        let candidates: Vec<Candidate> = (0..4u8)
            .map(|i| Candidate {
                validator: [10 + i; 32],
                account: [10 + i; 32],
                class: Class::Full,
                stake: 5_000,
                free_quota_bytes: u64::MAX,
                network: None,
            })
            .collect();
        let row = PlacementRow {
            n_full: 2,
            s_full: 6,
            n_mobile: 0,
            s_mobile: 0,
        };

        let finished = cli_storage_upload(
            &mut sessions,
            &bud3,
            &CliUploadParams {
                uploader,
                signing_chain_id: 45261,
                chunk_size: 199,
                profile: P,
                lifetime_epochs: 20,
                now_secs: 100,
            },
            &payload,
            &row,
            &candidates,
        )
        .unwrap();

        let key = finished.record.commitment;
        let nft_id = [0x88; 32];
        let shares = match &finished.unsigned_tx {
            StorageTxV3::RegisterObject { shares, .. } => shares.clone(),
            _ => panic!("expected RegisterObject"),
        };
        let mut net = MemorySymbolNetwork::default();
        for (seg_idx, sh) in &shares {
            let seg_syms = &finished.segments[usize::try_from(*seg_idx).unwrap()];
            let start = usize::try_from(sh.first_esi).unwrap();
            let end = start + usize::try_from(sh.symbols).unwrap();
            for sym in &seg_syms[start..end] {
                net.insert(sh.validator, key, sym.clone());
            }
        }

        apply_bud3_tx(&mut bud3, uploader, finished.unsigned_tx, 1).unwrap();
        bud3.bind_nft(nft_id, uploader, &key).unwrap();

        let viewed = cli_storage_view(&bud3, &net, &key, Some(nft_id), None, None).unwrap();
        assert_eq!(viewed, payload);
    }

    #[test]
    fn cli_validator_register_mobile_class() {
        let addr = Address([0x19; 32]);
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
        let addr = Address([0x77; 32]);
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
