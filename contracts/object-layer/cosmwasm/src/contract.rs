//! Budlum settlement endpoint, CosmWasm family.
//!
//! Custody and home calls are closed until departure and escape can return
//! assets. Only finalized checkpoint tracking remains available. Instantiated
//! with no migrate admin:
//! no admin, no upgrade, no pause.
//!
//! Events are `wasm-budlum/object-layer/<name>/v1` with string attributes;
//! the layouts are pinned by `src/object_layer/family/cosmwasm.rs`. CW20
//! and CW721 arrivals come through the standard `Receive` hooks, so the
//! sender of the hook is the token contract itself and the amount is what
//! that contract reports moving to the endpoint.

use crate::verifier;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    entry_point, from_json, to_json_binary, Binary, Deps, DepsMut, Env, Event, MessageInfo,
    Response, StdError, StdResult, Uint128,
};
use cw20::Cw20ReceiveMsg;
use cw_storage_plus::{Item, Map};

/// Standard CW721 `SendNft` hook message (`cosmwasm-std 2` compatible).
#[cw_serde]
pub struct Cw721ReceiveMsg {
    pub sender: String,
    pub token_id: String,
    pub msg: Binary,
}

/// Seconds without a newly accepted checkpoint before the exit opens.
pub const SILENCE_WINDOW_SECS: u64 = 1_209_600;

const LAST_ACCEPTED_HEIGHT: Item<u64> = Item::new("last_accepted_height");
const LAST_ACCEPTED_AT: Item<u64> = Item::new("last_accepted_at");
const HOME_NONCE: Map<&str, u64> = Map::new("home_nonce");

#[cw_serde]
#[derive(Default)]
pub struct InstantiateMsg {
    /// Optional pinned finality committee bound once at instantiation.
    pub committee: Option<verifier::CommitteeConfig>,
}

#[cw_serde]
pub enum ExecuteMsg {
    /// CW20 `Send` hook. `msg` is the JSON `ArriveMsg`.
    Receive(Cw20ReceiveMsg),
    /// CW721 `SendNft` hook. `msg` is the JSON `ArriveMsg`.
    ReceiveNft(Cw721ReceiveMsg),
    /// Budlum runs `calls` (hex of the canonical call list) as the home
    /// identity of `info.sender`.
    HomeCall {
        calls: Binary,
    },
    /// Permissionlessly rotate the finality committee via a `> 2/3` handoff certificate.
    RotateCommittee {
        handoff: verifier::CommitteeHandoffProof,
    },
    /// Verify and record a finalized Budlum checkpoint via signature-format proof.
    RecordCheckpoint {
        height: u64,
        state_root: [u8; 32],
        header_hash: [u8; 32],
        proof: verifier::SignedFinalityProof,
    },
    AcceptHeader {
        height: u64,
    },
    Release {
        proof: Binary,
    },
    Escape {
        proof: Binary,
    },
}

#[cw_serde]
pub struct ArriveMsg {
    /// 64 lower-case hex characters, or `None` to keep the asset with the
    /// depositor's home identity.
    pub recipient: Option<String>,
}

#[cw_serde]
pub enum QueryMsg {
    HeightFinal { height: u64 },
    RootAtHeight { height: u64 },
    LatestFinalHeight {},
    FinalityModeAtHeight { height: u64 },
    AcceptedProofFormat {},
}

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    if !info.funds.is_empty() {
        return Err(StdError::generic_err("no funds at instantiate"));
    }
    LAST_ACCEPTED_HEIGHT.save(deps.storage, &0)?;
    LAST_ACCEPTED_AT.save(deps.storage, &env.block.time.seconds())?;
    if let Some(committee) = msg.committee.as_ref() {
        verifier::initialize_committee(deps.storage, committee)?;
    }
    Ok(Response::new())
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::HeightFinal { height } => {
            to_json_binary(&verifier::height_final(deps.storage, height))
        }
        QueryMsg::RootAtHeight { height } => {
            to_json_binary(&verifier::root_at_height(deps.storage, height))
        }
        QueryMsg::LatestFinalHeight {} => {
            to_json_binary(&verifier::latest_final_height(deps.storage))
        }
        QueryMsg::FinalityModeAtHeight { height } => {
            to_json_binary(&verifier::finality_mode_at_height(deps.storage, height))
        }
        QueryMsg::AcceptedProofFormat {} => to_json_binary(&verifier::accepted_proof_format()),
    }
}

fn recipient(msg: &Binary) -> StdResult<Option<String>> {
    let parsed: ArriveMsg = if msg.is_empty() {
        ArriveMsg { recipient: None }
    } else {
        from_json(msg)?
    };
    if let Some(r) = &parsed.recipient {
        let ok = r.len() == 64
            && r.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            return Err(StdError::generic_err(
                "recipient must be 64 lower-case hex characters",
            ));
        }
    }
    Ok(parsed.recipient)
}

fn arrive_event(
    kind: &str,
    token: &str,
    token_id: Option<&str>,
    amount: Uint128,
    depositor: &str,
    recipient: Option<String>,
) -> Event {
    let mut e = Event::new("budlum/object-layer/arrive/v1")
        .add_attribute("kind", kind)
        .add_attribute("token", token)
        .add_attribute("amount", amount.to_string())
        .add_attribute("depositor", depositor);
    if let Some(id) = token_id {
        e = e.add_attribute("token_id", id);
    }
    if let Some(r) = recipient {
        e = e.add_attribute("recipient", r);
    }
    e
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    if !info.funds.is_empty() {
        return Err(StdError::generic_err("native funds are not taken"));
    }
    // A Receive hook acknowledges a token transfer. With both exit paths
    // closed, acknowledging it would permanently trap CW20/CW721 assets.
    // Direct calls to hooks must not fabricate Arrive events either.
    if matches!(
        &msg,
        ExecuteMsg::Receive(_) | ExecuteMsg::ReceiveNft(_) | ExecuteMsg::HomeCall { .. }
    ) {
        return Err(StdError::generic_err(
            "not open: object-layer arrival and exit proofs",
        ));
    }
    match msg {
        ExecuteMsg::Receive(r) => {
            if r.amount.is_zero() {
                return Err(StdError::generic_err("nothing received"));
            }
            let to = recipient(&r.msg)?;
            // `info.sender` is the CW20 contract: the hook is only callable
            // by the token that moved the balance.
            Ok(Response::new().add_event(arrive_event(
                "fungible",
                info.sender.as_str(),
                None,
                r.amount,
                &r.sender,
                to,
            )))
        }
        ExecuteMsg::ReceiveNft(r) => {
            let to = recipient(&r.msg)?;
            if r.token_id.is_empty() || r.token_id.len() > 256 {
                return Err(StdError::generic_err("token_id length"));
            }
            Ok(Response::new().add_event(arrive_event(
                "unique",
                info.sender.as_str(),
                Some(&r.token_id),
                Uint128::one(),
                &r.sender,
                to,
            )))
        }
        ExecuteMsg::HomeCall { calls } => {
            let sender = info.sender.as_str();
            let nonce = HOME_NONCE.may_load(deps.storage, sender)?.unwrap_or(0);
            HOME_NONCE.save(deps.storage, sender, &(nonce + 1))?;
            Ok(Response::new().add_event(
                Event::new("budlum/object-layer/call/v1")
                    .add_attribute("sender", sender)
                    .add_attribute("nonce", nonce.to_string())
                    .add_attribute("calls", hex::encode(calls.as_slice())),
            ))
        }
        ExecuteMsg::RotateCommittee { handoff } => {
            let new_epoch = verifier::rotate_committee(deps.storage, deps.api, &handoff)?;
            Ok(Response::new()
                .add_attribute("action", "rotate_committee")
                .add_attribute("epoch", new_epoch.to_string()))
        }
        ExecuteMsg::RecordCheckpoint {
            height,
            state_root,
            header_hash,
            proof,
        } => {
            verifier::record(
                deps.storage,
                deps.api,
                height,
                state_root,
                header_hash,
                &proof,
            )?;
            Ok(Response::new()
                .add_attribute("action", "record_checkpoint")
                .add_attribute("height", height.to_string()))
        }
        ExecuteMsg::AcceptHeader { height } => {
            if height <= LAST_ACCEPTED_HEIGHT.load(deps.storage)? {
                return Err(StdError::generic_err("not newer"));
            }
            if !verifier::height_final(deps.storage, height) {
                return Err(StdError::generic_err("not final"));
            }
            LAST_ACCEPTED_HEIGHT.save(deps.storage, &height)?;
            LAST_ACCEPTED_AT.save(deps.storage, &env.block.time.seconds())?;
            Ok(Response::new())
        }
        // Both need an opening of the object-layer root in an accepted
        // Budlum header.
        ExecuteMsg::Release { .. } | ExecuteMsg::Escape { .. } => Err(StdError::generic_err(
            "not open: needs the object-layer root opening",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::Addr;

    #[test]
    fn custody_and_home_calls_stay_closed_without_exit_proofs() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&Addr::unchecked("token"), &[]);
        for msg in [
            ExecuteMsg::Receive(Cw20ReceiveMsg {
                sender: "owner".into(),
                amount: Uint128::new(10),
                msg: Binary::default(),
            }),
            ExecuteMsg::ReceiveNft(Cw721ReceiveMsg {
                sender: "owner".into(),
                token_id: "unique-1".into(),
                msg: Binary::default(),
            }),
            ExecuteMsg::HomeCall {
                calls: Binary::default(),
            },
        ] {
            let err = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap_err();
            assert!(err.to_string().contains("not open"), "{err}");
        }
        assert!(HOME_NONCE
            .may_load(&deps.storage, "token")
            .unwrap()
            .is_none());
    }

    #[test]
    fn instantiate_record_query_and_accept_header_enforce_quorum_on_replays() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&Addr::unchecked("relayer"), &[]);
        let pks = [
            "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
            "204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c21",
            "66cd608b928b88e50e0efeaa33faf1c43cefe07294b0b87e9fe0aba6a3cf7633",
            "20828bf5c5bdcacb684863336c202fb5599da48be5596615742170705beca9f7",
        ];
        let sigs = [
            "1376dada0ff884f37eba41a2f4be9d3a1df740abd4dc494422eb6202dec9a8b4da90327a59bfe0d366ffd3b33d26ef2cc03b7b08b5e3b7073b601e5146c47804",
            "a5a778aad6a12dd0016361aafe9050fb5b1aad1bac6a0a317ef5bdda2f89be426deb088c24a723152347670fcd0f7f89c261237bf6a6b81eb10f282526dd0e0a",
            "978eeb5b57ef4121f333ac4890607319d38551e1b493ff25beac307e73fc81683897a96beba2e615c08edfea3292eaeb195f05df5e57dc39148be3c75a5d900a",
        ];
        let committee = verifier::CommitteeConfig {
            budlum_chain_id: 1,
            epoch: 7,
            threshold: 3,
            members: pks
                .iter()
                .map(|h| Binary::from(hex::decode(h).unwrap()))
                .collect(),
        };
        instantiate(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            InstantiateMsg {
                committee: Some(committee),
            },
        )
        .unwrap();

        let proof = verifier::SignedFinalityProof {
            chain_id: 1,
            epoch: 7,
            mode: verifier::FinalityMode::Hybrid,
            signatures: sigs
                .iter()
                .enumerate()
                .map(|(i, s)| verifier::SignerSignature {
                    signer_index: i as u32,
                    signature: Binary::from(hex::decode(s).unwrap()),
                })
                .collect(),
        };
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::RecordCheckpoint {
                height: 42,
                state_root: [0x42; 32],
                header_hash: [0x99; 32],
                proof,
            },
        )
        .unwrap();

        let is_final: bool = from_json(
            query(
                deps.as_ref(),
                env.clone(),
                QueryMsg::HeightFinal { height: 42 },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(is_final);
        let root: [u8; 32] = from_json(
            query(
                deps.as_ref(),
                env.clone(),
                QueryMsg::RootAtHeight { height: 42 },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(root, [0x42; 32]);
        let latest: u64 =
            from_json(query(deps.as_ref(), env.clone(), QueryMsg::LatestFinalHeight {}).unwrap())
                .unwrap();
        assert_eq!(latest, 42);
        let mode: verifier::FinalityMode = from_json(
            query(
                deps.as_ref(),
                env.clone(),
                QueryMsg::FinalityModeAtHeight { height: 42 },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(mode, verifier::FinalityMode::Hybrid);

        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::AcceptHeader { height: 42 },
        )
        .unwrap();

        // Unauthenticated RecordCheckpoint replay must not emit a valid response.
        let unauth_err = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::RecordCheckpoint {
                height: 42,
                state_root: [0x42; 32],
                header_hash: [0x99; 32],
                proof: verifier::SignedFinalityProof {
                    chain_id: 1,
                    epoch: 7,
                    mode: verifier::FinalityMode::Hybrid,
                    signatures: Vec::new(),
                },
            },
        )
        .unwrap_err();
        assert!(
            unauth_err.to_string().contains("insufficient quorum"),
            "{unauth_err}"
        );
    }
}
