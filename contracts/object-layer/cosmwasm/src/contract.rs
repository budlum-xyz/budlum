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
    entry_point, from_json, Binary, DepsMut, Env, Event, MessageInfo, Response, StdError,
    StdResult, Uint128,
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
pub struct InstantiateMsg {}

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

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    if !info.funds.is_empty() {
        return Err(StdError::generic_err("no funds at instantiate"));
    }
    LAST_ACCEPTED_HEIGHT.save(deps.storage, &0)?;
    LAST_ACCEPTED_AT.save(deps.storage, &env.block.time.seconds())?;
    Ok(Response::new())
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
        ExecuteMsg::AcceptHeader { height } => {
            if height <= LAST_ACCEPTED_HEIGHT.load(deps.storage)? {
                return Err(StdError::generic_err("not newer"));
            }
            if !verifier::height_final(height) {
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
}
