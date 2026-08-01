//! Every path that moves value without consensus is named here, and refuses
//! on mainnet.
//!
//! B38. Two methods on `ChainHandle` credited accounts with no signature, no
//! nonce, no proof and no supply accounting:
//!
//! ```text
//! ChainHandle::add_balance(addr, amount)   -> state.add_balance, saturating
//! ChainHandle::init_genesis_account(addr)  -> balance = GENESIS_BALANCE (1e9)
//! ```
//!
//! The second is the worse of the two, and its name is why it survived
//! review. "init_genesis_account" describes a moment in the chain's life, and
//! the body checked nothing about that moment: no height, no network, no
//! genesis flag. Measured against the body as it stood:
//!
//! ```text
//! height          0  -> 1,000,000,000
//! height 10,000,000  -> 1,000,000,000
//! spend down to 5, call again -> 1,000,000,000
//! ```
//!
//! It does not stack on a single address, so it is not a mint loop. It is an
//! unlimited refill: any address returns to 1e9 as often as it is drained, and
//! a fresh address arrives already funded. `BUD_TOTAL_SUPPLY` is 1e14, so
//! about a hundred thousand calls exceed the entire supply, while
//! `nonzero_block_reward_config_cannot_mint` and its neighbours go on
//! asserting that no path can mint.
//!
//! Nothing in production called either one. That is the same shape as B27:
//! the hazard is not what runs today, it is what the next person wires up
//! after reading a name that promises genesis and a signature that accepts
//! any address at any height.
//!
//! They are gated rather than deleted, because devnet and the RPC tests do
//! need funded accounts. The gate is the chain id, matching
//! `mainnet_requires_signed_remote_snapshot`, which is how this tree already
//! asks the question.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::account::GENESIS_BALANCE;
use crate::core::address::Address;
use crate::core::chain_config::Network;
use std::sync::Arc;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

/// Same shape the rest of the suite uses (`block_reward.rs::fresh_chain`).
/// 45262 is the devnet chain id, deliberately not mainnet.
fn devnet_chain() -> Blockchain {
    Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None)
}

fn mainnet_chain() -> Blockchain {
    let mut bc = devnet_chain();
    bc.chain_id = Network::Mainnet.chain_id().value();
    bc
}

/// A mainnet chain refuses the faucet.
#[test]
fn the_faucet_refuses_on_mainnet() {
    let mut bc = mainnet_chain();

    let err = bc
        .fund_development_account(&addr(1))
        .expect_err("mainnet must refuse a faucet top-up");
    assert!(
        err.contains("mainnet"),
        "the refusal should say which chain refused: {err}"
    );
    assert_eq!(
        bc.state.get_balance(&addr(1)),
        0,
        "a refused faucet call must not move a single unit"
    );
}

/// A mainnet chain refuses an out-of-consensus credit.
#[test]
fn the_out_of_consensus_credit_refuses_on_mainnet() {
    let mut bc = mainnet_chain();

    let err = bc
        .credit_development_account(&addr(2), 5_000)
        .expect_err("mainnet must refuse an unsigned credit");
    assert!(
        err.contains("consensus"),
        "the refusal should say what is being bypassed: {err}"
    );
    assert_eq!(bc.state.get_balance(&addr(2)), 0);
}

/// The canary. If the gate were inverted or the chain id comparison were
/// wrong, the two tests above would still pass on a chain that refuses
/// everything. This proves the development chain is still served.
#[test]
fn a_development_chain_still_gets_funded() {
    let mut bc = devnet_chain();
    assert_ne!(
        bc.chain_id,
        Network::Mainnet.chain_id().value(),
        "the test fixture must not be a mainnet chain, or this canary proves nothing"
    );

    bc.fund_development_account(&addr(3))
        .expect("a devnet chain must still be able to fund an account");
    assert_eq!(bc.state.get_balance(&addr(3)), GENESIS_BALANCE);

    bc.credit_development_account(&addr(4), 777)
        .expect("a devnet chain must still be able to credit an account");
    assert_eq!(bc.state.get_balance(&addr(4)), 777);
}

/// The refill behaviour that made this worth gating, pinned on devnet so the
/// finding stays legible: the faucet is not a mint loop, it is a refill.
#[test]
fn the_faucet_refills_rather_than_stacking() {
    let mut bc = devnet_chain();
    let a = addr(5);

    bc.fund_development_account(&a).expect("devnet");
    let first = bc.state.get_balance(&a);
    bc.fund_development_account(&a).expect("devnet");
    let second = bc.state.get_balance(&a);
    assert_eq!(
        first, second,
        "two calls must not stack, or this is a mint loop and gating is not enough"
    );

    // A second address arrives already funded, which is the other half of
    // "unlimited": the supply cost is per address, and addresses are free.
    let b = addr(6);
    assert_eq!(bc.state.get_balance(&b), 0);
    bc.fund_development_account(&b).expect("devnet");
    assert_eq!(
        bc.state.get_balance(&b),
        GENESIS_BALANCE,
        "every fresh address can be funded, so the cost to an attacker is \
         one address, not one chain"
    );
}

/// No production path may call either method.
///
/// The gate above bounds the damage on mainnet. This bounds it everywhere
/// else: if a future change wires the faucet into block production, the RPC
/// surface or the relayer, the count moves and this fails by name.
///
/// Scanned as source rather than by call graph, because the point is to catch
/// a new call site the moment it is written, before it has behaviour to test.
#[test]
fn nothing_outside_tests_calls_the_out_of_consensus_paths() {
    let sources: [(&str, &str); 6] = [
        ("chain/blockchain.rs", include_str!("../chain/blockchain.rs")),
        ("chain/chain_actor.rs", include_str!("../chain/chain_actor.rs")),
        ("rpc/server.rs", include_str!("../rpc/server.rs")),
        ("execution/executor.rs", include_str!("../execution/executor.rs")),
        ("relayer/worker.rs", include_str!("../relayer/worker.rs")),
        ("network/node.rs", include_str!("../network/node.rs")),
    ];

    for (name, src) in sources {
        // Cut at the LAST `#[cfg(test)]`, not the first.
        //
        // Splitting on the first was the initial version of this test and it
        // was vacuous: `blockchain.rs` carries a `#[cfg(test)]` attribute at
        // character 2437 of 278364, so 99% of the file, including the
        // definitions this test is about, was thrown away before counting.
        // The test reported `calls=0 allowed=0` for a file that contains both
        // methods, and would have gone on reporting that no matter what was
        // added.
        //
        // The last occurrence is the trailing test module in this tree's
        // layout. Comments are stripped too, so a doc comment describing the
        // hazard is not counted as the hazard.
        let cut = src.rfind("#[cfg(test)]").unwrap_or(src.len());
        let code = &src[..cut];
        let stripped: String = code
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//") && !t.starts_with("/*") && !t.starts_with('*')
            })
            .collect::<Vec<_>>()
            .join("\n");

        // A cut that discards most of the file would make the count
        // meaningless, which is exactly how this test failed the first time.
        assert!(
            code.len() * 2 > src.len(),
            "{name}: the production slice is {} of {} bytes. The `#[cfg(test)]` \
             cut is throwing away most of the file, so the counts below would \
             prove nothing.",
            code.len(),
            src.len()
        );

        for hazard in ["fund_development_account", "credit_development_account"] {
            let calls = stripped.matches(&format!("{hazard}(")).count();
            let defs = stripped.matches(&format!("fn {hazard}(")).count();
            // The definition, and in chain_actor the one dispatch arm that
            // forwards the command, are the only permitted mentions.
            let allowance = defs + usize::from(name == "chain/chain_actor.rs");
            assert!(
                calls <= allowance,
                "{name}: `{hazard}` has {calls} mentions against {allowance} allowed. \
                 A production caller was added. That path credits an account without \
                 a signature, a nonce or a proof; if it is genuinely needed, it needs \
                 a reviewed reason here, not a silent extra call site."
            );
        }
    }
}

/// The canary for the scan above: it has to be able to fail.
///
/// A scan that reports "no offenders" is worth nothing until it has been shown
/// to notice one, and this is the specific mistake the tree has made before,
/// a gate counting matches in a file it never actually read.
#[test]
fn the_production_call_scan_can_detect_a_call() {
    let fixture = "fn somewhere() {\n    chain.fund_development_account(&addr);\n}\n";
    let calls = fixture.matches("fund_development_account(").count();
    assert_eq!(
        calls, 1,
        "the counting rule used by the scan above must see a plain call site"
    );

    let commented = "// chain.fund_development_account(&addr);\n";
    let stripped: String = commented
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        stripped.matches("fund_development_account(").count(),
        0,
        "and it must not count a commented-out mention"
    );
}
