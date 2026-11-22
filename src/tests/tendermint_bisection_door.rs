//! Door tests for the production multi-step ICS-07 bisection anchor-rotation
//! surface: `IntakeState::rotate_tendermint_anchor_bisection`.
//!
//! RED -> GREEN (GOREV-146; reconstruction of commit `502ffc84`, which the
//! 2026-11-22 sandbox reset destroyed before it could be pushed): these seven
//! tests were the red half first — the method did not exist — and
//! `intake.rs::rotate_tendermint_anchor_bisection` is the green half. The
//! bisection machinery itself (`tendermint_bisection::verify_bisection`,
//! GOREV-07) predates this change; what lands here is its production wiring
//! plus the fail-closed gates around it.
//!
//! Every test that can leave the pin behind asserts the pin is bit-identical
//! afterwards: a refused rotation must not move the anchor a millimetre.

use crate::cross_domain::external::intake::{IntakeError, IntakeState};
use crate::cross_domain::external::registry::RegistryError;
use crate::cross_domain::external::spec::AdapterError;
use crate::cross_domain::external::tendermint::{
    validator_address_of, validator_set_commitment, validator_set_hash, vote_sign_bytes,
    PinnedTendermintAnchor, TendermintCommitEvidence, TendermintLightParams, TendermintSignature,
    TendermintValidator, TrustedTendermintState, MAX_BISECTION_STEPS,
};
use crate::crypto::primitives::KeyPair;
use sha2::{Digest, Sha256};

const CHAIN: &str = "bisection-door-1";
const NET: &str = "bisection-door-net";
const TRUSTING: u64 = 86_400;
const T0: u64 = 1_750_000_000;

fn keys(seeds: &[[u8; 32]]) -> Vec<KeyPair> {
    seeds
        .iter()
        .map(|s| KeyPair::from_seed(s).expect("key"))
        .collect()
}

fn vals(pairs: &[(&KeyPair, u64)]) -> Vec<TendermintValidator> {
    pairs
        .iter()
        .map(|(kp, power)| {
            let pk = kp.public_key_bytes();
            TendermintValidator {
                address: validator_address_of(&pk),
                public_key: pk,
                voting_power: *power,
            }
        })
        .collect()
}

fn params(trusting_period_secs: u64) -> TendermintLightParams {
    let p = TendermintLightParams {
        trusting_period_secs,
        unbonding_period_secs: trusting_period_secs + trusting_period_secs / 2 + 1,
        max_clock_drift_secs: 7_200,
        max_height_drift: crate::cross_domain::external::tendermint::MAX_HEIGHT_DRIFT,
    };
    p.validate().expect("fixture params are valid");
    p
}

fn trusted_state(
    chain_id: &str,
    validators: Vec<TendermintValidator>,
    trusting_period_secs: u64,
) -> TrustedTendermintState {
    let next_validators_hash = validator_set_hash(&validators);
    TrustedTendermintState {
        chain_id: chain_id.to_string(),
        height: 100,
        time_secs: T0,
        trusting_period_secs,
        validators,
        next_validators_hash,
    }
}

fn pin(intake: &mut IntakeState, chain_id: &str, validators: &[TendermintValidator]) {
    intake.pinned_tendermint_anchors.insert(
        NET.to_string(),
        PinnedTendermintAnchor {
            chain_id: chain_id.to_string(),
            validator_set_hash: validator_set_commitment(validators),
        },
    );
}

fn pin_hash(intake: &IntakeState) -> [u8; 32] {
    intake.pinned_tendermint_anchors[NET].validator_set_hash
}

/// Local copy of the private `build_signed_tm_commit` test helper from
/// `tendermint.rs` (it is `fn`-private to that module; the door tests build
/// the same commits through the same construction so the byte-level signing
/// path under test is unchanged).
fn build_signed_tm_commit(
    chain_id: &str,
    height: u64,
    commit_time: u64,
    app_hash: [u8; 32],
    next_validators_hash: [u8; 32],
    val_keys: &[(&KeyPair, u64)],
    signer_positions: &[usize],
) -> TendermintCommitEvidence {
    let validators = vals(val_keys);
    let validators_hash = validator_set_hash(&validators);
    let proposer_address = validators[0].address;
    let parts_hash = Sha256::digest(app_hash).into();
    let mut commit = TendermintCommitEvidence {
        chain_id: chain_id.to_string(),
        height,
        round: 0,
        block_hash: [0u8; 32],
        parts_total: 1,
        parts_hash,
        version_block: 11,
        last_block_hash: [0x11; 32],
        last_parts_total: 1,
        last_parts_hash: [0x22; 32],
        last_commit_hash: [0x33; 32],
        data_hash: [0x44; 32],
        validators_hash,
        next_validators_hash,
        consensus_hash: [0x66; 32],
        app_hash,
        last_results_hash: [0x88; 32],
        evidence_hash: [0xaa; 32],
        proposer_address,
        commit_time,
        commit_time_nanos: 0,
        validators,
        signatures: Vec::new(),
    };
    commit.block_hash = commit.header_hash();
    let ts_i64 = i64::try_from(commit_time).expect("ts");
    commit.signatures = signer_positions
        .iter()
        .map(|&pos| {
            let (kp, _) = val_keys[pos];
            let pk = kp.public_key_bytes();
            let msg = vote_sign_bytes(
                chain_id,
                height,
                0,
                &commit.block_hash,
                1,
                &parts_hash,
                (ts_i64, 0),
            );
            TendermintSignature {
                address: validator_address_of(&pk),
                timestamp_seconds: ts_i64,
                timestamp_nanos: 0,
                signature: kp.sign(&msg).to_vec(),
            }
        })
        .collect();
    commit
}

/// The zero-overlap turnover used across the door tests: `T` -> `W` keeps
/// `t1,t2` (200/400 = 50% > 1/3 of trusted), `W` -> `B` keeps `w1,w2`
/// (200/400 > 1/3 of the staged `W`), while `T` -> `B` directly shares
/// **zero** trusted power and must be refused.
struct Turnover {
    t_keys: Vec<KeyPair>,
    w_keys: Vec<KeyPair>,
    b_keys: Vec<KeyPair>,
}

impl Turnover {
    fn new() -> Self {
        Self {
            t_keys: keys(&[[1; 32], [2; 32], [3; 32], [4; 32]]),
            w_keys: keys(&[[1; 32], [2; 32], [0x21; 32], [0x22; 32]]),
            b_keys: keys(&[[0x21; 32], [0x22; 32], [0x31; 32], [0x32; 32]]),
        }
    }

    fn t_pairs(&self) -> Vec<(&KeyPair, u64)> {
        self.t_keys.iter().map(|k| (k, 100)).collect()
    }

    fn w_pairs(&self) -> Vec<(&KeyPair, u64)> {
        self.w_keys.iter().map(|k| (k, 100)).collect()
    }

    fn b_pairs(&self) -> Vec<(&KeyPair, u64)> {
        self.b_keys.iter().map(|k| (k, 100)).collect()
    }

    fn trusted(&self) -> TrustedTendermintState {
        trusted_state(CHAIN, vals(&self.t_pairs()), TRUSTING)
    }

    /// `W`-set commit at height 150, fully signed (50% trusted overlap).
    fn step_w(&self, next_validators_hash: [u8; 32]) -> TendermintCommitEvidence {
        build_signed_tm_commit(
            CHAIN,
            150,
            T0 + 100,
            [0xA1; 32],
            next_validators_hash,
            &self.w_pairs(),
            &[0, 1, 2, 3],
        )
    }

    /// `B`-set commit at height 300, fully signed (50% overlap with `W`,
    /// zero overlap with `T`).
    fn step_b(&self) -> TendermintCommitEvidence {
        build_signed_tm_commit(
            CHAIN,
            300,
            T0 + 200,
            [0xB1; 32],
            [0x77; 32],
            &self.b_pairs(),
            &[0, 1, 2, 3],
        )
    }
}

#[test]
fn a_multi_step_rotation_refuses_an_unpinned_network() {
    let turn = Turnover::new();
    let mut intake = IntakeState::new();
    let steps = [turn.step_w([0x41; 32])];
    assert!(
        matches!(
            intake.rotate_tendermint_anchor_bisection(
                NET,
                &turn.trusted(),
                params(TRUSTING),
                &steps,
                T0 + 300,
            ),
            Err(IntakeError::CommitteeNotPinned)
        ),
        "an unpinned network must be refused before anything else is read"
    );
}

#[test]
fn a_multi_step_rotation_refuses_chain_id_and_validator_set_mismatches() {
    let turn = Turnover::new();
    let mut intake = IntakeState::new();
    let t_vals = vals(&turn.t_pairs());
    pin(&mut intake, CHAIN, &t_vals);
    let before = pin_hash(&intake);
    let steps = [turn.step_w([0x41; 32])];

    // chain-id mismatch: the pin names `CHAIN`, the checkpoint claims another.
    let wrong_chain = trusted_state("other-chain-9", t_vals.clone(), TRUSTING);
    assert!(
        matches!(
            intake.rotate_tendermint_anchor_bisection(
                NET,
                &wrong_chain,
                params(TRUSTING),
                &steps,
                T0 + 300,
            ),
            Err(IntakeError::CommitteeNotPinned)
        ),
        "a checkpoint from another chain must be refused even when the network is pinned"
    );

    // validator-set mismatch: right chain, wrong trusted validators.
    let wrong_vals = trusted_state(CHAIN, vals(&turn.w_pairs()), TRUSTING);
    assert!(
        matches!(
            intake.rotate_tendermint_anchor_bisection(
                NET,
                &wrong_vals,
                params(TRUSTING),
                &steps,
                T0 + 300,
            ),
            Err(IntakeError::CommitteeNotPinned)
        ),
        "a checkpoint whose validator set is not the pinned commitment must be refused"
    );

    assert_eq!(
        pin_hash(&intake),
        before,
        "refusals leave the pin bit-identical"
    );
}

#[test]
fn a_multi_step_rotation_refuses_light_params_that_widen_the_trusting_period() {
    let turn = Turnover::new();
    let mut intake = IntakeState::new();
    let t_vals = vals(&turn.t_pairs());
    pin(&mut intake, CHAIN, &t_vals);
    let before = pin_hash(&intake);
    let steps = [turn.step_w([0x41; 32])];

    let widened = params(TRUSTING * 2);
    let err = intake
        .rotate_tendermint_anchor_bisection(NET, &turn.trusted(), widened, &steps, T0 + 300)
        .expect_err("light params that widen the trusting period must be refused");
    assert!(
        matches!(
            err,
            IntakeError::Registry(RegistryError::Adapter(AdapterError::ConsensusRule { .. }))
        ),
        "the refusal is a consensus rule, not a silent clamp: {err:?}"
    );
    assert_eq!(
        pin_hash(&intake),
        before,
        "refusals leave the pin bit-identical"
    );
}

#[test]
fn a_multi_step_rotation_refuses_empty_and_oversized_step_lists() {
    let turn = Turnover::new();
    let mut intake = IntakeState::new();
    let t_vals = vals(&turn.t_pairs());
    pin(&mut intake, CHAIN, &t_vals);
    let before = pin_hash(&intake);

    let err = intake
        .rotate_tendermint_anchor_bisection(NET, &turn.trusted(), params(TRUSTING), &[], T0 + 300)
        .expect_err("an empty bisection proves nothing and must be refused");
    assert!(matches!(
        err,
        IntakeError::Registry(RegistryError::Adapter(AdapterError::ConsensusRule { .. }))
    ));

    let one = turn.step_w([0x41; 32]);
    let oversized = vec![one; MAX_BISECTION_STEPS + 1];
    let err = intake
        .rotate_tendermint_anchor_bisection(
            NET,
            &turn.trusted(),
            params(TRUSTING),
            &oversized,
            T0 + 300,
        )
        .expect_err("a step list past MAX_BISECTION_STEPS must be refused");
    assert!(matches!(
        err,
        IntakeError::Registry(RegistryError::Adapter(AdapterError::ConsensusRule { .. }))
    ));
    assert_eq!(
        pin_hash(&intake),
        before,
        "refusals leave the pin bit-identical"
    );
}

#[test]
fn a_direct_zero_overlap_skip_is_refused_but_the_bisection_path_advances_the_pin() {
    let turn = Turnover::new();
    let mut intake = IntakeState::new();
    let t_vals = vals(&turn.t_pairs());
    pin(&mut intake, CHAIN, &t_vals);
    let before = pin_hash(&intake);

    // Direct T -> B: zero trusted overlap, refused on its own.
    let direct = [turn.step_b()];
    assert!(
        matches!(
            intake.rotate_tendermint_anchor_bisection(
                NET,
                &turn.trusted(),
                params(TRUSTING),
                &direct,
                T0 + 300,
            ),
            Err(IntakeError::Registry(RegistryError::Adapter(
                AdapterError::ConsensusRule { .. }
            )))
        ),
        "a direct skip with zero trusted overlap must be refused"
    );
    assert_eq!(
        pin_hash(&intake),
        before,
        "the refused direct path leaves the pin bit-identical"
    );

    // The bisection path T -> W -> B carries > 1/3 overlap on every hop and
    // advances the pin to the final header's committed next set.
    let steps = [
        turn.step_w(validator_set_hash(&vals(&turn.b_pairs()))),
        turn.step_b(),
    ];
    let tip = intake
        .rotate_tendermint_anchor_bisection(
            NET,
            &turn.trusted(),
            params(TRUSTING),
            &steps,
            T0 + 300,
        )
        .expect("the two-hop bisection carries > 1/3 overlap on every hop");
    assert_eq!(tip.height, 300);
    let advanced = tip.next_validators_hash.unwrap_or(tip.validator_set_hash);
    assert_eq!(
        advanced, [0x77; 32],
        "the pin advances to the final header's committed next set"
    );
    assert_ne!(advanced, before, "the pin actually moved off the T anchor");
    assert_eq!(
        pin_hash(&intake),
        advanced,
        "the stored pin is the verified tip"
    );
}

#[test]
fn a_failing_middle_step_leaves_the_pin_untouched() {
    let turn = Turnover::new();
    let mut intake = IntakeState::new();
    let t_vals = vals(&turn.t_pairs());
    pin(&mut intake, CHAIN, &t_vals);
    let before = pin_hash(&intake);

    // Step 2 is signed by only 2 of 4 `B` validators (50% target power): no
    // quorum. The whole bisection must roll back, pin included.
    let bad = build_signed_tm_commit(
        CHAIN,
        300,
        T0 + 200,
        [0xB2; 32],
        [0x77; 32],
        &turn.b_pairs(),
        &[2, 3],
    );
    let steps = [turn.step_w([0x41; 32]), bad, turn.step_b()];
    let err = intake
        .rotate_tendermint_anchor_bisection(
            NET,
            &turn.trusted(),
            params(TRUSTING),
            &steps,
            T0 + 300,
        )
        .expect_err("a bisection with a failing middle step must be refused");
    assert!(matches!(
        err,
        IntakeError::Registry(RegistryError::Adapter(AdapterError::ConsensusRule { .. }))
    ));
    assert_eq!(
        pin_hash(&intake),
        before,
        "a failed bisection leaves the pin bit-identical — no partial advance"
    );
}

#[test]
fn an_expired_trusted_checkpoint_is_refused() {
    let turn = Turnover::new();
    let mut intake = IntakeState::new();
    let t_vals = vals(&turn.t_pairs());
    pin(&mut intake, CHAIN, &t_vals);
    let before = pin_hash(&intake);

    let steps = [turn.step_w([0x41; 32])];
    let err = intake
        .rotate_tendermint_anchor_bisection(
            NET,
            &turn.trusted(),
            params(TRUSTING),
            &steps,
            T0 + TRUSTING + 1,
        )
        .expect_err("a checkpoint older than its trusting period must be refused");
    assert!(
        matches!(
            err,
            IntakeError::Registry(RegistryError::Adapter(AdapterError::Stale { .. }))
        ),
        "expiry is the light client's Stale refusal, fail-closed: {err:?}"
    );
    assert_eq!(
        pin_hash(&intake),
        before,
        "refusals leave the pin bit-identical"
    );
}
