// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {AppBindingExecutor, BudlumAppBindingClaimer} from "../app_binding/AppBindingExecutor.sol";
import {
    BudlumPaymentReceiver,
    GlobalHeader,
    AppBindingPayment,
    IBudlumFinality,
    PaymentProof
} from "../app_binding/BudlumPaymentReceiver.sol";
import {BudlumRemoteAccountFactory} from "../app_binding/BudlumRemoteAccountFactory.sol";

contract Counter {
    uint256 public count;

    function bump() external payable {
        count += 1;
    }

    function fail() external pure {
        revert("no");
    }
}

contract ClaimingApp is BudlumAppBindingClaimer {
    function claim(uint32 domainKey, bytes32 payout) external {
        _claimBudlumPayout(domainKey, payout);
    }
}

contract FinalityStub is IBudlumFinality {
    mapping(uint64 => bytes32) public roots;
    uint64 public latestFinalHeight;

    function set(uint64 height, bytes32 root) external {
        roots[height] = root;
        if (root != bytes32(0) && height > latestFinalHeight) {
            latestFinalHeight = height;
        }
    }

    function rootAtHeight(uint64 height) external view returns (bytes32) {
        return roots[height];
    }

    function heightFinal(uint64 height) external view returns (bool) {
        return roots[height] != bytes32(0);
    }
}

contract Receiver is BudlumPaymentReceiver {
    constructor(IBudlumFinality finality_, bytes32 appId_) BudlumPaymentReceiver(finality_, appId_) {}

    function consume(PaymentProof calldata proof) external returns (uint64) {
        return _consumePayment(proof).amount;
    }
}

/// A second account that fulfils through the executor: the per-account guard
/// must let it through even after the test contract has used its own slot.
contract Filler {
    function bind(AppBindingExecutor executor, bytes32 solver) external {
        executor.registerSolverKey(solver);
    }

    function run(AppBindingExecutor executor, bytes32 intent, address target) external {
        executor.execute(intent, target, abi.encodeCall(Counter.bump, ()), hex"01");
    }
}

/// An account that binds somebody else's solver key and fulfils with its own
/// harmless call: the griefing move the per-account slot has to absorb.
contract Attacker {
    function bind(AppBindingExecutor executor, bytes32 solver) external {
        executor.registerSolverKey(solver);
    }

    function run(AppBindingExecutor executor, bytes32 intent, address target) external {
        executor.execute(intent, target, abi.encodeCall(Counter.bump, ()), hex"01");
    }
}

contract AppBindingTest is Harness {
    AppBindingExecutor internal executor;
    Counter internal counter;

    bytes32 internal constant SOLVER = bytes32(uint256(1));

    function setUp() public {
        executor = new AppBindingExecutor();
        counter = new Counter();
        executor.registerSolverKey(SOLVER);
    }

    /// Same values as `event_payload_hashes_match_the_solidity_known_answers`
    /// in src/settlement/app_binding.rs.
    function test_payload_hashes_match_the_rust_known_answers() public {
        bytes memory beneficiary = new bytes(20);
        for (uint256 i = 0; i < 20; i++) {
            beneficiary[i] = 0x44;
        }
        bytes32 fulfilledHash = executor.fulfilledPayloadHash(
            bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111)),
            address(0x2222222222222222222222222222222222222222),
            bytes32(uint256(0x3333333333333333333333333333333333333333333333333333333333333333)),
            7,
            beneficiary,
            bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555))
        );
        assertEq(
            fulfilledHash,
            0x6adf4090bb15ec7ee9af78d320f48e22c0eb09b68dd2a3a4ea36db9eeb0c5097,
            "fulfilled payload hash"
        );
        ClaimingApp app = new ClaimingApp();
        assertEq(
            app.claimPayloadHash(
                bytes32(uint256(0x6666666666666666666666666666666666666666666666666666666666666666)),
                bytes32(uint256(0x7777777777777777777777777777777777777777777777777777777777777777))
            ),
            0xdf19fce601b54d83b5233db52f5c9d767af6e434f4839e9382aeae049349d7c1,
            "claim payload hash"
        );
    }

    function test_an_intent_is_fulfilled_once() public {
        bytes32 intent = keccak256("intent");
        executor.execute(intent, address(counter), abi.encodeCall(Counter.bump, ()), hex"01");
        assertEq(counter.count(), 1, "the call was made");
        assertTrue(executor.fulfilled(intent, address(this)), "the caller's own slot is used");
        vm.expectPartialRevert(AppBindingExecutor.AlreadyFulfilled.selector);
        executor.execute(intent, address(counter), abi.encodeCall(Counter.bump, ()), hex"01");
    }

    /// The once-per-intent guard is per executing account: a second account
    /// cannot burn the id, and cannot be blocked by the first account either.
    function test_the_once_per_intent_guard_is_per_account() public {
        bytes32 intent = keccak256("contested-intent");
        executor.execute(intent, address(counter), abi.encodeCall(Counter.bump, ()), hex"01");
        assertTrue(executor.fulfilled(intent, address(this)), "the caller's slot is used");
        assertEq(counter.count(), 1, "the call was made");

        // Another account still gets to fulfil the same intent: the first
        // one cannot burn the id for everyone.
        Filler filler = new Filler();
        filler.bind(executor, bytes32(uint256(2)));
        filler.run(executor, intent, address(counter));
        assertTrue(executor.fulfilled(intent, address(filler)), "the other account's slot was free");
        assertEq(counter.count(), 2, "the second call was made too");
    }

    /// Binding somebody else's Budlum key no longer spends that solver's slot.
    ///
    /// `registerSolverKey` is permissionless and proves nothing, so an attacker
    /// could bind the awarded solver's address and `execute` the intent with its
    /// own target: the awarded solver then reverted `AlreadyFulfilled` forever,
    /// could never emit the event the settlement door requires, and the
    /// deadline handed anyone the liveness slash of its bond. The slot is the
    /// executing account's now, so the griefing move buys nothing.
    function test_binding_another_solvers_key_cannot_burn_its_slot() public {
        bytes32 intent = keccak256("griefed-intent");
        Attacker attacker = new Attacker();

        // The attacker names the awarded solver and fulfils with a harmless call.
        attacker.bind(executor, SOLVER);
        attacker.run(executor, intent, address(counter));
        assertEq(counter.count(), 1, "the attacker's call went through");

        // The real solver is not blocked: the intent is theirs to fulfil, and
        // their event still carries their own key.
        executor.execute(intent, address(counter), abi.encodeCall(Counter.bump, ()), hex"01");
        assertEq(counter.count(), 2, "the awarded solver still fulfils the intent");
        assertTrue(executor.fulfilled(intent, address(this)), "the solver's own slot is used");
        assertTrue(executor.fulfilled(intent, address(attacker)), "and the attacker only spent its own");
    }

    /// A fulfilment names the solver the executing account bound, never one the
    /// caller chose for this call. The executor cannot authenticate a Budlum
    /// address, so it must not accept one it was merely told about.
    function test_an_unbound_account_cannot_fulfil() public {
        Filler stranger = new Filler();
        vm.expectPartialRevert(AppBindingExecutor.SolverKeyNotBound.selector);
        stranger.run(executor, keccak256("unbound"), address(counter));
        assertEq(counter.count(), 0, "no call was made");
    }

    /// The binding is immutable, so one account cannot re-point its
    /// fulfilments at another solver's address after the fact.
    function test_a_solver_key_cannot_be_repointed() public {
        assertEq(executor.solverKey(address(this)), SOLVER, "the binding is in place");
        vm.expectPartialRevert(AppBindingExecutor.SolverKeyAlreadyBound.selector);
        executor.registerSolverKey(bytes32(uint256(3)));
        assertEq(executor.solverKey(address(this)), SOLVER, "the binding did not move");
    }

    /// A zero binding would name no solver at all, so it is refused rather than
    /// treated as an unbound account that later cannot be bound.
    function test_a_zero_solver_key_is_refused() public {
        Filler filler = new Filler();
        vm.expectPartialRevert(AppBindingExecutor.SolverKeyIsZero.selector);
        filler.bind(executor, bytes32(0));
    }

    /// The payload hash the settlement door checks commits to the bound
    /// solver, and the slot `execute` spends is the executing account's.
    function test_the_payload_hash_commits_to_the_bound_solver() public {
        bytes32 intent = keccak256("bound-solver-intent");
        bytes32 callHash = keccak256(abi.encodeCall(Counter.bump, ()));
        assertTrue(
            executor.fulfilledPayloadHash(intent, address(counter), callHash, 0, hex"01", SOLVER)
                != executor.fulfilledPayloadHash(
                    intent, address(counter), callHash, 0, hex"01", bytes32(uint256(2))
                ),
            "the payload hash commits to the solver"
        );
        executor.execute(intent, address(counter), abi.encodeCall(Counter.bump, ()), hex"01");
        assertTrue(executor.fulfilled(intent, address(this)), "the executor's own slot is the one used");
        assertEq(executor.solverKey(address(this)), SOLVER, "and the event names the bound solver");
    }

    function test_a_call_to_an_address_with_no_code_is_refused() public {
        vm.expectPartialRevert(AppBindingExecutor.CallFailed.selector);
        executor.execute(keccak256("no-code"), address(0xdead), hex"", hex"01");
    }

    function test_a_failed_call_emits_nothing_and_reverts() public {
        vm.expectPartialRevert(AppBindingExecutor.CallFailed.selector);
        executor.execute(
            keccak256("intent"), address(counter), abi.encodeCall(Counter.fail, ()), hex"01"
        );
        assertTrue(!executor.fulfilled(keccak256("intent"), address(this)), "not marked fulfilled");
    }

    function _proof(Receiver receiver, FinalityStub finality, bytes32 appId)
        internal
        returns (PaymentProof memory proof)
    {
        proof.payment = AppBindingPayment(
            keccak256("payment"),
            appId,
            bytes32(uint256(9)),
            bytes32(uint256(10)),
            500,
            hex"aa",
            bytes32(0),
            3,
            uint64(block.chainid),
            abi.encodePacked(address(receiver))
        );
        proof.index = 0;
        proof.path = new bytes32[](0);
        proof.paymentsRoot = receiver.paymentLeaf(proof.payment);
        proof.restHash = keccak256("rest");
        proof.header.version = 8;
        proof.header.timestampMs = uint128(block.timestamp) * 1000;
        proof.header.checkpointHeight = 20;
        proof.header.hasAppBindingRoot = true;
        proof.header.appBindingRoot = receiver.appBindingRegistryRoot(proof.paymentsRoot, proof.restHash);
        proof.stateRootBody = keccak256("body");
        finality.set(20, receiver.stateRootFromOpening(proof.stateRootBody, receiver.headerHash(proof.header)));
    }

    function _word(uint8 value) internal pure returns (bytes32) {
        return bytes32(uint256(value) * (type(uint256).max / 255));
    }

    /// Independent SHA-256/LE-length vectors for the payment leaf, V9 header,
    /// and state-root opening. Prior tests created their trusted state root
    /// with the same Solidity functions under test and could miss a shared
    /// Rust/Solidity encoding mismatch.
    function test_payment_and_v8_header_match_independent_vectors() public {
        Receiver receiver = new Receiver(new FinalityStub(), _word(1));
        AppBindingPayment memory payment = AppBindingPayment(
            _word(0x11),
            _word(0x22),
            _word(0x33),
            _word(0x44),
            500,
            hex"deadbeef",
            _word(0x55),
            123,
            1,
            hex"1111111111111111111111111111111111111111"
        );
        assertEq(
            receiver.paymentLeaf(payment),
            hex"510b31874ed3e3e1a879168ea6bffc8269ae75d7c30c3c4158001878b45abfd9",
            "payment leaf fixture"
        );

        GlobalHeader memory header;
        header.version = 8;
        header.globalHeight = 17;
        header.previousGlobalHash = _word(1);
        header.chainId = 45_261;
        header.timestampMs = 123_456;
        header.domainRegistryRoot = _word(2);
        header.domainCommitmentRoot = _word(3);
        header.messageRoot = _word(4);
        header.bridgeStateRoot = _word(5);
        header.replayNonceRoot = _word(6);
        header.proposer = abi.encodePacked(_word(7));
        header.settlementFinalityRoot = _word(8);
        header.hasStorageRoot = true;
        header.storageRoot = _word(9);
        header.hasIdentityRoot = true;
        header.identityRoot = _word(10);
        header.checkpointHeight = 17;
        header.hasAppBindingRoot = true;
        header.appBindingRoot = _word(11);
        bytes32 headerHash = receiver.headerHash(header);
        assertEq(headerHash, hex"570f166c9fc7b73b4fd2934964752678d7789ce7ece8da2552f7f184becd8151", "V9 header fixture");
        assertEq(
            receiver.stateRootFromOpening(_word(12), headerHash),
            hex"7215039be4c3172fb04d6e331d2c77f62772e0223ed0ed6e53ee642cc426ce84",
            "state root opening fixture"
        );
    }

    function test_a_proven_payment_is_consumed_once() public {
        FinalityStub finality = new FinalityStub();
        bytes32 appId = keccak256("app");
        Receiver receiver = new Receiver(finality, appId);
        PaymentProof memory proof = _proof(receiver, finality, appId);
        assertEq(receiver.consume(proof), 500, "amount");
        vm.expectPartialRevert(BudlumPaymentReceiver.AlreadyConsumed.selector);
        receiver.consume(proof);
    }

    function test_a_payment_under_another_root_is_refused() public {
        FinalityStub finality = new FinalityStub();
        bytes32 appId = keccak256("app");
        Receiver receiver = new Receiver(finality, appId);
        PaymentProof memory proof = _proof(receiver, finality, appId);
        proof.payment.amount = 501;
        vm.expectPartialRevert(BudlumPaymentReceiver.ProofInvalid.selector);
        receiver.consume(proof);
    }

    function test_check_payment_refuses_wrong_app_binding() public {
        FinalityStub finality = new FinalityStub();
        bytes32 appA = keccak256("app-a");
        bytes32 appB = keccak256("app-b");
        Receiver receiver = new Receiver(finality, appA);
        PaymentProof memory proof = _proof(receiver, finality, appB);
        assertEq(keccak256(bytes(receiver.checkPayment(proof))), keccak256("wrong app_binding"), "wrong app_binding refused");
        vm.expectPartialRevert(BudlumPaymentReceiver.WrongAppBinding.selector);
        receiver.consume(proof);
    }

    function test_a_payment_bound_to_another_receiver_is_refused() public {
        FinalityStub finality = new FinalityStub();
        bytes32 appId = keccak256("app");
        Receiver first = new Receiver(finality, appId);
        Receiver second = new Receiver(finality, appId);
        PaymentProof memory proof = _proof(first, finality, appId);
        assertEq(keccak256(bytes(second.checkPayment(proof))), keccak256("receiver binding"), "wrong receiver refused");
        vm.expectPartialRevert(BudlumPaymentReceiver.ProofInvalid.selector);
        second.consume(proof);
    }

    function test_a_stale_payment_proof_is_refused() public {
        FinalityStub finality = new FinalityStub();
        bytes32 appId = keccak256("app");
        Receiver receiver = new Receiver(finality, appId);
        PaymentProof memory proof = _proof(receiver, finality, appId);
        vm.warp(block.timestamp + 30 days + 1);
        assertEq(keccak256(bytes(receiver.checkPayment(proof))), keccak256("proof too old"), "stale proof refused");
        vm.expectPartialRevert(BudlumPaymentReceiver.ProofInvalid.selector);
        receiver.consume(proof);
    }

    function test_proof_refuses_a_rewritten_header_or_payment_path() public {
        FinalityStub finality = new FinalityStub();
        bytes32 appId = keccak256("app");
        Receiver receiver = new Receiver(finality, appId);
        PaymentProof memory changed = _proof(receiver, finality, appId);
        changed.header.hasAiRoot = true;
        assertTrue(
            keccak256(bytes(receiver.checkPayment(changed))) == keccak256("state root opening"),
            "presence-tagged header must be bound to the finalized state root"
        );

        changed = _proof(receiver, finality, appId);
        changed.path = new bytes32[](1);
        changed.path[0] = bytes32(uint256(77));
        assertTrue(
            keccak256(bytes(receiver.checkPayment(changed))) == keccak256("payment path"),
            "invented sibling cannot authenticate a single-payment window"
        );

        changed = _proof(receiver, finality, appId);
        changed.restHash = bytes32(uint256(88));
        assertTrue(
            keccak256(bytes(receiver.checkPayment(changed))) == keccak256("app_binding root opening"),
            "registry opening must match the finalized header"
        );
    }

    function test_remote_accounts_land_at_their_predicted_address() public {
        FinalityStub finality = new FinalityStub();
        BudlumRemoteAccountFactory factory = new BudlumRemoteAccountFactory(finality);
        address predicted = factory.accountAddress(keccak256("app"), bytes32(uint256(9)));
        address deployed = factory.deploy(keccak256("app"), bytes32(uint256(9)));
        assertTrue(predicted == deployed, "CREATE2 address");
    }
}
