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
import {FinalityMode} from "../external-domain/BudlumFinalityVerifier.sol";
import {BudlumRemoteAccount, BudlumRemoteAccountFactory} from "../app_binding/BudlumRemoteAccountFactory.sol";

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
    mapping(uint64 => FinalityMode) public modes;
    uint64 public latestFinalHeight;

    function set(uint64 height, bytes32 root) external {
        setWithMode(height, root, root == bytes32(0) ? FinalityMode.None : FinalityMode.Hybrid);
    }

    function setWithMode(uint64 height, bytes32 root, FinalityMode mode) public {
        roots[height] = root;
        modes[height] = mode;
        if (root != bytes32(0) && mode != FinalityMode.None && height > latestFinalHeight) {
            latestFinalHeight = height;
        }
    }

    function rootAtHeight(uint64 height) external view returns (bytes32) {
        return roots[height];
    }

    function heightFinal(uint64 height) external view returns (bool) {
        return roots[height] != bytes32(0) && modes[height] != FinalityMode.None;
    }

    function finalityModeAtHeight(uint64 height) external view returns (FinalityMode) {
        return modes[height];
    }
}

contract Receiver is BudlumPaymentReceiver {
    constructor(IBudlumFinality finality_, bytes32 appId_) BudlumPaymentReceiver(finality_, appId_) {}

    function consume(PaymentProof calldata proof) external returns (uint64) {
        return _consumePayment(proof).amount;
    }
}

/// Opt-in consumer that explicitly accepts single-half optimistic finality.
contract OptimisticOptInReceiver is BudlumPaymentReceiver {
    constructor(IBudlumFinality finality_, bytes32 appId_) BudlumPaymentReceiver(finality_, appId_) {}

    function _requiresHybridFinality() internal pure override returns (bool) {
        return false;
    }

    function consume(PaymentProof calldata proof) external returns (uint64) {
        return _consumePayment(proof).amount;
    }
}

/// A second origin-chain account used to prove that only the account named by
/// the finalized award permit can call the executor.
contract Filler {
    function run(AppBindingExecutor executor, bytes32 intent, address target) external {
        executor.execute(intent, target, abi.encodeCall(Counter.bump, ()), hex"01");
    }
}

/// An unawarded account attempting to pre-empt the exact authorized call.
contract Attacker {
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
    }

    function _authorize(
        bytes32 intent,
        address solver,
        bytes32 budlumSolver,
        address target,
        bytes memory data,
        bytes memory beneficiary,
        uint64 value
    ) internal {
        executor.authorizeIntent(intent, solver, budlumSolver, target, keccak256(data), value, keccak256(beneficiary));
    }

    function _authorizeSelf(bytes32 intent, address target, bytes memory data) internal {
        _authorize(intent, address(this), SOLVER, target, data, hex"01", 0);
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
            fulfilledHash, 0x6adf4090bb15ec7ee9af78d320f48e22c0eb09b68dd2a3a4ea36db9eeb0c5097, "fulfilled payload hash"
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
        bytes memory data = abi.encodeCall(Counter.bump, ());
        _authorizeSelf(intent, address(counter), data);
        executor.execute(intent, address(counter), data, hex"01");
        assertEq(counter.count(), 1, "the call was made");
        assertTrue(executor.fulfilled(intent), "the one intent slot is used");
        vm.expectPartialRevert(AppBindingExecutor.AlreadyFulfilled.selector);
        executor.execute(intent, address(counter), data, hex"01");
    }

    /// A random account cannot perform or pre-empt the exact call that the
    /// finalized award assigned to another solver.
    function test_only_the_authorized_solver_can_execute_the_intent() public {
        bytes32 intent = keccak256("contested-intent");
        bytes memory data = abi.encodeCall(Counter.bump, ());
        _authorizeSelf(intent, address(counter), data);
        Attacker attacker = new Attacker();

        vm.expectPartialRevert(AppBindingExecutor.NotAwardedSolver.selector);
        attacker.run(executor, intent, address(counter));
        assertEq(counter.count(), 0, "the unawarded account made no call");
        assertTrue(!executor.fulfilled(intent), "the attacker did not burn the intent");

        executor.execute(intent, address(counter), data, hex"01");
        assertEq(counter.count(), 1, "the awarded solver still fulfils");
        assertTrue(executor.fulfilled(intent), "the intent is now consumed");
    }

    function test_an_intent_without_a_finalized_award_permit_cannot_execute() public {
        vm.expectPartialRevert(AppBindingExecutor.IntentNotAuthorized.selector);
        executor.execute(keccak256("unbound"), address(counter), abi.encodeCall(Counter.bump, ()), hex"01");
        assertEq(counter.count(), 0, "no call was made");
    }

    function test_only_the_deployment_authority_can_mirror_an_award() public {
        bytes32 intent = keccak256("foreign-authority");
        bytes memory data = abi.encodeCall(Counter.bump, ());
        vm.expectPartialRevert(AppBindingExecutor.NotAuthority.selector);
        vm.prank(address(0xBEEF));
        executor.authorizeIntent(
            intent, address(this), SOLVER, address(counter), keccak256(data), 0, keccak256(hex"01")
        );
        assertTrue(!executor.fulfilled(intent), "an unauthorized permit changed nothing");
    }

    function test_an_award_permit_is_immutable() public {
        bytes32 intent = keccak256("immutable-award");
        bytes memory data = abi.encodeCall(Counter.bump, ());
        _authorizeSelf(intent, address(counter), data);
        Filler replacement = new Filler();
        vm.expectPartialRevert(AppBindingExecutor.AlreadyAuthorized.selector);
        _authorize(intent, address(replacement), bytes32(uint256(2)), address(counter), data, hex"01", 0);
    }

    function test_the_exact_call_is_bound_by_the_award_permit() public {
        bytes32 intent = keccak256("exact-call");
        bytes memory data = abi.encodeCall(Counter.bump, ());
        Counter other = new Counter();
        _authorizeSelf(intent, address(counter), data);

        vm.expectPartialRevert(AppBindingExecutor.AuthorizationMismatch.selector);
        executor.execute(intent, address(other), data, hex"01");
        vm.expectPartialRevert(AppBindingExecutor.AuthorizationMismatch.selector);
        executor.execute(intent, address(counter), abi.encodeCall(Counter.fail, ()), hex"01");
        vm.expectPartialRevert(AppBindingExecutor.AuthorizationMismatch.selector);
        executor.execute(intent, address(counter), data, hex"02");
        vm.deal(address(this), 1);
        vm.expectPartialRevert(AppBindingExecutor.AuthorizationMismatch.selector);
        executor.execute{value: 1}(intent, address(counter), data, hex"01");
        assertEq(counter.count(), 0, "a mismatched permit made no call");
        assertEq(other.count(), 0, "a mismatched target made no call");
        assertTrue(!executor.fulfilled(intent), "a mismatch did not consume the intent");
    }

    /// The payload hash checked by settlement commits to the Budlum solver
    /// rooted in the authority's immutable intent permit.
    function test_the_payload_hash_commits_to_the_authorized_solver() public {
        bytes32 intent = keccak256("bound-solver-intent");
        bytes memory data = abi.encodeCall(Counter.bump, ());
        bytes32 callHash = keccak256(data);
        assertTrue(
            executor.fulfilledPayloadHash(intent, address(counter), callHash, 0, hex"01", SOLVER)
                != executor.fulfilledPayloadHash(intent, address(counter), callHash, 0, hex"01", bytes32(uint256(2))),
            "the payload hash commits to the solver"
        );
        _authorizeSelf(intent, address(counter), data);
        executor.execute(intent, address(counter), data, hex"01");
        assertTrue(executor.fulfilled(intent), "the authorized intent slot is used");
    }

    function test_a_call_to_an_address_with_no_code_is_refused() public {
        bytes32 intent = keccak256("no-code");
        _authorizeSelf(intent, address(0xdead), hex"");
        vm.expectPartialRevert(AppBindingExecutor.CallFailed.selector);
        executor.execute(intent, address(0xdead), hex"", hex"01");
    }

    function test_a_failed_call_emits_nothing_and_reverts() public {
        bytes32 intent = keccak256("intent");
        bytes memory data = abi.encodeCall(Counter.fail, ());
        _authorizeSelf(intent, address(counter), data);
        vm.expectPartialRevert(AppBindingExecutor.CallFailed.selector);
        executor.execute(intent, address(counter), data, hex"01");
        assertTrue(!executor.fulfilled(intent), "not marked fulfilled");
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
        assertEq(
            keccak256(bytes(receiver.checkPayment(proof))), keccak256("wrong app_binding"), "wrong app_binding refused"
        );
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
        vm.expectPartialRevert(BudlumRemoteAccountFactory.InvalidAccountParams.selector);
        factory.deploy(keccak256("app"), bytes32(0));
    }

    function test_receiver_and_executor_refuse_zero_version_deep_path_and_self_call() public {
        FinalityStub finality = new FinalityStub();
        bytes32 appId = keccak256("app");
        Receiver receiver = new Receiver(finality, appId);

        PaymentProof memory zeroVer = _proof(receiver, finality, appId);
        zeroVer.header.version = 0;
        assertTrue(
            keccak256(bytes(receiver.checkPayment(zeroVer))) == keccak256("header version"),
            "version 0 header must be refused"
        );

        PaymentProof memory deepPath = _proof(receiver, finality, appId);
        deepPath.path = new bytes32[](65);
        assertTrue(
            keccak256(bytes(receiver.checkPayment(deepPath))) == keccak256("payment path"),
            "over-deep Merkle path must be refused"
        );

        vm.expectPartialRevert(AppBindingExecutor.InvalidAuthorization.selector);
        _authorize(keccak256("self"), address(this), SOLVER, address(executor), hex"", hex"01", 0);
    }

    function test_classical_only_finality_is_refused_by_receiver_and_remote_account() public {
        FinalityStub finality = new FinalityStub();
        bytes32 appId = keccak256("app-mode");
        bytes32 owner = bytes32(uint256(9));

        // 1. Default BudlumPaymentReceiver refuses ClassicalOnly and PostQuantumOnly.
        Receiver receiver = new Receiver(finality, appId);
        PaymentProof memory proof = _proof(receiver, finality, appId);
        bytes32 root = finality.rootAtHeight(20);

        finality.setWithMode(20, root, FinalityMode.ClassicalOnly);
        assertEq(
            keccak256(bytes(receiver.checkPayment(proof))),
            keccak256("hybrid finality required"),
            "default receiver refuses ClassicalOnly"
        );
        vm.expectPartialRevert(BudlumPaymentReceiver.ProofInvalid.selector);
        receiver.consume(proof);

        finality.setWithMode(20, root, FinalityMode.PostQuantumOnly);
        assertEq(
            keccak256(bytes(receiver.checkPayment(proof))),
            keccak256("hybrid finality required"),
            "default receiver refuses PostQuantumOnly"
        );
        vm.expectPartialRevert(BudlumPaymentReceiver.ProofInvalid.selector);
        receiver.consume(proof);

        // 2. An explicit opt-in receiver can accept ClassicalOnly while seeing its mode.
        OptimisticOptInReceiver optIn = new OptimisticOptInReceiver(finality, appId);
        PaymentProof memory optInProof = _proof(Receiver(address(optIn)), finality, appId);
        bytes32 optInRoot = finality.rootAtHeight(20);
        finality.setWithMode(20, optInRoot, FinalityMode.ClassicalOnly);
        assertTrue(finality.finalityModeAtHeight(20) == FinalityMode.ClassicalOnly, "mode visible as ClassicalOnly");
        assertEq(optIn.consume(optInProof), 500, "explicit opt-in consumer accepts ClassicalOnly");

        // 3. BudlumRemoteAccount refuses arbitrary value execution on ClassicalOnly.
        BudlumRemoteAccountFactory factory = new BudlumRemoteAccountFactory(finality);
        BudlumRemoteAccount account = BudlumRemoteAccount(payable(factory.deploy(appId, owner)));
        bytes memory callData = abi.encodeCall(Counter.bump, ());
        bytes32 auth = account.callAuthorization(address(counter), 0, callData, 0);

        PaymentProof memory remoteProof;
        remoteProof.payment = AppBindingPayment(
            keccak256("remote-call-payment"),
            appId,
            owner,
            bytes32(uint256(10)),
            500,
            hex"aa",
            auth,
            3,
            uint64(block.chainid),
            abi.encodePacked(address(account))
        );
        remoteProof.index = 0;
        remoteProof.path = new bytes32[](0);
        remoteProof.paymentsRoot = account.paymentLeaf(remoteProof.payment);
        remoteProof.restHash = keccak256("rest");
        remoteProof.header.version = 8;
        remoteProof.header.timestampMs = uint128(block.timestamp) * 1000;
        remoteProof.header.checkpointHeight = 25;
        remoteProof.header.hasAppBindingRoot = true;
        remoteProof.header.appBindingRoot =
            account.appBindingRegistryRoot(remoteProof.paymentsRoot, remoteProof.restHash);
        remoteProof.stateRootBody = keccak256("body");
        bytes32 remoteRoot =
            account.stateRootFromOpening(remoteProof.stateRootBody, account.headerHash(remoteProof.header));

        finality.setWithMode(25, remoteRoot, FinalityMode.ClassicalOnly);
        vm.expectPartialRevert(BudlumRemoteAccount.HybridFinalityRequired.selector);
        account.execute(remoteProof, address(counter), 0, callData);
        assertEq(counter.count(), 0, "ClassicalOnly must not execute remote call");
        assertEq(account.nonce(), 0, "ClassicalOnly must not advance remote nonce");

        // Upgrading the fixture height to Hybrid allows execution.
        finality.setWithMode(25, remoteRoot, FinalityMode.Hybrid);
        account.execute(remoteProof, address(counter), 0, callData);
        assertEq(counter.count(), 1, "Hybrid finality executes remote call");
        assertEq(account.nonce(), 1, "Hybrid finality advances remote nonce");
    }
}
