// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {GraftExecutor, BudlumGraftClaimer} from "../graft/GraftExecutor.sol";
import {
    BudlumPaymentReceiver,
    GlobalHeader,
    GraftPayment,
    IBudlumFinality,
    PaymentProof
} from "../graft/BudlumPaymentReceiver.sol";
import {BudlumRemoteAccountFactory} from "../graft/BudlumRemoteAccountFactory.sol";

contract Counter {
    uint256 public count;

    function bump() external payable {
        count += 1;
    }

    function fail() external pure {
        revert("no");
    }
}

contract ClaimingApp is BudlumGraftClaimer {
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
    constructor(IBudlumFinality finality_, bytes32 graftId_) BudlumPaymentReceiver(finality_, graftId_) {}

    function consume(PaymentProof calldata proof) external returns (uint64) {
        return _consumePayment(proof).amount;
    }
}

/// A second origin-chain account used to prove that only the account named by
/// the finalized award permit can call the executor.
contract Filler {
    function run(GraftExecutor executor, bytes32 intent, address target) external {
        executor.execute(intent, target, abi.encodeCall(Counter.bump, ()), hex"01");
    }
}

/// An unawarded account attempting to pre-empt the exact authorized call.
contract Attacker {
    function run(GraftExecutor executor, bytes32 intent, address target) external {
        executor.execute(intent, target, abi.encodeCall(Counter.bump, ()), hex"01");
    }
}

contract GraftTest is Harness {
    GraftExecutor internal executor;
    Counter internal counter;

    bytes32 internal constant SOLVER = bytes32(uint256(1));

    function setUp() public {
        executor = new GraftExecutor();
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
    /// in src/settlement/graft.rs.
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
            fulfilledHash, 0xf7d3f98632aa75076903668db4def05736bf895dafa1e6f23c94d87c9a0b3192, "fulfilled payload hash"
        );
        ClaimingApp app = new ClaimingApp();
        assertEq(
            app.claimPayloadHash(
                bytes32(uint256(0x6666666666666666666666666666666666666666666666666666666666666666)),
                bytes32(uint256(0x7777777777777777777777777777777777777777777777777777777777777777))
            ),
            0x331af272e430b9515307696fd158d2eef3760d1e18c6cb5cc5f85450302b1e05,
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
        vm.expectPartialRevert(GraftExecutor.AlreadyFulfilled.selector);
        executor.execute(intent, address(counter), data, hex"01");
    }

    /// A random account cannot perform or pre-empt the exact call that the
    /// finalized award assigned to another solver.
    function test_only_the_authorized_solver_can_execute_the_intent() public {
        bytes32 intent = keccak256("contested-intent");
        bytes memory data = abi.encodeCall(Counter.bump, ());
        _authorizeSelf(intent, address(counter), data);
        Attacker attacker = new Attacker();

        vm.expectPartialRevert(GraftExecutor.NotAwardedSolver.selector);
        attacker.run(executor, intent, address(counter));
        assertEq(counter.count(), 0, "the unawarded account made no call");
        assertTrue(!executor.fulfilled(intent), "the attacker did not burn the intent");

        executor.execute(intent, address(counter), data, hex"01");
        assertEq(counter.count(), 1, "the awarded solver still fulfils");
        assertTrue(executor.fulfilled(intent), "the intent is now consumed");
    }

    function test_an_intent_without_a_finalized_award_permit_cannot_execute() public {
        vm.expectPartialRevert(GraftExecutor.IntentNotAuthorized.selector);
        executor.execute(keccak256("unbound"), address(counter), abi.encodeCall(Counter.bump, ()), hex"01");
        assertEq(counter.count(), 0, "no call was made");
    }

    function test_only_the_deployment_authority_can_mirror_an_award() public {
        bytes32 intent = keccak256("foreign-authority");
        bytes memory data = abi.encodeCall(Counter.bump, ());
        vm.expectPartialRevert(GraftExecutor.NotAuthority.selector);
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
        vm.expectPartialRevert(GraftExecutor.AlreadyAuthorized.selector);
        _authorize(intent, address(replacement), bytes32(uint256(2)), address(counter), data, hex"01", 0);
    }

    function test_the_exact_call_is_bound_by_the_award_permit() public {
        bytes32 intent = keccak256("exact-call");
        bytes memory data = abi.encodeCall(Counter.bump, ());
        Counter other = new Counter();
        _authorizeSelf(intent, address(counter), data);

        vm.expectPartialRevert(GraftExecutor.AuthorizationMismatch.selector);
        executor.execute(intent, address(other), data, hex"01");
        vm.expectPartialRevert(GraftExecutor.AuthorizationMismatch.selector);
        executor.execute(intent, address(counter), abi.encodeCall(Counter.fail, ()), hex"01");
        vm.expectPartialRevert(GraftExecutor.AuthorizationMismatch.selector);
        executor.execute(intent, address(counter), data, hex"02");
        vm.deal(address(this), 1);
        vm.expectPartialRevert(GraftExecutor.AuthorizationMismatch.selector);
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
        vm.expectPartialRevert(GraftExecutor.CallFailed.selector);
        executor.execute(intent, address(0xdead), hex"", hex"01");
    }

    function test_a_failed_call_emits_nothing_and_reverts() public {
        bytes32 intent = keccak256("intent");
        bytes memory data = abi.encodeCall(Counter.fail, ());
        _authorizeSelf(intent, address(counter), data);
        vm.expectPartialRevert(GraftExecutor.CallFailed.selector);
        executor.execute(intent, address(counter), data, hex"01");
        assertTrue(!executor.fulfilled(intent), "not marked fulfilled");
    }

    function _proof(Receiver receiver, FinalityStub finality, bytes32 graftId)
        internal
        returns (PaymentProof memory proof)
    {
        proof.payment = GraftPayment({
            paymentId: keccak256("payment"),
            graftId: graftId,
            payer: bytes32(uint256(9)),
            recipient: bytes32(uint256(10)),
            amount: 500,
            originRecipient: hex"aa",
            memoHash: bytes32(0),
            paidAtBlock: 3,
            targetChainId: uint64(block.chainid),
            targetReceiver: abi.encodePacked(address(receiver))
        });
        proof.index = 0;
        proof.path = new bytes32[](0);
        proof.paymentsRoot = receiver.paymentLeaf(proof.payment);
        proof.restHash = keccak256("rest");
        proof.header.version = 7;
        proof.header.timestampMs = uint128(block.timestamp) * 1000;
        proof.header.checkpointHeight = 20;
        proof.header.hasGraftRoot = true;
        proof.header.graftRoot = receiver.graftRegistryRoot(proof.paymentsRoot, proof.restHash);
        proof.stateRootBody = keccak256("body");
        finality.set(20, receiver.stateRootFromOpening(proof.stateRootBody, receiver.headerHash(proof.header)));
    }

    function test_a_proven_payment_is_consumed_once() public {
        FinalityStub finality = new FinalityStub();
        bytes32 graftId = keccak256("app");
        Receiver receiver = new Receiver(finality, graftId);
        PaymentProof memory proof = _proof(receiver, finality, graftId);
        assertEq(receiver.consume(proof), 500, "amount");
        vm.expectPartialRevert(BudlumPaymentReceiver.AlreadyConsumed.selector);
        receiver.consume(proof);
    }

    function test_a_payment_under_another_root_is_refused() public {
        FinalityStub finality = new FinalityStub();
        bytes32 graftId = keccak256("app");
        Receiver receiver = new Receiver(finality, graftId);
        PaymentProof memory proof = _proof(receiver, finality, graftId);
        proof.payment.amount = 501;
        vm.expectPartialRevert(BudlumPaymentReceiver.ProofInvalid.selector);
        receiver.consume(proof);
    }

    function test_check_payment_refuses_wrong_graft() public {
        FinalityStub finality = new FinalityStub();
        bytes32 appA = keccak256("app-a");
        bytes32 appB = keccak256("app-b");
        Receiver receiver = new Receiver(finality, appA);
        PaymentProof memory proof = _proof(receiver, finality, appB);
        assertEq(keccak256(bytes(receiver.checkPayment(proof))), keccak256("wrong graft"), "wrong graft refused");
        vm.expectPartialRevert(BudlumPaymentReceiver.WrongGraft.selector);
        receiver.consume(proof);
    }

    function test_a_payment_bound_to_another_receiver_is_refused() public {
        FinalityStub finality = new FinalityStub();
        bytes32 graftId = keccak256("app");
        Receiver first = new Receiver(finality, graftId);
        Receiver second = new Receiver(finality, graftId);
        PaymentProof memory proof = _proof(first, finality, graftId);
        assertEq(keccak256(bytes(second.checkPayment(proof))), keccak256("receiver binding"), "wrong receiver refused");
        vm.expectPartialRevert(BudlumPaymentReceiver.ProofInvalid.selector);
        second.consume(proof);
    }

    function test_a_stale_payment_proof_is_refused() public {
        FinalityStub finality = new FinalityStub();
        bytes32 graftId = keccak256("app");
        Receiver receiver = new Receiver(finality, graftId);
        PaymentProof memory proof = _proof(receiver, finality, graftId);
        vm.warp(block.timestamp + 30 days + 1);
        assertEq(keccak256(bytes(receiver.checkPayment(proof))), keccak256("proof too old"), "stale proof refused");
        vm.expectPartialRevert(BudlumPaymentReceiver.ProofInvalid.selector);
        receiver.consume(proof);
    }

    function test_remote_accounts_land_at_their_predicted_address() public {
        FinalityStub finality = new FinalityStub();
        BudlumRemoteAccountFactory factory = new BudlumRemoteAccountFactory(finality);
        address predicted = factory.accountAddress(keccak256("app"), bytes32(uint256(9)));
        address deployed = factory.deploy(keccak256("app"), bytes32(uint256(9)));
        assertTrue(predicted == deployed, "CREATE2 address");
    }
}
