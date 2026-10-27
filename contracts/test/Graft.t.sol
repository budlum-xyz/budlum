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

    function set(uint64 height, bytes32 root) external {
        roots[height] = root;
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

/// A second account that fulfils through the executor: the per-caller guard
/// must let it through even after the test contract has used its own slot.
contract Filler {
    function run(GraftExecutor executor, bytes32 intent, address target) external {
        executor.execute(intent, bytes32(uint256(2)), target, abi.encodeCall(Counter.bump, ()), hex"01");
    }
}

contract GraftTest is Harness {
    GraftExecutor internal executor;
    Counter internal counter;

    function setUp() public {
        executor = new GraftExecutor();
        counter = new Counter();
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
            fulfilledHash,
            0xf7d3f98632aa75076903668db4def05736bf895dafa1e6f23c94d87c9a0b3192,
            "fulfilled payload hash"
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
        executor.execute(intent, bytes32(uint256(1)), address(counter), abi.encodeCall(Counter.bump, ()), hex"01");
        assertEq(counter.count(), 1, "the call was made");
        vm.expectRevert(GraftExecutor.AlreadyFulfilled.selector);
        executor.execute(intent, bytes32(uint256(1)), address(counter), abi.encodeCall(Counter.bump, ()), hex"01");
    }

    /// The once-per-intent guard is per caller: a second account cannot burn
    /// the id, and cannot be blocked by the first caller either.
    function test_the_once_per_intent_guard_is_per_caller() public {
        bytes32 intent = keccak256("contested-intent");
        executor.execute(intent, bytes32(uint256(1)), address(counter), abi.encodeCall(Counter.bump, ()), hex"01");
        assertTrue(executor.fulfilled(intent, address(this)), "the caller's slot is used");
        assertEq(counter.count(), 1, "the call was made");

        // Another account still gets to fulfil the same intent: the first
        // caller cannot burn the id for everyone.
        Filler filler = new Filler();
        filler.run(executor, intent, address(counter));
        assertTrue(executor.fulfilled(intent, address(filler)), "the other caller's slot was free");
        assertEq(counter.count(), 2, "the second call was made too");
    }

    function test_a_call_to_an_address_with_no_code_is_refused() public {
        vm.expectRevert(GraftExecutor.CallFailed.selector);
        executor.execute(
            keccak256("no-code"), bytes32(uint256(1)), address(0xdead), hex"", hex"01"
        );
    }

    function test_a_failed_call_emits_nothing_and_reverts() public {
        vm.expectRevert(GraftExecutor.CallFailed.selector);
        executor.execute(
            keccak256("intent"), bytes32(uint256(1)), address(counter), abi.encodeCall(Counter.fail, ()), hex"01"
        );
        assertTrue(!executor.fulfilled(keccak256("intent"), address(this)), "not marked fulfilled");
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
            paidAtBlock: 3
        });
        proof.index = 0;
        proof.path = new bytes32[](0);
        proof.paymentsRoot = receiver.paymentLeaf(proof.payment);
        proof.restHash = keccak256("rest");
        proof.header.version = 7;
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
        vm.expectRevert(BudlumPaymentReceiver.AlreadyConsumed.selector);
        receiver.consume(proof);
    }

    function test_a_payment_under_another_root_is_refused() public {
        FinalityStub finality = new FinalityStub();
        bytes32 graftId = keccak256("app");
        Receiver receiver = new Receiver(finality, graftId);
        PaymentProof memory proof = _proof(receiver, finality, graftId);
        proof.payment.amount = 501;
        vm.expectRevert(BudlumPaymentReceiver.ProofInvalid.selector);
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
