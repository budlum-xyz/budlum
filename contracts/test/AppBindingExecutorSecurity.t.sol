// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {AppBindingExecutor, BudlumAppBindingClaimer} from "../app_binding/AppBindingExecutor.sol";
import {BudlumHash} from "../lib/BudlumHash.sol";

contract ReturnBombTarget {
    uint256 private constant BOMB_BYTES = 262_144;

    function bombSuccess() external pure {
        assembly {
            return(0, BOMB_BYTES)
        }
    }

    function bombRevert() external pure {
        assembly {
            revert(0, BOMB_BYTES)
        }
    }
}

contract ClaimOutboundHarness is BudlumAppBindingClaimer {
    function claim(uint32 domainKey, bytes32 payout) external {
        _claimBudlumPayout(domainKey, payout);
    }

    function rawEmit(bytes memory kind, bytes32 recipient, bytes32 correlationId, bytes32 payloadHash) external {
        _emitOutbound(kind, recipient, correlationId, payloadHash);
    }
}

contract HashHarness {
    function sentinelValue() external pure returns (bytes32) {
        bytes[] memory fields = new bytes[](1);
        fields[0] = "BDLM_MERKLE_ODD_SENTINEL_V1";
        return BudlumHash.hashFields(fields);
    }

    function node(bytes32 left, bytes32 right) external pure returns (bytes32) {
        return BudlumHash.merkleNode(left, right);
    }

    function verify(bytes32 finalizedRoot, bytes32 leaf, uint256 index, bytes32[] memory siblings)
        external
        pure
        returns (bool)
    {
        return BudlumHash.verifyLeafAgainstRoot(finalizedRoot, leaf, index, siblings);
    }
}

contract AppBindingExecutorSecurityTest is Harness {
    AppBindingExecutor internal executor;
    ReturnBombTarget internal bomb;
    bytes32 internal constant SOLVER = bytes32(uint256(0xA11CE));

    function setUp() public {
        executor = new AppBindingExecutor();
        bomb = new ReturnBombTarget();
    }

    function test_authorize_intent_rejects_zero_calldata_or_beneficiary_hash() public {
        vm.expectPartialRevert(AppBindingExecutor.InvalidAuthorization.selector);
        executor.authorizeIntent(
            keccak256("zero-calldata-hash"),
            address(this),
            SOLVER,
            address(bomb),
            bytes32(0),
            0,
            keccak256(hex"01")
        );

        vm.expectPartialRevert(AppBindingExecutor.InvalidAuthorization.selector);
        executor.authorizeIntent(
            keccak256("zero-beneficiary-hash"),
            address(this),
            SOLVER,
            address(bomb),
            keccak256(abi.encodeCall(ReturnBombTarget.bombSuccess, ())),
            0,
            bytes32(0)
        );
    }

    function test_execute_survives_returnbomb_and_caps_return_and_revert_data() public {
        bytes32 intentOk = keccak256("returnbomb-ok");
        bytes memory okCall = abi.encodeCall(ReturnBombTarget.bombSuccess, ());
        executor.authorizeIntent(
            intentOk, address(this), SOLVER, address(bomb), keccak256(okCall), 0, keccak256(hex"01")
        );

        bytes memory ret = executor.execute{gas: 300_000}(intentOk, address(bomb), okCall, hex"01");
        assertTrue(executor.fulfilled(intentOk), "returnbomb target must still fulfill cleanly");
        assertEq(ret.length, 1024, "return data must be capped at 1024 bytes");

        bytes32 intentFail = keccak256("returnbomb-revert");
        bytes memory failCall = abi.encodeCall(ReturnBombTarget.bombRevert, ());
        executor.authorizeIntent(
            intentFail, address(this), SOLVER, address(bomb), keccak256(failCall), 0, keccak256(hex"01")
        );

        vm.expectPartialRevert(AppBindingExecutor.CallFailed.selector);
        executor.execute{gas: 300_000}(intentFail, address(bomb), failCall, hex"01");
    }

    function test_claimer_and_outbound_reject_zero_domain_or_malformed_outbound() public {
        ClaimOutboundHarness h = new ClaimOutboundHarness();

        vm.expectRevert();
        h.budlumAppBindingId(0);

        vm.expectRevert();
        h.claim(0, bytes32(uint256(7)));

        vm.expectRevert();
        h.rawEmit("", bytes32(0), bytes32(uint256(1)), bytes32(uint256(2)));

        vm.expectRevert();
        h.rawEmit("budlum/test/v1", bytes32(0), bytes32(0), bytes32(uint256(2)));

        vm.expectRevert();
        h.rawEmit("budlum/test/v1", bytes32(0), bytes32(uint256(1)), bytes32(0));
    }

    function test_budlum_hash_rejects_sentinel_leaf_and_zero_sibling() public {
        HashHarness h = new HashHarness();
        bytes32 sentinel = h.sentinelValue();
        bytes32[] memory empty = new bytes32[](0);
        assertTrue(!h.verify(sentinel, sentinel, 0, empty), "odd-promote sentinel must never verify as a leaf");

        bytes32 leaf = keccak256("real-leaf");
        bytes32[] memory zeroSib = new bytes32[](1);
        zeroSib[0] = bytes32(0);
        bytes32 forgedRoot = h.node(leaf, bytes32(0));
        assertTrue(!h.verify(forgedRoot, leaf, 0, zeroSib), "all-zero sibling must be rejected");
    }
}
