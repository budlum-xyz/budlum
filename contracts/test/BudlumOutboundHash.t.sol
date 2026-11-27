// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {BudlumHash} from "../lib/BudlumHash.sol";
import {BudlumOutboundEmitter} from "../lib/BudlumOutbound.sol";

contract OutboundHarness is BudlumOutboundEmitter {
    function emitRaw(bytes calldata kind, bytes32 recipient, bytes32 correlationId, bytes32 payloadHash) external {
        _emitOutbound(kind, recipient, correlationId, payloadHash);
    }
}

contract BudlumOutboundHashTest is Harness {
    OutboundHarness internal emitter;

    bytes32 internal constant RECIPIENT = bytes32(uint256(0xA11CE));
    bytes32 internal constant CORRELATION = bytes32(uint256(0xC0DE));
    bytes32 internal constant PAYLOAD = bytes32(uint256(0xBEEF));

    function setUp() public {
        emitter = new OutboundHarness();
    }

    function _sentinel() internal pure returns (bytes32) {
        bytes[] memory fields = new bytes[](1);
        fields[0] = "BDLM_MERKLE_ODD_SENTINEL_V1";
        return BudlumHash.hashFields(fields);
    }

    function _promote(bytes32 node) internal pure returns (bytes32) {
        bytes[] memory fields = new bytes[](2);
        fields[0] = "BDLM_MERKLE_ODD_PROMOTE_V1";
        fields[1] = bytes.concat(node);
        return BudlumHash.hashFields(fields);
    }

    function test_outbound_accepts_valid_bounds_including_zero_correlation() public {
        bytes memory maxKind = new bytes(128);
        for (uint256 i = 0; i < 128; i++) {
            maxKind[i] = bytes1("a");
        }
        emitter.emitRaw(maxKind, RECIPIENT, bytes32(0), PAYLOAD);
        emitter.emitRaw("budlum/test/v1", RECIPIENT, CORRELATION, PAYLOAD);
    }

    function test_outbound_refuses_empty_and_overlong_kind() public {
        vm.expectPartialRevert(BudlumOutboundEmitter.InvalidOutboundKind.selector);
        emitter.emitRaw("", RECIPIENT, CORRELATION, PAYLOAD);

        bytes memory tooLong = new bytes(129);
        for (uint256 i = 0; i < 129; i++) {
            tooLong[i] = bytes1("a");
        }
        vm.expectPartialRevert(BudlumOutboundEmitter.InvalidOutboundKind.selector);
        emitter.emitRaw(tooLong, RECIPIENT, CORRELATION, PAYLOAD);
    }

    function test_outbound_refuses_zero_recipient_and_zero_payload_hash() public {
        vm.expectPartialRevert(BudlumOutboundEmitter.InvalidOutboundRecipient.selector);
        emitter.emitRaw("budlum/test/v1", bytes32(0), CORRELATION, PAYLOAD);

        vm.expectPartialRevert(BudlumOutboundEmitter.InvalidOutboundPayloadHash.selector);
        emitter.emitRaw("budlum/test/v1", RECIPIENT, CORRELATION, bytes32(0));
    }

    function test_root_from_proof_accepts_honest_three_and_five_leaf_tail_promotions() public pure {
        bytes32 sentinel = _sentinel();
        bytes32 l0 = bytes32(uint256(1));
        bytes32 l1 = bytes32(uint256(2));
        bytes32 l2 = bytes32(uint256(3));
        bytes32 h01 = BudlumHash.merkleNode(l0, l1);
        bytes32 root3 = BudlumHash.merkleNode(h01, _promote(l2));

        bytes32[] memory pf3 = new bytes32[](2);
        pf3[0] = sentinel;
        pf3[1] = h01;
        (bool ok3, bytes32 got3) = BudlumHash.rootFromProof(l2, 2, pf3);
        assertTrue(ok3, "honest 3-leaf tail proof must verify");
        assertEq(got3, root3, "3-leaf root matches");

        bytes32 l3 = bytes32(uint256(4));
        bytes32 l4 = bytes32(uint256(5));
        bytes32 h23 = BudlumHash.merkleNode(l2, l3);
        bytes32 h0123 = BudlumHash.merkleNode(h01, h23);
        bytes32 root5 = BudlumHash.merkleNode(h0123, _promote(_promote(l4)));

        bytes32[] memory pf5 = new bytes32[](3);
        pf5[0] = sentinel;
        pf5[1] = sentinel;
        pf5[2] = h0123;
        (bool ok5, bytes32 got5) = BudlumHash.rootFromProof(l4, 4, pf5);
        assertTrue(ok5, "honest 5-leaf double-promoted tail proof must verify");
        assertEq(got5, root5, "5-leaf root matches");
    }

    function test_root_from_proof_refuses_terminal_zero_index_and_non_monotonic_tail_promotions() public pure {
        bytes32 sentinel = _sentinel();
        bytes32 leaf = bytes32(uint256(7));
        bytes32 sib1 = bytes32(uint256(8));
        bytes32 sib2 = bytes32(uint256(9));

        // 1. Single-step phantom promotion at index 0 (no honest tree promotes its root).
        bytes32[] memory phantomSingle = new bytes32[](1);
        phantomSingle[0] = sentinel;
        (bool okSingle,) = BudlumHash.rootFromProof(leaf, 0, phantomSingle);
        assertTrue(!okSingle, "index 0 terminal promotion must be refused");

        // 2. Multi-step promotion starting at index 0 (node 0 always has node 1 in non-root layers).
        bytes32[] memory zeroIdxPromoted = new bytes32[](2);
        zeroIdxPromoted[0] = sentinel;
        zeroIdxPromoted[1] = sib1;
        (bool okZeroIdx,) = BudlumHash.rootFromProof(leaf, 0, zeroIdxPromoted);
        assertTrue(!okZeroIdx, "index 0 promotion must be refused");

        // 3. Promoted tail at step 0 (index=2 -> layer0 len=3 -> layer1 len=2), paired left at step 1
        //    (idx=1 -> root reached), then falsely claiming a right sibling at step 2 (idx=0).
        bytes32[] memory stickyViolation = new bytes32[](3);
        stickyViolation[0] = sentinel;
        stickyViolation[1] = sib1;
        stickyViolation[2] = sib2;
        (bool okSticky,) = BudlumHash.rootFromProof(leaf, 2, stickyViolation);
        assertTrue(!okSticky, "post-promotion tail cannot later claim a right sibling");

        // 4. Promoted tail at index=4 (layer0 len=5 -> layer1 len=3, idx=2) claiming a right sibling
        //    instead of promoting at layer 1.
        bytes32[] memory rightAfterPromote = new bytes32[](3);
        rightAfterPromote[0] = sentinel;
        rightAfterPromote[1] = sib1;
        rightAfterPromote[2] = sib2;
        (bool okRightAfterPromote,) = BudlumHash.rootFromProof(leaf, 4, rightAfterPromote);
        assertTrue(!okRightAfterPromote, "promoted node at even parent index cannot pair on the right");
    }
}
