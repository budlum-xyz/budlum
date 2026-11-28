// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {BudlumHash} from "../lib/BudlumHash.sol";
import {BudlumStateReader} from "../lib/BudlumStateReader.sol";
import {FinalityMode, IBudlumFinality} from "../external-domain/BudlumFinalityVerifier.sol";

/// @notice A finality oracle whose answers the test sets directly.
contract FinalityStub is IBudlumFinality {
    mapping(uint64 => bool) public finalHeights;
    mapping(uint64 => bytes32) public roots;
    FinalityMode public mode = FinalityMode.Hybrid;

    function setFinal(uint64 height, bytes32 root) external {
        finalHeights[height] = true;
        roots[height] = root;
    }

    function setMode(FinalityMode next) external {
        mode = next;
    }

    function rootAtHeight(uint64 height) external view returns (bytes32) {
        return roots[height];
    }

    function heightFinal(uint64 height) external view returns (bool) {
        return finalHeights[height];
    }

    function latestFinalHeight() external pure returns (uint64) {
        return 0;
    }

    function finalityModeAtHeight(uint64) external view returns (FinalityMode) {
        return mode;
    }
}

/// @notice The reader and the tree are `internal`; this harness exposes the
///         exact helpers the suite needs, with no logic of its own.
contract ReaderHarness {
    function rootFromProof(bytes32 leaf, uint256 index, bytes32[] calldata siblings)
        external
        pure
        returns (bool, bytes32)
    {
        return BudlumHash.rootFromProof(leaf, index, siblings);
    }

    function verifyLeafAtHeight(
        IBudlumFinality finality,
        uint64 height,
        bytes32 leaf,
        uint256 index,
        bytes32[] calldata siblings
    ) external view returns (bool) {
        return BudlumStateReader.verifyLeafAtHeight(finality, height, leaf, index, siblings);
    }

    function verifyBalance(
        IBudlumFinality finality,
        uint64 height,
        bytes32 account,
        bytes32 assetId,
        uint128 amount,
        uint64 nonce,
        uint256 index,
        bytes32[] calldata siblings
    ) external view returns (bool) {
        return BudlumStateReader.verifyBalance(finality, height, account, assetId, amount, nonce, index, siblings);
    }
}

/// @notice `verifyLeafAtHeight` is the one external surface of the state
///         reader that no test reached. Its contract is fail-closed: the height
///         must be final, the mode must not be None, the root must be non-zero
///         and the proof must open to that root. Every branch is pinned here.
contract BudlumStateReaderTest is Harness {
    FinalityStub internal finality;
    ReaderHarness internal reader;

    bytes32 internal leafA = keccak256("leafA");
    bytes32 internal leafB = keccak256("leafB");
    bytes32 internal root;

    function setUp() public {
        finality = new FinalityStub();
        reader = new ReaderHarness();
        root = BudlumHash.merkleNode(leafA, leafB);
    }

    function _siblings(bytes32 s) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](1);
        out[0] = s;
    }

    // -------------------------------------------------------- kabul yollari

    function test_a_final_height_with_a_valid_proof_is_accepted() public {
        finality.setFinal(7, root);
        assertTrue(reader.verifyLeafAtHeight(finality, 7, leafA, 0, _siblings(leafB)), "index 0 must open");
        assertTrue(reader.verifyLeafAtHeight(finality, 7, leafB, 1, _siblings(leafA)), "index 1 must open");
    }

    function test_a_single_leaf_tree_needs_no_sibling() public {
        finality.setFinal(7, leafA);
        bytes32[] memory none = new bytes32[](0);
        assertTrue(reader.verifyLeafAtHeight(finality, 7, leafA, 0, none), "a one-leaf tree is its own root");
    }

    function test_verify_balance_composes_the_leaf_and_the_proof() public {
        bytes32 leaf = BudlumHash.balanceLeaf(bytes32("acct"), bytes32("asset"), 5, 9);
        finality.setFinal(3, leaf);
        bytes32[] memory none = new bytes32[](0);
        assertTrue(reader.verifyBalance(finality, 3, bytes32("acct"), bytes32("asset"), 5, 9, 0, none), "balance fact");
    }

    // ---------------------------------------------------------- ret yollari

    function test_a_zero_finality_address_is_refused() public view {
        bytes32[] memory none = new bytes32[](0);
        assertTrue(!reader.verifyLeafAtHeight(IBudlumFinality(address(0)), 7, leafA, 0, none), "no oracle, no proof");
    }

    function test_a_non_final_height_is_refused() public view {
        assertTrue(!reader.verifyLeafAtHeight(finality, 7, leafA, 0, _siblings(leafB)), "unfinalized height");
    }

    function test_a_none_finality_mode_is_refused() public {
        finality.setFinal(7, root);
        finality.setMode(FinalityMode.None);
        assertTrue(!reader.verifyLeafAtHeight(finality, 7, leafA, 0, _siblings(leafB)), "None mode");
    }

    function test_a_zero_root_is_refused_even_when_final() public {
        finality.setFinal(7, bytes32(0));
        assertTrue(!reader.verifyLeafAtHeight(finality, 7, leafA, 0, _siblings(leafB)), "zero root");
    }

    function test_a_wrong_leaf_is_refused() public {
        finality.setFinal(7, root);
        assertTrue(!reader.verifyLeafAtHeight(finality, 7, keccak256("other"), 0, _siblings(leafB)), "wrong leaf");
    }

    function test_a_swapped_index_is_refused() public {
        finality.setFinal(7, root);
        assertTrue(!reader.verifyLeafAtHeight(finality, 7, leafA, 1, _siblings(leafB)), "index/leaf mismatch");
    }

    function test_a_truncated_proof_is_refused() public {
        finality.setFinal(7, root);
        bytes32[] memory none = new bytes32[](0);
        assertTrue(!reader.verifyLeafAtHeight(finality, 7, leafA, 0, none), "missing sibling");
    }

    function test_an_oversized_proof_is_refused() public {
        finality.setFinal(7, root);
        bytes32[] memory long = new bytes32[](65);
        for (uint256 i = 0; i < long.length; i++) {
            long[i] = keccak256(abi.encode(i));
        }
        assertTrue(!reader.verifyLeafAtHeight(finality, 7, leafA, 0, long), "depth above 64");
    }

    function test_a_root_that_does_not_match_is_refused() public {
        finality.setFinal(7, keccak256("another root"));
        assertTrue(!reader.verifyLeafAtHeight(finality, 7, leafA, 0, _siblings(leafB)), "root mismatch");
    }
}
