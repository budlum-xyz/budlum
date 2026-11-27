// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {BudlumBls} from "../lib/BudlumBls.sol";
import {BudlumHash} from "../lib/BudlumHash.sol";
import {BudlumStateReader} from "../lib/BudlumStateReader.sol";
import {BudlumRemoteAccountFactory} from "../app_binding/BudlumRemoteAccountFactory.sol";
import {FinalityMode, IBudlumFinality} from "../external-domain/BudlumFinalityVerifier.sol";

contract MockFinalityForReader is IBudlumFinality {
    mapping(uint64 => bytes32) public roots;
    mapping(uint64 => bool) public isFinal;
    mapping(uint64 => FinalityMode) public modes;
    uint64 public latest;

    function setHeight(uint64 height, bytes32 root, bool finalized, FinalityMode mode) external {
        roots[height] = root;
        isFinal[height] = finalized;
        modes[height] = mode;
        if (finalized && height > latest) {
            latest = height;
        }
    }

    function rootAtHeight(uint64 height) external view returns (bytes32) {
        return roots[height];
    }

    function heightFinal(uint64 height) external view returns (bool) {
        return isFinal[height];
    }

    function latestFinalHeight() external view returns (uint64) {
        return latest;
    }

    function finalityModeAtHeight(uint64 height) external view returns (FinalityMode) {
        return modes[height];
    }
}

contract BudlumBlsStateReaderTest is Harness {
    bytes internal constant MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    function _writeFpAt(bytes memory uncompressed, uint256 coordIdx, bytes memory fp48) internal pure {
        uint256 base = coordIdx * 64 + 16;
        for (uint256 i = 0; i < 48; i++) {
            uncompressed[base + i] = fp48[i];
        }
    }

    function test_bls_g2_matches_rejects_noncanonical_fp_coordinates() public pure {
        bytes memory uncompressed = new bytes(256);
        bytes memory compressed = new bytes(96);

        // X_c1 = 1, X_c0 = 2, Y_c1 = 0, Y_c0 = MODULUS (non-canonical >= p, > HALF_MODULUS).
        uncompressed[80 + 47] = 0x01;
        uncompressed[16 + 47] = 0x02;
        _writeFpAt(uncompressed, 2, MODULUS);

        compressed[0] = bytes1(uint8(0x80 | 0x20));
        compressed[47] = 0x01;
        compressed[48 + 47] = 0x02;

        assertTrue(!BudlumBls.g2Matches(compressed, uncompressed), "Y_c0 equal to field modulus must be rejected");

        // Also check X_c0 = MODULUS while Y_c0 = 1 (canonical Y, non-canonical X).
        bytes memory uncompressedX = new bytes(256);
        bytes memory compressedX = new bytes(96);
        _writeFpAt(uncompressedX, 0, MODULUS);
        uncompressedX[144 + 47] = 0x01;
        compressedX[0] = bytes1(uint8(0x80));
        for (uint256 i = 0; i < 48; i++) {
            compressedX[48 + i] = MODULUS[i];
        }
        assertTrue(!BudlumBls.g2Matches(compressedX, uncompressedX), "X_c0 equal to field modulus must be rejected");
    }

    function test_state_reader_rejects_classical_only_and_codeless_finality() public {
        MockFinalityForReader finality = new MockFinalityForReader();
        bytes32 account = bytes32(uint256(0x11));
        bytes32 assetId = bytes32(uint256(0x22));
        uint128 amount = 500;
        uint64 nonce = 3;
        bytes32 leaf = BudlumHash.balanceLeaf(account, assetId, amount, nonce);
        bytes32[] memory emptySiblings = new bytes32[](0);
        (bool okRoot, bytes32 root) = BudlumHash.rootFromProof(leaf, 0, emptySiblings);
        assertTrue(okRoot, "single-leaf root derivation must succeed");

        // ClassicalOnly must never satisfy state reader inclusion checks without hybrid PQ settlement.
        finality.setHeight(42, root, true, FinalityMode.ClassicalOnly);
        bool classicalAccepted =
            BudlumStateReader.verifyBalance(finality, 42, account, assetId, amount, nonce, 0, emptySiblings);
        assertTrue(!classicalAccepted, "classical-only mode must not be accepted as hybrid finality");

        // Codeless non-zero finality address must return false rather than reverting on empty returndata.
        bool codelessAccepted = BudlumStateReader.verifyBalance(
            IBudlumFinality(address(0xBEEF)), 42, account, assetId, amount, nonce, 0, emptySiblings
        );
        assertTrue(!codelessAccepted, "codeless finality address must fail closed with false");

        // Hybrid finality at the same root succeeds.
        finality.setHeight(42, root, true, FinalityMode.Hybrid);
        bool hybridAccepted =
            BudlumStateReader.verifyBalance(finality, 42, account, assetId, amount, nonce, 0, emptySiblings);
        assertTrue(hybridAccepted, "hybrid finality with valid root must succeed");
    }

    function test_remote_account_factory_reverts_with_typed_error_on_duplicate_deploy() public {
        MockFinalityForReader finality = new MockFinalityForReader();
        BudlumRemoteAccountFactory factory = new BudlumRemoteAccountFactory(finality);
        bytes32 appId = keccak256("app-v1");
        bytes32 owner = keccak256("budlum-owner-1");

        address predicted = factory.accountAddress(appId, owner);
        address deployed = factory.deploy(appId, owner);
        assertTrue(predicted == deployed, "predicted CREATE2 address must match deployed address");

        bytes4 alreadyDeployedSelector = bytes4(keccak256("AccountAlreadyDeployed(address)"));
        vm.expectPartialRevert(alreadyDeployedSelector);
        factory.deploy(appId, owner);
    }
}
