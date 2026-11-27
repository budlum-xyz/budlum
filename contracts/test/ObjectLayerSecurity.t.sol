// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {FinalityMode} from "../external-domain/BudlumFinalityVerifier.sol";
import {BudlumHash} from "../lib/BudlumHash.sol";
import {BudlumObjectLayerFinality, IBudlumHeaderFinality} from "../object-layer/BudlumFinalityVerifier.sol";
import {BudlumSettlementEndpoint, IBudlumObjectLayerFinality} from "../object-layer/BudlumSettlementEndpoint.sol";

contract PermissiveHeaderFinalityStub is IBudlumHeaderFinality {
    mapping(uint64 => bytes32) public finalizedRoot;

    function setFinalizedRoot(uint64 height, bytes32 root) external {
        finalizedRoot[height] = root;
    }

    function isFinalizedHeader(uint64 height, bytes32 headerHash, bytes32 stateRootBody) external view returns (bool) {
        bytes[] memory fields = new bytes[](3);
        fields[0] = "BDLM_STATE_ROOT_GLOBAL_HEADER_V1";
        fields[1] = bytes.concat(stateRootBody);
        fields[2] = bytes.concat(headerHash);
        return finalizedRoot[height] != bytes32(0) && finalizedRoot[height] == BudlumHash.hashFields(fields);
    }

    function finalityModeAtHeight(uint64 height) external view returns (FinalityMode) {
        return finalizedRoot[height] == bytes32(0) ? FinalityMode.None : FinalityMode.Hybrid;
    }
}

contract ObjectLayerSecurityTest is Harness {
    PermissiveHeaderFinalityStub internal stub;
    BudlumObjectLayerFinality internal objectLayer;
    BudlumSettlementEndpoint internal endpoint;

    function setUp() public {
        stub = new PermissiveHeaderFinalityStub();
        objectLayer = new BudlumObjectLayerFinality(IBudlumHeaderFinality(address(stub)));
        endpoint = new BudlumSettlementEndpoint(IBudlumObjectLayerFinality(address(objectLayer)), 100);
    }

    function _openingRoot(bytes32 body, bytes32 header) internal pure returns (bytes32) {
        bytes[] memory fields = new bytes[](3);
        fields[0] = "BDLM_STATE_ROOT_GLOBAL_HEADER_V1";
        fields[1] = bytes.concat(body);
        fields[2] = bytes.concat(header);
        return BudlumHash.hashFields(fields);
    }

    function test_record_rejects_zero_height_and_zero_state_root_body() public {
        bytes32 body = bytes32(uint256(0x11));
        bytes32 header = bytes32(uint256(0x22));
        stub.setFinalizedRoot(0, _openingRoot(body, header));

        vm.expectPartialRevert(BudlumObjectLayerFinality.NotAccepted.selector);
        objectLayer.record(0, header, body);

        stub.setFinalizedRoot(7, _openingRoot(bytes32(0), header));
        vm.expectPartialRevert(BudlumObjectLayerFinality.NotAccepted.selector);
        objectLayer.record(7, header, bytes32(0));
    }

    function test_record_replay_with_mismatched_state_root_body_reverts_conflict() public {
        uint64 height = 12;
        bytes32 bodyA = bytes32(uint256(0xAA));
        bytes32 bodyB = bytes32(uint256(0xBB));
        bytes32 header = bytes32(uint256(0xCC));
        stub.setFinalizedRoot(height, _openingRoot(bodyA, header));

        objectLayer.record(height, header, bodyA);
        // Exact same (height, header, bodyA) remains idempotent.
        objectLayer.record(height, header, bodyA);

        // Presenting a different stateRootBody under the same headerHash must revert Conflict().
        vm.expectPartialRevert(BudlumObjectLayerFinality.Conflict.selector);
        objectLayer.record(height, header, bodyB);
    }

    function test_asset_class_and_asset_id_reject_zero_home_domain() public {
        address homeToken = address(0x1234);
        vm.expectPartialRevert(BudlumSettlementEndpoint.InvalidAssetClass.selector);
        endpoint.assetClassId(0, 0, homeToken);

        vm.expectPartialRevert(BudlumSettlementEndpoint.InvalidAssetClass.selector);
        endpoint.assetId(0, 1, homeToken, 42);
    }
}
