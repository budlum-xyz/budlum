// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {FinalityMode} from "../external-domain/BudlumFinalityVerifier.sol";
import {BudlumSettlementEndpoint, IBudlumObjectLayerFinality} from "../object-layer/BudlumSettlementEndpoint.sol";

contract MockObjectLayerFinality is IBudlumObjectLayerFinality {
    mapping(uint64 => bytes32) public headers;
    mapping(uint64 => bool) public finals;
    mapping(uint64 => FinalityMode) public modes;

    function setHeader(uint64 height, bytes32 headerHash, bool isFinal, FinalityMode mode) external {
        headers[height] = headerHash;
        finals[height] = isFinal;
        modes[height] = mode;
    }

    function headerAt(uint64 height) external view returns (bytes32) {
        return headers[height];
    }

    function heightFinal(uint64 height) external view returns (bool) {
        return finals[height];
    }

    function finalityModeAt(uint64 height) external view returns (FinalityMode) {
        return modes[height];
    }
}

contract BudlumSettlementEndpointGuardTest is Harness {
    function test_asset_class_id_rejects_zero_home_domain() public {
        MockObjectLayerFinality fin = new MockObjectLayerFinality();
        BudlumSettlementEndpoint endpoint = new BudlumSettlementEndpoint(fin, 100);

        vm.expectPartialRevert(BudlumSettlementEndpoint.InvalidAssetClass.selector);
        endpoint.assetClassId(0, 1, address(0x1234));

        vm.expectPartialRevert(BudlumSettlementEndpoint.InvalidAssetClass.selector);
        endpoint.assetId(0, 0, address(0x1234), 0);
    }

    function test_silent_stays_false_until_an_authenticated_header_is_accepted() public {
        vm.warp(1_000);
        MockObjectLayerFinality fin = new MockObjectLayerFinality();
        BudlumSettlementEndpoint endpoint = new BudlumSettlementEndpoint(fin, 100);

        // Even after silenceWindow elapses, silent() must stay false when no header was ever accepted.
        vm.warp(1_200);
        assertTrue(!endpoint.silent(), "silent must stay false without an accepted header");

        // Once a Hybrid header is accepted, silent() becomes false immediately and true only after > silenceWindow.
        fin.setHeader(10, bytes32(uint256(0xABCD)), true, FinalityMode.Hybrid);
        endpoint.acceptHeader(10);
        assertTrue(!endpoint.silent(), "freshly accepted header resets silence timer");

        vm.warp(1_300);
        assertTrue(!endpoint.silent(), "exact boundary silenceWindow is not yet silent");

        vm.warp(1_301);
        assertTrue(endpoint.silent(), "strictly past silenceWindow after accepted header opens silent()");
    }
}
