// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {BudlumUniversal, BudlumUol} from "../uel/BudlumUniversal.sol";

contract UelCallerHarness {
    function doCall(uint8 ee, bytes memory target, bytes memory input, uint256 valueAttos, uint64 gasBgu)
        external
        returns (bool, bytes memory)
    {
        return BudlumUniversal.call(ee, target, input, valueAttos, gasBgu);
    }

    function doStaticCall(uint8 ee, bytes memory target, bytes memory input, uint64 gasBgu)
        external
        view
        returns (bool, bytes memory)
    {
        return BudlumUniversal.staticCall(ee, target, input, gasBgu);
    }

    function doBalanceOf(bytes32 classId, bytes memory holder) external view returns (uint128) {
        return BudlumUol.balanceOf(classId, holder);
    }

    function doHolderOf(bytes32 assetId) external view returns (bytes memory) {
        return BudlumUol.holderOf(assetId);
    }

    function doTransfer(bytes32 classId, bytes32 assetId, bytes memory to, uint128 amount) external returns (bool) {
        return BudlumUol.transfer(classId, assetId, to, amount);
    }

    function doAccept(bytes32 offerId) external returns (bool) {
        return BudlumUol.accept(offerId);
    }
}

contract UelPrecompileSecurityTest is Harness {
    UelCallerHarness internal uel;

    function setUp() public {
        uel = new UelCallerHarness();
    }

    function test_universal_call_surfaces_transport_error_on_empty_precompile_and_bounds_inputs() public {
        vm.expectPartialRevert(BudlumUniversal.PrecompileTransportFailed.selector);
        uel.doCall(0x02, hex"deadbeef", hex"01", 0, 50_000);

        vm.expectPartialRevert(BudlumUniversal.PrecompileTransportFailed.selector);
        uel.doStaticCall(0x02, hex"deadbeef", hex"01", 50_000);

        vm.expectPartialRevert(BudlumUniversal.InvalidUniversalCall.selector);
        uel.doCall(0x0D, hex"deadbeef", hex"", 0, 50_000);

        vm.expectPartialRevert(BudlumUniversal.InvalidUniversalCall.selector);
        uel.doCall(0x02, hex"deadbeef", hex"", uint256(type(uint128).max) + 1, 50_000);

        vm.mockCall(address(0x000000000000000000000000000000000000B001), "", abi.encode(true, bytes("ok-ret")));
        (bool okCall, bytes memory ret) = uel.doCall(0x02, hex"deadbeef", hex"01", 100, 50_000);
        assertTrue(okCall, "mounted precompile succeeds");
        assertEq(keccak256(ret), keccak256(bytes("ok-ret")), "decoded precompile bytes");
    }

    function test_uol_surfaces_typed_precompile_failure_and_rejects_zero_identifiers() public {
        vm.expectPartialRevert(BudlumUol.UolPrecompileFailed.selector);
        uel.doBalanceOf(bytes32(uint256(1)), hex"abcd");

        vm.expectPartialRevert(BudlumUol.UolPrecompileFailed.selector);
        uel.doHolderOf(bytes32(uint256(1)));

        vm.expectPartialRevert(BudlumUol.InvalidUolRequest.selector);
        uel.doTransfer(bytes32(uint256(1)), bytes32(0), hex"abcd", 0);

        vm.expectPartialRevert(BudlumUol.InvalidUolRequest.selector);
        uel.doAccept(bytes32(0));

        vm.mockCall(address(0x000000000000000000000000000000000000B002), "", abi.encode(uint128(42)));
        assertEq(uel.doBalanceOf(bytes32(uint256(1)), hex"abcd"), 42, "mounted UOL precompile decodes uint128");
    }
}
