// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {BudlumUniversal, BudlumUol} from "../uel/BudlumUniversal.sol";

contract UniversalCallerHarness {
    function doCall(uint8 ee, bytes calldata target, bytes calldata input, uint256 valueAttos, uint64 gasBgu)
        external
        returns (bool ok, bytes memory ret)
    {
        return BudlumUniversal.call(ee, target, input, valueAttos, gasBgu);
    }

    function doStaticCall(uint8 ee, bytes calldata target, bytes calldata input, uint64 gasBgu)
        external
        view
        returns (bool ok, bytes memory ret)
    {
        return BudlumUniversal.staticCall(ee, target, input, gasBgu);
    }

    function uolBalance(bytes32 classId, bytes calldata holder) external view returns (uint128) {
        return BudlumUol.balanceOf(classId, holder);
    }

    function uolHolder(bytes32 assetId) external view returns (bytes memory) {
        return BudlumUol.holderOf(assetId);
    }

    function uolTransfer(bytes32 classId, bytes32 assetId, bytes calldata to, uint128 amount) external returns (bool) {
        return BudlumUol.transfer(classId, assetId, to, amount);
    }

    function uolOffer(
        bytes32 classId,
        bytes32 assetId,
        bytes calldata taker,
        bytes calldata payment,
        uint128 amount,
        uint64 expiry
    ) external returns (bytes32) {
        return BudlumUol.offer(classId, assetId, taker, payment, amount, expiry);
    }

    function uolAccept(bytes32 offerId) external returns (bool) {
        return BudlumUol.accept(offerId);
    }
}

contract BudlumUniversalSlasherTest is Harness {
    function test_universal_and_uol_reject_missing_precompile_empty_returndata_and_unknown_ee() public {
        UniversalCallerHarness caller = new UniversalCallerHarness();

        // On an EVM chain lacking 0x...B001 / 0x...B002 precompiles, CALL returns (true, "")
        // and must revert with typed transport errors rather than an empty ABI decode panic.
        vm.expectPartialRevert(BudlumUniversal.PrecompileTransportFailed.selector);
        caller.doCall(BudlumUniversal.EE_WASM, hex"01", hex"", 0, 50_000);

        vm.expectPartialRevert(BudlumUniversal.PrecompileTransportFailed.selector);
        caller.doStaticCall(BudlumUniversal.EE_WASM, hex"01", hex"", 50_000);

        vm.expectPartialRevert(BudlumUol.UolPrecompileFailed.selector);
        caller.uolBalance(bytes32(uint256(1)), hex"01");

        vm.expectPartialRevert(BudlumUol.UolPrecompileFailed.selector);
        caller.uolHolder(bytes32(uint256(1)));

        vm.expectPartialRevert(BudlumUol.UolPrecompileFailed.selector);
        caller.uolTransfer(bytes32(uint256(1)), bytes32(uint256(2)), abi.encodePacked(address(0x1234)), 10);

        vm.expectPartialRevert(BudlumUol.UolPrecompileFailed.selector);
        caller.uolOffer(bytes32(uint256(1)), bytes32(uint256(2)), hex"01", hex"02", 10, 99);

        vm.expectPartialRevert(BudlumUol.UolPrecompileFailed.selector);
        caller.uolAccept(bytes32(uint256(7)));

        // Unknown execution environment (> EE_RV32 = 0x0C) must fail closed with InvalidExecutionEnvironment.
        bytes4 invalidEeSelector = bytes4(keccak256("InvalidExecutionEnvironment(uint8)"));
        vm.expectPartialRevert(invalidEeSelector);
        caller.doCall(0xFF, hex"01", hex"", 0, 50_000);

        // Properly ABI-encoded mock precompile responses succeed.
        vm.mockCall(
            BudlumUniversal.PRECOMPILE,
            bytes(""),
            abi.encode(true, bytes(hex"cafe"))
        );
        (bool ok, bytes memory ret) = caller.doStaticCall(BudlumUniversal.EE_WASM, hex"01", hex"abcd", 50_000);
        assertTrue(ok && keccak256(ret) == keccak256(hex"cafe"), "valid B001 precompile response must decode");

        vm.mockCall(BudlumUol.UOL_PRECOMPILE, bytes(""), abi.encode(bytes32(uint256(1))));
        bytes32 createdOffer = caller.uolOffer(bytes32(uint256(1)), bytes32(uint256(2)), hex"01", hex"02", 10, 99);
        assertEq(createdOffer, bytes32(uint256(1)), "valid B002 offer response must decode");
        assertTrue(caller.uolAccept(createdOffer), "valid B002 accept response must decode");
    }
}
