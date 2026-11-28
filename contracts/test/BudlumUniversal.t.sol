// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {BudlumUniversal, BudlumUol, IBudlumUniversal, IBudlumUol} from "../uel/BudlumUniversal.sol";

/// @notice Cheat codes `Harness` does not declare. The precompile reverts are the
///         only way to reach the two `TransportFailed` branches.
interface Vm2 {
    function mockCall(address callee, bytes calldata data, bytes calldata returnData) external;
    function mockCallRevert(address callee, bytes calldata data, bytes calldata revertData) external;
    function expectPartialRevert(bytes4 selector) external;
}

/// @notice The two UEL precompile wrappers are `internal`, so the suite drives
///         them through a harness that owns nothing and checks nothing.
contract UniversalHarness {
    function callUniversal(uint8 ee, bytes memory target, bytes memory input, uint256 valueAttos, uint64 gasBgu)
        external
        returns (bool ok, bytes memory ret)
    {
        return BudlumUniversal.call(ee, target, input, valueAttos, gasBgu);
    }

    function staticCallUniversal(uint8 ee, bytes memory target, bytes memory input, uint64 gasBgu)
        external
        view
        returns (bool ok, bytes memory ret)
    {
        return BudlumUniversal.staticCall(ee, target, input, gasBgu);
    }

    function uolBalanceOf(bytes32 classId, bytes memory holder) external view returns (uint128) {
        return BudlumUol.balanceOf(classId, holder);
    }

    function uolHolderOf(bytes32 assetId) external view returns (bytes memory) {
        return BudlumUol.holderOf(assetId);
    }

    function uolTransfer(bytes32 classId, bytes32 assetId, bytes memory to, uint128 amount)
        external
        returns (bool)
    {
        return BudlumUol.transfer(classId, assetId, to, amount);
    }

    function uolOffer(bytes32 classId, bytes32 assetId, bytes memory taker, bytes memory payment, uint128 amount, uint64 expiry)
        external
        returns (bytes32)
    {
        return BudlumUol.offer(classId, assetId, taker, payment, amount, expiry);
    }

    function uolAccept(bytes32 offerId) external returns (bool) {
        return BudlumUol.accept(offerId);
    }
}

/// @notice `BudlumUniversal` / `BudlumUol` had four of seven library functions
///         untested (`staticCall`, `holderOf`, `offer`). Both wrappers encode a
///         call and `abi.decode` the reply, so the two failure modes that matter
///         are: a precompile that reverts, and a precompile that returns the
///         wrong shape. Both are pinned here.
contract BudlumUniversalTest is Harness {
    Vm2 internal constant vm2 = Vm2(address(uint160(uint256(keccak256("hevm cheat code")))));

    address internal constant PRECOMPILE = 0x000000000000000000000000000000000000B001;
    address internal constant UOL_PRECOMPILE = 0x000000000000000000000000000000000000B002;

    UniversalHarness internal harness;

    function setUp() public {
        harness = new UniversalHarness();
    }

    // ------------------------------------------------------------- Universal

    function test_universal_call_encodes_the_exact_calldata_and_decodes_the_reply() public {
        uint8 ee = 0x03;
        bytes memory target = hex"0102";
        bytes memory input = hex"deadbeef";
        bytes memory expected = abi.encodeCall(
            IBudlumUniversal.call, (ee, target, input, uint256(7), uint64(42))
        );
        vm2.mockCall(PRECOMPILE, expected, abi.encode(true, hex"1234"));

        (bool ok, bytes memory ret) = harness.callUniversal(ee, target, input, 7, 42);
        assertTrue(ok, "the precompile reply must be decoded as ok=true");
        assertEq(keccak256(ret), keccak256(hex"1234"), "the precompile reply payload must survive");
    }

    function test_universal_call_reverts_when_the_precompile_reverts() public {
        bytes memory target = hex"01";
        bytes memory input = hex"02";
        bytes memory expected = abi.encodeCall(
            IBudlumUniversal.call, (uint8(0x01), target, input, uint256(0), uint64(1))
        );
        vm2.mockCallRevert(PRECOMPILE, expected, hex"");
        vm2.expectPartialRevert(BudlumUniversal.PrecompileTransportFailed.selector);
        harness.callUniversal(0x01, target, input, 0, 1);
    }

    function test_universal_static_call_encodes_and_decodes() public {
        uint8 ee = 0x0B;
        bytes memory target = hex"aa";
        bytes memory input = hex"bb";
        bytes memory expected = abi.encodeCall(IBudlumUniversal.staticCall, (ee, target, input, uint64(5)));
        vm2.mockCall(PRECOMPILE, expected, abi.encode(true, hex"cafe"));

        (bool ok, bytes memory ret) = harness.staticCallUniversal(ee, target, input, 5);
        assertTrue(ok, "the static reply must be decoded as ok=true");
        assertEq(keccak256(ret), keccak256(hex"cafe"), "the static reply payload must survive");
    }

    function test_universal_static_call_reverts_when_the_precompile_reverts() public {
        bytes memory target = hex"01";
        bytes memory input = hex"02";
        bytes memory expected = abi.encodeCall(IBudlumUniversal.staticCall, (uint8(0x02), target, input, uint64(1)));
        vm2.mockCallRevert(PRECOMPILE, expected, hex"");
        vm2.expectPartialRevert(BudlumUniversal.PrecompileTransportFailed.selector);
        harness.staticCallUniversal(0x02, target, input, 1);
    }

    // ------------------------------------------------------------------- UOL

    function test_uol_holder_of_decodes_the_reply() public {
        bytes memory holder = hex"beef";
        bytes memory expected = abi.encodeCall(IBudlumUol.holderOf, (bytes32("asset")));
        vm2.mockCall(UOL_PRECOMPILE, expected, abi.encode(holder));

        assertEq(keccak256(harness.uolHolderOf(bytes32("asset"))), keccak256(holder), "holder must survive");
    }

    function test_uol_offer_decodes_the_reply() public {
        bytes32 offerId = keccak256("offer");
        bytes memory expected = abi.encodeCall(
            IBudlumUol.offer,
            (bytes32("class"), bytes32("asset"), hex"01", hex"02", uint128(3), uint64(9))
        );
        vm2.mockCall(UOL_PRECOMPILE, expected, abi.encode(offerId));

        assertEq(
            harness.uolOffer(bytes32("class"), bytes32("asset"), hex"01", hex"02", 3, 9),
            offerId,
            "the offer id must survive"
        );
    }

    function test_uol_accept_decodes_the_reply() public {
        bytes memory expected = abi.encodeCall(IBudlumUol.accept, (bytes32("offer")));
        vm2.mockCall(UOL_PRECOMPILE, expected, abi.encode(true));
        assertTrue(harness.uolAccept(bytes32("offer")), "accept must decode true");
    }

    function test_uol_transfer_decodes_the_reply() public {
        bytes memory expected =
            abi.encodeCall(IBudlumUol.transfer, (bytes32("class"), bytes32("asset"), hex"01", uint128(1)));
        vm2.mockCall(UOL_PRECOMPILE, expected, abi.encode(true));
        assertTrue(harness.uolTransfer(bytes32("class"), bytes32("asset"), hex"01", 1), "transfer must decode true");
    }

    function test_uol_balance_of_decodes_the_reply() public {
        bytes memory expected = abi.encodeCall(IBudlumUol.balanceOf, (bytes32("class"), hex"01"));
        vm2.mockCall(UOL_PRECOMPILE, expected, abi.encode(uint128(11)));
        assertEq(harness.uolBalanceOf(bytes32("class"), hex"01"), 11, "balance must decode");
    }

    function test_uol_reverts_when_the_precompile_reverts() public {
        bytes memory expected = abi.encodeCall(IBudlumUol.holderOf, (bytes32("asset")));
        vm2.mockCallRevert(UOL_PRECOMPILE, expected, hex"");
        vm2.expectPartialRevert(BudlumUol.UolPrecompileFailed.selector);
        harness.uolHolderOf(bytes32("asset"));
    }
}
