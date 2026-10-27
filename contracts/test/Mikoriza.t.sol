// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {BudlumBls} from "../lib/BudlumBls.sol";
import {BudlumRegistrar} from "../mikoriza/BudlumRegistrar.sol";
import {BudlumSlasher, DoubleVote} from "../mikoriza/BudlumSlasher.sol";
import {IAllocationManager, OperatorSet, SlashingParams} from "../mikoriza/IAllocationManager.sol";

contract AllocationManagerStub is IAllocationManager {
    mapping(address => bool) public members;
    mapping(address => uint256) public stake;
    address public lastSlashed;

    function setMember(address operator, uint256 amount) external {
        members[operator] = true;
        stake[operator] = amount;
    }

    function getMinimumSlashableStake(OperatorSet memory, address[] memory operators, address[] memory strategies, uint32)
        external
        view
        returns (uint256[][] memory out)
    {
        out = new uint256[][](operators.length);
        for (uint256 i = 0; i < operators.length; i++) {
            out[i] = new uint256[](strategies.length);
            out[i][0] = stake[operators[i]];
        }
    }

    function isMemberOfOperatorSet(address operator, OperatorSet memory) external view returns (bool) {
        return members[operator];
    }

    function slashOperator(address, SlashingParams calldata params)
        external
        returns (uint256, uint256[] memory shares)
    {
        lastSlashed = params.operator;
        shares = new uint256[](params.strategies.length);
        return (1, shares);
    }
}

/// The registrar with the binding step opened for tests: the BLS check
/// needs the EIP-2537 precompiles, which the Cancun profile lacks.
contract RegistrarHarness is BudlumRegistrar {
    constructor(IAllocationManager manager, address[] memory strategies_)
        BudlumRegistrar(manager, 1, strategies_, 45_261, keccak256("generator"), 1e17)
    {}

    function forceBind(address operator, bytes32 validator, bytes memory compressedKey) external {
        bindings[validator] = Binding({operator: operator, compressedKey: compressedKey, uncompressedKey: hex"01"});
        validatorOf[operator] = validator;
    }
}

contract MikorizaTest is Harness {
    AllocationManagerStub internal manager;
    RegistrarHarness internal registrar;
    address internal constant OPERATOR = address(0x0A0A0a0a0a0a0a0A0a0a0A0a0A0A0A0a0a0a0a0a);

    function setUp() public {
        manager = new AllocationManagerStub();
        address[] memory strategies = new address[](1);
        strategies[0] = address(0x5);
        registrar = new RegistrarHarness(manager, strategies);
    }

    /// Same values as `allocation_hashes_match_the_solidity_known_answers` in
    /// src/settlement/shared_security.rs.
    function test_allocation_hashes_match_the_rust_known_answers() public view {
        bytes memory key = new bytes(96);
        for (uint256 i = 0; i < 96; i++) {
            key[i] = 0xB1;
        }
        assertEq(
            registrar.allocationPayloadHash(
                bytes32(uint256(0x0202020202020202020202020202020202020202020202020202020202020202)),
                OPERATOR,
                1000,
                5,
                key
            ),
            0xc96d2795c2307e106fd9c6098059b2ad146ed8499feba20254d53775b209e1b2,
            "allocation payload hash"
        );
        assertEq(
            registrar.operatorCorrelation(OPERATOR),
            0x1d4cf8803bf3fbf7ec0ac2dc3bd646223ffae6bd5a90caf226a8fcb80ac54b3e,
            "operator correlation"
        );
    }

    function test_an_allocation_is_reported_in_gwei_once_per_block() public {
        manager.setMember(OPERATOR, 32 ether);
        registrar.forceBind(OPERATOR, bytes32(uint256(2)), new bytes(96));
        assertEq(registrar.reportAllocation(OPERATOR), 32e9, "units are gwei");
        vm.expectRevert(BudlumRegistrar.AlreadyReported.selector);
        registrar.reportAllocation(OPERATOR);
        vm.roll(block.number + 1);
        registrar.reportAllocation(OPERATOR);
    }

    function test_an_unbound_operator_cannot_be_reported() public {
        vm.expectRevert(BudlumRegistrar.NotBound.selector);
        registrar.reportAllocation(OPERATOR);
    }

    function test_only_the_slasher_slashes() public {
        vm.expectRevert(BudlumRegistrar.OnlySlasher.selector);
        registrar.slashForDoubleVote(OPERATOR, "x");
    }

    function test_the_slasher_refuses_two_signatures_of_one_hash() public {
        BudlumSlasher slasher = registrar.slasher();
        vm.expectRevert(BudlumSlasher.SameHash.selector);
        slasher.slashDoubleVote(
            DoubleVote({
                budlumValidator: bytes32(uint256(2)),
                epoch: 1,
                height: 10,
                hashA: hex"aa",
                negSigA: hex"",
                hashB: hex"aa",
                negSigB: hex""
            }),
            hex""
        );
    }

    function test_the_slasher_signs_the_rust_checkpoint_message() public {
        BudlumSlasher slasher = registrar.slasher();
        bytes memory message = slasher.checkpointSigningMessage(3, 40, "ab");
        assertEq(
            keccak256(message),
            keccak256(
                abi.encodePacked(
                    "BUDLUM_PRECOMMIT_V2",
                    "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_",
                    hex"cdb0000000000000",
                    hex"0300000000000000",
                    hex"2800000000000000",
                    "ab"
                )
            ),
            "checkpoint_signing_message"
        );
    }

    function test_a_compressed_key_without_the_compression_flag_does_not_match() public pure {
        assertTrue(!BudlumBls.g2Matches(new bytes(96), new bytes(256)), "flags required");
    }
}
