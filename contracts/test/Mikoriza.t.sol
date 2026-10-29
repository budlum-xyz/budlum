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
        vm.expectPartialRevert(BudlumRegistrar.AlreadyReported.selector);
        registrar.reportAllocation(OPERATOR);
        vm.roll(block.number + 1);
        registrar.reportAllocation(OPERATOR);
    }

    function test_an_unbound_operator_cannot_be_reported() public {
        vm.expectPartialRevert(BudlumRegistrar.NotBound.selector);
        registrar.reportAllocation(OPERATOR);
    }

    function test_only_the_slasher_slashes() public {
        vm.expectPartialRevert(BudlumRegistrar.OnlySlasher.selector);
        registrar.slashForDoubleVote(OPERATOR, "x");
    }

    function test_the_slasher_refuses_two_signatures_of_one_hash() public {
        BudlumSlasher slasher = registrar.slasher();
        vm.expectPartialRevert(BudlumSlasher.SameHash.selector);
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
        // A golden vector, not a re-encoding of the encoder under test: these
        // are the bytes the Rust implementation produces for
        // `checkpoint_signing_message(45261, 3, 40, "ab")`. The Rust test
        // `the_checkpoint_preimage_is_the_one_the_slasher_golden_vector_pins`
        // (src/chain/finality.rs) asserts the identical literal, so the two
        // implementations are pinned to one another: neither side can drift
        // without the other's test failing.
        bytes memory expected =
            hex"4255444c554d5f505245434f4d4d49545f5632424c535f5349475f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f504f505fcdb0000000000000030000000000000028000000000000006162";
        assertEq(keccak256(message), keccak256(expected), "checkpoint_signing_message");
    }

    function test_a_compressed_key_without_the_compression_flag_does_not_match() public pure {
        assertTrue(!BudlumBls.g2Matches(new bytes(96), new bytes(256)), "flags required");
    }

    function test_bls_rejects_identity_keys_signatures_and_generator_before_pairing() public view {
        bytes memory compressed = new bytes(96);
        compressed[0] = 0x80; // Pretend the all-zero affine point is compressed.
        bytes memory identityG2 = new bytes(256);
        bytes memory identityG1 = new bytes(128);
        assertTrue(!BudlumBls.g2Matches(compressed, identityG2), "identity key cannot match");

        // These need not be valid points: all three calls must return false
        // before the EIP-2537 precompiles, including on the Cancun CI profile.
        bytes memory nonzeroG2 = new bytes(256);
        bytes memory nonzeroG1 = new bytes(128);
        nonzeroG2[255] = 0x01;
        nonzeroG1[127] = 0x01;
        assertTrue(!BudlumBls.verify(identityG2, "message", identityG1, nonzeroG2), "identity key");
        assertTrue(!BudlumBls.verify(nonzeroG2, "message", identityG1, nonzeroG2), "identity signature");
        assertTrue(!BudlumBls.verify(nonzeroG2, "message", nonzeroG1, identityG2), "identity generator");
    }
}
