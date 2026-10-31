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
        bytes32 row = bindingKey(validator, operator);
        bindings[row] = Binding({operator: operator, compressedKey: compressedKey, uncompressedKey: hex"01"});
        // The history the slasher checks, written the way `bind` writes it.
        boundKeys[row][keccak256(hex"01")] = true;
        validatorOf[operator] = validator;
    }

    /// The retire-on-move branch `bind` takes, without the BLS check it sits
    /// behind: it is the same internal helpers `bind` runs.
    function forceMove(address operator, bytes32 validator, bytes memory compressedKey) external {
        _retireMovedRow(operator, validator, compressedKey);
    }

    /// A rebind that replaces the live row and records the new key in the
    /// history, the way `bind` does once the BLS check has passed.
    function forceRebind(
        address operator,
        bytes32 validator,
        bytes memory compressedKey,
        bytes memory uncompressedKey
    ) external {
        bytes32 row = bindingKey(validator, operator);
        bindings[row] =
            Binding({operator: operator, compressedKey: compressedKey, uncompressedKey: uncompressedKey});
        boundKeys[row][keccak256(uncompressedKey)] = true;
        validatorOf[operator] = validator;
    }
}

contract MikorizaTest is Harness {
    AllocationManagerStub internal manager;
    RegistrarHarness internal registrar;
    address internal constant OPERATOR = address(0x0A0A0a0a0a0a0a0A0a0a0A0a0A0A0A0a0a0a0a0a);
    address internal constant OTHER_OPERATOR = address(0x0B0b0b0b0B0B0B0B0b0b0b0b0B0B0B0B0B0b0B0b);

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
                operator: OPERATOR,
                epoch: 1,
                height: 10,
                hashA: hex"aa",
                negSigA: hex"",
                hashB: hex"aa",
                negSigB: hex""
            }),
            hex"",
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

    /// The finding: one operator-set member used to occupy a validator's only
    /// slot for good. A binding is now the operator's own claim, so a claim by
    /// someone else cannot take it away and cannot be blocked by it either.
    function test_two_operators_claim_one_validator_without_a_lock() public {
        bytes32 validator = bytes32(uint256(2));
        registrar.forceBind(OPERATOR, validator, hex"aa");
        registrar.forceBind(OTHER_OPERATOR, validator, hex"bb");
        assertEq(keccak256(registrar.compressedKeyOf(validator, OPERATOR)), keccak256(hex"aa"), "first claim kept");
        assertEq(
            keccak256(registrar.compressedKeyOf(validator, OTHER_OPERATOR)), keccak256(hex"bb"), "second claim is its own"
        );
    }

    /// A rebinding replaces the operator's own claim (the key rotated, or the
    /// operator moved) and the validator slot is not burned by the first one.
    function test_an_operator_rebinds_itself() public {
        bytes32 validator = bytes32(uint256(2));
        registrar.forceBind(OPERATOR, validator, hex"aa");
        registrar.forceBind(OPERATOR, validator, hex"cc");
        assertEq(keccak256(registrar.compressedKeyOf(validator, OPERATOR)), keccak256(hex"cc"), "rebound");
    }

    /// A move to another validator with the same key retires the row it
    /// leaves behind: one key never stands behind two validators at once.
    function test_a_move_with_the_same_key_retires_the_old_row() public {
        bytes32 from = bytes32(uint256(2));
        bytes32 to = bytes32(uint256(3));
        registrar.forceBind(OPERATOR, from, hex"aa");
        registrar.forceMove(OPERATOR, to, hex"aa");
        assertEq(registrar.compressedKeyOf(from, OPERATOR).length, 0, "old row retired");
    }

    /// A rotated key is a different key, so the earlier claim stays its own.
    function test_a_move_with_a_rotated_key_keeps_the_earlier_claim() public {
        bytes32 from = bytes32(uint256(2));
        bytes32 to = bytes32(uint256(3));
        registrar.forceBind(OPERATOR, from, hex"aa");
        registrar.forceMove(OPERATOR, to, hex"bb");
        assertEq(keccak256(registrar.compressedKeyOf(from, OPERATOR)), keccak256(hex"aa"), "kept");
    }

    /// A report is the reporting operator's own claim: another operator's key
    /// for the same validator is neither used nor enough to report.
    function test_an_allocation_is_reported_from_the_reporting_operators_own_claim() public {
        bytes32 validator = bytes32(uint256(2));
        manager.setMember(OPERATOR, 32 ether);
        manager.setMember(OTHER_OPERATOR, 64 ether);
        registrar.forceBind(OPERATOR, validator, hex"aa");
        vm.expectPartialRevert(BudlumRegistrar.NotBound.selector);
        registrar.reportAllocation(OTHER_OPERATOR);
        registrar.forceBind(OTHER_OPERATOR, validator, hex"bb");
        assertEq(registrar.reportAllocation(OPERATOR), 32e9, "the first operator's own stake");
        assertEq(registrar.reportAllocation(OTHER_OPERATOR), 64e9, "the second operator's own stake");
    }

    /// The slasher checks the evidence against the key the named operator
    /// bound, so an operator that has not bound the validator cannot be
    /// slashed on someone else's key.
    function test_the_slasher_slashes_only_the_named_operators_own_key() public {
        BudlumSlasher slasher = registrar.slasher();
        bytes32 validator = bytes32(uint256(2));
        registrar.forceBind(OPERATOR, validator, hex"aa");
        vm.expectPartialRevert(BudlumSlasher.NotBound.selector);
        slasher.slashDoubleVote(
            DoubleVote({
                budlumValidator: validator,
                operator: OTHER_OPERATOR,
                epoch: 1,
                height: 10,
                hashA: hex"aa",
                negSigA: new bytes(128),
                hashB: hex"bb",
                negSigB: new bytes(128)
            }),
            hex"01",
            bytes("generator")
        );
    }

    /// The same evidence naming the operator that did bind reaches the
    /// signature check instead: the bound key is the one verified, and a
    /// one-byte harness key is refused before the pairing precompile.
    function test_the_slasher_verifies_the_named_operators_bound_key() public {
        BudlumSlasher slasher = registrar.slasher();
        bytes32 validator = bytes32(uint256(2));
        registrar.forceBind(OPERATOR, validator, hex"aa");
        vm.expectPartialRevert(BudlumSlasher.SignatureInvalid.selector);
        slasher.slashDoubleVote(
            DoubleVote({
                budlumValidator: validator,
                operator: OPERATOR,
                epoch: 1,
                height: 10,
                hashA: hex"aa",
                negSigA: new bytes(128),
                hashB: hex"bb",
                negSigB: new bytes(128)
            }),
            hex"01",
            bytes("generator")
        );
    }

    /// The high finding: an operator that double votes and then rebinds to a
    /// fresh key must stay slashable on the key that signed. The slasher now
    /// takes the evidenced key and asks the registrar whether the operator
    /// ever bound it, never what it holds now.
    function test_a_rebound_key_stays_accountable() public {
        bytes32 validator = bytes32(uint256(2));
        registrar.forceBind(OPERATOR, validator, hex"aa");
        // A rotation: the live row now holds another key.
        registrar.forceRebind(OPERATOR, validator, hex"bb", hex"02");
        assertEq(keccak256(registrar.compressedKeyOf(validator, OPERATOR)), keccak256(hex"bb"), "live row moved");
        assertTrue(registrar.wasBound(validator, OPERATOR, hex"01"), "the key that signed is still answerable");
        assertTrue(registrar.wasBound(validator, OPERATOR, hex"02"), "the key it rotated to is too");
        assertTrue(!registrar.wasBound(validator, OPERATOR, hex"ff"), "a key never bound is not");
    }
}
