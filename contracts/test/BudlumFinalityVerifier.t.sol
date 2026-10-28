// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {
    Attestation,
    BudlumFinalityVerifier,
    IExternalFraudProofVerifier
} from "../external-domain/BudlumFinalityVerifier.sol";

/// A fraud verifier whose answer the test sets.
contract FraudVerifierStub is IExternalFraudProofVerifier {
    bool public answer;

    function set(bool value) external {
        answer = value;
    }

    function verifyFraud(bytes32, bytes calldata) external view returns (bool) {
        return answer;
    }
}

/// F01-F06 negative tests. The default profile runs on Cancun, which has
/// neither the BLS nor the ML-DSA precompile: an attestation with no
/// verification path at all is refused, and the window tests deploy a
/// verifier against mocked BLS precompiles to exercise the BLS-only regime
/// (ML-DSA still absent). The deployment rule (item 2): no deployment while
/// any of these is red.
contract BudlumFinalityVerifierTest is Harness {
    uint64 internal constant CHAIN = 45_261;
    uint256 internal constant WINDOW = 10;

    FraudVerifierStub internal fraud;
    BudlumFinalityVerifier internal verifier;

    bytes internal committee = _filled(256, 0x02);
    bytes internal generator = _filled(256, 0x03);
    bytes internal mlDsaKey = _filled(1952, 0x06);

    function setUp() public {
        fraud = new FraudVerifierStub();
        verifier = new BudlumFinalityVerifier(
            CHAIN, WINDOW, address(fraud), keccak256(committee), keccak256(generator), keccak256(mlDsaKey)
        );
    }

    function _filled(uint256 len, uint8 value) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = bytes1(value);
        }
    }

    function _attestation(uint64 height, bytes32 root) internal view returns (Attestation memory) {
        return Attestation({
            height: height,
            stateRoot: root,
            epoch: 3,
            chainId: CHAIN,
            g2AggregatePubkey: committee,
            g2Generator: generator,
            g1NegSignature: _filled(128, 0x04),
            mlDsaSignature: _filled(3309, 0x05),
            mlDsaPubkey: mlDsaKey,
            mlDsaEthVariant: false
        });
    }

    /// A verifier constructed where only the BLS suite answers: pairing,
    /// G1 add and map-Fp-to-G1 mocked on the reserved addresses (Cancun has
    /// none of them), ML-DSA left absent. The constructor probes the pairing
    /// while the mocks are active, so `hasBlsPrecompile` latches true and
    /// `hasMlDsaPrecompile` stays false - the BLS-only regime. The mocks
    /// place no code at the addresses, so the probes still see them as
    /// codeless reserved addresses.
    function _blsOnlyVerifier() internal returns (BudlumFinalityVerifier) {
        bytes memory g1 = new bytes(128);
        vm.mockCall(address(0x0b), bytes(""), g1);
        vm.mockCall(address(0x10), bytes(""), g1);
        vm.mockCall(address(0x0f), bytes(""), abi.encode(uint256(1)));
        return new BudlumFinalityVerifier(
            CHAIN, WINDOW, address(fraud), keccak256(committee), keccak256(generator), keccak256(mlDsaKey)
        );
    }

    // F01: the trust anchor is the constructor; zero hashes and an EOA fraud
    // verifier are refused.
    function test_F01_constructor_refuses_zero_key_hashes() public {
        vm.expectPartialRevert(BudlumFinalityVerifier.UntrustedKey.selector);
        new BudlumFinalityVerifier(CHAIN, WINDOW, address(fraud), bytes32(0), keccak256(generator), keccak256(mlDsaKey));
    }

    function test_F01_constructor_refuses_an_eoa_fraud_verifier() public {
        vm.expectPartialRevert(BudlumFinalityVerifier.FraudProofVerifierNotContract.selector);
        new BudlumFinalityVerifier(
            CHAIN, WINDOW, address(0xBEEF), keccak256(committee), keccak256(generator), keccak256(mlDsaKey)
        );
    }

    // F02: a missing precompile leaves the attestation pending, never accepted,
    // until the window closes.
    // F02: a chain with no verification precompile for either half refuses
    // the attestation outright; it does not open a window nothing could
    // ever have checked.
    function test_F02_an_attestation_with_no_verification_path_is_refused() public {
        vm.expectPartialRevert(BudlumFinalityVerifier.NoVerificationPath.selector);
        verifier.verify(_attestation(42, bytes32(uint256(7))));
    }

    // F02 (BLS-only regime): with the classical half verified and ML-DSA
    // still absent, the post-quantum half takes the window and settles after
    // it, the event's weaker guarantee made explicit by the pending state.
    function test_F02_a_chain_without_ml_dsa_keeps_the_attestation_pending() public {
        BudlumFinalityVerifier bls = _blsOnlyVerifier();
        bytes32 digest = bls.verify(_attestation(42, bytes32(uint256(7))));
        assertTrue(!bls.isAccepted(digest), "pending is not accepted");
        vm.expectPartialRevert(BudlumFinalityVerifier.ChallengeWindowOpen.selector);
        bls.settle(digest);
        vm.roll(block.number + WINDOW);
        bls.settle(digest);
        assertTrue(bls.isAccepted(digest), "accepted after the window");
        assertTrue(bls.heightFinal(42), "height final");
    }

    // F03: the probes do not mistake an empty address for a precompile.
    function test_F03_probes_report_no_precompile_on_cancun() public view {
        assertTrue(!verifier.hasBlsPrecompile(), "no BLS precompile");
        assertTrue(!verifier.hasMlDsaPrecompile(), "no ML-DSA precompile");
    }

    // F04: the attestation binds the chain and the pinned keys.
    function test_F04_wrong_chain_is_refused() public {
        Attestation memory a = _attestation(42, bytes32(uint256(7)));
        a.chainId = CHAIN + 1;
        vm.expectPartialRevert(BudlumFinalityVerifier.WrongChainId.selector);
        verifier.verify(a);
    }

    function test_F04_an_unpinned_committee_key_is_refused() public {
        Attestation memory a = _attestation(42, bytes32(uint256(7)));
        a.g2AggregatePubkey = _filled(256, 0x09);
        vm.expectPartialRevert(BudlumFinalityVerifier.UntrustedKey.selector);
        verifier.verify(a);
    }

    // F05: a proven fraud is terminal: no settle, no re-verify.
    function test_F05_a_proven_fraud_is_terminal() public {
        BudlumFinalityVerifier bls = _blsOnlyVerifier();
        Attestation memory a = _attestation(42, bytes32(uint256(7)));
        bytes32 digest = bls.verify(a);
        fraud.set(true);
        bls.challenge(digest, hex"01");
        vm.roll(block.number + WINDOW);
        vm.expectPartialRevert(BudlumFinalityVerifier.ChallengeResolved.selector);
        bls.settle(digest);
        vm.expectPartialRevert(BudlumFinalityVerifier.AlreadyFraudulent.selector);
        bls.verify(a);
    }

    function test_F05_a_rejected_fraud_proof_leaves_the_window_open() public {
        BudlumFinalityVerifier bls = _blsOnlyVerifier();
        bytes32 digest = bls.verify(_attestation(42, bytes32(uint256(7))));
        vm.expectPartialRevert(BudlumFinalityVerifier.FraudProofRejected.selector);
        bls.challenge(digest, hex"01");
    }

    // F06: one pending claim per height.
    function test_F06_a_second_root_for_a_pending_height_is_refused() public {
        BudlumFinalityVerifier bls = _blsOnlyVerifier();
        bls.verify(_attestation(42, bytes32(uint256(7))));
        vm.expectPartialRevert(BudlumFinalityVerifier.PendingAttestation.selector);
        bls.verify(_attestation(42, bytes32(uint256(8))));
    }

    function test_F06_a_conflicting_root_after_finality_is_refused() public {
        BudlumFinalityVerifier bls = _blsOnlyVerifier();
        bytes32 digest = bls.verify(_attestation(42, bytes32(uint256(7))));
        vm.roll(block.number + WINDOW);
        bls.settle(digest);
        vm.expectPartialRevert(BudlumFinalityVerifier.ConflictingRoot.selector);
        bls.verify(_attestation(42, bytes32(uint256(8))));
    }
}
