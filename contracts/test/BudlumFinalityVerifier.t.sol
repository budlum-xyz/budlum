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

/// F01-F06 negative tests. The default
/// profile runs on Cancun, which has neither the BLS nor the ML-DSA
/// precompile, so every attestation takes the optimistic path. The
/// deployment rule (item 2): no deployment while any of these is red.
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
    function test_F02_missing_precompiles_keep_the_attestation_pending() public {
        bytes32 digest = verifier.verify(_attestation(42, bytes32(uint256(7))));
        assertTrue(!verifier.isAccepted(digest), "pending is not accepted");
        vm.expectPartialRevert(BudlumFinalityVerifier.ChallengeWindowOpen.selector);
        verifier.settle(digest);
        vm.roll(block.number + WINDOW);
        verifier.settle(digest);
        assertTrue(verifier.isAccepted(digest), "accepted after the window");
        assertTrue(verifier.heightFinal(42), "height final");
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
        Attestation memory a = _attestation(42, bytes32(uint256(7)));
        bytes32 digest = verifier.verify(a);
        fraud.set(true);
        verifier.challenge(digest, hex"01");
        vm.roll(block.number + WINDOW);
        vm.expectPartialRevert(BudlumFinalityVerifier.ChallengeResolved.selector);
        verifier.settle(digest);
        vm.expectPartialRevert(BudlumFinalityVerifier.AlreadyFraudulent.selector);
        verifier.verify(a);
    }

    function test_F05_a_rejected_fraud_proof_leaves_the_window_open() public {
        bytes32 digest = verifier.verify(_attestation(42, bytes32(uint256(7))));
        vm.expectPartialRevert(BudlumFinalityVerifier.FraudProofRejected.selector);
        verifier.challenge(digest, hex"01");
    }

    // F06: one pending claim per height.
    function test_F06_a_second_root_for_a_pending_height_is_refused() public {
        verifier.verify(_attestation(42, bytes32(uint256(7))));
        vm.expectPartialRevert(BudlumFinalityVerifier.PendingAttestation.selector);
        verifier.verify(_attestation(42, bytes32(uint256(8))));
    }

    function test_F06_a_conflicting_root_after_finality_is_refused() public {
        bytes32 digest = verifier.verify(_attestation(42, bytes32(uint256(7))));
        vm.roll(block.number + WINDOW);
        verifier.settle(digest);
        vm.expectPartialRevert(BudlumFinalityVerifier.ConflictingRoot.selector);
        verifier.verify(_attestation(42, bytes32(uint256(8))));
    }
}
