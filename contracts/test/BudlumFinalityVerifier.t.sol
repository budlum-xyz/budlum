// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {
    Attestation,
    BudlumFinalityVerifier,
    IExternalFraudProofVerifier
} from "../external-domain/BudlumFinalityVerifier.sol";
import {BudlumHash} from "../lib/BudlumHash.sol";
import {BudlumObjectLayerFinality, IBudlumHeaderFinality} from "../object-layer/BudlumFinalityVerifier.sol";
import {BudlumSettlementEndpoint, IBudlumObjectLayerFinality} from "../object-layer/BudlumSettlementEndpoint.sol";

/// Test tokens: both mutations must roll back when the endpoint refuses custody.
contract CustodyErc20 {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract CustodyErc721 {
    mapping(uint256 => address) public ownerOf;

    function mint(address to, uint256 id) external {
        ownerOf[id] = to;
    }

    function safeTransferFrom(address from, address to, uint256 id) external {
        require(ownerOf[id] == from, "owner");
        ownerOf[id] = to;
        bytes4 received = BudlumSettlementEndpoint(to).onERC721Received(msg.sender, from, id, "");
        require(received == BudlumSettlementEndpoint.onERC721Received.selector, "receiver");
    }
}

/// A finality boolean alone is not a usable header opening.
contract BooleanOnlyFinality is IBudlumObjectLayerFinality {
    function heightFinal(uint64) external pure returns (bool) {
        return true;
    }

    function headerAt(uint64) external pure returns (bytes32) {
        return bytes32(0);
    }
}

/// Only the test fixture may install a finalized root without BLS/ML-DSA.
contract SeededFinalityVerifier is BudlumFinalityVerifier {
    constructor(address fraud)
        BudlumFinalityVerifier(45_261, 10, fraud, bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)))
    {}

    function seedFinalized(uint64 height, bytes32 stateRoot) external {
        heightFinal[height] = true;
        rootAtHeight[height] = stateRoot;
    }
}

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

/// negative tests. The default profile runs on Cancun, which has
/// neither the BLS nor the ML-DSA precompile: an attestation with no
/// verification path at all is refused. The window tests (F02 pending, F05,
/// F06) run under the `prague` profile, where the real EIP-2537 pairing
/// precompile answers and ML-DSA is still absent - the BLS-only regime the
/// challenge window exists for. Their BLS material is a valid fixture
/// generated from the Rust side (chain::finality::sign_bls under the Budlum
/// signature DST; root = signingRoot with foundry's chain id 31337), so the
/// classical half really verifies on prague and a mock can never stand in:
/// the probe rejects any address carrying code, which is exactly what
/// `vm.mockCall` places. The deployment rule (item 2): no deployment while
/// any of these is red.
contract BudlumFinalityVerifierTest is Harness {
    uint64 internal constant CHAIN = 45_261;
    uint256 internal constant WINDOW = 10;

    FraudVerifierStub internal fraud;
    BudlumFinalityVerifier internal verifier;

    // Valid BLS fixture: PK = sk*G2 and the signature over this suite's
    // signing root, generated on the Rust side (see the file header).
    bytes internal committee = hex"0000000000000000000000000000000003102696de47a8ff5f84b1e06a4c49f66d3d91db26aa983d9f682aa8dd40a04782774feade5b8283b66d110d932c98870000000000000000000000000000000016f2753675030c982f167778cccec6637d4a91b2c1942f879993d3af2562cfd982f0618f764a15b4dd369df28b35eb0b0000000000000000000000000000000001edbbe15bc722126ea27e155f354f5f89774ed035dd31077e6076eb702ce4ada29a68b8f2f523aa35407b818937c5df000000000000000000000000000000001273f61d9f71c16394cf54241a127dac1a380febcc1ee66eedb4859d7e17daa4dd6bcbdffbcd37c74ddbd9c9f1283dd9";
    bytes internal generator = hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
    bytes internal mlDsaKey = _filled(1952, 0x06);

    function setUp() public {
        fraud = new FraudVerifierStub();
        verifier = new BudlumFinalityVerifier(
            CHAIN, WINDOW, address(fraud), keccak256(committee), keccak256(generator), keccak256(mlDsaKey)
        );
    }

    function test_object_layer_header_requires_finalized_state_root_opening() public {
        SeededFinalityVerifier seeded = new SeededFinalityVerifier(address(fraud));
        BudlumObjectLayerFinality objectLayer = new BudlumObjectLayerFinality(IBudlumHeaderFinality(address(seeded)));
        BudlumSettlementEndpoint endpoint =
            new BudlumSettlementEndpoint(IBudlumObjectLayerFinality(address(objectLayer)), 100);
        uint64 height = 45;
        bytes32 body = bytes32(uint256(11));
        bytes32 header = bytes32(uint256(22));
        bytes[] memory fields = new bytes[](3);
        fields[0] = "BDLM_STATE_ROOT_GLOBAL_HEADER_V1";
        fields[1] = abi.encodePacked(body);
        fields[2] = abi.encodePacked(header);
        bytes32 stateRoot = BudlumHash.hashFields(fields);

        // Neither a fabricated checkpoint digest nor an unfinalized root can
        // mark a height final. The old synthetic digest was never accepted by
        // the attestation verifier and did not bind this header to its root.
        bytes32 oldDigest = keccak256(abi.encode("BDLM_OBJECT_LAYER_CHECKPOINT_V1", height, header));
        assertTrue(!seeded.isAccepted(oldDigest), "synthetic digest is not an attestation");
        vm.expectPartialRevert(BudlumObjectLayerFinality.NotAccepted.selector);
        objectLayer.record(height, header, body);
        seeded.seedFinalized(height, stateRoot);

        assertTrue(seeded.isFinalizedHeader(height, header, body), "canonical opening accepted");
        assertTrue(!seeded.isFinalizedHeader(height + 1, header, body), "height must be final");
        assertTrue(!seeded.isFinalizedHeader(height, header, bytes32(uint256(12))), "wrong body refused");
        assertTrue(!seeded.isFinalizedHeader(height, bytes32(uint256(23)), body), "wrong header refused");
        assertTrue(!seeded.isFinalizedHeader(height, bytes32(0), body), "zero header refused");
        vm.expectPartialRevert(BudlumObjectLayerFinality.NotAccepted.selector);
        objectLayer.record(height, bytes32(uint256(23)), body);
        vm.expectPartialRevert(BudlumObjectLayerFinality.NotAccepted.selector);
        objectLayer.record(height, header, bytes32(uint256(12)));
        assertTrue(!objectLayer.heightFinal(height), "failed openings cannot record a height");
        vm.expectPartialRevert(BudlumSettlementEndpoint.NotFinal.selector);
        endpoint.acceptHeader(height);
        assertEq(endpoint.lastAcceptedHeaderHash(), bytes32(0), "unrecorded header cannot reset clock");

        objectLayer.record(height, header, body);
        assertEq(objectLayer.headerAt(height), header, "only finalized header recorded");
        assertTrue(objectLayer.heightFinal(height), "authenticated header available");
        endpoint.acceptHeader(height);
        assertEq(endpoint.lastAcceptedHeaderHash(), header, "endpoint pins exact finalized header");
        assertEq(endpoint.lastAcceptedHeight(), height, "checkpoint height pinned with its hash");
        vm.expectPartialRevert(BudlumSettlementEndpoint.NotNewer.selector);
        endpoint.acceptHeader(height);
    }

    function test_closed_endpoint_derives_home_nft_identity_without_wrapping() public {
        BudlumObjectLayerFinality objectLayer =
            new BudlumObjectLayerFinality(IBudlumHeaderFinality(address(verifier)));
        BudlumSettlementEndpoint endpoint =
            new BudlumSettlementEndpoint(IBudlumObjectLayerFinality(address(objectLayer)), 100);
        address homeToken = address(0x1234);
        bytes32 classId = endpoint.assetClassId(7, 1, homeToken);
        bytes32 nft = endpoint.assetId(7, 1, homeToken, 42);
        // Independently computed from Rust's length-prefixed SHA-256 fields
        // (class kind 1 + 20-byte address, 32-byte big-endian token id).
        assertEq(classId, hex"576171f96ac9ae7b964102b486f5c4f88dfe7e7392c724fabd947d8185c6d35a", "class vector");
        assertEq(nft, hex"5d3daa94a35f601a36f79a53870d2245dc536e6efd31488a02a03c813cdb6a1e", "NFT vector");
        assertEq(endpoint.assetId(7, 1, homeToken, 42), nft, "round trip must retain home id");
        assertTrue(endpoint.assetId(8, 1, homeToken, 42) != nft, "home domain changes identity");
        assertTrue(endpoint.assetId(7, 1, homeToken, 43) != nft, "native token id changes identity");
        assertTrue(endpoint.assetId(7, 1, address(0x1235), 42) != nft, "class changes identity");
        assertTrue(endpoint.assetId(7, 0, homeToken, 0) != nft, "fungible identity differs");
        vm.expectPartialRevert(BudlumSettlementEndpoint.InvalidAssetClass.selector);
        endpoint.assetId(7, 0, homeToken, 42);
        vm.expectPartialRevert(BudlumSettlementEndpoint.InvalidAssetClass.selector);
        endpoint.assetClassId(7, 2, homeToken); // RecordV1 not active
        vm.expectPartialRevert(BudlumSettlementEndpoint.InvalidAssetClass.selector);
        endpoint.assetClassId(7, 1, address(0));
        vm.expectPartialRevert(BudlumSettlementEndpoint.NotOpen.selector);
        endpoint.release(abi.encode(classId, nft, address(this)));
        vm.expectPartialRevert(BudlumSettlementEndpoint.NotOpen.selector);
        endpoint.escape(abi.encode(classId, nft, address(this)));
    }

    function test_endpoint_rejects_finality_boolean_without_header_hash() public {
        BooleanOnlyFinality booleanOnly = new BooleanOnlyFinality();
        BudlumSettlementEndpoint endpoint =
            new BudlumSettlementEndpoint(IBudlumObjectLayerFinality(address(booleanOnly)), 100);
        vm.expectPartialRevert(BudlumSettlementEndpoint.NotFinal.selector);
        endpoint.acceptHeader(1);
        assertEq(endpoint.lastAcceptedHeight(), 0, "boolean cannot advance checkpoint");
        assertEq(endpoint.lastAcceptedHeaderHash(), bytes32(0), "no header was pinned");
    }

    function test_object_layer_ingress_is_closed_until_release_and_escape_work() public {
        BudlumObjectLayerFinality objectLayer =
            new BudlumObjectLayerFinality(IBudlumHeaderFinality(address(verifier)));
        BudlumSettlementEndpoint endpoint =
            new BudlumSettlementEndpoint(IBudlumObjectLayerFinality(address(objectLayer)), 100);
        address owner = address(this);
        CustodyErc20 erc20 = new CustodyErc20();
        erc20.mint(owner, 100);
        vm.expectPartialRevert(BudlumSettlementEndpoint.NotOpen.selector);
        endpoint.deposit20(address(erc20), 50, bytes32(uint256(1)));
        assertEq(erc20.balanceOf(owner), 100, "deposit must not debit ERC-20 owner");
        assertEq(erc20.balanceOf(address(endpoint)), 0, "no ERC-20 custody");

        CustodyErc721 erc721 = new CustodyErc721();
        erc721.mint(owner, 77);
        vm.expectPartialRevert(BudlumSettlementEndpoint.NotOpen.selector);
        erc721.safeTransferFrom(owner, address(endpoint), 77);
        assertTrue(erc721.ownerOf(77) == owner, "safe transfer must roll back NFT ownership");
        vm.expectPartialRevert(BudlumSettlementEndpoint.NotOpen.selector);
        endpoint.onERC721Received(owner, owner, 77, "");

        vm.expectPartialRevert(BudlumSettlementEndpoint.NotOpen.selector);
        endpoint.homeCall(hex"abcd");
        assertEq(endpoint.homeNonce(owner), 0, "closed home calls cannot advance nonce");
        vm.expectPartialRevert(BudlumSettlementEndpoint.NotOpen.selector);
        endpoint.release("");
        vm.expectPartialRevert(BudlumSettlementEndpoint.NotOpen.selector);
        endpoint.escape("");
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
            g1NegSignature: hex"0000000000000000000000000000000003bea287d52673a612814c670c22f1a2e93783abd10e2a18edfbc1f18c7a4f9c83d1564599baf31b2dad9fc7c0edf541000000000000000000000000000000000aa85720ba64eab113ac83e02ba5aae2dfb4a9729043670dc02d86951e2f85e5b98e4d22c1e2c9639608dbce9c94a5e0",
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
        BudlumFinalityVerifier bls = verifier;
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
        BudlumFinalityVerifier bls = verifier;
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
        BudlumFinalityVerifier bls = verifier;
        bytes32 digest = bls.verify(_attestation(42, bytes32(uint256(7))));
        vm.expectPartialRevert(BudlumFinalityVerifier.FraudProofRejected.selector);
        bls.challenge(digest, hex"01");
    }

    // F06: one pending claim per height.
    function test_F06_a_second_root_for_a_pending_height_is_refused() public {
        BudlumFinalityVerifier bls = verifier;
        bls.verify(_attestation(42, bytes32(uint256(7))));
        vm.expectPartialRevert(BudlumFinalityVerifier.PendingAttestation.selector);
        bls.verify(_attestation(42, bytes32(uint256(8))));
    }

    function test_F06_a_conflicting_root_after_finality_is_refused() public {
        BudlumFinalityVerifier bls = verifier;
        bytes32 digest = bls.verify(_attestation(42, bytes32(uint256(7))));
        vm.roll(block.number + WINDOW);
        bls.settle(digest);
        vm.expectPartialRevert(BudlumFinalityVerifier.ConflictingRoot.selector);
        bls.verify(_attestation(42, bytes32(uint256(8))));

        Attestation memory duplicateAfterFinal = _attestation(42, bytes32(uint256(7)));
        duplicateAfterFinal.mlDsaSignature = _filled(3309, 0xCC);
        vm.expectPartialRevert(BudlumFinalityVerifier.AlreadyAccepted.selector);
        bls.verify(duplicateAfterFinal);
    }

    function test_zero_state_root_is_refused() public {
        vm.expectPartialRevert(BudlumFinalityVerifier.SignatureInvalid.selector);
        verifier.verify(_attestation(42, bytes32(0)));
    }

    function test_F06_a_mutated_ml_dsa_blob_cannot_shadow_the_committee_attestation() public {
        BudlumFinalityVerifier bls = verifier;
        bytes32 root = bytes32(uint256(7));
        Attestation memory malleable = _attestation(42, root);
        malleable.mlDsaSignature = _filled(3309, 0xAA);
        bytes32 malleableDigest = bls.verify(malleable);

        Attestation memory committeeAtt = _attestation(42, root);
        bytes32 committeeDigest = bls.verify(committeeAtt);
        assertTrue(malleableDigest != committeeDigest, "distinct envelope digests");

        vm.roll(block.number + WINDOW);
        bls.settle(malleableDigest);
        bls.settle(committeeDigest);
        assertTrue(bls.isAccepted(committeeDigest), "committee digest accepted");
        assertTrue(bls.isAccepted(bls.pendingIdentity(42, root)), "substance identity accepted");
    }

    function test_F06_a_challenged_malleable_envelope_cannot_bar_honest_finality() public {
        BudlumFinalityVerifier bls = verifier;
        bytes32 root = bytes32(uint256(7));

        // 1. Both envelopes open; proving fraud on the mutated envelope leaves
        //    the committee's own envelope free to settle the height.
        Attestation memory malleable = _attestation(42, root);
        malleable.mlDsaSignature = _filled(3309, 0xAA);
        bytes32 malleableDigest = bls.verify(malleable);
        Attestation memory committeeAtt = _attestation(42, root);
        bytes32 committeeDigest = bls.verify(committeeAtt);

        fraud.set(true);
        bls.challenge(malleableDigest, hex"01");
        vm.roll(block.number + WINDOW);
        vm.expectPartialRevert(BudlumFinalityVerifier.ChallengeResolved.selector);
        bls.settle(malleableDigest);
        bls.settle(committeeDigest);
        assertTrue(bls.heightFinal(42), "honest height settled despite challenged malleable envelope");
        assertEq(bls.rootAtHeight(42), root, "honest root recorded");

        // 2. Mutated envelope arrives first and is challenged before the honest
        //    committee envelope is submitted; the honest envelope still verifies and settles.
        BudlumFinalityVerifier bls2 = new BudlumFinalityVerifier(
            CHAIN, WINDOW, address(fraud), keccak256(committee), keccak256(generator), keccak256(mlDsaKey)
        );
        Attestation memory earlyBad = _attestation(42, root);
        earlyBad.mlDsaSignature = _filled(3309, 0xBB);
        bytes32 earlyBadDigest = bls2.verify(earlyBad);
        bls2.challenge(earlyBadDigest, hex"01");

        Attestation memory honest = _attestation(42, root);
        bytes32 honestDigest = bls2.verify(honest);
        vm.roll(block.number + WINDOW);
        bls2.settle(honestDigest);
        assertTrue(bls2.heightFinal(42), "honest height settled after early bad envelope challenged");
    }
}
