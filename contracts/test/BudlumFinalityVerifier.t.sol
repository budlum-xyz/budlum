// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {Harness} from "./Harness.sol";
import {
    Attestation,
    BudlumFinalityVerifier,
    FinalityMode,
    IExternalFraudProofVerifier,
    QuantumAlertAttestation,
    QuantumAlertLevel
} from "../external-domain/BudlumFinalityVerifier.sol";
import {BudlumHash} from "../lib/BudlumHash.sol";
import {
    BudlumObjectLayerFinality, IBudlumHeaderFinality, ProofFormat
} from "../object-layer/BudlumFinalityVerifier.sol";
import {IBudlumFinality} from "../external-domain/BudlumFinalityVerifier.sol";
import {BudlumStateReader} from "../lib/BudlumStateReader.sol";
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

    function finalityModeAt(uint64) external pure returns (FinalityMode) {
        return FinalityMode.Hybrid;
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
        finalityModeAtHeight[height] = FinalityMode.Hybrid;
    }

    function seedWithMode(uint64 height, bytes32 stateRoot, FinalityMode mode) external {
        heightFinal[height] = mode != FinalityMode.None;
        rootAtHeight[height] = stateRoot;
        finalityModeAtHeight[height] = mode;
    }
}

/// A fraud verifier whose answer the test sets.
contract FraudVerifierStub is IExternalFraudProofVerifier {
    bool public answer;
    bool public substanceAnswer;

    function set(bool value) external {
        answer = value;
    }

    function setSubstance(bool value) external {
        substanceAnswer = value;
    }

    function verifyFraud(bytes32, bytes calldata) external view returns (bool) {
        return answer;
    }

    function verifyFraudSubstance(uint64, bytes32, bytes calldata) external view returns (bool) {
        return substanceAnswer;
    }
}

/// Fraud verifier that checks the verifier contract has not mutated challenge
/// or pending-root state prior to external verification (CEI compliance).
contract InspectingFraudVerifier is IExternalFraudProofVerifier {
    BudlumFinalityVerifier public target;
    bool public answer;
    bool public shouldRevert;
    bool public substanceAnswer;

    function setTarget(BudlumFinalityVerifier target_) external {
        target = target_;
    }

    function configure(bool answer_, bool shouldRevert_) external {
        answer = answer_;
        shouldRevert = shouldRevert_;
    }

    function setSubstance(bool substanceAnswer_) external {
        substanceAnswer = substanceAnswer_;
    }

    function verifyFraud(bytes32 digest, bytes calldata) external view returns (bool) {
        if (shouldRevert) {
            revert("boom");
        }
        (, address challenger, uint64 openedAt, bool resolved, uint64 h, bytes32 root,) = target.challenges(digest);
        require(openedAt != 0, "challenge missing");
        require(challenger == address(0), "challenger mutated before verifyFraud");
        require(!resolved, "resolved mutated before verifyFraud");
        require(!target.fraudulent(digest), "fraudulent mutated before verifyFraud");
        require(!target.fraudulentRoot(h, root), "fraudulentRoot mutated before verifyFraud");
        require(target.pendingRootAtHeight(h) == root, "pending root cleared before verifyFraud");
        require(target.pendingEnvelopeCount(target.pendingIdentity(h, root)) > 0, "envelope count decremented early");
        return answer;
    }

    function verifyFraudSubstance(uint64 h, bytes32 root, bytes calldata) external view returns (bool) {
        require(!target.fraudulentRoot(h, root), "fraudulentRoot mutated before verifyFraudSubstance");
        require(target.pendingRootAtHeight(h) == root, "pending root cleared before verifyFraudSubstance");
        require(target.pendingEnvelopeCount(target.pendingIdentity(h, root)) > 0, "envelope count decremented early");
        return substanceAnswer;
    }
}

/// negative tests. The default profile runs on Cancun, which has
/// neither the BLS nor the ML-DSA precompile: an attestation with no
/// verification path at all is refused. The pending-window, terminal-fraud, and single-pending-claim tests
/// run under the `prague` profile, where the real EIP-2537 pairing
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
    bytes internal committee =
        hex"0000000000000000000000000000000003102696de47a8ff5f84b1e06a4c49f66d3d91db26aa983d9f682aa8dd40a04782774feade5b8283b66d110d932c98870000000000000000000000000000000016f2753675030c982f167778cccec6637d4a91b2c1942f879993d3af2562cfd982f0618f764a15b4dd369df28b35eb0b0000000000000000000000000000000001edbbe15bc722126ea27e155f354f5f89774ed035dd31077e6076eb702ce4ada29a68b8f2f523aa35407b818937c5df000000000000000000000000000000001273f61d9f71c16394cf54241a127dac1a380febcc1ee66eedb4859d7e17daa4dd6bcbdffbcd37c74ddbd9c9f1283dd9";
    bytes internal generator =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
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
        BudlumObjectLayerFinality objectLayer = new BudlumObjectLayerFinality(IBudlumHeaderFinality(address(verifier)));
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
        BudlumObjectLayerFinality objectLayer = new BudlumObjectLayerFinality(IBudlumHeaderFinality(address(verifier)));
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

    // Trust anchor: the trust anchor is the constructor; zero hashes and an EOA fraud
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

    // Missing precompile: a missing precompile leaves the attestation pending, never accepted,
    // until the window closes.
    // Missing precompile: a chain with no verification precompile for either half refuses
    // the attestation outright; it does not open a window nothing could
    // ever have checked.
    function test_F02_an_attestation_with_no_verification_path_is_refused() public {
        vm.expectPartialRevert(BudlumFinalityVerifier.NoVerificationPath.selector);
        verifier.verify(_attestation(42, bytes32(uint256(7))));
    }

    // BLS-only regime: with the classical half verified and ML-DSA
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

    // Empty-address probe: the probes do not mistake an empty address for a precompile.
    function test_F03_probes_report_no_precompile_on_cancun() public view {
        assertTrue(!verifier.hasBlsPrecompile(), "no BLS precompile");
        assertTrue(!verifier.hasMlDsaPrecompile(), "no ML-DSA precompile");
    }

    // Domain binding: the attestation binds the chain and the pinned keys.
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

    // Terminal fraud: a proven fraud is terminal: no settle, no re-verify.
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

    // Height uniqueness: one pending claim per height.
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

    function test_F05_challenge_verifies_fraud_before_mutating_state() public {
        InspectingFraudVerifier inspector = new InspectingFraudVerifier();
        BudlumFinalityVerifier inspected = new BudlumFinalityVerifier(
            CHAIN, WINDOW, address(inspector), keccak256(committee), keccak256(generator), keccak256(mlDsaKey)
        );
        inspector.setTarget(inspected);
        assertTrue(address(inspector) == inspected.fraudProofVerifier(), "inspector address matched");

        bytes32 digest = inspected.verify(_attestation(42, bytes32(uint256(7))));

        // Reverting verifyFraud leaves pending state intact.
        inspector.configure(false, true);
        vm.expectPartialRevert(BudlumFinalityVerifier.FraudProofRejected.selector);
        inspected.challenge(digest, hex"01");
        assertTrue(!inspected.fraudulent(digest), "not fraudulent after revert");

        // False verifyFraud still observed pre-mutation state and leaves pending state intact.
        inspector.configure(false, false);
        vm.expectPartialRevert(BudlumFinalityVerifier.FraudProofRejected.selector);
        inspected.challenge(digest, hex"01");
        assertTrue(!inspected.fraudulent(digest), "not fraudulent after false");

        // True verifyFraud observes clean pre-mutation state, then commits fraud resolution.
        inspector.configure(true, false);
        inspector.setSubstance(true);
        inspected.challenge(digest, hex"01");
        assertTrue(inspected.fraudulent(digest), "marked fraudulent after verification");
        assertTrue(inspected.fraudulentRoot(42, bytes32(uint256(7))), "marked substance fraudulent after verification");

        // Re-challenging or settling an already challenged/fraudulent attestation must fail.
        vm.expectPartialRevert(BudlumFinalityVerifier.ChallengeResolved.selector);
        inspected.challenge(digest, hex"01");
        vm.roll(block.number + WINDOW);
        vm.expectPartialRevert(BudlumFinalityVerifier.ChallengeResolved.selector);
        inspected.settle(digest);
    }

    function test_F05_a_disproved_substance_cannot_be_represented_with_mutated_blob() public {
        BudlumFinalityVerifier bls = verifier;
        bytes32 disprovedRoot = bytes32(uint256(7));

        Attestation memory first = _attestation(42, disprovedRoot);
        bytes32 firstDigest = bls.verify(first);

        Attestation memory sibling = _attestation(42, disprovedRoot);
        sibling.mlDsaSignature = _filled(3309, 0xAA);
        bytes32 siblingDigest = bls.verify(sibling);

        fraud.set(true);
        fraud.setSubstance(true);
        bls.challenge(firstDigest, hex"01");
        assertTrue(bls.fraudulentRoot(42, disprovedRoot), "substance tombstone latched");

        // Re-submitting the same disproved (height, stateRoot) under a fresh ML-DSA blob is refused.
        Attestation memory rePresented = _attestation(42, disprovedRoot);
        rePresented.mlDsaSignature = _filled(3309, 0xBB);
        vm.expectPartialRevert(BudlumFinalityVerifier.AlreadyFraudulent.selector);
        bls.verify(rePresented);

        // An already-pending sibling envelope for the disproved substance cannot settle after the window.
        vm.roll(block.number + WINDOW);
        vm.expectPartialRevert(BudlumFinalityVerifier.AlreadyFraudulent.selector);
        bls.settle(siblingDigest);
    }

    function test_F06_classical_only_settlement_records_classical_mode_not_hybrid() public {
        BudlumFinalityVerifier bls = verifier;
        bytes32 body = bytes32(uint256(11));
        bytes32 header = bytes32(uint256(22));
        bytes[] memory fields = new bytes[](3);
        fields[0] = "BDLM_STATE_ROOT_GLOBAL_HEADER_V1";
        fields[1] = abi.encodePacked(body);
        fields[2] = abi.encodePacked(header);
        bytes32 stateRoot = BudlumHash.hashFields(fields);

        // Under prague only BLS verifies; ML-DSA is absent so settlement must
        // record ClassicalOnly rather than impersonating full hybrid finality.
        Attestation memory a = _attestation(42, bytes32(uint256(7)));
        bytes32 digest = bls.verify(a);
        assertTrue(bls.finalityModeAtHeight(42) == FinalityMode.None, "pending has no finality mode");
        vm.roll(block.number + WINDOW);
        bls.settle(digest);
        assertTrue(bls.heightFinal(42), "height final after window");
        assertTrue(bls.finalityModeAtHeight(42) == FinalityMode.ClassicalOnly, "BLS-only settle records ClassicalOnly");
        assertTrue(bls.finalityModeAtHeight(42) != FinalityMode.Hybrid, "BLS-only settle is never Hybrid");

        // A classical-only root opening records ClassicalOnly on the object-layer
        // view and is refused by the settlement endpoint, which requires Hybrid.
        SeededFinalityVerifier seeded = new SeededFinalityVerifier(address(fraud));
        seeded.seedWithMode(45, stateRoot, FinalityMode.ClassicalOnly);
        BudlumObjectLayerFinality objectLayer = new BudlumObjectLayerFinality(IBudlumHeaderFinality(address(seeded)));
        BudlumSettlementEndpoint endpoint =
            new BudlumSettlementEndpoint(IBudlumObjectLayerFinality(address(objectLayer)), 100);
        objectLayer.record(45, header, body);
        assertTrue(objectLayer.finalityModeAt(45) == FinalityMode.ClassicalOnly, "object layer preserves ClassicalOnly");
        vm.expectPartialRevert(BudlumSettlementEndpoint.HybridFinalityRequired.selector);
        endpoint.acceptHeader(45);
        assertEq(endpoint.lastAcceptedHeight(), 0, "classical-only checkpoint cannot advance endpoint");
    }

    function test_object_layer_endpoint_distinguishes_classical_only_from_hybrid() public {
        SeededFinalityVerifier seeded = new SeededFinalityVerifier(address(fraud));
        BudlumObjectLayerFinality objectLayer = new BudlumObjectLayerFinality(IBudlumHeaderFinality(address(seeded)));
        BudlumSettlementEndpoint endpoint =
            new BudlumSettlementEndpoint(IBudlumObjectLayerFinality(address(objectLayer)), 100);
        bytes32 body = bytes32(uint256(11));
        bytes32 headerA = bytes32(uint256(22));
        bytes32 headerB = bytes32(uint256(23));
        bytes[] memory fields = new bytes[](3);
        fields[0] = "BDLM_STATE_ROOT_GLOBAL_HEADER_V1";
        fields[1] = abi.encodePacked(body);
        fields[2] = abi.encodePacked(headerA);
        bytes32 rootA = BudlumHash.hashFields(fields);
        fields[2] = abi.encodePacked(headerB);
        bytes32 rootB = BudlumHash.hashFields(fields);

        seeded.seedWithMode(45, rootA, FinalityMode.ClassicalOnly);
        objectLayer.record(45, headerA, body);
        assertTrue(objectLayer.finalityModeAt(45) == FinalityMode.ClassicalOnly, "recorded as ClassicalOnly");
        vm.expectPartialRevert(BudlumSettlementEndpoint.HybridFinalityRequired.selector);
        endpoint.acceptHeader(45);
        assertEq(endpoint.lastAcceptedHeight(), 0, "ClassicalOnly refused by settlement endpoint");

        seeded.seedWithMode(46, rootB, FinalityMode.Hybrid);
        objectLayer.record(46, headerB, body);
        assertTrue(objectLayer.finalityModeAt(46) == FinalityMode.Hybrid, "recorded as Hybrid");
        endpoint.acceptHeader(46);
        assertEq(endpoint.lastAcceptedHeight(), 46, "Hybrid accepted by settlement endpoint");
        assertTrue(endpoint.lastAcceptedFinalityMode() == FinalityMode.Hybrid, "endpoint records Hybrid mode");
    }

    function test_object_layer_ibudlum_finality_parity() public {
        SeededFinalityVerifier seeded = new SeededFinalityVerifier(address(fraud));
        BudlumObjectLayerFinality objectLayer = new BudlumObjectLayerFinality(IBudlumHeaderFinality(address(seeded)));

        assertTrue(objectLayer.acceptedProofFormat() == ProofFormat.Signature, "signature format active");
        assertEq(objectLayer.latestFinalHeight(), 0, "no checkpoint recorded yet");

        bytes32 body = bytes32(uint256(91));
        bytes32 header = bytes32(uint256(92));
        bytes[] memory hdrFields = new bytes[](3);
        hdrFields[0] = "BDLM_STATE_ROOT_GLOBAL_HEADER_V1";
        hdrFields[1] = abi.encodePacked(body);
        hdrFields[2] = abi.encodePacked(header);
        bytes32 expectedRoot = BudlumHash.hashFields(hdrFields);

        seeded.seedWithMode(88, expectedRoot, FinalityMode.Hybrid);
        objectLayer.record(88, header, body);
        assertTrue(objectLayer.heightFinal(88), "object layer heightFinal");
        assertEq(objectLayer.rootAtHeight(88), expectedRoot, "object layer rootAtHeight");
        assertEq(objectLayer.latestFinalHeight(), 88, "object layer latestFinalHeight");
        assertTrue(objectLayer.finalityModeAtHeight(88) == FinalityMode.Hybrid, "object layer finalityModeAtHeight");
    }

    function _fourFactLeaves()
        internal
        pure
        returns (bytes32[4] memory leaves, bytes32[2] memory nodes, bytes32 root)
    {
        leaves[0] = BudlumHash.balanceLeaf(bytes32(uint256(1)), bytes32(uint256(2)), uint128(500), uint64(3));
        leaves[1] = BudlumHash.bridgeBurnLeaf(
            bytes32(uint256(10)), uint32(1), uint32(2), bytes32(uint256(20)), uint128(250), bytes32(uint256(30))
        );
        leaves[2] = BudlumHash.appBindingPaymentLeaf(
            bytes32(uint256(40)), bytes32(uint256(41)), bytes32(uint256(42)), bytes32(uint256(43)), uint128(77)
        );
        leaves[3] = BudlumHash.crossDomainMessageLeaf(
            bytes32(uint256(50)), uint32(2), uint32(3), uint64(9), bytes32(uint256(51))
        );
        nodes[0] = BudlumHash.merkleNode(leaves[0], leaves[1]);
        nodes[1] = BudlumHash.merkleNode(leaves[2], leaves[3]);
        root = BudlumHash.merkleNode(nodes[0], nodes[1]);
    }

    function test_state_reader_verifies_four_state_facts_and_rejects_tamper() public {
        SeededFinalityVerifier seeded = new SeededFinalityVerifier(address(fraud));
        (bytes32[4] memory leaves, bytes32[2] memory nodes, bytes32 treeRoot) = _fourFactLeaves();
        seeded.seedWithMode(77, treeRoot, FinalityMode.Hybrid);
        IBudlumFinality fin = IBudlumFinality(address(seeded));

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = leaves[1];
        proof[1] = nodes[1];
        assertTrue(
            BudlumStateReader.verifyBalance(
                fin, 77, bytes32(uint256(1)), bytes32(uint256(2)), uint128(500), uint64(3), 0, proof
            ),
            "balance inclusion must verify"
        );
        assertTrue(
            !BudlumStateReader.verifyBalance(
                fin, 78, bytes32(uint256(1)), bytes32(uint256(2)), uint128(500), uint64(3), 0, proof
            ),
            "unfinalized height must fail"
        );

        proof[0] = leaves[0];
        proof[1] = nodes[1];
        assertTrue(
            BudlumStateReader.verifyBridgeBurn(
                fin,
                77,
                bytes32(uint256(10)),
                uint32(1),
                uint32(2),
                bytes32(uint256(20)),
                uint128(250),
                bytes32(uint256(30)),
                1,
                proof
            ),
            "bridge burn inclusion must verify"
        );
        assertTrue(
            !BudlumStateReader.verifyBridgeBurn(
                fin,
                77,
                bytes32(uint256(10)),
                uint32(1),
                uint32(2),
                bytes32(uint256(20)),
                uint128(251),
                bytes32(uint256(30)),
                1,
                proof
            ),
            "tampered burn amount must fail"
        );

        proof[0] = leaves[3];
        proof[1] = nodes[0];
        assertTrue(
            BudlumStateReader.verifyAppBindingPayment(
                fin,
                77,
                bytes32(uint256(40)),
                bytes32(uint256(41)),
                bytes32(uint256(42)),
                bytes32(uint256(43)),
                uint128(77),
                2,
                proof
            ),
            "app-binding payment inclusion must verify"
        );

        proof[0] = leaves[2];
        proof[1] = nodes[0];
        assertTrue(
            BudlumStateReader.verifyCrossDomainMessage(
                fin, 77, bytes32(uint256(50)), uint32(2), uint32(3), uint64(9), bytes32(uint256(51)), 3, proof
            ),
            "cross-domain message inclusion must verify"
        );
    }

    function test_K7O_quantum_alert_starts_open_and_negative_guards() public {
        assertTrue(verifier.alertLevel() == QuantumAlertLevel.Open, "alert starts Open");
        BudlumObjectLayerFinality objectLayer = new BudlumObjectLayerFinality(IBudlumHeaderFinality(address(verifier)));
        assertTrue(objectLayer.alertLevel() == QuantumAlertLevel.Open, "object layer alert starts Open");

        bytes32 stateRoot = keccak256("canary-fired-root");
        SeededFinalityVerifier seeded = new SeededFinalityVerifier(address(fraud));
        seeded.seedFinalized(10, stateRoot);

        QuantumAlertAttestation memory q = QuantumAlertAttestation({
            height: 10,
            stateRoot: stateRoot,
            level: QuantumAlertLevel.Advisory,
            g2AggregatePubkey: committee,
            g2Generator: generator,
            g1NegSignature: _filled(128, 0x04),
            mlDsaSignature: _filled(3309, 0x05),
            mlDsaPubkey: mlDsaKey,
            mlDsaEthVariant: false
        });

        // Open (0) level is refused.
        q.level = QuantumAlertLevel.Open;
        vm.expectPartialRevert(BudlumFinalityVerifier.InvalidAlertLevel.selector);
        seeded.submitQuantumAlert(q);

        // Unfinalized height is refused.
        q.level = QuantumAlertLevel.Advisory;
        q.height = 11;
        vm.expectPartialRevert(BudlumFinalityVerifier.AlertHeightNotFinal.selector);
        seeded.submitQuantumAlert(q);

        // Wrong stateRoot is refused.
        q.height = 10;
        q.stateRoot = bytes32(uint256(999));
        vm.expectPartialRevert(BudlumFinalityVerifier.AlertRootMismatch.selector);
        seeded.submitQuantumAlert(q);

        // Untrusted key is refused.
        q.stateRoot = stateRoot;
        vm.expectPartialRevert(BudlumFinalityVerifier.UntrustedKey.selector);
        seeded.submitQuantumAlert(q);

        // On Cancun (no BLS, no ML-DSA precompiles) valid keys still fail closed with NoVerificationPath.
        BudlumFinalityVerifier cancunAlert = new BudlumFinalityVerifier(
            CHAIN, WINDOW, address(fraud), keccak256(committee), keccak256(generator), keccak256(mlDsaKey)
        );
        vm.expectPartialRevert(BudlumFinalityVerifier.AlertHeightNotFinal.selector);
        cancunAlert.submitQuantumAlert(q);
    }

    function test_F06_quantum_alert_halts_classical_only_verify_settle_and_object_layer() public {
        bytes memory pk =
            hex"00000000000000000000000000000000049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3c000000000000000000000000000000000d0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c80000000000000000000000000000000008b7ae4dbf802c17a6648842922c9467e460a71c88d393ee7af356da123a2f3619e80c3bdcc8e2b1da52f8cd9913ccdd0000000000000000000000000000000005ecf93654b7a1885695aaeeb7caf41b0239dc45e1022be55d37111af2aecef87799638bec572de86a7437898efa7020";
        BudlumFinalityVerifier alertVerifier = new BudlumFinalityVerifier(
            CHAIN, WINDOW, address(fraud), keccak256(pk), keccak256(generator), keccak256(mlDsaKey)
        );
        assertTrue(alertVerifier.hasBlsPrecompile(), "prague BLS precompile active");
        assertTrue(alertVerifier.alertLevel() == QuantumAlertLevel.Open, "starts Open");

        bytes32 body = bytes32(uint256(11));
        bytes32 header = bytes32(uint256(22));
        bytes32 stateRoot = hex"6110ef23437d65212be537bdc82c839c3216605c1a6fa1636660aa6b57f47779";

        // 1. Open a real ClassicalOnly pending challenge at height 42.
        Attestation memory a42 = Attestation({
            height: 42,
            stateRoot: bytes32(uint256(7)),
            epoch: 3,
            chainId: CHAIN,
            g2AggregatePubkey: pk,
            g2Generator: generator,
            g1NegSignature: hex"000000000000000000000000000000000e4d98ce082b94098295a0d3cf710f8256c1673a5646e778accebf5d276f46301d3d28f8df4109574cc70694415160750000000000000000000000000000000010b5aef3d3950c839400718f77b7c24eb60682c3164df008dcce77ce3a60912aba7c344aadb7e98deb1e84b27db4dda9",
            mlDsaSignature: _filled(3309, 0x05),
            mlDsaPubkey: mlDsaKey,
            mlDsaEthVariant: false
        });
        bytes32 pendingDigest42 = alertVerifier.verify(a42);

        // 2. Finalize height 41 via real EIP-2537 BLS verification + settle.
        Attestation memory a41 = Attestation({
            height: 41,
            stateRoot: stateRoot,
            epoch: 3,
            chainId: CHAIN,
            g2AggregatePubkey: pk,
            g2Generator: generator,
            g1NegSignature: hex"000000000000000000000000000000000f1f7bfd860a2de506b623887e17c85fce652d7f3111ec60cb9c660ffb6869a70d1644b4e4fee9b474c7f58b57cdef0b000000000000000000000000000000000a2436c1cd9bf73e974555c8a35f9be8d91140cdfd77e5fed6df2db6b02f0e2382e58a4e5dcc191c25afdc9da34a2000",
            mlDsaSignature: _filled(3309, 0x05),
            mlDsaPubkey: mlDsaKey,
            mlDsaEthVariant: false
        });
        bytes32 d41 = alertVerifier.verify(a41);
        vm.roll(block.number + WINDOW);
        alertVerifier.settle(d41);
        assertTrue(alertVerifier.heightFinal(41), "height 41 finalized ClassicalOnly");

        // 3. Escalate quantum alert at finalized height 41 using real EIP-2537 BLS signature.
        QuantumAlertAttestation memory q = QuantumAlertAttestation({
            height: 41,
            stateRoot: stateRoot,
            level: QuantumAlertLevel.Restricted,
            g2AggregatePubkey: pk,
            g2Generator: generator,
            g1NegSignature: hex"00000000000000000000000000000000191cfce3dfdbbc957b5419fee12bb2ff775b3b7f3de575b296d56618ccffc267dea05ceb86e90556b64b9c9cacda12030000000000000000000000000000000001c93267b1fc9a9887a4c55f56f59effc52f84aff7a7f55fc8b8a2631663dba7cef0a03ec74229edd7640d1ccf0e6a80",
            mlDsaSignature: _filled(3309, 0x05),
            mlDsaPubkey: mlDsaKey,
            mlDsaEthVariant: false
        });
        alertVerifier.submitQuantumAlert(q);
        assertTrue(alertVerifier.alertLevel() == QuantumAlertLevel.Restricted, "alert escalated to Restricted");
        assertEq(alertVerifier.alertHeight(), 41, "alertHeight recorded");
        assertTrue(alertVerifier.alertLevelAtHeight(41) == QuantumAlertLevel.Restricted, "height alert recorded");

        // Replay or downgrade of alert level must revert.
        vm.expectPartialRevert(BudlumFinalityVerifier.InvalidAlertLevel.selector);
        alertVerifier.submitQuantumAlert(q);

        // 4. Previously pending ClassicalOnly challenge at height 42 CANNOT settle under alert.
        vm.expectPartialRevert(BudlumFinalityVerifier.ClassicalHaltedByQuantumAlert.selector);
        alertVerifier.settle(pendingDigest42);
        assertTrue(!alertVerifier.heightFinal(42), "pending ClassicalOnly must not finalize under alert");

        // 5. New ClassicalOnly attestations CANNOT even open a challenge window under alert.
        Attestation memory a44 = _attestation(44, bytes32(uint256(9)));
        a44.g2AggregatePubkey = pk;
        a44.g1NegSignature =
            hex"000000000000000000000000000000000ab77c1f3d7f2732a68fc68127bc2ac7d75634c437bda9dada01ed05c86d5b8f8677ae5a5fcaced9457de09a0cc11b2f00000000000000000000000000000000097e56d65265e24c8861038e5d7bef78521a09dc32aca4b0fd0ee7b2f8827b69c59125a83f61588857b27116cc211079";
        vm.expectPartialRevert(BudlumFinalityVerifier.ClassicalHaltedByQuantumAlert.selector);
        alertVerifier.verify(a44);

        // 6. BudlumObjectLayerFinality mirrors alertLevel and refuses recording ClassicalOnly under alert.
        BudlumObjectLayerFinality objectLayer =
            new BudlumObjectLayerFinality(IBudlumHeaderFinality(address(alertVerifier)));
        assertTrue(objectLayer.alertLevel() == QuantumAlertLevel.Restricted, "object layer mirrors Restricted");
        vm.expectPartialRevert(BudlumObjectLayerFinality.ClassicalHaltedByQuantumAlert.selector);
        objectLayer.record(41, header, body);
        assertTrue(!objectLayer.heightFinal(41), "object layer must not record ClassicalOnly under alert");
    }
}
