// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

/// @notice Minimal finality read surface consumed by downstream Graft receivers.
interface IBudlumFinality {
    function rootAtHeight(uint64 height) external view returns (bytes32);
    function heightFinal(uint64 height) external view returns (bool);
}

/// @title BudlumFinalityVerifier
/// @notice Verifies Budlum's hybrid finality proof (BLS12-381 aggregate +
///         post-quantum ML-DSA) on an EVM chain.
struct Attestation {
    uint64 height;
    bytes32 stateRoot;
    uint64 epoch;
    uint64 chainId;
    bytes g2AggregatePubkey;
    bytes g2Generator;
    bytes g1NegSignature;
    bytes mlDsaSignature;
    bytes mlDsaPubkey;
    bool mlDsaEthVariant;
}

struct Challenge {
    bytes32 attestationDigest;
    address challenger;
    uint64 openedAt;
    bool resolved;
    uint64 height;
    bytes32 stateRoot;
}

interface IExternalFraudProofVerifier {
    function verifyFraud(bytes32 attestationDigest, bytes calldata proof)
        external
        view
        returns (bool);
}

contract BudlumFinalityVerifier is IBudlumFinality {
    address internal constant PRECOMPILE_BLS_G1ADD = address(0x0b);
    address internal constant PRECOMPILE_BLS_PAIRING = address(0x0f);
    address internal constant PRECOMPILE_BLS_MAP_FP_TO_G1 = address(0x10);
    address internal constant PRECOMPILE_MODEXP = address(0x05);
    bytes internal constant BLS_FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    bytes internal constant BLS_DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
    address internal constant PRECOMPILE_MLDSA = address(0x12);
    address internal constant PRECOMPILE_MLDSA_ETH = address(0x13);

    uint256 internal constant GAS_BLS_PAIRING_PROBE = 15e4;
    uint256 internal constant GAS_BLS_PAIRING_VERIFY = 4e5;
    uint256 internal constant GAS_MLDSA_VERIFY = 6e4;
    uint256 internal constant GAS_MALFORMED_PROBE = 5_000;

    uint256 internal constant PAIRING_PROBE_BYTES = 384;
    uint256 internal constant G2_UNCOMPRESSED_LEN = 256;
    uint256 internal constant G1_UNCOMPRESSED_LEN = 128;
    uint256 internal constant WORD_LEN = 32;
    uint256 internal constant FP_PADDED_LEN = 64;
    uint256 internal constant FP_BYTE_LEN = 48;
    uint256 internal constant MODEXP_EXP_LEN = 1;
    bytes1 internal constant MODEXP_EXP_BYTE = 0x01;
    uint16 internal constant XMD_LEN_IN_BYTES = 128;
    uint8 internal constant XMD_BLOCK_1 = 1;
    uint8 internal constant XMD_BLOCK_2 = 2;
    uint8 internal constant XMD_BLOCK_3 = 3;
    uint8 internal constant XMD_BLOCK_4 = 4;

    uint256 public immutable challengeWindow;
    address public immutable fraudProofVerifier;
    uint64 public immutable budlumChainId;
    bytes32 public immutable committeePubkeyHash;
    bytes32 public immutable g2GeneratorHash;
    bytes32 public immutable mlDsaPubkeyHash;

    mapping(bytes32 => bool) public accepted;
    mapping(uint64 => bytes32) public override rootAtHeight;
    mapping(uint64 => bytes32) public pendingRootAtHeight;
    mapping(uint64 => bytes32) public pendingAttestationAtHeight;
    mapping(uint64 => bool) public override heightFinal;
    mapping(bytes32 => Challenge) public challenges;
    mapping(bytes32 => bool) public fraudulent;
    mapping(uint64 => mapping(bytes32 => bool)) public fraudulentRoot;

    bool public immutable hasBlsPrecompile;
    bool public immutable hasMlDsaPrecompile;

    event AttestationVerified(bytes32 indexed digest, uint64 height, bytes32 stateRoot);
    event AttestationOptimistic(bytes32 indexed digest, uint64 height, string reason);
    event ChallengeOpened(bytes32 indexed digest, address indexed challenger);
    event ChallengeProven(bytes32 indexed digest, address indexed challenger, bool fraud);

    error WrongChainId(uint64 expected, uint64 got);
    error AlreadyAccepted(bytes32 digest);
    error BadSignatureLength(string what);
    error UntrustedKey(string what);
    error PrecompileRefused(string what);
    error NoVerificationPath();
    error ChallengeWindowOpen(bytes32 digest, uint256 blocksLeft);
    error ChallengeWindowClosed(bytes32 digest);
    error AlreadyChallenged(bytes32 digest);
    error NoSuchChallenge(bytes32 digest);
    error ChallengeResolved(bytes32 digest);
    error AlreadyFraudulent(bytes32 digest);
    error NoFraudProofVerifier();
    error FraudProofVerifierNotContract(address verifier);
    error FraudProofRejected(bytes32 digest);
    error PendingAttestation(uint64 height, bytes32 digest);
    error NoChallengeWindow();
    error SignatureInvalid(string what);
    error ConflictingRoot(uint64 height, bytes32 held, bytes32 got);

    constructor(
        uint64 budlumChainId_,
        uint256 challengeWindow_,
        address fraudProofVerifier_,
        bytes32 committeePubkeyHash_,
        bytes32 g2GeneratorHash_,
        bytes32 mlDsaPubkeyHash_
    ) {
        if (fraudProofVerifier_ == address(0)) {
            revert NoFraudProofVerifier();
        }
        if (fraudProofVerifier_.code.length == 0) {
            revert FraudProofVerifierNotContract(fraudProofVerifier_);
        }
        if (committeePubkeyHash_ == bytes32(0)
            || g2GeneratorHash_ == bytes32(0)
            || mlDsaPubkeyHash_ == bytes32(0)) {
            revert UntrustedKey("constructor key hashes must be non-zero");
        }
        if (challengeWindow_ == 0) {
            revert NoChallengeWindow();
        }
        budlumChainId = budlumChainId_;
        challengeWindow = challengeWindow_;
        fraudProofVerifier = fraudProofVerifier_;
        committeePubkeyHash = committeePubkeyHash_;
        g2GeneratorHash = g2GeneratorHash_;
        mlDsaPubkeyHash = mlDsaPubkeyHash_;
        hasBlsPrecompile = _probeBlsPairing(new bytes(PAIRING_PROBE_BYTES));
        hasMlDsaPrecompile =
            _probeRejectsMalformed(PRECOMPILE_MLDSA)
                || _probeRejectsMalformed(PRECOMPILE_MLDSA_ETH);
    }

    function pendingIdentity(uint64 height, bytes32 stateRoot) public pure returns (bytes32) {
        return keccak256(abi.encode("bud-attestation-pending-v1", height, stateRoot));
    }

    function attestationDigest(Attestation calldata a) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                "bud-attestation-v1",
                a.height,
                a.stateRoot,
                a.epoch,
                a.chainId,
                keccak256(a.g2AggregatePubkey),
                keccak256(a.g2Generator),
                keccak256(a.g1NegSignature),
                keccak256(a.mlDsaSignature),
                keccak256(a.mlDsaPubkey),
                a.mlDsaEthVariant
            )
        );
    }

    function signingRoot(Attestation calldata a) public view returns (bytes32) {
        return keccak256(
            bytes.concat(
                bytes("bud-finality-signing-root-v1"),
                bytes32(block.chainid),
                bytes8(a.height),
                a.stateRoot,
                bytes8(a.epoch),
                bytes8(a.chainId)
            )
        );
    }

    function verify(Attestation calldata a) external returns (bytes32 digest) {
        if (a.chainId != budlumChainId) {
            revert WrongChainId(budlumChainId, a.chainId);
        }
        digest = attestationDigest(a);
        if (accepted[digest]) {
            revert AlreadyAccepted(digest);
        }
        if (fraudulent[digest]) {
            revert AlreadyFraudulent(digest);
        }
        if (fraudulentRoot[a.height][a.stateRoot]) {
            revert AlreadyFraudulent(digest);
        }
        if (challenges[digest].openedAt != 0) {
            revert AlreadyChallenged(digest);
        }

        if (keccak256(a.g2AggregatePubkey) != committeePubkeyHash) {
            revert UntrustedKey("aggregate pubkey is not the pinned committee key");
        }
        if (keccak256(a.g2Generator) != g2GeneratorHash) {
            revert UntrustedKey("G2 generator is not the pinned generator");
        }
        if (keccak256(a.mlDsaPubkey) != mlDsaPubkeyHash) {
            revert UntrustedKey("ML-DSA pubkey is not the pinned key");
        }

        bytes32 held = rootAtHeight[a.height];
        if (held != bytes32(0) && held != a.stateRoot && heightFinal[a.height]) {
            revert ConflictingRoot(a.height, held, a.stateRoot);
        }
        bytes32 identity = pendingIdentity(a.height, a.stateRoot);
        bytes32 pendingDigest = pendingAttestationAtHeight[a.height];
        if (pendingDigest != bytes32(0) && pendingDigest != identity) {
            revert PendingAttestation(a.height, pendingDigest);
        }
        bytes32 pendingRoot = pendingRootAtHeight[a.height];
        if (pendingRoot != bytes32(0) && pendingRoot != a.stateRoot) {
            revert ConflictingRoot(a.height, pendingRoot, a.stateRoot);
        }

        bytes32 root = signingRoot(a);

        bool blsOk = false;
        bool pqOk = false;

        if (hasBlsPrecompile) {
            blsOk = _verifyBls(root, a.g2AggregatePubkey, a.g2Generator, a.g1NegSignature);
        }
        if (hasMlDsaPrecompile) {
            pqOk = _verifyMlDsa(root, a.mlDsaPubkey, a.mlDsaSignature, a.mlDsaEthVariant);
        }

        if (hasBlsPrecompile && !blsOk) {
            revert SignatureInvalid("BLS signature does not verify");
        }
        if (hasMlDsaPrecompile && !pqOk) {
            revert SignatureInvalid("ML-DSA signature does not verify");
        }

        if (blsOk && pqOk) {
            accepted[digest] = true;
            accepted[identity] = true;
            rootAtHeight[a.height] = a.stateRoot;
            heightFinal[a.height] = true;
            if (pendingDigest == identity) {
                pendingAttestationAtHeight[a.height] = bytes32(0);
                pendingRootAtHeight[a.height] = bytes32(0);
            }
            emit AttestationVerified(digest, a.height, a.stateRoot);
            return digest;
        }

        if (!blsOk && !pqOk) {
            revert NoVerificationPath();
        }

        // Optimistic path, reached only when exactly one half verified and
        // the other half's precompile is missing. The attestation is NOT
        // marked accepted here; it is marked accepted only when the window
        // closes, via `settle`. A caller that treats an open window as
        // accepted is reading the wrong function.
        string memory reason = blsOk ? "post-quantum half unverified" : "classical half unverified";
        challenges[digest] = Challenge({
            attestationDigest: digest,
            challenger: address(0),
            openedAt: uint64(block.number),
            resolved: false,
            height: a.height,
            stateRoot: a.stateRoot
        });
        pendingRootAtHeight[a.height] = a.stateRoot;
        pendingAttestationAtHeight[a.height] = identity;
        emit AttestationOptimistic(digest, a.height, reason);
    }

    function challenge(bytes32 digest, bytes calldata fraudProof) external {
        Challenge storage c = challenges[digest];
        if (c.openedAt == 0) {
            revert NoSuchChallenge(digest);
        }
        if (c.resolved) {
            revert ChallengeResolved(digest);
        }
        uint256 elapsed = block.number - uint256(c.openedAt);
        if (elapsed >= challengeWindow) {
            revert ChallengeWindowClosed(digest);
        }
        uint64 challengeHeight = c.height;
        bytes32 challengeRoot = c.stateRoot;
        bytes32 challengeIdentity = pendingIdentity(challengeHeight, challengeRoot);
        c.challenger = msg.sender;
        c.resolved = true;
        fraudulent[digest] = true;
        fraudulentRoot[challengeHeight][challengeRoot] = true;
        accepted[digest] = false;
        accepted[challengeIdentity] = false;
        if (pendingAttestationAtHeight[challengeHeight] == challengeIdentity) {
            pendingAttestationAtHeight[challengeHeight] = bytes32(0);
            pendingRootAtHeight[challengeHeight] = bytes32(0);
        }
        bool fraud;
        try IExternalFraudProofVerifier(fraudProofVerifier).verifyFraud(digest, fraudProof) returns (bool proven) {
            fraud = proven;
        } catch {
            revert FraudProofRejected(digest);
        }
        if (!fraud) {
            revert FraudProofRejected(digest);
        }
        emit ChallengeOpened(digest, msg.sender);
        emit ChallengeProven(digest, msg.sender, true);
    }

    function settle(bytes32 digest) external {
        Challenge storage c = challenges[digest];
        if (c.openedAt == 0) {
            revert NoSuchChallenge(digest);
        }
        if (c.resolved) {
            revert ChallengeResolved(digest);
        }
        if (fraudulent[digest] || fraudulentRoot[c.height][c.stateRoot]) {
            revert AlreadyFraudulent(digest);
        }
        uint256 elapsed = block.number - uint256(c.openedAt);
        if (elapsed < challengeWindow) {
            revert ChallengeWindowOpen(digest, challengeWindow - elapsed);
        }
        bytes32 held = rootAtHeight[c.height];
        if (held != bytes32(0) && held != c.stateRoot) {
            revert ConflictingRoot(c.height, held, c.stateRoot);
        }
        bytes32 identity = pendingIdentity(c.height, c.stateRoot);
        bool sameFinalized = heightFinal[c.height] && rootAtHeight[c.height] == c.stateRoot;
        if (!sameFinalized
            && (pendingAttestationAtHeight[c.height] != identity
                || pendingRootAtHeight[c.height] != c.stateRoot))
        {
            revert PendingAttestation(c.height, pendingAttestationAtHeight[c.height]);
        }
        if (!sameFinalized) {
            pendingAttestationAtHeight[c.height] = bytes32(0);
            pendingRootAtHeight[c.height] = bytes32(0);
            rootAtHeight[c.height] = c.stateRoot;
            heightFinal[c.height] = true;
        }
        c.resolved = true;
        accepted[digest] = true;
        accepted[identity] = true;
        emit ChallengeProven(digest, c.challenger, false);
    }

    function isAccepted(bytes32 digest) external view returns (bool) {
        return accepted[digest];
    }

    function _verifyBls(bytes32 root, bytes calldata g2Pubkey, bytes calldata g2Generator, bytes calldata g1NegSignature)
        internal
        view
        returns (bool)
    {
        if (g2Pubkey.length != G2_UNCOMPRESSED_LEN) {
            revert BadSignatureLength("aggregate pubkey must be an uncompressed G2 point (256 bytes)");
        }
        if (g2Generator.length != G2_UNCOMPRESSED_LEN) {
            revert BadSignatureLength("generator must be an uncompressed G2 point (256 bytes)");
        }
        if (g1NegSignature.length != G1_UNCOMPRESSED_LEN) {
            revert BadSignatureLength("negated signature must be an uncompressed G1 point (128 bytes)");
        }
        if (_isInfinity(g2Pubkey) || _isInfinity(g2Generator) || _isInfinity(g1NegSignature)) {
            revert SignatureInvalid("BLS points at infinity cannot verify an attestation");
        }
        bytes memory input = bytes.concat(
            _hashToG1(root), g2Pubkey,
            g1NegSignature, g2Generator
        );
        if (gasleft() < GAS_BLS_PAIRING_VERIFY) {
            return false;
        }
        (bool ok, bytes memory out) = PRECOMPILE_BLS_PAIRING.staticcall{gas: GAS_BLS_PAIRING_VERIFY}(input);
        if (!ok || out.length < WORD_LEN) {
            return false;
        }
        uint256 result;
        assembly {
            result := mload(add(out, WORD_LEN))
        }
        return result == 1;
    }

    function _isInfinity(bytes calldata point) internal pure returns (bool) {
        for (uint256 i = 0; i < point.length; i++) {
            if (point[i] != 0) {
                return false;
            }
        }
        return true;
    }

    function _hashToG1(bytes32 root) internal view returns (bytes memory) {
        bytes memory dstPrime = bytes.concat(BLS_DST, bytes1(uint8(BLS_DST.length)));
        bytes32 b0 = sha256(
            bytes.concat(new bytes(FP_PADDED_LEN), root, bytes2(XMD_LEN_IN_BYTES), bytes1(0), dstPrime)
        );
        bytes32 b1 = sha256(bytes.concat(b0, bytes1(XMD_BLOCK_1), dstPrime));
        bytes32 b2 = sha256(bytes.concat(b0 ^ b1, bytes1(XMD_BLOCK_2), dstPrime));
        bytes32 b3 = sha256(bytes.concat(b0 ^ b2, bytes1(XMD_BLOCK_3), dstPrime));
        bytes32 b4 = sha256(bytes.concat(b0 ^ b3, bytes1(XMD_BLOCK_4), dstPrime));
        bytes memory p0 = _mapToG1(bytes.concat(b1, b2));
        bytes memory p1 = _mapToG1(bytes.concat(b3, b4));
        (bool ok, bytes memory out) = PRECOMPILE_BLS_G1ADD.staticcall(bytes.concat(p0, p1));
        if (!ok || out.length != G1_UNCOMPRESSED_LEN) {
            revert PrecompileRefused("G1 add");
        }
        return out;
    }

    function _mapToG1(bytes memory element64) internal view returns (bytes memory) {
        (bool ok, bytes memory reduced) = PRECOMPILE_MODEXP.staticcall(
            bytes.concat(
                bytes32(FP_PADDED_LEN),
                bytes32(MODEXP_EXP_LEN),
                bytes32(FP_BYTE_LEN),
                element64,
                MODEXP_EXP_BYTE,
                BLS_FIELD_MODULUS
            )
        );
        if (!ok || reduced.length != FP_BYTE_LEN) {
            revert PrecompileRefused("modexp");
        }
        bytes memory out;
        (ok, out) = PRECOMPILE_BLS_MAP_FP_TO_G1.staticcall(bytes.concat(bytes16(0), reduced));
        if (!ok || out.length != G1_UNCOMPRESSED_LEN) {
            revert PrecompileRefused("map to G1");
        }
        return out;
    }

    function _verifyMlDsa(
        bytes32 root,
        bytes calldata pubkey,
        bytes calldata signature,
        bool ethVariant
    ) internal view returns (bool) {
        address target = ethVariant ? PRECOMPILE_MLDSA_ETH : PRECOMPILE_MLDSA;
        if (!_probeRejectsMalformed(target)) {
            return false;
        }
        if (gasleft() < GAS_MLDSA_VERIFY) {
            return false;
        }
        bytes memory input = bytes.concat(root, pubkey, signature);
        (bool ok, bytes memory out) = target.staticcall{gas: GAS_MLDSA_VERIFY}(input);
        if (!ok || out.length < WORD_LEN) {
            return false;
        }
        uint256 result;
        assembly {
            result := mload(add(out, WORD_LEN))
        }
        return result == 1;
    }

    function _probeBlsPairing(bytes memory probe) internal view returns (bool) {
        if (PRECOMPILE_BLS_PAIRING.code.length > 0 || gasleft() < GAS_BLS_PAIRING_PROBE) {
            return false;
        }
        (bool ok, bytes memory out) = PRECOMPILE_BLS_PAIRING.staticcall{gas: GAS_BLS_PAIRING_PROBE}(probe);
        return ok && out.length == WORD_LEN;
    }

    function _probeRejectsMalformed(address target) internal view returns (bool) {
        if (target.code.length > 0 || gasleft() < GAS_MALFORMED_PROBE) {
            return false;
        }
        (bool ok, bytes memory out) = target.staticcall{gas: GAS_MALFORMED_PROBE}(hex"00");
        return !ok || out.length == WORD_LEN;
    }
}
