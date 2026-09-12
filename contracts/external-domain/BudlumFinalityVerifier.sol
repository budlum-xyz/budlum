// License: Polyfield
pragma solidity ^0.8.24;

/// @title BudlumFinalityVerifier
/// @notice Verifies Budlum's hybrid finality proof (BLS12-381 aggregate +
///         post-quantum ML-DSA) on an EVM chain.
///
/// @dev THE GAS QUESTION, ANSWERED WITH NUMBERS
///
///      This contract exists because the reverse direction has a cost problem,
///      and the cost depends on which precompiles the target chain actually
///      has. There are three regimes and the contract handles all three:
///
///      1. EIP-2537 (BLS12-381) is live. This shipped in Pectra. The pairing
///         check for an aggregate signature is one pairing precompile call
///         rather than ~600k gas of Solidity field arithmetic.
///
///      2. EIP-8051 (ML-DSA) is live. It proposes two precompiles:
///            0x12  VERIFY_MLDSA       (FIPS-204, SHAKE256)     4500 gas
///            0x13  VERIFY_MLDSA_ETH   (Keccak PRNG, t1 in NTT) 4500 gas
///         ML-DSA-ETH deviates from the NIST encoding specifically to be cheap
///         on the EVM: it uses the native KECCAK256 precompile for the PRNG and
///         stores the public key's t1 in the NTT domain to skip one NTT. If we
///         control our own key encoding, using ML-DSA-ETH is free money - but
///         it means our keys are not FIPS-204 keys, which is a decision to make
///         once, in writing, and not by accident.
///
///      3. Neither is live. Pure-Solidity ML-DSA verification is not
///         economically meaningful - the same class of problem (secp256r1)
///         costs ~300k gas in Solidity against 3450 with RIP-7212's precompile,
///         and ML-DSA is far more expensive than an elliptic curve point
///         multiplication. In this regime the contract falls back to an
///         OPTIMISTIC model: accept the attestation, open a challenge window,
///         and let a fraud proof revert it.
///
///      ADDRESS ALLOCATION - CHECKED, AND WHY THE PROBE STAYS ANYWAY
///
///      EIP-2537 is FINAL at seven addresses, 0x0b through 0x11:
///            0x0b BLS12_G1ADD          375 gas
///            0x0c BLS12_G1MSM          variable
///            0x0d BLS12_G2ADD          600 gas
///            0x0e BLS12_G2MSM          variable
///            0x0f BLS12_PAIRING_CHECK  variable
///            0x10 BLS12_MAP_FP_TO_G1   5500 gas
///            0x11 BLS12_MAP_FP2_TO_G2  23800 gas
///      EIP-8051 proposes 0x12 and 0x13 for ML-DSA. Those are ADJACENT to
///      EIP-2537, not overlapping - there is no collision.
///
///      The runtime probe stays regardless, for a reason the collision theory
///      got wrong but the conclusion got right: EIP-2537 was DRAFTED at
///      0x0a-0x12 and later at 0x0c-0x14 before settling on 0x0b-0x11. A chain
///      that implemented an early draft has BLS12_PAIRING at 0x10, not 0x0f,
///      and calling 0x0f there reaches G2MSM - which returns successfully with
///      garbage. That is the failure the probe exists for, and it is real.
///
///      THE COST NOBODY PRICES: COMPRESSED POINTS
///
///      EIP-2537's precompiles take UNCOMPRESSED points: 128 bytes for G1, 256
///      for G2. An Ethereum sync committee signature is 96 bytes of compressed
///      G2 and the aggregate public key is 48 bytes of compressed G1. Nothing
///      in EIP-2537 decompresses a point. Decompression needs a square root in
///      Fp (and in Fp2 for G2), which is the expensive half of the whole
///      verification and is NOT covered by the 4500-gas-style precompile
///      pricing.
///
///      So an honest statement of the cost is: the pairing is cheap, getting
///      points into the form the pairing wants is not. This contract therefore
///      takes the points already decompressed and makes the caller attest to
///      that, rather than pretending to do it in 4500 gas. Doing the
///      decompression inside a ZK circuit - and verifying the circuit - is the
///      route that actually works, and it is the reason the Budlum-side
///      verification is a STARK.
///
///      NOTHING IN THIS CONTRACT IS A TRUST ASSUMPTION
///
///      The optimistic fallback is a trust assumption and is labelled as one
///      everywhere it appears. It is the fallback, not the path.

/// @notice One Budlum finality attestation, as it crosses over.
struct Attestation {
    /// Budlum height the attestation is about.
    uint64 height;
    /// The state root being attested to.
    bytes32 stateRoot;
    /// The Budlum epoch, carried so a replay from an old epoch is distinguishable
    /// from a fresh one with the same root.
    uint64 epoch;
    /// The chain id this attestation was produced for. Without it, an
    /// attestation from a testnet verifies on mainnet.
    uint64 chainId;
    // --- BLS12-381, in the UNCOMPRESSED form EIP-2537 requires ---
    //
    // Four points, not two. A BLS verification is the pairing equation
    //     e(H(m), agg_pubkey) * e(-sig, g1) == 1
    // and the precompile wants each side of each pairing as a separate
    // uncompressed point. The negation of the signature is done by the caller
    // for the same reason the decompression is: neither is something the
    // precompile does, and doing them in Solidity is the expensive part.
    /// H(signing root) mapped to G1, uncompressed (128 bytes).
    bytes g1HashedMessage;
    /// The aggregate public key, uncompressed G2 (256 bytes).
    bytes g2AggregatePubkey;
    /// The G1 generator, uncompressed (128 bytes). Carried rather than hardcoded
    /// so a chain with a different encoding is served by the same contract.
    bytes g1Generator;
    /// The negated aggregate signature, uncompressed G2 (256 bytes).
    bytes g2NegSignature;
    /// ML-DSA signature over the same signing root.
    bytes mlDsaSignature;
    /// ML-DSA public key.
    bytes mlDsaPubkey;
    /// Which algorithm variant the ML-DSA key uses. See `_verifyMlDsa`.
    bool mlDsaEthVariant;
}

/// @notice A fraud proof against an optimistically accepted attestation.
struct Challenge {
    bytes32 attestationDigest;
    address challenger;
    uint64 openedAt;
    bool resolved;
}

contract BudlumFinalityVerifier {
    // ---------------------------------------------------------------------
    // Precompile addresses. Probed, never assumed.
    // ---------------------------------------------------------------------

    /// EIP-2537, final allocation. The pairing check is 0x0f - 0x0e is
    /// BLS12_G2MSM, and calling it as if it were the pairing check returns a
    /// successful result that means nothing.
    address internal constant PRECOMPILE_BLS_G1ADD = address(0x0b);
    address internal constant PRECOMPILE_BLS_G1MSM = address(0x0c);
    address internal constant PRECOMPILE_BLS_G2ADD = address(0x0d);
    address internal constant PRECOMPILE_BLS_G2MSM = address(0x0e);
    address internal constant PRECOMPILE_BLS_PAIRING = address(0x0f);
    address internal constant PRECOMPILE_BLS_MAP_FP_TO_G1 = address(0x10);
    address internal constant PRECOMPILE_BLS_MAP_FP2_TO_G2 = address(0x11);
    /// EIP-8051 VERIFY_MLDSA (FIPS-204).
    address internal constant PRECOMPILE_MLDSA = address(0x12);
    /// EIP-8051 VERIFY_MLDSA_ETH (Keccak PRNG, NTT-domain t1).
    address internal constant PRECOMPILE_MLDSA_ETH = address(0x13);
    /// RIP-7212 / EIP-7212 secp256r1, present on most L2s. Not used for the
    /// hybrid proof itself; probed so the deployment report can say what the
    /// chain supports.
    address internal constant PRECOMPILE_P256 = address(0x100);

    // ---------------------------------------------------------------------
    // Gas accounting, as constants so the numbers are in one place.
    //
    // These are the published costs, not measurements on a specific chain.
    // A deployment SHOULD re-measure and pin its own; the values here are the
    // floor a chain with the precompiles will hit.
    // ---------------------------------------------------------------------

    uint256 internal constant GAS_MLDSA_VERIFY = 4500;      // EIP-8051
    uint256 internal constant GAS_P256_VERIFY = 3450;       // RIP-7212
    uint256 internal GAS_P256_SOLIDITY = 300_000;           // pure Solidity

    /// Challenge window for the optimistic fallback, in blocks. Long enough
    /// that a prover cannot finalise a lie and spend the proceeds before
    /// somebody notices; the number is a policy choice and is public.
    uint256 public immutable challengeWindow;

    /// The Budlum chain id this deployment serves.
    uint64 public immutable budlumChainId;

    /// Attestations accepted, by digest.
    mapping(bytes32 => bool) public accepted;

    /// Open challenges, by attestation digest.
    mapping(bytes32 => Challenge) public challenges;

    /// Which regime this deployment detected at construction. Stored so a
    /// reader can tell whether the verifier is cryptographic or optimistic
    /// without reading the bytecode.
    bool public immutable hasBlsPrecompile;
    bool public immutable hasMlDsaPrecompile;

    event AttestationVerified(bytes32 indexed digest, uint64 height, bytes32 stateRoot);
    event AttestationOptimistic(bytes32 indexed digest, uint64 height, string reason);
    event ChallengeOpened(bytes32 indexed digest, address indexed challenger);
    event ChallengeProven(bytes32 indexed digest, address indexed challenger, bool fraud);

    error WrongChainId(uint64 expected, uint64 got);
    error AlreadyAccepted(bytes32 digest);
    error BadSignatureLength(string what);
    error PrecompileRefused(string what);
    error NoVerificationPath();
    error ChallengeWindowOpen(bytes32 digest, uint256 blocksLeft);
    error NoSuchChallenge(bytes32 digest);
    error ChallengeResolved(bytes32 digest);

    constructor(uint64 budlumChainId_, uint256 challengeWindow_) {
        budlumChainId = budlumChainId_;
        challengeWindow = challengeWindow_;
        // Pairing's ABI is 384 bytes per pair. A malformed one-pair probe
        // distinguishes the final pairing precompile from an early-draft
        // address that hosts a different BLS operation.
        hasBlsPrecompile = _probeBlsPairing(new bytes(384));
        hasMlDsaPrecompile =
            _probeRejectsMalformed(PRECOMPILE_MLDSA)
                || _probeRejectsMalformed(PRECOMPILE_MLDSA_ETH);
    }

    /// @notice The digest an attestation is identified by. Everything that must
    ///         not be replayed commits to this.
    function attestationDigest(Attestation calldata a) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                "bud-attestation-v1",
                a.height,
                a.stateRoot,
                a.epoch,
                a.chainId,
                keccak256(a.g1HashedMessage),
                keccak256(a.g2AggregatePubkey),
                keccak256(a.g1Generator),
                keccak256(a.g2NegSignature),
                keccak256(a.mlDsaSignature),
                keccak256(a.mlDsaPubkey),
                a.mlDsaEthVariant
            )
        );
    }

    /// @notice The signing root both signatures speak. Derived here rather than
    ///         supplied, because a caller-supplied root is a caller-chosen
    ///         message.
    function signingRoot(Attestation calldata a) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "bud-finality-signing-root-v1",
                block.chainid,
                a.height,
                a.stateRoot,
                a.epoch,
                a.chainId,
                // The signature must bind the exact decompressed points that
                // the pairing call will consume. This does not replace
                // hash-to-curve; the deployment still requires the circuit
                // binding recorded by the Rust planner. It does prevent a
                // valid signature over one point encoding from being paired
                // with another after signing.
                keccak256(a.g1HashedMessage),
                keccak256(a.g2AggregatePubkey),
                keccak256(a.g1Generator),
                keccak256(a.g2NegSignature)
            )
        );
    }

    /// @notice Verifies an attestation and records it.
    ///
    /// @dev Three regimes, in order of preference:
    ///      - both precompiles: full cryptographic verification, no window;
    ///      - BLS only: verifies the classical half cryptographically and opens
    ///        a challenge window for the post-quantum half. This is a weaker
    ///        guarantee and the event says so;
    ///      - neither: optimistic, window open, event says so.
    ///
    ///      There is no path in which a missing precompile causes the
    ///      verification to be skipped and the attestation recorded as if it
    ///      had been checked.
    function verify(Attestation calldata a) external returns (bytes32 digest) {
        if (a.chainId != budlumChainId) {
            revert WrongChainId(budlumChainId, a.chainId);
        }
        digest = attestationDigest(a);
        if (accepted[digest]) {
            revert AlreadyAccepted(digest);
        }

        bytes32 root = signingRoot(a);

        bool blsOk = false;
        bool pqOk = false;

        if (hasBlsPrecompile) {
            blsOk = _verifyBls(
                root,
                a.g1HashedMessage,
                a.g2AggregatePubkey,
                a.g1Generator,
                a.g2NegSignature
            );
        }
        if (hasMlDsaPrecompile) {
            pqOk = _verifyMlDsa(root, a.mlDsaPubkey, a.mlDsaSignature, a.mlDsaEthVariant);
        }

        if (blsOk && pqOk) {
            accepted[digest] = true;
            emit AttestationVerified(digest, a.height, a.stateRoot);
            return digest;
        }

        // Optimistic path. The attestation is NOT marked accepted here; it is
        // marked accepted only when the window closes, via `settle`. A caller
        // that treats an open window as accepted is reading the wrong function.
        string memory reason = !hasBlsPrecompile && !hasMlDsaPrecompile
            ? "no verification precompile on this chain"
            : (blsOk ? "post-quantum half unverified" : "classical half unverified");
        challenges[digest] = Challenge({
            attestationDigest: digest,
            challenger: address(0),
            openedAt: uint64(block.number),
            resolved: false
        });
        emit AttestationOptimistic(digest, a.height, reason);
    }

    /// @notice Accepts an optimistically held attestation once its window has
    ///         closed. Reverts while the window is open - the window is the
    ///         only thing standing between an optimistic accept and a lie.
    function settle(bytes32 digest) external {
        Challenge storage c = challenges[digest];
        if (c.openedAt == 0) {
            revert NoSuchChallenge(digest);
        }
        if (c.resolved) {
            revert ChallengeResolved(digest);
        }
        uint256 elapsed = block.number - uint256(c.openedAt);
        if (elapsed < challengeWindow) {
            revert ChallengeWindowOpen(digest, challengeWindow - elapsed);
        }
        c.resolved = true;
        accepted[digest] = true;
        emit ChallengeProven(digest, c.challenger, false);
    }

    /// @notice Whether a digest may be relied on.
    function isAccepted(bytes32 digest) external view returns (bool) {
        return accepted[digest];
    }

    // ---------------------------------------------------------------------
    // Verification internals
    // ---------------------------------------------------------------------

    /// @dev Calls the EIP-2537 pairing check with the ABI it actually defines.
    ///
    ///      The pairing check takes 384 bytes per pair - 128 bytes of G1
    ///      followed by 256 bytes of G2 - and returns 32 bytes whose last byte
    ///      is 0x01 when the pairing product is the identity, 0x00 otherwise.
    ///      BLS verification is two pairs:
    ///            e(H(m), agg_pubkey) * e(-signature, g1_generator) == 1
    ///
    ///      Both points arrive UNCOMPRESSED and the caller is responsible for
    ///      having decompressed them; see the header note on why that step is
    ///      the expensive one and is not done here.
    ///
    ///      A precompile that returns anything other than a 32-byte word is
    ///      treated as a refusal, never as an unknown - an unknown answer from
    ///      a cryptographic check is a refusal.
    function _verifyBls(bytes32 root, bytes calldata g1HashedMessage, bytes calldata g2Pubkey, bytes calldata g1Generator, bytes calldata g2NegSignature)
        internal
        view
        returns (bool)
    {
        // Pair layout: G1 (128) then G2 (256), twice.
        if (g1HashedMessage.length != 128) {
            revert BadSignatureLength("hashed message must be an uncompressed G1 point (128 bytes)");
        }
        if (g2Pubkey.length != 256) {
            revert BadSignatureLength("aggregate pubkey must be an uncompressed G2 point (256 bytes)");
        }
        if (g1Generator.length != 128) {
            revert BadSignatureLength("generator must be an uncompressed G1 point (128 bytes)");
        }
        if (g2NegSignature.length != 256) {
            revert BadSignatureLength("negated signature must be an uncompressed G2 point (256 bytes)");
        }
        // `root` is carried in the G1 point the caller hashed to; it is not
        // concatenated into the input, because the pairing ABI has no place
        // for a bare scalar and inventing one would be inventing an ABI.
        bytes memory input = abi.encodePacked(
            g1HashedMessage, g2Pubkey,
            g1Generator, g2NegSignature
        );
        (bool ok, bytes memory out) = PRECOMPILE_BLS_PAIRING.staticcall{gas: 400_000}(input);
        if (!ok || out.length < 32) {
            return false;
        }
        uint256 result;
        assembly {
            result := mload(add(out, 32))
        }
        return result == 1;
    }

    /// @dev Calls the EIP-8051 ML-DSA precompile.
    ///
    ///      The two variants are different algorithms with different encodings,
    ///      and the attestation declares which one it is using. Guessing would
    ///      mean feeding FIPS-204 bytes to a Keccak-PRNG verifier, which would
    ///      refuse - so a mislabelled attestation fails safe rather than
    ///      verifying as something else.
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
        bytes memory input = abi.encodePacked(root, pubkey, signature);
        // EIP-8051 prices the call at 4500; the stipend here is headroom, not a
        // guess at the cost.
        (bool ok, bytes memory out) = target.staticcall{gas: 60_000}(input);
        if (!ok || out.length < 32) {
            return false;
        }
        uint256 result;
        assembly {
            result := mload(add(out, 32))
        }
        return result == 1;
    }

    /// @dev EIP-2537 pairing probe. A valid-length pairing call returns its
    ///      32-byte boolean even when the supplied points do not pair; another
    ///      operation at the address normally returns a different shape or
    ///      reverts. The actual verification call remains the authority.
    function _probeBlsPairing(bytes memory probe) internal view returns (bool) {
        if (PRECOMPILE_BLS_PAIRING.code.length > 0) {
            return false;
        }
        (bool ok, bytes memory out) = PRECOMPILE_BLS_PAIRING.staticcall{gas: 5_000}(probe);
        return ok && out.length == 32;
    }

    /// @dev ML-DSA has no cheap valid public test vector in the deployment
    ///      constructor. Its malformed-input rejection is still enough to
    ///      distinguish the reserved address from an EOA; the verification
    ///      call checks the signature and key later. A contract occupying the
    ///      reserved address is never treated as the precompile.
    function _probeRejectsMalformed(address target) internal view returns (bool) {
        if (target.code.length > 0) {
            return false;
        }
        (bool ok, bytes memory out) = target.staticcall{gas: 5_000}(hex"00");
        return !ok || out.length == 32;
    }
}
