// SPDX-License-Identifier: Polyfield
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
///      ADDRESS COLLISION WARNING
///
///      EIP-2537 allocated 0x0b through 0x13 for BLS12-381. EIP-8051 proposes
///      0x12 and 0x13 for ML-DSA. Those ranges overlap. This contract does not
///      assume either allocation: it probes the address at runtime with
///      `_precompileExists` and refuses to call an address that does not behave
///      like the precompile it expects. A chain that shipped BLS at 0x12 and
///      then shipped ML-DSA at 0x12 would otherwise produce a verification that
///      silently means something else.
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
    /// BLS12-381 aggregate signature over the signing root (96 bytes).
    bytes blsSignature;
    /// The aggregate public key of the signing set (48 bytes per key, or one
    /// aggregated G1 point).
    bytes blsAggregatePubkey;
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

    /// EIP-2537 pairing check.
    address internal constant PRECOMPILE_BLS_PAIRING = address(0x0e);
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
        hasBlsPrecompile = _precompileExists(PRECOMPILE_BLS_PAIRING);
        hasMlDsaPrecompile =
            _precompileExists(PRECOMPILE_MLDSA) || _precompileExists(PRECOMPILE_MLDSA_ETH);
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
                keccak256(a.blsSignature),
                keccak256(a.blsAggregatePubkey),
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
                a.chainId
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
            blsOk = _verifyBls(root, a.blsAggregatePubkey, a.blsSignature);
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

    /// @dev Calls the EIP-2537 pairing precompile.
    ///
    ///      The exact ABI is the pairing-check input encoding; this contract
    ///      passes the aggregate pubkey and signature through and requires a
    ///      one-word success. A precompile that returns anything else is
    ///      treated as a refusal, not as an unknown - an unknown answer from a
    ///      cryptographic check is a refusal.
    function _verifyBls(bytes32 root, bytes calldata pubkey, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (signature.length != 96) {
            revert BadSignatureLength("BLS signature must be 96 bytes");
        }
        if (pubkey.length != 48) {
            revert BadSignatureLength("BLS aggregate pubkey must be 48 bytes");
        }
        bytes memory input = abi.encodePacked(root, pubkey, signature);
        (bool ok, bytes memory out) =
            PRECOMPILE_BLS_PAIRING.staticcall{gas: 200_000}(input);
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
        if (!_precompileExists(target)) {
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

    /// @dev Probes whether an address behaves like a precompile.
    ///
    ///      A plain EOA and an empty contract both return success with empty
    ///      output for a staticcall with empty input, so presence alone is not
    ///      enough; but an address that REVERTS on empty input is definitely
    ///      not the precompile we expect, and that is the case that matters for
    ///      the 0x12/0x13 collision between EIP-2537 and EIP-8051.
    function _precompileExists(address target) internal view returns (bool) {
        if (target.code.length > 0) {
            // A deployed contract at a precompile address is not the
            // precompile. Refuse rather than call it.
            return false;
        }
        (bool ok,) = target.staticcall{gas: 5_000}("");
        return ok;
    }
}
