// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

/// @title BudlumFinalityVerifier
/// @notice Verifies Budlum's hybrid finality proof (BLS12-381 aggregate +
///         post-quantum ML-DSA) on an EVM chain.
///
/// @dev BLG-1074 (P60-F07): this source is deployment-ready code, but no
///      Sepolia deployment is claimed by this repository. The verifier has no
///      upgrade or owner path: its chain id, key hashes, fraud verifier and
///      challenge policy are immutable constructor commitments. The Rust
///      `EvmFinalityAttestation` encoder and the negative contract locks cover
///      the cross-language signing root and the six F01-F06 refusal boundaries.
///      An operator still needs an independent deployment ceremony and must
///      publish the constructor key-hash manifest before relying on an address.
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
    // Budlum signs with public keys in G2 and signatures in G1. The
    // verification is the pairing equation
    //     e(H(root), agg_pubkey) * e(-sig, g2) == 1
    // H(root) is derived inside the contract, never supplied. The aggregate
    // public key and the G2 generator are carried here but must match the
    // hashes pinned at construction. The signature is negated by the caller
    // because the precompile does not negate points.
    /// The aggregate public key, uncompressed G2 (256 bytes).
    bytes g2AggregatePubkey;
    /// The G2 generator, uncompressed (256 bytes).
    bytes g2Generator;
    /// The negated aggregate signature, uncompressed G1 (128 bytes).
    bytes g1NegSignature;
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
    uint64 height;
    bytes32 stateRoot;
}

/// @notice A deployment-specific fraud-proof verifier. The optimistic path
///         stays permissionless because anybody may call `challenge`; this
///         interface is only the cryptographic predicate for the proof itself.
interface IExternalFraudProofVerifier {
    function verifyFraud(bytes32 attestationDigest, bytes calldata proof)
        external
        view
        returns (bool);
}

contract BudlumFinalityVerifier {
    // ---------------------------------------------------------------------
    // Precompile addresses. Probed, never assumed.
    // ---------------------------------------------------------------------

    /// EIP-2537, final allocation. The pairing check is 0x0f - 0x0e is
    /// BLS12_G2MSM, and calling it as if it were the pairing check returns a
    /// successful result that means nothing.
    address internal constant PRECOMPILE_BLS_G1ADD = address(0x0b);
    address internal constant PRECOMPILE_BLS_PAIRING = address(0x0f);
    address internal constant PRECOMPILE_BLS_MAP_FP_TO_G1 = address(0x10);
    /// EIP-198 modexp, present on every EVM chain. Used to reduce the
    /// hash-to-field bytes modulo the BLS12-381 base field prime.
    address internal constant PRECOMPILE_MODEXP = address(0x05);
    /// BLS12-381 base field prime p, 48 bytes big-endian.
    bytes internal constant BLS_FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    /// Budlum BLS signature DST. Must equal `BLS_SIGNATURE_DST` in
    /// src/chain/finality.rs.
    bytes internal constant BLS_DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
    /// EIP-8051 VERIFY_MLDSA (FIPS-204).
    address internal constant PRECOMPILE_MLDSA = address(0x12);
    /// EIP-8051 VERIFY_MLDSA_ETH (Keccak PRNG, NTT-domain t1).
    address internal constant PRECOMPILE_MLDSA_ETH = address(0x13);

    // ---------------------------------------------------------------------
    // Gas accounting, as constants so the numbers are in one place.
    //
    // These are the published costs, not measurements on a specific chain.
    // A deployment SHOULD re-measure and pin its own; the values here are the
    // floor a chain with the precompiles will hit.
    // ---------------------------------------------------------------------

    /// EIP-2537 pairing check costs 32600 * k + 37700 gas, so 70300 for the
    /// one-pair probe. The stipend leaves headroom. A smaller stipend makes
    /// the probe fail on a real chain.
    uint256 internal constant GAS_BLS_PAIRING_PROBE = 150_000;

    /// Challenge window for the optimistic fallback, in blocks. Long enough
    /// that a prover cannot finalise a lie and spend the proceeds before
    /// somebody notices; the number is a policy choice and is public.
    uint256 public immutable challengeWindow;

    /// The verifier for a fraud proof in the optimistic regime. It is a
    /// verifier contract, not an owner key: it cannot decide which domain is
    /// good, it can only answer whether the submitted proof contradicts this
    /// digest.
    address public immutable fraudProofVerifier;

    /// The Budlum chain id this deployment serves.
    uint64 public immutable budlumChainId;

    /// Trusted keys, pinned at construction as hashes of the exact bytes an
    /// attestation must carry. An attestation whose key bytes do not hash to
    /// these values is refused, so a caller cannot bring its own key.
    bytes32 public immutable committeePubkeyHash;
    bytes32 public immutable g2GeneratorHash;
    bytes32 public immutable mlDsaPubkeyHash;

    /// Attestations accepted, by digest.
    mapping(bytes32 => bool) public accepted;

    /// The one state root allowed per Budlum height. Set by the first digest
    /// that is accepted or opens a window. A different root for the same
    /// height is refused until a fraud proof clears the claim.
    mapping(uint64 => bytes32) public rootAtHeight;

    /// A pending optimistic claim reserves both the root and the attestation
    /// digest for its height. This prevents two different roots (or two
    /// independently challengeable digests for one root) from racing through
    /// separate windows.
    mapping(uint64 => bytes32) public pendingRootAtHeight;
    mapping(uint64 => bytes32) public pendingAttestationAtHeight;

    /// Heights with an accepted digest. Their claim is never cleared.
    mapping(uint64 => bool) public heightFinal;

    /// Open challenges, by attestation digest.
    mapping(bytes32 => Challenge) public challenges;

    /// Digests a fraud proof has disproved. Once set this is terminal:
    /// `verify` refuses the digest forever, so `settle` can never accept it
    /// after the fact. A per-challenge record is ephemeral (the struct is
    /// rewritten when a window opens); the fraud verdict must outlive it.
    mapping(bytes32 => bool) public fraudulent;

    /// Claims a fraud proof has disproved, keyed by `(height, stateRoot)`.
    /// Keying fraud by digest alone lets a submitter re-present the exact
    /// same disproved `(height, stateRoot)` under a fresh `epoch` or signature
    /// blob and settle it in a second window (CWE-294).
    mapping(uint64 => mapping(bytes32 => bool)) public fraudulentRoot;

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
            // The constructor is the only trust-anchor ceremony. A zero hash
            // would make the "pinned" key an accidental empty-input policy.
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
                keccak256(a.g2AggregatePubkey),
                keccak256(a.g2Generator),
                keccak256(a.g1NegSignature),
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
    ///      - neither: refused (`NoVerificationPath`): nothing on this chain
    ///        could check either half, so the attestation does not enter the
    ///        window and no event claims otherwise.
    ///      A window opens only for a half whose precompile is missing. If a
    ///      precompile is present and its check fails, `verify` reverts.
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
        if (fraudulent[digest]) {
            revert AlreadyFraudulent(digest);
        }
        if (fraudulentRoot[a.height][a.stateRoot]) {
            revert AlreadyFraudulent(digest);
        }
        if (challenges[digest].openedAt != 0) {
            // A digest gets one window: re-verifying would overwrite the
            // challenge record, reset `openedAt`, and postpone `settle`
            // indefinitely (and before the `fraudulent` guard, would revive
            // a fraud-proven attestation).
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

        // A finalized root and a pending optimistic root are both exclusive
        // claims. The pending digest check closes the second window race: one
        // height may not have two independently challengeable attestations.
        bytes32 held = rootAtHeight[a.height];
        if (held != bytes32(0) && held != a.stateRoot && heightFinal[a.height]) {
            revert ConflictingRoot(a.height, held, a.stateRoot);
        }
        bytes32 pendingDigest = pendingAttestationAtHeight[a.height];
        if (pendingDigest != bytes32(0) && pendingDigest != digest) {
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

        // A half whose precompile is present must verify. A failed check is a
        // refusal, never a reason to open a window: only a MISSING precompile
        // may fall back to the optimistic path.
        if (hasBlsPrecompile && !blsOk) {
            revert SignatureInvalid("BLS signature does not verify");
        }
        if (hasMlDsaPrecompile && !pqOk) {
            revert SignatureInvalid("ML-DSA signature does not verify");
        }

        if (blsOk && pqOk) {
            accepted[digest] = true;
            rootAtHeight[a.height] = a.stateRoot;
            heightFinal[a.height] = true;
            emit AttestationVerified(digest, a.height, a.stateRoot);
            return digest;
        }

        // Neither half verified: the chain carries no verification
        // precompile for either half, so nothing about this attestation has
        // been checked. Such an attestation must not enter the challenge
        // window either - the window would accept it after silence, on a
        // chain where neither half could ever have been verified, and the
        // event would describe a check that never happened. Refuse: a
        // deployment where no verification path runs must not be relied on.
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
        pendingAttestationAtHeight[a.height] = digest;
        emit AttestationOptimistic(digest, a.height, reason);
    }

    /// @notice Challenges an optimistic attestation with a cryptographic fraud
    ///         proof. A rejected fraud proof leaves the window open, so a
    ///         malformed challenge cannot grief settlement; a proven fraud
    ///         permanently prevents settlement and clears reliance on the
    ///         digest.
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
        bool fraud;
        try IExternalFraudProofVerifier(fraudProofVerifier).verifyFraud(digest, fraudProof) returns (bool proven) {
            fraud = proven;
        } catch {
            revert FraudProofRejected(digest);
        }
        if (!fraud) {
            revert FraudProofRejected(digest);
        }
        c.challenger = msg.sender;
        c.resolved = true;
        fraudulent[digest] = true;
        fraudulentRoot[c.height][c.stateRoot] = true;
        accepted[digest] = false;
        if (pendingAttestationAtHeight[c.height] == digest) {
            pendingAttestationAtHeight[c.height] = bytes32(0);
            pendingRootAtHeight[c.height] = bytes32(0);
        }
        emit ChallengeOpened(digest, msg.sender);
        emit ChallengeProven(digest, msg.sender, true);
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
        if (fraudulent[digest] || fraudulentRoot[c.height][c.stateRoot]) {
            revert AlreadyFraudulent(digest);
        }
        uint256 elapsed = block.number - uint256(c.openedAt);
        if (elapsed < challengeWindow) {
            revert ChallengeWindowOpen(digest, challengeWindow - elapsed);
        }
        // Reject settlement if another root already finalized this height or
        // if this challenge is no longer the pending claim for its height.
        bytes32 held = rootAtHeight[c.height];
        if (held != bytes32(0) && held != c.stateRoot) {
            revert ConflictingRoot(c.height, held, c.stateRoot);
        }
        if (pendingAttestationAtHeight[c.height] != digest
            || pendingRootAtHeight[c.height] != c.stateRoot) {
            revert PendingAttestation(c.height, pendingAttestationAtHeight[c.height]);
        }
        pendingAttestationAtHeight[c.height] = bytes32(0);
        pendingRootAtHeight[c.height] = bytes32(0);
        c.resolved = true;
        accepted[digest] = true;
        rootAtHeight[c.height] = c.stateRoot;
        heightFinal[c.height] = true;
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
    ///      Budlum BLS is public key in G2, signature in G1, with two pairs:
    ///            e(H(root), agg_pubkey) * e(-signature, g2_generator) == 1
    ///      H(root) is `_hashToG1(root)`, so the signature is bound to the
    ///      signing root. The key and generator were checked against the
    ///      pinned hashes by the caller.
    ///
    ///      A precompile that returns anything other than a 32-byte word is
    ///      treated as a refusal, never as an unknown - an unknown answer from
    ///      a cryptographic check is a refusal.
    function _verifyBls(bytes32 root, bytes calldata g2Pubkey, bytes calldata g2Generator, bytes calldata g1NegSignature)
        internal
        view
        returns (bool)
    {
        if (g2Pubkey.length != 256) {
            revert BadSignatureLength("aggregate pubkey must be an uncompressed G2 point (256 bytes)");
        }
        if (g2Generator.length != 256) {
            revert BadSignatureLength("generator must be an uncompressed G2 point (256 bytes)");
        }
        if (g1NegSignature.length != 128) {
            revert BadSignatureLength("negated signature must be an uncompressed G1 point (128 bytes)");
        }
        // Pair layout: G1 (128) then G2 (256), twice.
        bytes memory input = abi.encodePacked(
            _hashToG1(root), g2Pubkey,
            g1NegSignature, g2Generator
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

    /// @dev RFC 9380 hash_to_curve for BLS12381G1_XMD:SHA-256_SSWU_RO_ with
    ///      the Budlum signature DST (same as `BLS_SIGNATURE_DST` in
    ///      src/chain/finality.rs). Two field elements come from
    ///      expand_message_xmd (128 bytes, four SHA-256 blocks). Each goes
    ///      through the EIP-2537 map precompile, which also clears the
    ///      cofactor, and the two points are added.
    function _hashToG1(bytes32 root) internal view returns (bytes memory) {
        bytes memory dstPrime = abi.encodePacked(BLS_DST, uint8(BLS_DST.length));
        bytes32 b0 = sha256(abi.encodePacked(new bytes(64), root, uint16(128), uint8(0), dstPrime));
        bytes32 b1 = sha256(abi.encodePacked(b0, uint8(1), dstPrime));
        bytes32 b2 = sha256(abi.encodePacked(b0 ^ b1, uint8(2), dstPrime));
        bytes32 b3 = sha256(abi.encodePacked(b0 ^ b2, uint8(3), dstPrime));
        bytes32 b4 = sha256(abi.encodePacked(b0 ^ b3, uint8(4), dstPrime));
        bytes memory p0 = _mapToG1(abi.encodePacked(b1, b2));
        bytes memory p1 = _mapToG1(abi.encodePacked(b3, b4));
        (bool ok, bytes memory out) = PRECOMPILE_BLS_G1ADD.staticcall(abi.encodePacked(p0, p1));
        if (!ok || out.length != 128) {
            revert PrecompileRefused("G1 add");
        }
        return out;
    }

    /// @dev Reduces 64 big-endian bytes modulo the BLS12-381 base field prime
    ///      with the modexp precompile (x^1 mod p), pads the 48-byte result to
    ///      the 64-byte EIP-2537 field element, and maps it to G1.
    function _mapToG1(bytes memory element64) internal view returns (bytes memory) {
        (bool ok, bytes memory reduced) = PRECOMPILE_MODEXP.staticcall(
            abi.encodePacked(uint256(64), uint256(1), uint256(48), element64, uint8(1), BLS_FIELD_MODULUS)
        );
        if (!ok || reduced.length != 48) {
            revert PrecompileRefused("modexp");
        }
        bytes memory out;
        (ok, out) = PRECOMPILE_BLS_MAP_FP_TO_G1.staticcall(abi.encodePacked(bytes16(0), reduced));
        if (!ok || out.length != 128) {
            revert PrecompileRefused("map to G1");
        }
        return out;
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
        (bool ok, bytes memory out) = PRECOMPILE_BLS_PAIRING.staticcall{gas: GAS_BLS_PAIRING_PROBE}(probe);
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
