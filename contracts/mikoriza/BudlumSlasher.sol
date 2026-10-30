// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {BudlumBls} from "../lib/BudlumBls.sol";
import {BudlumHash} from "../lib/BudlumHash.sol";

/// @notice The registrar side the slasher calls: the bound key, and the one
///         slashing entry point the registrar (the AVS) forwards to
///         EigenLayer.
interface IBudlumSlashTarget {
    function uncompressedKeyOf(bytes32 budlumValidator, address operator) external view returns (bytes memory);
    function slashForDoubleVote(address operator, string calldata description) external;
}

/// @title BudlumSlasher
/// @notice Slashes a Mikoriza operator on Ethereum for a Budlum finality
///         double vote (10.5): two BLS signatures by the
///         validator's bound key for different checkpoint hashes at the same
///         Budlum chain id, epoch and height.
///
///         The signed message is `checkpoint_signing_message`
///         (src/chain/finality.rs):
///             "BUDLUM_PRECOMMIT_V2" || "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"
///             || le64(chain_id) || le64(epoch) || le64(height) || hash
///         where `hash` is the checkpoint hash as Budlum writes it (64 hex
///         characters). Both signatures are verified with the EIP-2537
///         precompiles against the key the operator bound, and the
///         registrar slashes through the EigenLayer operator set.
///
///         Anyone may submit the evidence. A liveness fault is not slashable
///         here. There is no owner.
///
///         The evidence names the operator whose bound key signed, because a
///         binding is one operator's claim about a validator and no claim is
///         the validator's: the signatures are checked against the key that
///         operator bound, and an operator's key cannot be used to slash
///         another operator's stake.
/// @notice Two signatures of one validator at one checkpoint.
struct DoubleVote {
    bytes32 budlumValidator;
    /// The operator whose bound key produced both signatures.
    address operator;
    uint64 epoch;
    uint64 height;
    /// The first checkpoint hash, as Budlum writes it (64 hex characters).
    bytes hashA;
    /// The first signature, negated, uncompressed G1 (128 bytes).
    bytes negSigA;
    bytes hashB;
    bytes negSigB;
}

contract BudlumSlasher {
    IBudlumSlashTarget public immutable registrar;
    uint64 public immutable budlumChainId;
    bytes32 public immutable g2GeneratorHash;

    /// One slash per (validator, operator, epoch, height).
    mapping(bytes32 => bool) public slashed;

    event DoubleVoteSlashed(
        bytes32 indexed budlumValidator, address indexed operator, uint64 epoch, uint64 height
    );

    error SameHash();
    error UntrustedGenerator();
    error NotBound(bytes32 budlumValidator);
    error AlreadySlashed(bytes32 key);
    error SignatureInvalid(string which);

    constructor(address registrar_, uint64 budlumChainId_, bytes32 g2GeneratorHash_) {
        registrar = IBudlumSlashTarget(registrar_);
        budlumChainId = budlumChainId_;
        g2GeneratorHash = g2GeneratorHash_;
    }

    /// @notice The bytes a Budlum validator signs for a checkpoint.
    function checkpointSigningMessage(uint64 epoch, uint64 height, bytes memory checkpointHash)
        public
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            "BUDLUM_PRECOMMIT_V2",
            "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_",
            BudlumHash.le64(budlumChainId),
            BudlumHash.le64(epoch),
            BudlumHash.le64(height),
            checkpointHash
        );
    }

    /// @notice Slash `vote.operator` for signing two different hashes at one
    ///         checkpoint with the key it bound for `vote.budlumValidator`.
    /// @param vote The two signatures (negated, uncompressed G1) and hashes.
    /// @param g2Generator The G2 generator, uncompressed; must match the
    ///        pinned hash.
    function slashDoubleVote(DoubleVote calldata vote, bytes calldata g2Generator) external {
        if (keccak256(vote.hashA) == keccak256(vote.hashB)) {
            revert SameHash();
        }
        if (keccak256(g2Generator) != g2GeneratorHash) {
            revert UntrustedGenerator();
        }
        bytes32 key = keccak256(abi.encode(vote.budlumValidator, vote.operator, vote.epoch, vote.height));
        if (slashed[key]) {
            revert AlreadySlashed(key);
        }
        _checkSignatures(vote, g2Generator);
        slashed[key] = true;
        registrar.slashForDoubleVote(vote.operator, "budlum finality double vote");
        emit DoubleVoteSlashed(vote.budlumValidator, vote.operator, vote.epoch, vote.height);
    }

    function _checkSignatures(DoubleVote calldata vote, bytes calldata g2Generator) private view {
        bytes memory pubkey = registrar.uncompressedKeyOf(vote.budlumValidator, vote.operator);
        if (pubkey.length == 0) {
            revert NotBound(vote.budlumValidator);
        }
        if (!BudlumBls.verify(
            pubkey, checkpointSigningMessage(vote.epoch, vote.height, vote.hashA), vote.negSigA, g2Generator
        )) {
            revert SignatureInvalid("first");
        }
        if (!BudlumBls.verify(
            pubkey, checkpointSigningMessage(vote.epoch, vote.height, vote.hashB), vote.negSigB, g2Generator
        )) {
            revert SignatureInvalid("second");
        }
    }
}
