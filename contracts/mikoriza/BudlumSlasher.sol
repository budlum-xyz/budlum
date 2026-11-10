// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

import {BudlumBls} from "../lib/BudlumBls.sol";
import {BudlumHash} from "../lib/BudlumHash.sol";

interface IBudlumSlashTarget {
    function uncompressedKeyOf(bytes32 budlumValidator, address operator) external view returns (bytes memory);
    function wasBound(bytes32 budlumValidator, address operator, bytes calldata uncompressedKey)
        external
        view
        returns (bool);
    function slashForDoubleVote(address operator, string calldata description) external;
}

struct DoubleVote {
    bytes32 budlumValidator;
    address operator;
    uint64 epoch;
    uint64 height;
    bytes hashA;
    bytes negSigA;
    bytes hashB;
    bytes negSigB;
}

contract BudlumSlasher {
    IBudlumSlashTarget public immutable registrar;
    uint64 public immutable budlumChainId;
    bytes32 public immutable g2GeneratorHash;

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

    function checkpointSigningMessage(uint64 epoch, uint64 height, bytes memory checkpointHash)
        public
        view
        returns (bytes memory)
    {
        return bytes.concat(
            bytes("BUDLUM_PRECOMMIT_V2"),
            bytes("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"),
            BudlumHash.le64(budlumChainId),
            BudlumHash.le64(epoch),
            BudlumHash.le64(height),
            checkpointHash
        );
    }

    function slashDoubleVote(
        DoubleVote calldata vote,
        bytes calldata pubkey,
        bytes calldata g2Generator
    ) external {
        if (keccak256(vote.hashA) == keccak256(vote.hashB)) {
            revert SameHash();
        }
        if (keccak256(g2Generator) != g2GeneratorHash) {
            revert UntrustedGenerator();
        }
        _checkSignatures(vote, pubkey, g2Generator);
        bytes32 key = keccak256(abi.encode(keccak256(pubkey), vote.operator, vote.epoch, vote.height));
        if (slashed[key]) {
            revert AlreadySlashed(key);
        }
        slashed[key] = true;
        registrar.slashForDoubleVote(vote.operator, "budlum finality double vote");
        emit DoubleVoteSlashed(vote.budlumValidator, vote.operator, vote.epoch, vote.height);
    }

    function _checkSignatures(DoubleVote calldata vote, bytes calldata pubkey, bytes calldata g2Generator)
        private
        view
    {
        if (!registrar.wasBound(vote.budlumValidator, vote.operator, pubkey)) {
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
