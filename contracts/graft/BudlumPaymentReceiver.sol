// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {BudlumHash} from "../lib/BudlumHash.sol";

/// @notice The part of `BudlumFinalityVerifier` a receiver reads.
interface IBudlumFinality {
    function rootAtHeight(uint64 height) external view returns (bytes32);
    function heightFinal(uint64 height) external view returns (bool);
}

/// @notice A Budlum Graft payment as `GraftPayment` (src/settlement/graft.rs).
struct GraftPayment {
    bytes32 paymentId;
    bytes32 graftId;
    bytes32 payer;
    bytes32 recipient;
    uint64 amount;
    bytes originRecipient;
    bytes32 memoHash;
    uint64 paidAtBlock;
}

/// @notice A Budlum checkpoint header (`GlobalBlockHeader`, V7). Optional
///         roots carry a presence flag, as the Budlum preimage tags them.
struct GlobalHeader {
    uint16 version;
    uint64 globalHeight;
    bytes32 previousGlobalHash;
    uint64 chainId;
    uint128 timestampMs;
    bytes32 domainRegistryRoot;
    bytes32 domainCommitmentRoot;
    bytes32 messageRoot;
    bytes32 bridgeStateRoot;
    bytes32 replayNonceRoot;
    /// 32 bytes, or empty when the header has no proposer.
    bytes proposer;
    bytes32 settlementFinalityRoot;
    bool hasStorageRoot;
    bytes32 storageRoot;
    bool hasAiRoot;
    bytes32 aiRoot;
    bool hasIdentityRoot;
    bytes32 identityRoot;
    uint64 checkpointHeight;
    bool hasExternalIntakeRoot;
    bytes32 externalIntakeRoot;
    bool hasGraftRoot;
    bytes32 graftRoot;
    bool hasDelegationRoot;
    bytes32 delegationRoot;
}

/// @notice Everything `bud_graftPaymentProof` returns, in EVM form.
struct PaymentProof {
    GraftPayment payment;
    uint256 index;
    bytes32[] path;
    bytes32 paymentsRoot;
    bytes32 restHash;
    GlobalHeader header;
    bytes32 stateRootBody;
}

/// @title BudlumPaymentReceiver
/// @notice On-chain check of a Budlum Graft payment (8.5,
///         level 1 in a contract). The chain checked is the one
///         `verify_graft_payment` checks in Rust:
///
///         finalized Budlum state root (from BudlumFinalityVerifier)
///           = H("BDLM_STATE_ROOT_GLOBAL_HEADER_V1", body, header hash)
///         header.graft_root = H("BDLM_GRAFT_REGISTRY_V2", payments_root, rest)
///         payment leaf --path--> payments_root
///
///         An application inherits it and calls `_consumePayment`, which
///         refuses a payment for another Graft row and a payment used once.
abstract contract BudlumPaymentReceiver {
    IBudlumFinality public immutable finality;
    bytes32 public immutable graftId;

    mapping(bytes32 => bool) public consumed;

    event PaymentConsumed(bytes32 indexed paymentId, bytes32 payer, uint64 amount, bytes32 memoHash);

    error WrongGraft(bytes32 expected, bytes32 got);
    error AlreadyConsumed(bytes32 paymentId);
    error ProofInvalid(string link);

    constructor(IBudlumFinality finality_, bytes32 graftId_) {
        finality = finality_;
        graftId = graftId_;
    }

    function _consumePayment(PaymentProof calldata proof) internal returns (GraftPayment calldata) {
        if (proof.payment.graftId != graftId) {
            revert WrongGraft(graftId, proof.payment.graftId);
        }
        if (consumed[proof.payment.paymentId]) {
            revert AlreadyConsumed(proof.payment.paymentId);
        }
        string memory failed = checkPayment(proof);
        if (bytes(failed).length != 0) {
            revert ProofInvalid(failed);
        }
        consumed[proof.payment.paymentId] = true;
        emit PaymentConsumed(
            proof.payment.paymentId, proof.payment.payer, proof.payment.amount, proof.payment.memoHash
        );
        return proof.payment;
    }

    /// @notice The first link of the proof that does not hold, or "" when
    ///         every link holds.
    function checkPayment(PaymentProof calldata proof) public view returns (string memory) {
        (bool fits, bytes32 window) =
            BudlumHash.rootFromProof(paymentLeaf(proof.payment), proof.index, proof.path);
        if (!fits || window != proof.paymentsRoot) {
            return "payment path";
        }
        if (!proof.header.hasGraftRoot
            || proof.header.graftRoot != graftRegistryRoot(proof.paymentsRoot, proof.restHash)) {
            return "graft root opening";
        }
        uint64 height = proof.header.checkpointHeight;
        if (!finality.heightFinal(height)) {
            return "checkpoint not final";
        }
        bytes32 stateRoot = stateRootFromOpening(proof.stateRootBody, headerHash(proof.header));
        if (finality.rootAtHeight(height) != stateRoot) {
            return "state root opening";
        }
        return "";
    }

    /// @notice `GraftPayment::leaf_hash`.
    function paymentLeaf(GraftPayment calldata p) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](10);
        fields[0] = "BDLM_GRAFT_PAYMENT_LEAF_V1";
        fields[1] = abi.encodePacked(p.paymentId);
        fields[2] = abi.encodePacked(p.graftId);
        fields[3] = abi.encodePacked(p.payer);
        fields[4] = abi.encodePacked(p.recipient);
        fields[5] = BudlumHash.le64(p.amount);
        fields[6] = BudlumHash.le64(uint64(p.originRecipient.length));
        fields[7] = p.originRecipient;
        fields[8] = abi.encodePacked(p.memoHash);
        fields[9] = BudlumHash.le64(p.paidAtBlock);
        return BudlumHash.hashFields(fields);
    }

    /// @notice `GraftRootOpening::root`.
    function graftRegistryRoot(bytes32 paymentsRoot, bytes32 restHash) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](3);
        fields[0] = "BDLM_GRAFT_REGISTRY_V2";
        fields[1] = abi.encodePacked(paymentsRoot);
        fields[2] = abi.encodePacked(restHash);
        return BudlumHash.hashFields(fields);
    }

    /// @notice `AccountState::root_from_opening`.
    function stateRootFromOpening(bytes32 body, bytes32 summary) public pure returns (bytes32) {
        if (summary == bytes32(0)) {
            return body;
        }
        bytes[] memory fields = new bytes[](3);
        fields[0] = "BDLM_STATE_ROOT_GLOBAL_HEADER_V1";
        fields[1] = abi.encodePacked(body);
        fields[2] = abi.encodePacked(summary);
        return BudlumHash.hashFields(fields);
    }

    /// @notice `GlobalBlockHeader::calculate_hash_bytes` (V7).
    function headerHash(GlobalHeader calldata h) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](20);
        fields[0] = "BDLM_GLOBAL_BLOCK_V7";
        fields[1] = _le16(h.version);
        fields[2] = BudlumHash.le64(h.globalHeight);
        fields[3] = abi.encodePacked(h.previousGlobalHash);
        fields[4] = BudlumHash.le64(h.chainId);
        fields[5] = _le128(h.timestampMs);
        fields[6] = abi.encodePacked(h.domainRegistryRoot);
        fields[7] = abi.encodePacked(h.domainCommitmentRoot);
        fields[8] = abi.encodePacked(h.messageRoot);
        fields[9] = abi.encodePacked(h.bridgeStateRoot);
        fields[10] = abi.encodePacked(h.replayNonceRoot);
        fields[11] = h.proposer;
        fields[12] = abi.encodePacked(h.settlementFinalityRoot);
        fields[13] = _tagged(h.hasStorageRoot, h.storageRoot);
        fields[14] = _tagged(h.hasAiRoot, h.aiRoot);
        fields[15] = _tagged(h.hasIdentityRoot, h.identityRoot);
        fields[16] = BudlumHash.le64(h.checkpointHeight);
        fields[17] = _tagged(h.hasExternalIntakeRoot, h.externalIntakeRoot);
        fields[18] = _tagged(h.hasGraftRoot, h.graftRoot);
        fields[19] = _tagged(h.hasDelegationRoot, h.delegationRoot);
        return BudlumHash.hashFields(fields);
    }

    /// `presence_tagged`: one presence byte, then the root or zeros.
    function _tagged(bool present, bytes32 root) private pure returns (bytes memory) {
        return present ? abi.encodePacked(uint8(1), root) : abi.encodePacked(uint8(0), bytes32(0));
    }

    function _le16(uint16 value) private pure returns (bytes memory) {
        return abi.encodePacked(uint8(value), uint8(value >> 8));
    }

    function _le128(uint128 value) private pure returns (bytes memory out) {
        out = new bytes(16);
        for (uint256 i = 0; i < 16; i++) {
            out[i] = bytes1(uint8(value >> (8 * i)));
        }
    }
}
