// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

import {IBudlumFinality} from "../external-domain/BudlumFinalityVerifier.sol";
import {BudlumHash} from "../lib/BudlumHash.sol";

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

/// @notice A Budlum checkpoint header (`GlobalBlockHeader`, V7).
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
/// @notice On-chain check of a Budlum Graft payment (8.5, level 1 in a contract).
abstract contract BudlumPaymentReceiver {
    uint256 private constant PAYMENT_LEAF_FIELDS = 10;
    uint256 private constant OPENING_TRIPLE_FIELDS = 3;
    uint256 private constant HEADER_V7_FIELDS = 20;
    uint256 private constant U128_BYTE_LEN = 16;
    uint256 private constant BITS_PER_BYTE = 8;
    uint8 private constant TAG_ABSENT = 0;
    uint8 private constant TAG_PRESENT = 1;

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

    function paymentLeaf(GraftPayment calldata p) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](PAYMENT_LEAF_FIELDS);
        fields[0] = "BDLM_GRAFT_PAYMENT_LEAF_V1";
        fields[1] = bytes.concat(p.paymentId);
        fields[2] = bytes.concat(p.graftId);
        fields[3] = bytes.concat(p.payer);
        fields[4] = bytes.concat(p.recipient);
        fields[5] = BudlumHash.le64(p.amount);
        fields[6] = BudlumHash.le64(uint64(p.originRecipient.length));
        fields[7] = p.originRecipient;
        fields[8] = bytes.concat(p.memoHash);
        fields[9] = BudlumHash.le64(p.paidAtBlock);
        return BudlumHash.hashFields(fields);
    }

    function graftRegistryRoot(bytes32 paymentsRoot, bytes32 restHash) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](OPENING_TRIPLE_FIELDS);
        fields[0] = "BDLM_GRAFT_REGISTRY_V2";
        fields[1] = bytes.concat(paymentsRoot);
        fields[2] = bytes.concat(restHash);
        return BudlumHash.hashFields(fields);
    }

    function stateRootFromOpening(bytes32 body, bytes32 summary) public pure returns (bytes32) {
        if (summary == bytes32(0)) {
            return body;
        }
        bytes[] memory fields = new bytes[](OPENING_TRIPLE_FIELDS);
        fields[0] = "BDLM_STATE_ROOT_GLOBAL_HEADER_V1";
        fields[1] = bytes.concat(body);
        fields[2] = bytes.concat(summary);
        return BudlumHash.hashFields(fields);
    }

    function headerHash(GlobalHeader calldata h) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](HEADER_V7_FIELDS);
        fields[0] = "BDLM_GLOBAL_BLOCK_V7";
        fields[1] = _le16(h.version);
        fields[2] = BudlumHash.le64(h.globalHeight);
        fields[3] = bytes.concat(h.previousGlobalHash);
        fields[4] = BudlumHash.le64(h.chainId);
        fields[5] = _le128(h.timestampMs);
        fields[6] = bytes.concat(h.domainRegistryRoot);
        fields[7] = bytes.concat(h.domainCommitmentRoot);
        fields[8] = bytes.concat(h.messageRoot);
        fields[9] = bytes.concat(h.bridgeStateRoot);
        fields[10] = bytes.concat(h.replayNonceRoot);
        fields[11] = h.proposer;
        fields[12] = bytes.concat(h.settlementFinalityRoot);
        fields[13] = _tagged(h.hasStorageRoot, h.storageRoot);
        fields[14] = _tagged(h.hasAiRoot, h.aiRoot);
        fields[15] = _tagged(h.hasIdentityRoot, h.identityRoot);
        fields[16] = BudlumHash.le64(h.checkpointHeight);
        fields[17] = _tagged(h.hasExternalIntakeRoot, h.externalIntakeRoot);
        fields[18] = _tagged(h.hasGraftRoot, h.graftRoot);
        fields[19] = _tagged(h.hasDelegationRoot, h.delegationRoot);
        return BudlumHash.hashFields(fields);
    }

    function _tagged(bool present, bytes32 root) private pure returns (bytes memory) {
        return present ? bytes.concat(bytes1(TAG_PRESENT), root) : bytes.concat(bytes1(TAG_ABSENT), bytes32(0));
    }

    function _le16(uint16 value) private pure returns (bytes memory) {
        return bytes.concat(bytes1(uint8(value)), bytes1(uint8(value >> BITS_PER_BYTE)));
    }

    function _le128(uint128 value) private pure returns (bytes memory out) {
        out = new bytes(U128_BYTE_LEN);
        for (uint256 i = 0; i < U128_BYTE_LEN; i++) {
            out[i] = bytes1(uint8(value >> (BITS_PER_BYTE * i)));
        }
    }
}
