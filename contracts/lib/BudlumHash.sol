// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

/// @title BudlumHash
/// @notice Exact Solidity counterpart of Budlum's length-prefixed SHA-256 and
///         settlement Merkle root (`hash_fields_bytes` in src/crypto/hash.rs
///         and `merkle_root_from_proof` in src/settlement/app_binding.rs).
library BudlumHash {
    uint256 private constant U32_BYTE_LEN = 4;
    uint256 private constant U64_BYTE_LEN = 8;
    uint256 private constant U128_BYTE_LEN = 16;
    uint256 private constant BITS_PER_BYTE = 8;
    uint256 private constant BALANCE_LEAF_FIELDS = 5;
    uint256 private constant BURN_LEAF_FIELDS = 7;
    uint256 private constant PAYMENT_LEAF_FIELDS = 6;
    uint256 private constant MESSAGE_LEAF_FIELDS = 6;
    uint256 private constant MERKLE_PAIR_ARITY = 2;
    uint256 private constant MERKLE_PROMOTE_FIELDS = 2;
    uint256 private constant MERKLE_NODE_FIELDS = 3;
    uint256 private constant SENTINEL_FIELDS = 1;
    uint256 internal constant MAX_MERKLE_DEPTH = 64;

    /// 8-byte little-endian encoding of `value`.
    function le64(uint64 value) internal pure returns (bytes memory out) {
        out = new bytes(U64_BYTE_LEN);
        for (uint256 i = 0; i < U64_BYTE_LEN; i++) {
            out[i] = bytes1(uint8(value >> (BITS_PER_BYTE * i)));
        }
    }

    /// `hash_fields_bytes`: each slice prefixed with its 8-byte little-endian
    /// length, then one SHA-256 over the concatenation.
    function hashFields(bytes[] memory fields) internal pure returns (bytes32) {
        bytes memory preimage;
        for (uint256 i = 0; i < fields.length; i++) {
            bytes memory item = fields[i];
            preimage = bytes.concat(preimage, BudlumHash.le64(uint64(item.length)), item);
        }
        return sha256(preimage);
    }

    /// `merkle_node`: `H("BDLM_MERKLE_NODE_V1", left, right)`.
    function merkleNode(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        bytes[] memory fields = new bytes[](MERKLE_NODE_FIELDS);
        fields[0] = "BDLM_MERKLE_NODE_V1";
        fields[1] = bytes.concat(left);
        fields[2] = bytes.concat(right);
        return hashFields(fields);
    }

    /// `merkle_root_from_proof` of the settlement tree. Returns `(false, 0)`
    /// when the index does not fit the path.
    function rootFromProof(bytes32 leaf, uint256 index, bytes32[] memory siblings)
        internal
        pure
        returns (bool ok, bytes32 root)
    {
        if (siblings.length > MAX_MERKLE_DEPTH) {
            return (false, bytes32(0));
        }
        bytes32 cur = leaf;
        uint256 idx = index;
        bytes[] memory sentinelFields = new bytes[](SENTINEL_FIELDS);
        sentinelFields[0] = "BDLM_MERKLE_ODD_SENTINEL_V1";
        bytes32 sentinel = hashFields(sentinelFields);
        bool isTail = false;
        for (uint256 i = 0; i < siblings.length; i++) {
            if (siblings[i] == sentinel) {
                if (idx == 0 || idx % MERKLE_PAIR_ARITY != 0 || i + 1 == siblings.length) {
                    return (false, bytes32(0));
                }
                isTail = true;
                bytes[] memory promoteFields = new bytes[](MERKLE_PROMOTE_FIELDS);
                promoteFields[0] = "BDLM_MERKLE_ODD_PROMOTE_V1";
                promoteFields[1] = bytes.concat(cur);
                cur = hashFields(promoteFields);
            } else {
                if (isTail && idx % MERKLE_PAIR_ARITY == 0) {
                    return (false, bytes32(0));
                }
                if (idx % MERKLE_PAIR_ARITY == 0) {
                    cur = merkleNode(cur, siblings[i]);
                } else {
                    cur = merkleNode(siblings[i], cur);
                }
            }
            idx /= MERKLE_PAIR_ARITY;
        }
        if (idx != 0) {
            return (false, bytes32(0));
        }
        return (true, cur);
    }

    /// 4-byte little-endian encoding of `value`.
    function le32(uint32 value) internal pure returns (bytes memory out) {
        out = new bytes(U32_BYTE_LEN);
        for (uint256 i = 0; i < U32_BYTE_LEN; i++) {
            out[i] = bytes1(uint8(value >> (BITS_PER_BYTE * i)));
        }
    }

    /// 16-byte little-endian encoding of `value`.
    function le128(uint128 value) internal pure returns (bytes memory out) {
        out = new bytes(U128_BYTE_LEN);
        for (uint256 i = 0; i < U128_BYTE_LEN; i++) {
            out[i] = bytes1(uint8(value >> (BITS_PER_BYTE * i)));
        }
    }

    /// Canonical leaf commitment for a Budlum account asset balance fact.
    function balanceLeaf(bytes32 account, bytes32 assetId, uint128 amount, uint64 nonce)
        internal
        pure
        returns (bytes32)
    {
        bytes[] memory fields = new bytes[](BALANCE_LEAF_FIELDS);
        fields[0] = "BDLM_STATE_BALANCE_LEAF_V1";
        fields[1] = bytes.concat(account);
        fields[2] = bytes.concat(assetId);
        fields[3] = le128(amount);
        fields[4] = le64(nonce);
        return hashFields(fields);
    }

    /// Canonical leaf commitment for a Budlum bridge burn record fact.
    function bridgeBurnLeaf(
        bytes32 burnId,
        uint32 sourceDomainId,
        uint32 destDomainId,
        bytes32 token,
        uint128 amount,
        bytes32 recipient
    ) internal pure returns (bytes32) {
        bytes[] memory fields = new bytes[](BURN_LEAF_FIELDS);
        fields[0] = "BDLM_STATE_BRIDGE_BURN_LEAF_V1";
        fields[1] = bytes.concat(burnId);
        fields[2] = le32(sourceDomainId);
        fields[3] = le32(destDomainId);
        fields[4] = bytes.concat(token);
        fields[5] = le128(amount);
        fields[6] = bytes.concat(recipient);
        return hashFields(fields);
    }

    /// Canonical leaf commitment for an AppBinding payment fact.
    function appBindingPaymentLeaf(bytes32 intentId, bytes32 appId, bytes32 payer, bytes32 assetId, uint128 amount)
        internal
        pure
        returns (bytes32)
    {
        bytes[] memory fields = new bytes[](PAYMENT_LEAF_FIELDS);
        fields[0] = "BDLM_STATE_APP_PAYMENT_LEAF_V1";
        fields[1] = bytes.concat(intentId);
        fields[2] = bytes.concat(appId);
        fields[3] = bytes.concat(payer);
        fields[4] = bytes.concat(assetId);
        fields[5] = le128(amount);
        return hashFields(fields);
    }

    /// Canonical leaf commitment for a cross-domain delivered message fact.
    function crossDomainMessageLeaf(
        bytes32 messageId,
        uint32 sourceDomainId,
        uint32 destDomainId,
        uint64 nonce,
        bytes32 payloadHash
    ) internal pure returns (bytes32) {
        bytes[] memory fields = new bytes[](MESSAGE_LEAF_FIELDS);
        fields[0] = "BDLM_STATE_MESSAGE_LEAF_V1";
        fields[1] = bytes.concat(messageId);
        fields[2] = le32(sourceDomainId);
        fields[3] = le32(destDomainId);
        fields[4] = le64(nonce);
        fields[5] = bytes.concat(payloadHash);
        return hashFields(fields);
    }

    /// Verify a Merkle inclusion proof for `leaf` against a non-zero `finalizedRoot`.
    function verifyLeafAgainstRoot(bytes32 finalizedRoot, bytes32 leaf, uint256 index, bytes32[] memory siblings)
        internal
        pure
        returns (bool)
    {
        if (finalizedRoot == bytes32(0) || leaf == bytes32(0)) {
            return false;
        }
        (bool ok, bytes32 computed) = rootFromProof(leaf, index, siblings);
        return ok && computed == finalizedRoot;
    }
}
