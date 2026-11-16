// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

/// @title BudlumHash
/// @notice Exact Solidity counterpart of Budlum's length-prefixed SHA-256 and
///         settlement Merkle root (`hash_fields_bytes` in src/crypto/hash.rs
///         and `merkle_root_from_proof` in src/settlement/app_binding.rs).
library BudlumHash {
    uint256 private constant U64_BYTE_LEN = 8;
    uint256 private constant BITS_PER_BYTE = 8;
    uint256 private constant MERKLE_PAIR_ARITY = 2;
    uint256 private constant MERKLE_PROMOTE_FIELDS = 2;
    uint256 private constant MERKLE_NODE_FIELDS = 3;
    uint256 private constant SENTINEL_FIELDS = 1;

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
        bytes32 cur = leaf;
        uint256 idx = index;
        bytes[] memory sentinelFields = new bytes[](SENTINEL_FIELDS);
        sentinelFields[0] = "BDLM_MERKLE_ODD_SENTINEL_V1";
        bytes32 sentinel = hashFields(sentinelFields);
        for (uint256 i = 0; i < siblings.length; i++) {
            if (siblings[i] == sentinel) {
                if (idx % MERKLE_PAIR_ARITY != 0) {
                    return (false, bytes32(0));
                }
                bytes[] memory promoteFields = new bytes[](MERKLE_PROMOTE_FIELDS);
                promoteFields[0] = "BDLM_MERKLE_ODD_PROMOTE_V1";
                promoteFields[1] = bytes.concat(cur);
                cur = hashFields(promoteFields);
            } else if (idx % MERKLE_PAIR_ARITY == 0) {
                cur = merkleNode(cur, siblings[i]);
            } else {
                cur = merkleNode(siblings[i], cur);
            }
            idx /= MERKLE_PAIR_ARITY;
        }
        if (idx != 0) {
            return (false, bytes32(0));
        }
        return (true, cur);
    }
}
