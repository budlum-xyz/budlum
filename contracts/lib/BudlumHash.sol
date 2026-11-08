// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

/// @title BudlumHash
/// @notice The Budlum field hash, `hash_fields_bytes` in src/core/hash.rs:
///         SHA-256 over every field, each preceded by its length as a
///         little-endian u64. Contracts that emit payloads Budlum checks must
///         hash them exactly this way, so the two sides agree byte for byte.
library BudlumHash {
    /// A u64 as 8 little-endian bytes.
    function le64(uint64 value) internal pure returns (bytes memory out) {
        out = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            out[i] = bytes1(uint8(value >> (8 * i)));
        }
    }

    /// One length-prefixed field.
    function field(bytes memory value) internal pure returns (bytes memory) {
        return abi.encodePacked(le64(uint64(value.length)), value);
    }

    /// `hash_fields_bytes(fields)`.
    function hashFields(bytes[] memory fields) internal pure returns (bytes32) {
        bytes memory preimage;
        for (uint256 i = 0; i < fields.length; i++) {
            preimage = abi.encodePacked(preimage, field(fields[i]));
        }
        return sha256(preimage);
    }

    /// The Budlum address an EVM contract emits as: the 20-byte address
    /// right-aligned in a zeroed 32-byte word (`origin_emitter`).
    function originEmitter(address emitter) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(emitter)));
    }

    /// `merkle_node_hash` of the settlement tree.
    function merkleNode(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        bytes[] memory fields = new bytes[](3);
        fields[0] = "BDLM_MERKLE_NODE_V1";
        fields[1] = abi.encodePacked(left);
        fields[2] = abi.encodePacked(right);
        return hashFields(fields);
    }

    /// `merkle_odd_promote_hash` of the settlement tree.
    function merklePromote(bytes32 node) internal pure returns (bytes32) {
        bytes[] memory fields = new bytes[](2);
        fields[0] = "BDLM_MERKLE_ODD_PROMOTE_V1";
        fields[1] = abi.encodePacked(node);
        return hashFields(fields);
    }

    /// `odd_promotion_sentinel`: the sibling a proof records for a promoted
    /// step.
    function oddSentinel() internal pure returns (bytes32) {
        bytes[] memory fields = new bytes[](1);
        fields[0] = "BDLM_MERKLE_ODD_SENTINEL_V1";
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
        bytes32 sentinel = oddSentinel();
        for (uint256 i = 0; i < siblings.length; i++) {
            if (siblings[i] == sentinel) {
                cur = merklePromote(cur);
            } else if (idx % 2 == 0) {
                cur = merkleNode(cur, siblings[i]);
            } else {
                cur = merkleNode(siblings[i], cur);
            }
            idx /= 2;
        }
        if (idx != 0) {
            return (false, bytes32(0));
        }
        return (true, cur);
    }
}
