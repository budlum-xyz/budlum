// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

/// @title BudlumBls
/// @notice Budlum's BLS12-381 signatures on an EVM chain with the EIP-2537
///         precompiles: public keys in G2, signatures in G1, ciphersuite
///         `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_` (src/chain/finality.rs).
///
///         EIP-2537 takes uncompressed points (G1: 128 bytes, G2: 256 bytes,
///         each coordinate a 64-byte field element with 16 zero bytes of
///         padding). Budlum registers compressed keys (G2: 96 bytes, zcash
///         encoding). `g2Matches` ties the two forms: same x coordinate, same
///         sign of y, flags consistent. The pairing precompile rejects a point
///         that is off the curve or outside the subgroup.
library BudlumBls {
    address internal constant G1ADD = address(0x0b);
    address internal constant PAIRING = address(0x0f);
    address internal constant MAP_FP_TO_G1 = address(0x10);
    address internal constant MODEXP = address(0x05);

    bytes internal constant DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
    bytes internal constant FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    /// (p - 1) / 2: a coordinate above it is the "larger" square root.
    bytes internal constant HALF_MODULUS =
        hex"0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555";

    error PrecompileRefused(string what);

    /// RFC 9380 hash_to_curve to G1 (expand_message_xmd with SHA-256, two
    /// field elements, map each, add).
    function hashToG1(bytes memory message) internal view returns (bytes memory) {
        bytes memory dstPrime = abi.encodePacked(DST, uint8(DST.length));
        bytes32 b0 = sha256(abi.encodePacked(new bytes(64), message, uint16(128), uint8(0), dstPrime));
        bytes32 b1 = sha256(abi.encodePacked(b0, uint8(1), dstPrime));
        bytes32 b2 = sha256(abi.encodePacked(b0 ^ b1, uint8(2), dstPrime));
        bytes32 b3 = sha256(abi.encodePacked(b0 ^ b2, uint8(3), dstPrime));
        bytes32 b4 = sha256(abi.encodePacked(b0 ^ b3, uint8(4), dstPrime));
        bytes memory p0 = _mapToG1(abi.encodePacked(b1, b2));
        bytes memory p1 = _mapToG1(abi.encodePacked(b3, b4));
        (bool ok, bytes memory out) = G1ADD.staticcall(abi.encodePacked(p0, p1));
        if (!ok || out.length != 128) {
            revert PrecompileRefused("G1 add");
        }
        return out;
    }

    /// e(H(message), pubkey) * e(negSignature, g2Generator) == 1.
    function verify(
        bytes memory pubkeyG2,
        bytes memory message,
        bytes memory negSignatureG1,
        bytes memory g2Generator
    ) internal view returns (bool) {
        if (pubkeyG2.length != 256 || negSignatureG1.length != 128 || g2Generator.length != 256) {
            return false;
        }
        bytes memory input =
            abi.encodePacked(hashToG1(message), pubkeyG2, negSignatureG1, g2Generator);
        (bool ok, bytes memory out) = PAIRING.staticcall{gas: 400_000}(input);
        if (!ok || out.length != 32) {
            return false;
        }
        uint256 result;
        assembly {
            result := mload(add(out, 32))
        }
        return result == 1;
    }

    /// Whether the compressed key (96 bytes) and the uncompressed key (256
    /// bytes, EIP-2537 layout x.c0 | x.c1 | y.c0 | y.c1) name the same
    /// point.
    function g2Matches(bytes memory compressed, bytes memory uncompressed)
        internal
        pure
        returns (bool)
    {
        if (compressed.length != 96 || uncompressed.length != 256) {
            return false;
        }
        uint8 flags = uint8(compressed[0]);
        // Compressed, not infinity.
        if (flags & 0x80 == 0 || flags & 0x40 != 0) {
            return false;
        }
        bool largest = flags & 0x20 != 0;
        // Padding of every uncompressed coordinate is zero.
        for (uint256 c = 0; c < 4; c++) {
            for (uint256 i = 0; i < 16; i++) {
                if (uncompressed[c * 64 + i] != 0) {
                    return false;
                }
            }
        }
        // x.c1 is the first 48 compressed bytes (flags cleared), x.c0 the rest.
        for (uint256 i = 0; i < 48; i++) {
            bytes1 c1 = i == 0 ? bytes1(uint8(compressed[0]) & 0x1f) : compressed[i];
            if (c1 != uncompressed[64 + 16 + i]) {
                return false;
            }
            if (compressed[48 + i] != uncompressed[16 + i]) {
                return false;
            }
        }
        // The sign: y is the larger root when its c1 (or c0 when c1 is zero)
        // is above (p - 1) / 2.
        bool c1Zero = true;
        for (uint256 i = 0; i < 48; i++) {
            if (uncompressed[192 + 16 + i] != 0) {
                c1Zero = false;
                break;
            }
        }
        uint256 at = c1Zero ? 128 + 16 : 192 + 16;
        return _above(uncompressed, at, HALF_MODULUS) == largest;
    }

    /// Whether the 48 big-endian bytes at `data[at..]` exceed `bound`.
    function _above(bytes memory data, uint256 at, bytes memory bound)
        private
        pure
        returns (bool)
    {
        for (uint256 i = 0; i < 48; i++) {
            uint8 a = uint8(data[at + i]);
            uint8 b = uint8(bound[i]);
            if (a != b) {
                return a > b;
            }
        }
        return false;
    }

    function _mapToG1(bytes memory element64) private view returns (bytes memory) {
        (bool ok, bytes memory reduced) = MODEXP.staticcall(
            abi.encodePacked(uint256(64), uint256(1), uint256(48), element64, uint8(1), FIELD_MODULUS)
        );
        if (!ok || reduced.length != 48) {
            revert PrecompileRefused("modexp");
        }
        bytes memory out;
        (ok, out) = MAP_FP_TO_G1.staticcall(abi.encodePacked(bytes16(0), reduced));
        if (!ok || out.length != 128) {
            revert PrecompileRefused("map to G1");
        }
        return out;
    }
}
