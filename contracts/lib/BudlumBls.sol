// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

/// @title BudlumBls
/// @notice Budlum's BLS12-381 signatures on an EVM chain with the EIP-2537
///         precompiles: public keys in G2, signatures in G1, ciphersuite
///         `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_` (src/chain/finality.rs).
library BudlumBls {
    address internal constant G1ADD = address(0x0b);
    address internal constant PAIRING = address(0x0f);
    address internal constant MAP_FP_TO_G1 = address(0x10);
    address internal constant MODEXP = address(0x05);

    uint256 private constant ZMD_ZERO_PAD_LEN = 64;
    uint16 private constant XMD_LEN_IN_BYTES = 128;
    uint256 private constant G1_UNCOMPRESSED_LEN = 128;
    uint256 private constant G2_UNCOMPRESSED_LEN = 256;
    uint256 private constant G2_COMPRESSED_LEN = 96;
    uint256 private constant WORD_LEN = 32;
    uint256 private constant FP_BYTE_LEN = 48;
    uint256 private constant FP_PADDED_LEN = 64;
    uint256 private constant FP_PAD_PREFIX_LEN = 16;
    uint256 private constant G2_COORD_COUNT = 4;
    uint256 private constant G2_X_C0_OFFSET = 16;
    uint256 private constant G2_X_C1_OFFSET = 80;
    uint256 private constant G2_Y_C0_OFFSET = 144;
    uint256 private constant G2_Y_C1_OFFSET = 208;
    uint256 private constant MODEXP_EXP_LEN = 1;
    bytes1 private constant MODEXP_EXP_BYTE = 0x01;
    uint256 private constant GAS_BLS_PAIRING = 4e5;
    uint8 private constant XMD_BLOCK_1 = 1;
    uint8 private constant XMD_BLOCK_2 = 2;
    uint8 private constant XMD_BLOCK_3 = 3;
    uint8 private constant XMD_BLOCK_4 = 4;

    bytes internal constant DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
    bytes internal constant FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    bytes internal constant HALF_MODULUS =
        hex"0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555";

    error PrecompileRefused(string what);

    function verify(
        bytes memory pubkeyG2,
        bytes memory message,
        bytes memory negSignatureG1,
        bytes memory g2Generator
    ) internal view returns (bool) {
        if (
            pubkeyG2.length != G2_UNCOMPRESSED_LEN
                || negSignatureG1.length != G1_UNCOMPRESSED_LEN
                || g2Generator.length != G2_UNCOMPRESSED_LEN
        ) {
            return false;
        }
        if (_isInfinity(pubkeyG2) || _isInfinity(negSignatureG1) || _isInfinity(g2Generator)) {
            return false;
        }
        bytes memory hashedG1;
        {
            bytes memory dstPrime = bytes.concat(DST, bytes1(uint8(DST.length)));
            bytes32 b0 = sha256(
                bytes.concat(new bytes(ZMD_ZERO_PAD_LEN), message, bytes2(XMD_LEN_IN_BYTES), bytes1(0), dstPrime)
            );
            bytes32 b1 = sha256(bytes.concat(b0, bytes1(XMD_BLOCK_1), dstPrime));
            bytes32 b2 = sha256(bytes.concat(b0 ^ b1, bytes1(XMD_BLOCK_2), dstPrime));
            bytes32 b3 = sha256(bytes.concat(b0 ^ b2, bytes1(XMD_BLOCK_3), dstPrime));
            bytes32 b4 = sha256(bytes.concat(b0 ^ b3, bytes1(XMD_BLOCK_4), dstPrime));
            (bool addOk, bytes memory sum) =
                G1ADD.staticcall(bytes.concat(_mapToG1(bytes.concat(b1, b2)), _mapToG1(bytes.concat(b3, b4))));
            if (!addOk || sum.length != G1_UNCOMPRESSED_LEN) {
                revert PrecompileRefused("G1 add");
            }
            hashedG1 = sum;
        }
        bytes memory input = bytes.concat(hashedG1, pubkeyG2, negSignatureG1, g2Generator);
        (bool ok, bytes memory out) = PAIRING.staticcall{gas: GAS_BLS_PAIRING}(input);
        if (!ok || out.length != WORD_LEN) {
            return false;
        }
        uint256 result;
        assembly {
            result := mload(add(out, WORD_LEN))
        }
        return result == 1;
    }

    function g2Matches(bytes memory compressed, bytes memory uncompressed)
        internal
        pure
        returns (bool)
    {
        if (
            compressed.length != G2_COMPRESSED_LEN
                || uncompressed.length != G2_UNCOMPRESSED_LEN
                || _isInfinity(uncompressed)
        ) {
            return false;
        }
        uint8 flags = uint8(compressed[0]);
        if (flags & 0x80 == 0 || flags & 0x40 != 0) {
            return false;
        }
        bool largest = flags & 0x20 != 0;
        for (uint256 c = 0; c < G2_COORD_COUNT; c++) {
            for (uint256 i = 0; i < FP_PAD_PREFIX_LEN; i++) {
                if (uncompressed[c * FP_PADDED_LEN + i] != 0) {
                    return false;
                }
            }
        }
        for (uint256 i = 0; i < FP_BYTE_LEN; i++) {
            bytes1 c1 = i == 0 ? bytes1(flags & 0x1f) : compressed[i];
            if (c1 != uncompressed[G2_X_C1_OFFSET + i]) {
                return false;
            }
            if (compressed[FP_BYTE_LEN + i] != uncompressed[G2_X_C0_OFFSET + i]) {
                return false;
            }
        }
        bool c1Zero = true;
        for (uint256 i = 0; i < FP_BYTE_LEN; i++) {
            if (uncompressed[G2_Y_C1_OFFSET + i] != 0) {
                c1Zero = false;
                break;
            }
        }
        uint256 at = c1Zero ? G2_Y_C0_OFFSET : G2_Y_C1_OFFSET;
        return _greaterThanHalfModulus(uncompressed, at) == largest;
    }

    function _isInfinity(bytes memory point) private pure returns (bool) {
        for (uint256 i = 0; i < point.length; i++) {
            if (point[i] != 0) {
                return false;
            }
        }
        return true;
    }

    function _greaterThanHalfModulus(bytes memory buf, uint256 offset) private pure returns (bool) {
        bytes memory half = HALF_MODULUS;
        for (uint256 i = 0; i < FP_BYTE_LEN; i++) {
            uint8 a = uint8(buf[offset + i]);
            uint8 b = uint8(half[i]);
            if (a != b) {
                return a > b;
            }
        }
        return false;
    }

    function _mapToG1(bytes memory element64) private view returns (bytes memory) {
        (bool ok, bytes memory reduced) = MODEXP.staticcall(
            bytes.concat(
                bytes32(FP_PADDED_LEN),
                bytes32(MODEXP_EXP_LEN),
                bytes32(FP_BYTE_LEN),
                element64,
                MODEXP_EXP_BYTE,
                FIELD_MODULUS
            )
        );
        if (!ok || reduced.length != FP_BYTE_LEN) {
            revert PrecompileRefused("modexp");
        }
        bytes memory out;
        (ok, out) = MAP_FP_TO_G1.staticcall(bytes.concat(bytes16(0), reduced));
        if (!ok || out.length != G1_UNCOMPRESSED_LEN) {
            revert PrecompileRefused("map to G1");
        }
        return out;
    }
}
