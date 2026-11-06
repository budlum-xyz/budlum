// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

/// @title BudlumUniversal
/// @notice Solidity helper library for the Budlum UEL Universal Call precompile
///         at `0x000000000000000000000000000000000000B001` (Section 8.7.2, WP-27 / WP-30).
interface IBudlumUniversalPrecompile {
    event UniversalCallExecuted(uint8 indexed ee, bytes target, bool ok);

    function call(
        uint8 ee,
        bytes calldata target,
        bytes calldata input,
        uint256 valueAttos,
        uint64 gasBgu
    ) external returns (bool ok, bytes memory ret);

    function staticCall(
        uint8 ee,
        bytes calldata target,
        bytes calldata input,
        uint64 gasBgu
    ) external view returns (bool ok, bytes memory ret);
}

library BudlumUniversal {
    address internal constant PRECOMPILE = 0x000000000000000000000000000000000000b001;

    uint8 internal constant EE_BUDZERO = 0x00;
    uint8 internal constant EE_EVM = 0x01;
    uint8 internal constant EE_WASM = 0x02;
    uint8 internal constant EE_SVM = 0x03;
    uint8 internal constant EE_MOVE = 0x04;

    function universalCall(
        uint8 ee,
        bytes memory target,
        bytes memory input,
        uint256 valueAttos,
        uint64 gasBgu
    ) internal returns (bool ok, bytes memory ret) {
        return IBudlumUniversalPrecompile(PRECOMPILE).call(ee, target, input, valueAttos, gasBgu);
    }

    function universalStaticCall(
        uint8 ee,
        bytes memory target,
        bytes memory input,
        uint64 gasBgu
    ) internal view returns (bool ok, bytes memory ret) {
        return IBudlumUniversalPrecompile(PRECOMPILE).staticCall(ee, target, input, gasBgu);
    }
}
