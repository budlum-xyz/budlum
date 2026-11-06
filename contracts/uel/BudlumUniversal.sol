// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IBudlumUniversalPrecompile
/// @notice Canonical EVM precompile at `0x000000000000000000000000000000000000B001`
///         exposing synchronous cross-environment Universal Calls (`Section 8.7.2`).
interface IBudlumUniversalPrecompile {
    /// @notice Emitted by `0x...B001` upon every Universal Call so EVM indexers
    ///         observe cross-VM execution in transaction receipts (`Section 8.7.3`).
    event UniversalCallExecuted(uint8 ee, bytes target, bool ok);

    /// @notice Execute a stateful cross-environment Universal Call.
    /// @param ee Target environment catalog ID (`0x00` BudZero, `0x02` WASM, `0x03` SVM, `0x04` Move).
    /// @param target Target contract address in the callee environment's native encoding.
    /// @param input Callee environment native call payload (e.g. JSON for CosmWasm).
    /// @param valueAttos Amount of BUD in attoBUD (`10^-18 BUD`, i.e. EVM wei) transferred atomically.
    /// @param gasBgu Maximum BGU stipend forwarded to the callee.
    /// @return ok True if the callee succeeded; false if the callee reverted or ran out of gas.
    /// @return ret Raw return payload from the callee environment.
    function call(
        uint8 ee,
        bytes calldata target,
        bytes calldata input,
        uint256 valueAttos,
        uint64 gasBgu
    ) external returns (bool ok, bytes memory ret);

    /// @notice Execute a read-only (`static = true`) cross-environment Universal Call.
    function staticCall(
        uint8 ee,
        bytes calldata target,
        bytes calldata input,
        uint64 gasBgu
    ) external view returns (bool ok, bytes memory ret);
}

/// @title BudlumUniversal
/// @notice Helper library for invoking the Budlum UEL Universal Call precompile (`WP-30`).
library BudlumUniversal {
    address internal constant PRECOMPILE = 0x000000000000000000000000000000000000B001;

    uint8 internal constant EE_BUDZERO = 0x00;
    uint8 internal constant EE_EVM = 0x01;
    uint8 internal constant EE_WASM = 0x02;
    uint8 internal constant EE_SVM = 0x03;
    uint8 internal constant EE_MOVE = 0x04;

    error UniversalCallReverted(uint8 ee, bytes target, bytes revertData);

    function universalCall(
        uint8 ee,
        bytes memory target,
        bytes memory input,
        uint256 valueAttos,
        uint64 gasBgu
    ) internal returns (bool ok, bytes memory ret) {
        return IBudlumUniversalPrecompile(PRECOMPILE).call(ee, target, input, valueAttos, gasBgu);
    }

    function universalCallStrict(
        uint8 ee,
        bytes memory target,
        bytes memory input,
        uint256 valueAttos,
        uint64 gasBgu
    ) internal returns (bytes memory ret) {
        (bool ok, bytes memory out) =
            IBudlumUniversalPrecompile(PRECOMPILE).call(ee, target, input, valueAttos, gasBgu);
        if (!ok) {
            revert UniversalCallReverted(ee, target, out);
        }
        return out;
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
