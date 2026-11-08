// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

/// @title IBudlumUniversal
/// @notice Precompile interface at `0x000000000000000000000000000000000000B001`
///         for synchronous atomic Universal Calls across Budlum UEL environments.
interface IBudlumUniversal {
    /// @notice Emitted by the precompile on every Universal Call so EVM indexers
    ///         observe cross-environment invocations in standard receipts.
    event UniversalCallExecuted(uint8 ee, bytes target, bool ok);

    /// @notice Executes a state-mutating Universal Call into `ee`.
    function call(
        uint8 ee,
        bytes calldata target,
        bytes calldata input,
        uint256 valueAttos,
        uint64 gasBgu
    ) external returns (bool ok, bytes memory ret);

    /// @notice Executes a read-only (`static = true`) Universal Call into `ee`.
    function staticCall(
        uint8 ee,
        bytes calldata target,
        bytes calldata input,
        uint64 gasBgu
    ) external view returns (bool ok, bytes memory ret);
}

/// @title BudlumUniversal
/// @notice Ergonomic Solidity helper library wrapping the `0x...B001` precompile.
library BudlumUniversal {
    /// @notice Canonical UEL Universal Call precompile address.
    address internal constant PRECOMPILE =
        0x000000000000000000000000000000000000B001;

    uint8 internal constant EE_BUDZERO = 0x00;
    uint8 internal constant EE_EVM = 0x01;
    uint8 internal constant EE_WASM = 0x02;
    uint8 internal constant EE_SVM = 0x03;
    uint8 internal constant EE_MOVE = 0x04;

    /// @notice Emitted by `PRECOMPILE` for EVM receipt/log indexers.
    event UniversalCallExecuted(uint8 ee, bytes target, bool ok);

    error PrecompileTransportFailed();

    /// @notice Invokes `target` in environment `ee` with `valueAttos` attoBUD and `gasBgu`.
    function call(
        uint8 ee,
        bytes memory target,
        bytes memory input,
        uint256 valueAttos,
        uint64 gasBgu
    ) internal returns (bool ok, bytes memory ret) {
        bytes memory payload = abi.encodeCall(
            IBudlumUniversal.call,
            (ee, target, input, valueAttos, gasBgu)
        );
        (bool precompileOk, bytes memory rawOut) = PRECOMPILE.call(payload);
        if (!precompileOk) {
            revert PrecompileTransportFailed();
        }
        return abi.decode(rawOut, (bool, bytes));
    }

    /// @notice Invokes `target` in environment `ee` under `static = true` semantics.
    function staticCall(
        uint8 ee,
        bytes memory target,
        bytes memory input,
        uint64 gasBgu
    ) internal view returns (bool ok, bytes memory ret) {
        bytes memory payload = abi.encodeCall(
            IBudlumUniversal.staticCall,
            (ee, target, input, gasBgu)
        );
        (bool precompileOk, bytes memory rawOut) = PRECOMPILE.staticcall(payload);
        if (!precompileOk) {
            revert PrecompileTransportFailed();
        }
        return abi.decode(rawOut, (bool, bytes));
    }
}
