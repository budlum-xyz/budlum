// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

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
    uint8 internal constant EE_MOVE_SUI = 0x05;
    uint8 internal constant EE_CAIRO = 0x06;
    uint8 internal constant EE_NEAR_WASM = 0x07;
    uint8 internal constant EE_POLKAVM = 0x08;
    uint8 internal constant EE_TVM = 0x09;
    uint8 internal constant EE_UTXO = 0x0A;
    uint8 internal constant EE_PLUTUS = 0x0B;
    uint8 internal constant EE_RV32 = 0x0C;

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

/// @title IBudlumUol
/// @notice Precompile interface at `0x000000000000000000000000000000000000B002`
///         for Universal Object Layer (`UOL`) operations across Budlum UEL.
interface IBudlumUol {
    function balanceOf(bytes32 classId, bytes calldata holder) external view returns (uint128);

    function holderOf(bytes32 assetId) external view returns (bytes memory);

    function transfer(
        bytes32 classId,
        bytes32 assetId,
        bytes calldata to,
        uint128 amount
    ) external returns (bool ok);

    function offer(
        bytes32 classId,
        bytes32 assetId,
        bytes calldata taker,
        bytes calldata payment,
        uint128 amount,
        uint64 expiry
    ) external returns (bytes32 offerId);

    function accept(bytes32 offerId) external returns (bool ok);
}

/// @title BudlumUol
/// @notice Helper library wrapping the `0x...B002` Universal Object Layer precompile.
library BudlumUol {
    address internal constant UOL_PRECOMPILE =
        0x000000000000000000000000000000000000B002;

    error UolPrecompileFailed();

    function balanceOf(bytes32 classId, bytes memory holder) internal view returns (uint128) {
        bytes memory payload = abi.encodeCall(IBudlumUol.balanceOf, (classId, holder));
        (bool ok, bytes memory raw) = UOL_PRECOMPILE.staticcall(payload);
        if (!ok) revert UolPrecompileFailed();
        return abi.decode(raw, (uint128));
    }

    function holderOf(bytes32 assetId) internal view returns (bytes memory) {
        bytes memory payload = abi.encodeCall(IBudlumUol.holderOf, (assetId));
        (bool ok, bytes memory raw) = UOL_PRECOMPILE.staticcall(payload);
        if (!ok) revert UolPrecompileFailed();
        return abi.decode(raw, (bytes));
    }

    function transfer(
        bytes32 classId,
        bytes32 assetId,
        bytes memory to,
        uint128 amount
    ) internal returns (bool) {
        bytes memory payload = abi.encodeCall(IBudlumUol.transfer, (classId, assetId, to, amount));
        (bool ok, bytes memory raw) = UOL_PRECOMPILE.call(payload);
        if (!ok) revert UolPrecompileFailed();
        return abi.decode(raw, (bool));
    }

    function offer(
        bytes32 classId,
        bytes32 assetId,
        bytes memory taker,
        bytes memory payment,
        uint128 amount,
        uint64 expiry
    ) internal returns (bytes32) {
        bytes memory payload = abi.encodeCall(
            IBudlumUol.offer,
            (classId, assetId, taker, payment, amount, expiry)
        );
        (bool ok, bytes memory raw) = UOL_PRECOMPILE.call(payload);
        if (!ok) revert UolPrecompileFailed();
        return abi.decode(raw, (bytes32));
    }

    function accept(bytes32 offerId) internal returns (bool) {
        bytes memory payload = abi.encodeCall(IBudlumUol.accept, (offerId));
        (bool ok, bytes memory raw) = UOL_PRECOMPILE.call(payload);
        if (!ok) revert UolPrecompileFailed();
        return abi.decode(raw, (bool));
    }
}
