// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

/// @title BudlumOutboundEmitter
/// @notice The one log shape an EVM contract uses to speak to Budlum.
abstract contract BudlumOutboundEmitter {
    /// topic0 = keccak256("BudlumOutbound(bytes,bytes32,bytes32,bytes32)").
    event BudlumOutbound(
        bytes kind,
        bytes32 indexed recipient,
        bytes32 indexed correlationId,
        bytes32 payloadHash
    );

    function _emitOutbound(
        bytes memory kind,
        bytes32 recipient,
        bytes32 correlationId,
        bytes32 payloadHash
    ) internal {
        emit BudlumOutbound(kind, recipient, correlationId, payloadHash);
    }
}
