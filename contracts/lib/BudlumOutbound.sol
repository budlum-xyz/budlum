// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

/// @title BudlumOutboundEmitter
/// @notice The one log shape an EVM contract uses to speak to Budlum, matching
///         `src/cross_domain/evm/outbound.rs::message_from_log`.
abstract contract BudlumOutboundEmitter {
    uint256 internal constant MAX_OUTBOUND_KIND_BYTES = 128;

    /// topic0 = keccak256("BudlumOutbound(bytes,bytes32,bytes32,bytes32)").
    event BudlumOutbound(bytes kind, bytes32 indexed recipient, bytes32 indexed correlationId, bytes32 payloadHash);

    error InvalidOutboundKind(uint256 length);
    error InvalidOutboundRecipient();
    error InvalidOutboundPayloadHash();

    function _emitOutbound(bytes memory kind, bytes32 recipient, bytes32 correlationId, bytes32 payloadHash) internal {
        if (kind.length == 0 || kind.length > MAX_OUTBOUND_KIND_BYTES) {
            revert InvalidOutboundKind(kind.length);
        }
        if (recipient == bytes32(0)) {
            revert InvalidOutboundRecipient();
        }
        if (payloadHash == bytes32(0)) {
            revert InvalidOutboundPayloadHash();
        }
        emit BudlumOutbound(kind, recipient, correlationId, payloadHash);
    }
}
