// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

/// @title BudlumOutboundEmitter
/// @notice The one log shape an EVM contract uses to speak to Budlum. The
///         domain reporter turns each such log into a cross-domain message
///         (src/cross_domain/evm/outbound.rs, `message_from_log`):
///
///         | message field    | from                                  |
///         |------------------|---------------------------------------|
///         | `sender`         | the emitting contract, right-aligned  |
///         | `recipient`      | `recipient` (topic 1)                 |
///         | `correlation_id` | `correlationId` (topic 2)             |
///         | `kind`           | `Custom(kind)`                        |
///         | `payload_hash`   | `payloadHash`                         |
///
///         Budlum accepts the message only after the log's block reaches the
///         external root it anchored for the domain.
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
