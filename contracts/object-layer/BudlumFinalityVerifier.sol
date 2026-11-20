// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

/// @title Object-layer view of Budlum finality on an EVM home chain.
/// @notice A checkpoint header is only recorded when the external-domain
///         finality verifier confirms its opening against a finalized state
///         root. This is not an object-layer activation: settlement entry and
///         endpoint release/escape remain closed until their proofs are ready.
import {FinalityMode} from "../external-domain/BudlumFinalityVerifier.sol";

interface IBudlumHeaderFinality {
    function isFinalizedHeader(uint64 height, bytes32 headerHash, bytes32 stateRootBody) external view returns (bool);
    function finalityModeAtHeight(uint64 height) external view returns (FinalityMode);
}

interface IBudlumObjectLayerFinality {
    function heightFinal(uint64 height) external view returns (bool);
    function headerAt(uint64 height) external view returns (bytes32);
    function finalityModeAt(uint64 height) external view returns (FinalityMode);
}

contract BudlumObjectLayerFinality is IBudlumObjectLayerFinality {
    IBudlumHeaderFinality public immutable finality;

    /// Budlum checkpoint height => accepted global header hash.
    mapping(uint64 => bytes32) public override headerAt;
    /// Budlum checkpoint height => verification mode recorded by the finality verifier.
    mapping(uint64 => FinalityMode) public override finalityModeAt;

    event CheckpointRecorded(uint64 indexed height, bytes32 headerHash);

    error NotAccepted();
    error Conflict();
    error InvalidVerifier();

    constructor(IBudlumHeaderFinality finality_) {
        if (address(finality_) == address(0) || address(finality_).code.length == 0) {
            revert InvalidVerifier();
        }
        finality = finality_;
    }

    /// Record only a header committed by a finalized state root. The body is
    /// the other input of `AccountState::root_from_opening`; merely supplying
    /// an accepted attestation digest does not bind it to any header hash.
    function record(uint64 height, bytes32 headerHash, bytes32 stateRootBody) external {
        if (headerHash == bytes32(0)) revert NotAccepted();
        bytes32 known = headerAt[height];
        if (known != bytes32(0)) {
            if (known != headerHash) revert Conflict();
            return;
        }
        FinalityMode mode = _requireFinalizedHeader(height, headerHash, stateRootBody);
        headerAt[height] = headerHash;
        finalityModeAt[height] = mode;
        emit CheckpointRecorded(height, headerHash);
    }

    function heightFinal(uint64 height) external view override returns (bool) {
        return headerAt[height] != bytes32(0) && finalityModeAt[height] != FinalityMode.None;
    }

    function _requireFinalizedHeader(uint64 height, bytes32 headerHash, bytes32 stateRootBody)
        internal
        view
        returns (FinalityMode mode)
    {
        if (!finality.isFinalizedHeader(height, headerHash, stateRootBody)) {
            revert NotAccepted();
        }
        mode = finality.finalityModeAtHeight(height);
        if (mode == FinalityMode.None) {
            revert NotAccepted();
        }
    }
}
