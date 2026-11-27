// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

/// @title Object-layer view of Budlum finality on an EVM home chain.
/// @notice Implements the unified `IBudlumFinality` read surface alongside
///         `IBudlumObjectLayerFinality`. A checkpoint header is only recorded
///         when the external-domain finality verifier confirms its opening
///         against a finalized state root.
import {BudlumHash} from "../lib/BudlumHash.sol";
import {
    FinalityMode,
    IBudlumFinality,
    IBudlumQuantumAlert,
    QuantumAlertLevel
} from "../external-domain/BudlumFinalityVerifier.sol";

/// @notice Proof format accepted by an outbound Budlum finality verifier.
enum ProofFormat {
    None,
    Signature,
    Succinct
}

interface IBudlumHeaderFinality {
    function isFinalizedHeader(uint64 height, bytes32 headerHash, bytes32 stateRootBody) external view returns (bool);
    function finalityModeAtHeight(uint64 height) external view returns (FinalityMode);
}

interface IBudlumObjectLayerFinality {
    function heightFinal(uint64 height) external view returns (bool);
    function headerAt(uint64 height) external view returns (bytes32);
    function finalityModeAt(uint64 height) external view returns (FinalityMode);
}

contract BudlumObjectLayerFinality is IBudlumObjectLayerFinality, IBudlumFinality, IBudlumQuantumAlert {
    uint256 private constant HEADER_OPENING_FIELDS = 3;

    IBudlumHeaderFinality public immutable finality;

    /// Budlum checkpoint height => accepted global header hash.
    mapping(uint64 => bytes32) public override headerAt;
    /// Budlum checkpoint height => authenticated Budlum state root.
    mapping(uint64 => bytes32) public override rootAtHeight;
    /// Budlum checkpoint height => verification mode recorded by the finality verifier.
    mapping(uint64 => FinalityMode) public override finalityModeAt;
    /// Highest finalized checkpoint height recorded on this home chain.
    uint64 public override latestFinalHeight;

    event CheckpointRecorded(uint64 indexed height, bytes32 headerHash);

    error NotAccepted();
    error Conflict();
    error InvalidVerifier();
    error ClassicalHaltedByQuantumAlert(QuantumAlertLevel currentLevel);

    constructor(IBudlumHeaderFinality finality_) {
        if (address(finality_) == address(0) || address(finality_).code.length == 0) {
            revert InvalidVerifier();
        }
        finality = finality_;
    }

    /// @notice Proof format accepted by this verifier (`Signature` until succinct master proofs open).
    function acceptedProofFormat() external pure returns (ProofFormat) {
        return ProofFormat.Signature;
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
        QuantumAlertLevel currentAlert = alertLevel();
        if (mode == FinalityMode.ClassicalOnly && currentAlert != QuantumAlertLevel.Open) {
            revert ClassicalHaltedByQuantumAlert(currentAlert);
        }
        headerAt[height] = headerHash;
        rootAtHeight[height] = _computeStateRoot(headerHash, stateRootBody);
        finalityModeAt[height] = mode;
        if (height > latestFinalHeight) {
            latestFinalHeight = height;
        }
        emit CheckpointRecorded(height, headerHash);
    }

    function alertLevel() public view override returns (QuantumAlertLevel) {
        (bool ok, bytes memory data) = address(finality).staticcall(abi.encodeCall(IBudlumQuantumAlert.alertLevel, ()));
        if (!ok) {
            return QuantumAlertLevel.Open;
        }
        if (data.length != 32) {
            return QuantumAlertLevel.Isolated;
        }
        uint256 level = abi.decode(data, (uint256));
        if (level > uint256(QuantumAlertLevel.Isolated)) {
            return QuantumAlertLevel.Isolated;
        }
        return QuantumAlertLevel(level);
    }

    function heightFinal(uint64 height)
        external
        view
        override(IBudlumObjectLayerFinality, IBudlumFinality)
        returns (bool)
    {
        return headerAt[height] != bytes32(0) && finalityModeAt[height] != FinalityMode.None;
    }

    function finalityModeAtHeight(uint64 height) external view override returns (FinalityMode) {
        return finalityModeAt[height];
    }

    function _computeStateRoot(bytes32 headerHash, bytes32 stateRootBody) internal pure returns (bytes32) {
        bytes[] memory fields = new bytes[](HEADER_OPENING_FIELDS);
        fields[0] = "BDLM_STATE_ROOT_GLOBAL_HEADER_V1";
        fields[1] = bytes.concat(stateRootBody);
        fields[2] = bytes.concat(headerHash);
        return BudlumHash.hashFields(fields);
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
