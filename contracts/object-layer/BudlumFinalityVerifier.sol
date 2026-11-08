// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity 0.8.26;

/// @title Object-layer view of Budlum finality on an EVM home chain.
/// @notice The endpoint asks one question: is this Budlum checkpoint final,
///         and what is its global header hash. The full verifier
///         (`external-domain/BudlumFinalityVerifier.sol`) accepts attestations;
///         this adapter exposes only digests that verifier settled as accepted.
///         It holds no key and has no owner.
interface IAcceptedAttestations {
    function isAccepted(bytes32 digest) external view returns (bool);
}

contract BudlumObjectLayerFinality {
    IAcceptedAttestations public immutable attestations;

    /// Budlum checkpoint height => accepted global header hash.
    mapping(uint64 => bytes32) public headerAt;

    event CheckpointRecorded(uint64 indexed height, bytes32 headerHash, bytes32 digest);

    error NotAccepted();
    error Conflict();

    constructor(IAcceptedAttestations attestations_) {
        attestations = attestations_;
    }

    /// Record a checkpoint whose attestation digest the verifier accepted.
    /// The digest binds height and header hash, so a caller cannot pair an
    /// accepted digest with another header.
    function record(uint64 height, bytes32 headerHash) external {
        bytes32 digest = keccak256(abi.encode("BDLM_OBJECT_LAYER_CHECKPOINT_V1", height, headerHash));
        if (!attestations.isAccepted(digest)) revert NotAccepted();
        bytes32 known = headerAt[height];
        if (known != bytes32(0) && known != headerHash) revert Conflict();
        headerAt[height] = headerHash;
        emit CheckpointRecorded(height, headerHash, digest);
    }

    function heightFinal(uint64 height) external view returns (bool) {
        return headerAt[height] != bytes32(0);
    }
}
