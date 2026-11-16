// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

import {BudlumHash} from "../lib/BudlumHash.sol";
import {IBudlumObjectLayerFinality} from "./BudlumFinalityVerifier.sol";

/// @title Budlum settlement endpoint (EVM family).
/// @notice Closed EVM endpoint for the Budlum Universal Object Layer. It
///         tracks finalized checkpoints, but rejects custody and home calls
///         until departure and emergency-exit proofs can release assets.
///         No admin key. Not upgradeable. Not pausable.
/// @dev Event layouts are pinned by `src/object_layer/family/evm.rs`. Every
///      field sits in `data`; nothing is indexed.
contract BudlumSettlementEndpoint {
    uint8 internal constant FUNGIBLE = 0;
    uint8 internal constant UNIQUE = 1;
    uint256 private constant HASH_QUAD_FIELDS = 4;
    uint256 private constant SHIFT_BYTE_1 = 8;
    uint256 private constant SHIFT_BYTE_2 = 16;
    uint256 private constant SHIFT_BYTE_3 = 24;

    IBudlumObjectLayerFinality public immutable verifier;
    /// Seconds without a newly accepted checkpoint before the exit opens.
    uint256 public immutable silenceWindow;

    uint64 public lastAcceptedHeight;
    /// Authenticated header at `lastAcceptedHeight`. A future exit must prove
    /// its object-layer state against this exact checkpoint, not a caller's
    /// unbound choice of header at the same height.
    bytes32 public lastAcceptedHeaderHash;
    uint256 public lastAcceptedAt;
    mapping(address => uint64) public homeNonce;

    /// budlum/object-layer/arrive/v1
    event Arrive(uint8 kind, address token, uint256 tokenId, uint256 amount, address depositor, bytes32 recipient);
    /// budlum/object-layer/call/v1
    event HomeCall(address sender, uint64 nonce, bytes calls);
    /// budlum/object-layer/released/v1
    event Released(bytes32 departureId);
    /// budlum/object-layer/escaped/v1
    event Escaped(uint8 kind, address token, uint256 tokenId, address to);
    /// budlum/object-layer/header-accepted/v1
    event HeaderAccepted(uint64 height, bytes32 headerHash);

    error NotFinal();
    error NotNewer();
    error NotOpen(string step);
    error InvalidAssetClass();

    constructor(IBudlumObjectLayerFinality verifier_, uint256 silenceWindow_) {
        require(silenceWindow_ > 0, "silence window");
        verifier = verifier_;
        silenceWindow = silenceWindow_;
        lastAcceptedAt = block.timestamp;
    }

    /// Until release and escape can verify finalized ownership, accepting an
    /// ERC-721 would take custody without any possible exit. A caller can also
    /// invoke this hook directly and forge an Arrive event without transferring
    /// a token. Refuse both cases rather than returning the ERC-721 selector.
    function onERC721Received(address, address, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        revert NotOpen("object-layer arrival and exit proofs");
    }

    /// ERC-20 transfers cannot be returned while departure and escape remain
    /// closed. This door must not consume tokens or emit an arrival yet.
    function deposit20(address, uint256, bytes32) external pure {
        revert NotOpen("object-layer arrival and exit proofs");
    }

    /// Home identity calls must not create apparently actionable events before
    /// Budlum can verify and execute them through the object-layer door.
    function homeCall(bytes calldata) external pure {
        revert NotOpen("object-layer home call proof");
    }

    /// Pin the exact authenticated header, not just a finality boolean, before
    /// restarting the silence clock. This is a prerequisite for any later
    /// departure/escape opening; it does not activate custody or exit.
    function acceptHeader(uint64 height) external {
        if (height <= lastAcceptedHeight) revert NotNewer();
        bytes32 headerHash = _readFinalHeader(height);
        lastAcceptedHeight = height;
        lastAcceptedHeaderHash = headerHash;
        lastAcceptedAt = block.timestamp;
        emit HeaderAccepted(height, headerHash);
    }

    function silent() external view returns (bool) {
        return block.timestamp > lastAcceptedAt + silenceWindow;
    }

    /// EVM class identity is the Rust `AssetClassId::derive` value, not a
    /// wrapped token address. The class reference is the kind byte followed
    /// by the 20-byte *home* contract address. Read-only: this grants no
    /// ownership or permission to release anything.
    function assetClassId(uint32 homeDomain, uint8 kind, address token) public pure returns (bytes32) {
        if (kind > UNIQUE || token == address(0)) revert InvalidAssetClass();
        bytes memory classRef = bytes.concat(bytes1(kind), bytes20(token));
        bytes[] memory fields = new bytes[](HASH_QUAD_FIELDS);
        fields[0] = "BDLM_OBJECT_LAYER_CLASS_V1";
        fields[1] = bytes.concat(
            bytes1(uint8(homeDomain)),
            bytes1(uint8(homeDomain >> SHIFT_BYTE_1)),
            bytes1(uint8(homeDomain >> SHIFT_BYTE_2)),
            bytes1(uint8(homeDomain >> SHIFT_BYTE_3))
        );
        fields[2] = BudlumHash.le64(uint64(classRef.length));
        fields[3] = classRef;
        return BudlumHash.hashFields(fields);
    }

    /// The Rust `AssetId::derive` value. Fungible units have no native id;
    /// ERC-721 token ids are exactly one 32-byte big-endian ABI word. The
    /// class and token id remain stable over repeated arrivals and round trips.
    function assetId(uint32 homeDomain, uint8 kind, address token, uint256 tokenId)
        external
        pure
        returns (bytes32)
    {
        if (kind == FUNGIBLE && tokenId != 0) revert InvalidAssetClass();
        bytes memory nativeId = kind == FUNGIBLE ? new bytes(0) : bytes.concat(bytes32(tokenId));
        bytes[] memory fields = new bytes[](HASH_QUAD_FIELDS);
        fields[0] = "BDLM_OBJECT_LAYER_ASSET_V1";
        fields[1] = bytes.concat(assetClassId(homeDomain, kind, token));
        fields[2] = BudlumHash.le64(uint64(nativeId.length));
        fields[3] = nativeId;
        return BudlumHash.hashFields(fields);
    }

    /// Opens later: needs an opening of the object-layer root of
    /// an accepted global header (V9).
    function release(bytes calldata) external pure {
        revert NotOpen("departure proof");
    }

    /// Opens later: the exit rests on the state at the last
    /// accepted header, which needs the same opening.
    function escape(bytes calldata) external pure {
        revert NotOpen("escape proof");
    }

    function _readFinalHeader(uint64 height) internal view returns (bytes32) {
        if (!verifier.heightFinal(height)) revert NotFinal();
        bytes32 headerHash = verifier.headerAt(height);
        if (headerHash == bytes32(0)) revert NotFinal();
        return headerHash;
    }
}
