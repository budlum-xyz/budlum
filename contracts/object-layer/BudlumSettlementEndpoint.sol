// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity 0.8.26;

interface IERC20Like {
    function balanceOf(address who) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IBudlumObjectLayerFinality {
    function heightFinal(uint64 height) external view returns (bool);
}

/// @title Budlum settlement endpoint (EVM family, directive 9.3.2).
/// @notice Takes custody of ERC-20 and ERC-721 assets that enter the Budlum
///         Universal Object Layer, carries home calls, and tracks the last
///         accepted Budlum checkpoint for the silence window.
///         No admin key. Not upgradeable. Not pausable.
/// @dev Event layouts are pinned by `src/object_layer/family/evm.rs`. Every
///      field sits in `data`; nothing is indexed.
contract BudlumSettlementEndpoint {
    uint8 internal constant FUNGIBLE = 0;
    uint8 internal constant UNIQUE = 1;

    IBudlumObjectLayerFinality public immutable verifier;
    /// Seconds without a newly accepted checkpoint before the exit opens.
    uint256 public immutable silenceWindow;

    uint64 public lastAcceptedHeight;
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

    error NothingReceived();
    error TransferFailed();
    error NotFinal();
    error NotNewer();
    error NotOpen(string step);

    constructor(IBudlumObjectLayerFinality verifier_, uint256 silenceWindow_) {
        require(silenceWindow_ > 0, "silence window");
        verifier = verifier_;
        silenceWindow = silenceWindow_;
        lastAcceptedAt = block.timestamp;
    }

    /// ERC-721 arrival. `data` is the 32-byte Budlum recipient, or empty to
    /// keep the asset with the depositor's home identity.
    function onERC721Received(address, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4)
    {
        bytes32 recipient = data.length == 32 ? bytes32(data) : bytes32(0);
        emit Arrive(UNIQUE, msg.sender, tokenId, 1, from, recipient);
        return this.onERC721Received.selector;
    }

    /// ERC-20 arrival. The amount is what the endpoint received (balance
    /// difference), so fee-on-transfer tokens are measured, not trusted.
    function deposit20(address token, uint256 amount, bytes32 budlumRecipient) external {
        uint256 before = IERC20Like(token).balanceOf(address(this));
        if (!IERC20Like(token).transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        uint256 received = IERC20Like(token).balanceOf(address(this)) - before;
        if (received == 0) revert NothingReceived();
        emit Arrive(FUNGIBLE, token, 0, received, msg.sender, budlumRecipient);
    }

    /// A home call: Budlum runs `calls` as the home identity of msg.sender.
    function homeCall(bytes calldata calls) external {
        uint64 nonce = homeNonce[msg.sender]++;
        emit HomeCall(msg.sender, nonce, calls);
    }

    /// Accept a newer final Budlum checkpoint and restart the silence clock.
    function acceptHeader(uint64 height) external {
        if (height <= lastAcceptedHeight) revert NotNewer();
        if (!verifier.heightFinal(height)) revert NotFinal();
        lastAcceptedHeight = height;
        lastAcceptedAt = block.timestamp;
    }

    function silent() public view returns (bool) {
        return block.timestamp > lastAcceptedAt + silenceWindow;
    }

    /// Opens with WP-49 step 5: needs an opening of the object-layer root of
    /// an accepted global header (V9).
    function release(bytes calldata) external pure {
        revert NotOpen("WP-49 step 5: departure proof");
    }

    /// Opens with WP-49 step 5: the exit rests on the state at the last
    /// accepted header, which needs the same opening.
    function escape(bytes calldata) external pure {
        revert NotOpen("WP-49 step 5: escape proof");
    }
}
