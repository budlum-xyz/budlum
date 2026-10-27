// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

/// @notice The Foundry cheat codes the tests use. Declared here so the tree
///         carries no test library dependency.
interface Vm {
    /// Exact payload match: the next call must revert with exactly these
    /// bytes. Only meaningful when the full payload is known.
    function expectRevert(bytes calldata revertData) external;
    function expectRevert() external;
    /// Selector match: the next call must revert with this error, whatever
    /// its arguments are. This is the expectation the suites want - a custom
    /// error that carries arguments does not revert with four bytes.
    function expectPartialRevert(bytes4 selector) external;
    function roll(uint256 blockNumber) external;
    function prank(address sender) external;
    function deal(address who, uint256 amount) external;
    function chainId(uint256 newChainId) external;
}

/// @notice A minimal test base: the cheat-code handle and assertions that
///         revert with a message.
abstract contract Harness {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function assertTrue(bool condition, string memory message) internal pure {
        require(condition, message);
    }

    function assertEq(bytes32 a, bytes32 b, string memory message) internal pure {
        require(a == b, message);
    }

    function assertEq(uint256 a, uint256 b, string memory message) internal pure {
        require(a == b, message);
    }
}
