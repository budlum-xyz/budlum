// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

/// @notice The part of EigenLayer's AllocationManager (ELIP-002, operator
///         sets and unique stake) the Mikoriza contracts call. Declared here
///         rather than imported so the tree carries no Ethereum dependency;
///         the deployment ceremony checks the selectors against the deployed
///         EigenLayer release.
struct OperatorSet {
    address avs;
    uint32 id;
}

struct SlashingParams {
    address operator;
    uint32 operatorSetId;
    address[] strategies;
    uint256[] wadsToSlash;
    string description;
}

interface IAllocationManager {
    /// The minimum slashable stake of each operator for each strategy at
    /// `futureBlock`, in the strategy's shares.
    function getMinimumSlashableStake(
        OperatorSet memory operatorSet,
        address[] memory operators,
        address[] memory strategies,
        uint32 futureBlock
    ) external view returns (uint256[][] memory slashableStake);

    /// Whether `operator` is a member of `operatorSet`.
    function isMemberOfOperatorSet(address operator, OperatorSet memory operatorSet)
        external
        view
        returns (bool);

    /// Slash an operator of the caller's operator set.
    function slashOperator(address avs, SlashingParams calldata params)
        external
        returns (uint256 slashId, uint256[] memory shares);
}
