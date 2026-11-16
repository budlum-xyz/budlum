// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

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
    function getMinimumSlashableStake(
        OperatorSet memory operatorSet,
        address[] memory operators,
        address[] memory strategies,
        uint32 futureBlock
    ) external view returns (uint256[][] memory slashableStake);

    function isMemberOfOperatorSet(address operator, OperatorSet memory operatorSet)
        external
        view
        returns (bool);

    function slashOperator(address avs, SlashingParams calldata params)
        external
        returns (uint256 slashId, uint256[] memory shares);
}
