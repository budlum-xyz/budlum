// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

import {BudlumHash} from "../lib/BudlumHash.sol";
import {BudlumOutboundEmitter} from "../lib/BudlumOutbound.sol";

/// @title GraftExecutor
/// @notice Executes an intent on this chain and emits the fulfilment log.
contract GraftExecutor is BudlumOutboundEmitter {
    bytes internal constant FULFILLED_KIND = "budlum/graft/fulfilled/v1";
    uint64 private constant EVM_ADDRESS_BYTE_LEN = 20;
    uint256 private constant FULFILLED_PAYLOAD_FIELDS = 9;
    uint256 private constant POST_CALL_GAS_RESERVE = 8_000;

    mapping(bytes32 => mapping(address => bool)) public fulfilled;
    mapping(address => bytes32) public solverKey;

    event BudlumGraftFulfilled(
        bytes32 indexed intentId,
        address indexed target,
        bytes32 calldataHash,
        uint256 value,
        bytes beneficiary,
        bool success
    );

    event SolverKeyRegistered(address indexed account, bytes32 solverKey);

    error AlreadyFulfilled(bytes32 intentId);
    error ValueTooLarge(uint256 value);
    error CallFailed(bytes32 intentId, bytes reason);
    error SolverKeyNotBound(address account);
    error SolverKeyAlreadyBound(address account, bytes32 current);
    error SolverKeyIsZero();

    function registerSolverKey(bytes32 budlumSolver) external {
        if (budlumSolver == bytes32(0)) {
            revert SolverKeyIsZero();
        }
        bytes32 current = solverKey[msg.sender];
        if (current != bytes32(0)) {
            revert SolverKeyAlreadyBound(msg.sender, current);
        }
        solverKey[msg.sender] = budlumSolver;
        emit SolverKeyRegistered(msg.sender, budlumSolver);
    }

    function execute(
        bytes32 intentId,
        address target,
        bytes calldata data,
        bytes calldata beneficiary
    ) external payable returns (bytes memory result) {
        if (msg.sender == address(0) || target == address(0)) {
            revert CallFailed(intentId, "invalid address");
        }
        bytes32 budlumSolver = solverKey[msg.sender];
        if (budlumSolver == bytes32(0)) {
            revert SolverKeyNotBound(msg.sender);
        }
        if (fulfilled[intentId][msg.sender]) {
            revert AlreadyFulfilled(intentId);
        }
        if (msg.value > type(uint64).max) {
            revert ValueTooLarge(msg.value);
        }
        if (target.code.length == 0) {
            revert CallFailed(intentId, "target has no code");
        }
        uint256 availableGas = gasleft();
        if (availableGas <= POST_CALL_GAS_RESERVE) {
            revert CallFailed(intentId, "insufficient gas");
        }
        fulfilled[intentId][msg.sender] = true;
        uint256 callGas = availableGas - POST_CALL_GAS_RESERVE;
        bool ok;
        (ok, result) = target.call{gas: callGas, value: msg.value}(data);
        if (!ok) {
            revert CallFailed(intentId, result);
        }
        _emitFulfilled(intentId, budlumSolver, target, keccak256(data), beneficiary);
    }

    function _emitFulfilled(
        bytes32 intentId,
        bytes32 budlumSolver,
        address target,
        bytes32 callHash,
        bytes calldata beneficiary
    ) private {
        emit BudlumGraftFulfilled(intentId, target, callHash, msg.value, beneficiary, true);
        _emitOutbound(
            FULFILLED_KIND,
            bytes32(0),
            intentId,
            fulfilledPayloadHash(
                intentId, target, callHash, uint64(msg.value), beneficiary, budlumSolver
            )
        );
    }

    function fulfilledPayloadHash(
        bytes32 intentId,
        address target,
        bytes32 callHash,
        uint64 value,
        bytes memory beneficiary,
        bytes32 budlumSolver
    ) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](FULFILLED_PAYLOAD_FIELDS);
        fields[0] = "BDLM_GRAFT_FULFILLED_EVENT_V1";
        fields[1] = bytes.concat(intentId);
        fields[2] = BudlumHash.le64(EVM_ADDRESS_BYTE_LEN);
        fields[3] = bytes.concat(bytes20(target));
        fields[4] = bytes.concat(callHash);
        fields[5] = BudlumHash.le64(value);
        fields[6] = BudlumHash.le64(uint64(beneficiary.length));
        fields[7] = beneficiary;
        fields[8] = bytes.concat(budlumSolver);
        return BudlumHash.hashFields(fields);
    }
}

/// @title BudlumGraftClaimer
/// @notice What an origin application inherits to name its Budlum payout (`GraftTx::Claim`).
abstract contract BudlumGraftClaimer is BudlumOutboundEmitter {
    bytes internal constant CLAIM_KIND = "budlum/graft/claim/v1";
    uint256 private constant GRAFT_APP_FIELDS = 4;
    uint256 private constant CLAIM_PAYLOAD_FIELDS = 3;
    uint256 private constant U32_BYTE_LEN = 4;
    uint256 private constant BITS_PER_BYTE = 8;

    event BudlumGraftClaim(bytes32 indexed graftId, bytes32 payout);

    function budlumGraftId(uint32 domainKey) public view returns (bytes32) {
        bytes memory origin = bytes.concat(bytes20(address(this)));
        bytes[] memory fields = new bytes[](GRAFT_APP_FIELDS);
        fields[0] = "BDLM_GRAFT_APP_V1";
        fields[1] = _le32(domainKey);
        fields[2] = BudlumHash.le64(uint64(origin.length));
        fields[3] = origin;
        return BudlumHash.hashFields(fields);
    }

    function claimPayloadHash(bytes32 graftId, bytes32 payout) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](CLAIM_PAYLOAD_FIELDS);
        fields[0] = "BDLM_GRAFT_CLAIM_EVENT_V1";
        fields[1] = bytes.concat(graftId);
        fields[2] = bytes.concat(payout);
        return BudlumHash.hashFields(fields);
    }

    function _claimBudlumPayout(uint32 domainKey, bytes32 payout) internal {
        bytes32 graftId = budlumGraftId(domainKey);
        emit BudlumGraftClaim(graftId, payout);
        _emitOutbound(CLAIM_KIND, payout, graftId, claimPayloadHash(graftId, payout));
    }

    function _le32(uint32 value) private pure returns (bytes memory out) {
        out = new bytes(U32_BYTE_LEN);
        for (uint256 i = 0; i < U32_BYTE_LEN; i++) {
            out[i] = bytes1(uint8(value >> (BITS_PER_BYTE * i)));
        }
    }
}
