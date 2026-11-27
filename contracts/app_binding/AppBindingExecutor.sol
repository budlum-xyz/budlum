// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

import {BudlumHash} from "../lib/BudlumHash.sol";
import {BudlumOutboundEmitter} from "../lib/BudlumOutbound.sol";

/// @title AppBindingExecutor
/// @notice Executes an intent on this chain and emits the fulfilment log.
contract AppBindingExecutor is BudlumOutboundEmitter {
    bytes internal constant FULFILLED_KIND = "budlum/app_binding/fulfilled/v1";
    uint64 private constant EVM_ADDRESS_BYTE_LEN = 20;
    uint256 private constant FULFILLED_PAYLOAD_FIELDS = 9;
    uint256 private constant POST_CALL_GAS_RESERVE = 8_000;
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    struct IntentAuthorization {
        address solver;
        bytes32 budlumSolver;
        address target;
        bytes32 calldataHash;
        uint64 value;
        bytes32 beneficiaryHash;
    }

    /// The domain operator that deployed this executor. It mirrors only a
    /// finalized Budlum award into the exact origin-chain call below; random
    /// accounts cannot self-claim another solver's Budlum identity.
    address public immutable authority;
    mapping(bytes32 => IntentAuthorization) public intentAuthorization;
    mapping(bytes32 => bool) public fulfilled;
    uint256 private _reentrancyLock;

    event BudlumAppBindingFulfilled(
        bytes32 indexed intentId,
        address indexed target,
        bytes32 calldataHash,
        uint256 value,
        bytes beneficiary,
        bool success
    );

    event IntentAuthorized(
        bytes32 indexed intentId,
        address indexed solver,
        bytes32 indexed budlumSolver,
        address target,
        bytes32 calldataHash,
        uint64 value,
        bytes32 beneficiaryHash
    );

    error AlreadyFulfilled(bytes32 intentId);
    error AlreadyAuthorized(bytes32 intentId);
    error AuthorizationMismatch(bytes32 intentId);
    error CallFailed(bytes32 intentId, bytes reason);
    error InvalidAuthorization();
    error IntentNotAuthorized(bytes32 intentId);
    error NotAuthority(address caller);
    error NotAwardedSolver(bytes32 intentId, address caller);
    error ValueTooLarge(uint256 value);
    error ReentrantCall();

    constructor() {
        authority = msg.sender;
        _reentrancyLock = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        if (_reentrancyLock == _ENTERED) {
            revert ReentrantCall();
        }
        _reentrancyLock = _ENTERED;
        _;
        _reentrancyLock = _NOT_ENTERED;
    }

    /// Mirror one finalized Budlum award into a one-use, exact call permit.
    /// The permit binds the EVM account that must send `execute`, its awarded
    /// Budlum solver address, and every call field checked by settlement.
    function authorizeIntent(
        bytes32 intentId,
        address solver,
        bytes32 budlumSolver,
        address target,
        bytes32 calldataHash,
        uint64 value,
        bytes32 beneficiaryHash
    ) external {
        if (msg.sender != authority) {
            revert NotAuthority(msg.sender);
        }
        if (
            intentId == bytes32(0) || solver == address(0) || budlumSolver == bytes32(0) || target == address(0)
                || target == address(this)
        ) {
            revert InvalidAuthorization();
        }
        if (intentAuthorization[intentId].solver != address(0) || fulfilled[intentId]) {
            revert AlreadyAuthorized(intentId);
        }
        intentAuthorization[intentId] = IntentAuthorization({
            solver: solver,
            budlumSolver: budlumSolver,
            target: target,
            calldataHash: calldataHash,
            value: value,
            beneficiaryHash: beneficiaryHash
        });
        emit IntentAuthorized(intentId, solver, budlumSolver, target, calldataHash, value, beneficiaryHash);
    }

    function execute(bytes32 intentId, address target, bytes calldata data, bytes calldata beneficiary)
        external
        payable
        nonReentrant
        returns (bytes memory result)
    {
        IntentAuthorization memory authorization = intentAuthorization[intentId];
        if (authorization.solver == address(0)) {
            revert IntentNotAuthorized(intentId);
        }
        if (msg.sender != authorization.solver) {
            revert NotAwardedSolver(intentId, msg.sender);
        }
        if (fulfilled[intentId]) {
            revert AlreadyFulfilled(intentId);
        }
        if (msg.value > type(uint64).max) {
            revert ValueTooLarge(msg.value);
        }
        bytes32 callHash = keccak256(data);
        if (
            target != authorization.target || callHash != authorization.calldataHash || msg.value != authorization.value
                || keccak256(beneficiary) != authorization.beneficiaryHash
        ) {
            revert AuthorizationMismatch(intentId);
        }
        if (target.code.length == 0) {
            revert CallFailed(intentId, "target has no code");
        }
        uint256 availableGas = gasleft();
        if (availableGas <= POST_CALL_GAS_RESERVE) {
            revert CallFailed(intentId, "insufficient gas");
        }
        fulfilled[intentId] = true;
        uint256 callGas = availableGas - POST_CALL_GAS_RESERVE;
        bool ok;
        (ok, result) = target.call{gas: callGas, value: msg.value}(data);
        if (!ok) {
            revert CallFailed(intentId, result);
        }
        _emitFulfilled(intentId, authorization.budlumSolver, target, callHash, beneficiary);
    }

    function _emitFulfilled(
        bytes32 intentId,
        bytes32 budlumSolver,
        address target,
        bytes32 callHash,
        bytes calldata beneficiary
    ) private {
        emit BudlumAppBindingFulfilled(intentId, target, callHash, msg.value, beneficiary, true);
        _emitOutbound(
            FULFILLED_KIND,
            budlumSolver,
            intentId,
            fulfilledPayloadHash(intentId, target, callHash, uint64(msg.value), beneficiary, budlumSolver)
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
        fields[0] = "BDLM_APP_BINDING_FULFILLED_EVENT_V1";
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

/// @title BudlumAppBindingClaimer
/// @notice What an origin application inherits to name its Budlum payout (`AppBindingTx::Claim`).
abstract contract BudlumAppBindingClaimer is BudlumOutboundEmitter {
    bytes internal constant CLAIM_KIND = "budlum/app_binding/claim/v1";
    uint256 private constant APP_BINDING_APP_FIELDS = 4;
    uint256 private constant CLAIM_PAYLOAD_FIELDS = 3;
    uint256 private constant U32_BYTE_LEN = 4;
    uint256 private constant BITS_PER_BYTE = 8;

    event BudlumAppBindingClaim(bytes32 indexed appBindingId, bytes32 payout);

    error InvalidPayout();

    function budlumAppBindingId(uint32 domainKey) public view returns (bytes32) {
        bytes memory origin = bytes.concat(bytes20(address(this)));
        bytes[] memory fields = new bytes[](APP_BINDING_APP_FIELDS);
        fields[0] = "BDLM_APP_BINDING_APP_V1";
        fields[1] = _le32(domainKey);
        fields[2] = BudlumHash.le64(uint64(origin.length));
        fields[3] = origin;
        return BudlumHash.hashFields(fields);
    }

    function claimPayloadHash(bytes32 appBindingId, bytes32 payout) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](CLAIM_PAYLOAD_FIELDS);
        fields[0] = "BDLM_APP_BINDING_CLAIM_EVENT_V1";
        fields[1] = bytes.concat(appBindingId);
        fields[2] = bytes.concat(payout);
        return BudlumHash.hashFields(fields);
    }

    function _claimBudlumPayout(uint32 domainKey, bytes32 payout) internal {
        if (domainKey == 0 || payout == bytes32(0)) {
            revert InvalidPayout();
        }
        bytes32 appBindingId = budlumAppBindingId(domainKey);
        emit BudlumAppBindingClaim(appBindingId, payout);
        _emitOutbound(CLAIM_KIND, payout, appBindingId, claimPayloadHash(appBindingId, payout));
    }

    function _le32(uint32 value) private pure returns (bytes memory out) {
        out = new bytes(U32_BYTE_LEN);
        for (uint256 i = 0; i < U32_BYTE_LEN; i++) {
            out[i] = bytes1(uint8(value >> (BITS_PER_BYTE * i)));
        }
    }
}
