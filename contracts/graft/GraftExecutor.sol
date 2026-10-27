// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {BudlumHash} from "../lib/BudlumHash.sol";
import {BudlumOutboundEmitter} from "../lib/BudlumOutbound.sol";

/// @title GraftExecutor
/// @notice A solver makes the call a Budlum Graft intent asked for through
///         this contract, with its own gas and value (
///         8.5). The contract emits the fulfilment event Budlum's
///         `GraftTx::Fulfill` door checks against the intent
///         (src/settlement/graft.rs, `fulfilled_payload_hash`):
///
///         kind           budlum/graft/fulfilled/v1
///         sender         this contract (the domain's named executor)
///         correlation    the intent id
///         payload hash   H("BDLM_GRAFT_FULFILLED_EVENT_V1", intent_id,
///                        len, origin_app, call_hash, value, len,
///                        beneficiary, solver)
///
///         `origin_app` is the 20-byte target, `call_hash` is
///         keccak256(calldata), and `solver` is the solver's Budlum address.
///         A call that fails reverts: no event, no settlement, and the
///         solver keeps the risk it took by filling early.
///
///         There is no owner, no pause and no upgrade path.
contract GraftExecutor is BudlumOutboundEmitter {
    bytes internal constant FULFILLED_KIND = "budlum/graft/fulfilled/v1";

    /// One fulfilment per intent: a second call for the same intent would be
    /// a second event a solver could try to collect on.
    mapping(bytes32 => bool) public fulfilled;

    event BudlumGraftFulfilled(
        bytes32 indexed intentId,
        address indexed target,
        bytes32 calldataHash,
        uint256 value,
        bytes beneficiary,
        bool success
    );

    error AlreadyFulfilled(bytes32 intentId);
    error ValueTooLarge(uint256 value);
    error CallFailed(bytes32 intentId, bytes reason);

    /// @notice Make the call for `intentId` and emit the fulfilment.
    /// @param intentId The Budlum intent id.
    /// @param budlumSolver The solver's Budlum address, paid on settlement.
    /// @param target The origin application (the Graft row's `origin_app`).
    /// @param data The call data; its keccak256 is the intent's `call_hash`.
    /// @param beneficiary The intent's `origin_beneficiary` bytes.
    function execute(
        bytes32 intentId,
        bytes32 budlumSolver,
        address target,
        bytes calldata data,
        bytes calldata beneficiary
    ) external payable returns (bytes memory result) {
        if (fulfilled[intentId]) {
            revert AlreadyFulfilled(intentId);
        }
        if (msg.value > type(uint64).max) {
            revert ValueTooLarge(msg.value);
        }
        fulfilled[intentId] = true;
        bool ok;
        (ok, result) = target.call{value: msg.value}(data);
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

    /// @notice `fulfilled_payload_hash` of src/settlement/graft.rs.
    function fulfilledPayloadHash(
        bytes32 intentId,
        address target,
        bytes32 callHash,
        uint64 value,
        bytes memory beneficiary,
        bytes32 budlumSolver
    ) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](9);
        fields[0] = "BDLM_GRAFT_FULFILLED_EVENT_V1";
        fields[1] = abi.encodePacked(intentId);
        fields[2] = BudlumHash.le64(20);
        fields[3] = abi.encodePacked(target);
        fields[4] = abi.encodePacked(callHash);
        fields[5] = BudlumHash.le64(value);
        fields[6] = BudlumHash.le64(uint64(beneficiary.length));
        fields[7] = beneficiary;
        fields[8] = abi.encodePacked(budlumSolver);
        return BudlumHash.hashFields(fields);
    }
}

/// @title BudlumGraftClaimer
/// @notice What an origin application inherits to name its Budlum payout
///         (`GraftTx::Claim`). The application decides who may call
///         `_claimBudlumPayout`; the event is the application's own word.
abstract contract BudlumGraftClaimer is BudlumOutboundEmitter {
    bytes internal constant CLAIM_KIND = "budlum/graft/claim/v1";

    /// readable form of the claim.
    event BudlumGraftClaim(bytes32 indexed graftId, bytes32 payout);

    /// @notice `graft_id` of src/settlement/graft.rs for this application on
    ///         the Budlum domain `domainKey`.
    function budlumGraftId(uint32 domainKey) public view returns (bytes32) {
        bytes memory origin = abi.encodePacked(address(this));
        bytes[] memory fields = new bytes[](4);
        fields[0] = "BDLM_GRAFT_APP_V1";
        fields[1] = _le32(domainKey);
        fields[2] = BudlumHash.le64(uint64(origin.length));
        fields[3] = origin;
        return BudlumHash.hashFields(fields);
    }

    /// @notice `claim_payload_hash` of src/settlement/graft.rs.
    function claimPayloadHash(bytes32 graftId, bytes32 payout) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](3);
        fields[0] = "BDLM_GRAFT_CLAIM_EVENT_V1";
        fields[1] = abi.encodePacked(graftId);
        fields[2] = abi.encodePacked(payout);
        return BudlumHash.hashFields(fields);
    }

    function _claimBudlumPayout(uint32 domainKey, bytes32 payout) internal {
        bytes32 graftId = budlumGraftId(domainKey);
        emit BudlumGraftClaim(graftId, payout);
        _emitOutbound(CLAIM_KIND, payout, graftId, claimPayloadHash(graftId, payout));
    }

    function _le32(uint32 value) private pure returns (bytes memory out) {
        out = new bytes(4);
        for (uint256 i = 0; i < 4; i++) {
            out[i] = bytes1(uint8(value >> (8 * i)));
        }
    }
}
