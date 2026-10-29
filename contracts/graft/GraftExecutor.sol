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
///         The `solver` field is not a caller argument. The executing key on
///         this chain and the receiving Budlum key are different keys, so the
///         executor cannot verify a Budlum signature here and must not let a
///         caller name a solver freely: an unclaimed field let a bonded
///         relayer replay another solver's delivery under its own name, or
///         emit an event naming a solver that never authorised it. Each
///         origin-chain account binds one Budlum solver key once
///         (`registerSolverKey`), the binding is immutable, and `execute`
///         reads it - so a fulfilment is always attributable to the account
///         that authorised the payout.
///
///         There is no owner, no pause and no upgrade path.
contract GraftExecutor is BudlumOutboundEmitter {
    bytes internal constant FULFILLED_KIND = "budlum/graft/fulfilled/v1";

    /// One fulfilment per intent *per solver*: a second call for the same
    /// intent by the same solver would be a second event it could try to
    /// collect on.
    ///
    /// Scoped by the bound solver key rather than by `msg.sender` because this
    /// contract is permissionless. A global flag made the id first-come-first-
    /// served, so any account could burn an intent id with an empty call to a
    /// benign target and leave the real solver unable to fulfil - a griefing
    /// attack that costs the attacker one transaction. A slot per (intent,
    /// solver) means one solver can only ever use up its own, and operational
    /// key rotation inside one solver cannot mint a second collectable event
    /// for an intent that solver already fulfilled.
    mapping(bytes32 => mapping(bytes32 => bool)) public fulfilled;

    /// The Budlum address an origin-chain account authors fulfilments for.
    ///
    /// Set once by [`registerSolverKey`] and never re-pointed: a bound account
    /// that could move its binding could emit a fulfilment naming somebody
    /// else's solver key, and the settlement door would have no way to tell
    /// that apart from the solver itself.
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

    /// @notice Bind this account to the Budlum solver address its fulfilments
    ///         name. One-time, permissionless and free: binding costs a
    ///         transaction, not a deposit, and a wrong binding costs the
    ///         account every settlement it would have earned.
    /// @param budlumSolver The solver's Budlum address.
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

    /// @notice Make the call for `intentId` and emit the fulfilment.
    /// @param intentId The Budlum intent id.
    /// @param target The origin application (the Graft row's `origin_app`).
    /// @param data The call data; its keccak256 is the intent's `call_hash`.
    /// @param beneficiary The intent's `origin_beneficiary` bytes.
    function execute(
        bytes32 intentId,
        address target,
        bytes calldata data,
        bytes calldata beneficiary
    ) external payable returns (bytes memory result) {
        // The solver this fulfilment pays is the caller's binding, never a
        // caller-supplied argument: the executor cannot authenticate a Budlum
        // address, so it must not accept one it was merely told about.
        bytes32 budlumSolver = solverKey[msg.sender];
        if (budlumSolver == bytes32(0)) {
            revert SolverKeyNotBound(msg.sender);
        }
        if (fulfilled[intentId][budlumSolver]) {
            revert AlreadyFulfilled(intentId);
        }
        if (msg.value > type(uint64).max) {
            revert ValueTooLarge(msg.value);
        }
        // A call to an address with no code "succeeds" and proves nothing, and
        // it is what a griefer would use to burn an id cheaply.
        if (target.code.length == 0) {
            revert CallFailed(intentId, "target has no code");
        }
        fulfilled[intentId][budlumSolver] = true;
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
