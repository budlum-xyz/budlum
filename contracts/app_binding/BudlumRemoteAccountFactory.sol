// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

import {FinalityMode} from "../external-domain/BudlumFinalityVerifier.sol";
import {BudlumPaymentReceiver, AppBindingPayment, IBudlumFinality, PaymentProof} from "./BudlumPaymentReceiver.sol";

/// @title BudlumRemoteAccount
/// @notice An AppBinding level 3 account (8.3): an account on this chain that a
///         Budlum user controls with Budlum proofs alone.
contract BudlumRemoteAccount is BudlumPaymentReceiver {
    uint256 private constant POST_CALL_GAS_RESERVE = 5_000;
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    bytes32 public immutable budlumOwner;
    uint256 public nonce;
    uint256 private _reentrancyLock;

    event Executed(uint256 indexed nonce, address indexed target, uint256 value, bool success);

    error NotOwner(bytes32 payer);
    error WrongAuthorization();
    error InvalidCallTarget();
    error InsufficientRelayGas();
    error CallFailed(bytes reason);
    error InvalidOwner();
    error ReentrantCall();
    error HybridFinalityRequired(FinalityMode got);

    constructor(IBudlumFinality finality_, bytes32 appBindingId_, bytes32 budlumOwner_)
        BudlumPaymentReceiver(finality_, appBindingId_)
    {
        if (budlumOwner_ == bytes32(0)) {
            revert InvalidOwner();
        }
        budlumOwner = budlumOwner_;
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

    receive() external payable {}

    function callAuthorization(address target, uint256 value, bytes calldata data, uint256 callNonce)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                "budlum/remote-account/call/v1", block.chainid, address(this), target, value, keccak256(data), callNonce
            )
        );
    }

    function execute(PaymentProof calldata proof, address target, uint256 value, bytes calldata data)
        external
        nonReentrant
        returns (bytes memory result)
    {
        if (
            msg.sender == address(0) || target == address(0) || target == address(this)
                || ((data.length > 0 || value == 0) && target.code.length == 0)
        ) {
            revert InvalidCallTarget();
        }
        FinalityMode mode = finality.finalityModeAtHeight(proof.header.checkpointHeight);
        if (mode != FinalityMode.Hybrid) {
            revert HybridFinalityRequired(mode);
        }
        AppBindingPayment calldata payment = _consumePayment(proof);
        if (payment.payer != budlumOwner) {
            revert NotOwner(payment.payer);
        }
        uint256 callNonce = nonce;
        if (payment.memoHash != callAuthorization(target, value, data, callNonce)) {
            revert WrongAuthorization();
        }
        uint256 availableGas = gasleft();
        if (availableGas <= POST_CALL_GAS_RESERVE) {
            revert InsufficientRelayGas();
        }
        nonce = callNonce + 1;
        uint256 callGas = availableGas - POST_CALL_GAS_RESERVE;
        bool ok;
        (ok, result) = target.call{gas: callGas, value: value}(data);
        if (!ok) {
            revert CallFailed(result);
        }
        emit Executed(callNonce, target, value, true);
    }
}

/// @title BudlumRemoteAccountFactory
/// @notice Deploys one `BudlumRemoteAccount` per Budlum owner at a
///         deterministic CREATE2 address.
contract BudlumRemoteAccountFactory {
    IBudlumFinality public immutable finality;

    event AccountDeployed(bytes32 indexed budlumOwner, bytes32 appBindingId, address account);

    error InvalidFactoryConfig();
    error InvalidAccountParams();

    constructor(IBudlumFinality finality_) {
        if (address(finality_) == address(0) || address(finality_).code.length == 0) {
            revert InvalidFactoryConfig();
        }
        finality = finality_;
    }

    function _bytecode(bytes32 appBindingId, bytes32 budlumOwner) internal view returns (bytes memory) {
        return bytes.concat(type(BudlumRemoteAccount).creationCode, abi.encode(finality, appBindingId, budlumOwner));
    }

    function accountAddress(bytes32 appBindingId, bytes32 budlumOwner) external view returns (address) {
        bytes32 salt = keccak256(abi.encode(appBindingId, budlumOwner));
        bytes32 digest = keccak256(
            bytes.concat(bytes1(0xff), bytes20(address(this)), salt, keccak256(_bytecode(appBindingId, budlumOwner)))
        );
        return address(uint160(uint256(digest)));
    }

    function deploy(bytes32 appBindingId, bytes32 budlumOwner) external returns (address account) {
        if (appBindingId == bytes32(0) || budlumOwner == bytes32(0)) {
            revert InvalidAccountParams();
        }
        bytes32 salt = keccak256(abi.encode(appBindingId, budlumOwner));
        account = address(new BudlumRemoteAccount{salt: salt}(finality, appBindingId, budlumOwner));
        emit AccountDeployed(budlumOwner, appBindingId, account);
    }
}
