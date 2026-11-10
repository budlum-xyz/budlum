// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

import {BudlumPaymentReceiver, GraftPayment, IBudlumFinality, PaymentProof} from "./BudlumPaymentReceiver.sol";

/// @title BudlumRemoteAccount
/// @notice A Graft level 3 account (8.3): an account on this chain that a
///         Budlum user controls with Budlum proofs alone.
contract BudlumRemoteAccount is BudlumPaymentReceiver {
    uint256 private constant POST_CALL_GAS_RESERVE = 5_000;

    bytes32 public immutable budlumOwner;
    uint256 public nonce;

    event Executed(uint256 indexed nonce, address indexed target, uint256 value, bool success);

    error NotOwner(bytes32 payer);
    error WrongAuthorization();
    error InvalidCallTarget();
    error InsufficientRelayGas();
    error CallFailed(bytes reason);

    constructor(IBudlumFinality finality_, bytes32 graftId_, bytes32 budlumOwner_)
        BudlumPaymentReceiver(finality_, graftId_)
    {
        budlumOwner = budlumOwner_;
    }

    receive() external payable {}

    function callAuthorization(address target, uint256 value, bytes calldata data, uint256 callNonce)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode("budlum/remote-account/call/v1", block.chainid, address(this), target, value, keccak256(data), callNonce)
        );
    }

    function execute(PaymentProof calldata proof, address target, uint256 value, bytes calldata data)
        external
        returns (bytes memory result)
    {
        if (msg.sender == address(0) || target == address(0)) {
            revert InvalidCallTarget();
        }
        GraftPayment calldata payment = _consumePayment(proof);
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

    event AccountDeployed(bytes32 indexed budlumOwner, bytes32 graftId, address account);

    constructor(IBudlumFinality finality_) {
        finality = finality_;
    }

    function _bytecode(bytes32 graftId, bytes32 budlumOwner) internal view returns (bytes memory) {
        return bytes.concat(
            type(BudlumRemoteAccount).creationCode, abi.encode(finality, graftId, budlumOwner)
        );
    }

    function accountAddress(bytes32 graftId, bytes32 budlumOwner) external view returns (address) {
        bytes32 salt = keccak256(abi.encode(graftId, budlumOwner));
        bytes32 digest = keccak256(
            bytes.concat(bytes1(0xff), bytes20(address(this)), salt, keccak256(_bytecode(graftId, budlumOwner)))
        );
        return address(uint160(uint256(digest)));
    }

    function deploy(bytes32 graftId, bytes32 budlumOwner) external returns (address account) {
        bytes32 salt = keccak256(abi.encode(graftId, budlumOwner));
        account = address(new BudlumRemoteAccount{salt: salt}(finality, graftId, budlumOwner));
        emit AccountDeployed(budlumOwner, graftId, account);
    }
}
