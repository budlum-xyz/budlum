// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {BudlumPaymentReceiver, GraftPayment, IBudlumFinality, PaymentProof} from "./BudlumPaymentReceiver.sol";

/// @title BudlumRemoteAccount
/// @notice A Graft level 3 account (8.3): an account on
///         this chain that a Budlum user controls with Budlum proofs alone.
///         The user holds no ETH and no key on this chain. An application
///         sees the account itself as `msg.sender`.
///
///         Authorization rides a Graft payment to this account's Graft row:
///         the payment's payer must be the account's Budlum owner and its
///         memo hash must be `callAuthorization(target, value, data, nonce)`.
///         A solver relays the proof and pays the gas; the payment itself is
///         the user's signed, finalized Budlum transaction.
contract BudlumRemoteAccount is BudlumPaymentReceiver {
    bytes32 public immutable budlumOwner;
    uint256 public nonce;

    event Executed(uint256 indexed nonce, address indexed target, uint256 value, bool success);

    error NotOwner(bytes32 payer);
    error WrongAuthorization();
    error CallFailed(bytes reason);

    constructor(IBudlumFinality finality_, bytes32 graftId_, bytes32 budlumOwner_)
        BudlumPaymentReceiver(finality_, graftId_)
    {
        budlumOwner = budlumOwner_;
    }

    receive() external payable {}

    /// @notice The memo hash a Budlum payment carries to authorize one call.
    function callAuthorization(address target, uint256 value, bytes calldata data, uint256 callNonce)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode("budlum/remote-account/call/v1", block.chainid, address(this), target, value, keccak256(data), callNonce)
        );
    }

    /// @notice Make the call a finalized Budlum payment authorized.
    function execute(PaymentProof calldata proof, address target, uint256 value, bytes calldata data)
        external
        returns (bytes memory result)
    {
        GraftPayment calldata payment = _consumePayment(proof);
        if (payment.payer != budlumOwner) {
            revert NotOwner(payment.payer);
        }
        uint256 callNonce = nonce;
        if (payment.memoHash != callAuthorization(target, value, data, callNonce)) {
            revert WrongAuthorization();
        }
        nonce = callNonce + 1;
        bool ok;
        (ok, result) = target.call{value: value}(data);
        if (!ok) {
            revert CallFailed(result);
        }
        emit Executed(callNonce, target, value, true);
    }
}

/// @title BudlumRemoteAccountFactory
/// @notice Deploys one `BudlumRemoteAccount` per Budlum owner at a
///         deterministic CREATE2 address, so the address is known before the
///         account exists and can receive funds first.
contract BudlumRemoteAccountFactory {
    IBudlumFinality public immutable finality;

    event AccountDeployed(bytes32 indexed budlumOwner, bytes32 graftId, address account);

    constructor(IBudlumFinality finality_) {
        finality = finality_;
    }

    function _bytecode(bytes32 graftId, bytes32 budlumOwner) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(BudlumRemoteAccount).creationCode, abi.encode(finality, graftId, budlumOwner)
        );
    }

    /// @notice The address `deploy(graftId, budlumOwner)` creates.
    function accountAddress(bytes32 graftId, bytes32 budlumOwner) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(graftId, budlumOwner));
        bytes32 digest = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(_bytecode(graftId, budlumOwner)))
        );
        return address(uint160(uint256(digest)));
    }

    /// @notice Deploy the account; anyone may pay for it.
    function deploy(bytes32 graftId, bytes32 budlumOwner) external returns (address account) {
        bytes32 salt = keccak256(abi.encode(graftId, budlumOwner));
        account = address(new BudlumRemoteAccount{salt: salt}(finality, graftId, budlumOwner));
        emit AccountDeployed(budlumOwner, graftId, account);
    }
}
