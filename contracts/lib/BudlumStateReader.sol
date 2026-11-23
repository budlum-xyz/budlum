// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

import {BudlumHash} from "./BudlumHash.sol";
import {FinalityMode, IBudlumFinality} from "../external-domain/BudlumFinalityVerifier.sol";

/// @title BudlumStateReader
/// @notice Verifies Merkle inclusion proofs of finalized Budlum state facts
///         (account balance, bridge burn record, AppBinding payment, and
///         cross-domain message) against any `IBudlumFinality` verifier.
library BudlumStateReader {
    /// Fail-closed check: returns true only when `height` is finalized with a
    /// non-None finality mode, a non-zero state root, and a valid Merkle proof.
    function verifyLeafAtHeight(
        IBudlumFinality finality,
        uint64 height,
        bytes32 leaf,
        uint256 index,
        bytes32[] memory siblings
    ) internal view returns (bool) {
        if (address(finality) == address(0)) {
            return false;
        }
        if (!finality.heightFinal(height)) {
            return false;
        }
        if (finality.finalityModeAtHeight(height) == FinalityMode.None) {
            return false;
        }
        bytes32 finalizedRoot = finality.rootAtHeight(height);
        return BudlumHash.verifyLeafAgainstRoot(finalizedRoot, leaf, index, siblings);
    }

    function verifyBalance(
        IBudlumFinality finality,
        uint64 height,
        bytes32 account,
        bytes32 assetId,
        uint128 amount,
        uint64 nonce,
        uint256 index,
        bytes32[] memory siblings
    ) internal view returns (bool) {
        bytes32 leaf = BudlumHash.balanceLeaf(account, assetId, amount, nonce);
        return verifyLeafAtHeight(finality, height, leaf, index, siblings);
    }

    function verifyBridgeBurn(
        IBudlumFinality finality,
        uint64 height,
        bytes32 burnId,
        uint32 sourceDomainId,
        uint32 destDomainId,
        bytes32 token,
        uint128 amount,
        bytes32 recipient,
        uint256 index,
        bytes32[] memory siblings
    ) internal view returns (bool) {
        bytes32 leaf =
            BudlumHash.bridgeBurnLeaf(burnId, sourceDomainId, destDomainId, token, amount, recipient);
        return verifyLeafAtHeight(finality, height, leaf, index, siblings);
    }

    function verifyAppBindingPayment(
        IBudlumFinality finality,
        uint64 height,
        bytes32 intentId,
        bytes32 appId,
        bytes32 payer,
        bytes32 assetId,
        uint128 amount,
        uint256 index,
        bytes32[] memory siblings
    ) internal view returns (bool) {
        bytes32 leaf = BudlumHash.appBindingPaymentLeaf(intentId, appId, payer, assetId, amount);
        return verifyLeafAtHeight(finality, height, leaf, index, siblings);
    }

    function verifyCrossDomainMessage(
        IBudlumFinality finality,
        uint64 height,
        bytes32 messageId,
        uint32 sourceDomainId,
        uint32 destDomainId,
        uint64 nonce,
        bytes32 payloadHash,
        uint256 index,
        bytes32[] memory siblings
    ) internal view returns (bool) {
        bytes32 leaf =
            BudlumHash.crossDomainMessageLeaf(messageId, sourceDomainId, destDomainId, nonce, payloadHash);
        return verifyLeafAtHeight(finality, height, leaf, index, siblings);
    }
}
