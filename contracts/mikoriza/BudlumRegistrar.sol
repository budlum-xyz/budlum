// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// EIP-2537/Cancun+ target chains support EIP-3855 PUSH0 natively.
// aderyn-fp-next-line(push-zero-opcode)
pragma solidity 0.8.26;

import {BudlumBls} from "../lib/BudlumBls.sol";
import {BudlumHash} from "../lib/BudlumHash.sol";
import {BudlumOutboundEmitter} from "../lib/BudlumOutbound.sol";
import {BudlumSlasher} from "./BudlumSlasher.sol";
import {IAllocationManager, OperatorSet, SlashingParams} from "./IAllocationManager.sol";

/// @title BudlumRegistrar
/// @notice The Mikoriza AVS on Ethereum (10.2).
contract BudlumRegistrar is BudlumOutboundEmitter {
    bytes internal constant ALLOCATION_KIND = "budlum/mikoriza/allocation/v1";
    uint8 internal constant SOURCE_EIGENLAYER = 1;
    uint256 internal constant UNIT = 1e9;
    uint256 internal constant MAX_WAD = 1e18;
    uint256 internal constant MAX_STRATEGIES = 64;
    uint256 private constant OPERATOR_CORR_FIELDS = 2;
    uint256 private constant ALLOCATION_PAYLOAD_FIELDS = 7;
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    IAllocationManager public immutable allocationManager;
    uint32 public immutable operatorSetId;
    uint64 public immutable budlumChainId;
    bytes32 public immutable g2GeneratorHash;
    BudlumSlasher public immutable slasher;
    uint256 public immutable doubleVoteWad;

    // Reference-typed arrays cannot be declared `immutable` in Solidity 0.8.26.
    // aderyn-fp-next-line(state-variable-could-be-immutable)
    address[] internal strategies;

    struct Binding {
        address operator;
        bytes compressedKey;
        bytes uncompressedKey;
    }

    mapping(bytes32 => Binding) internal bindings;
    mapping(bytes32 => mapping(bytes32 => bool)) internal boundKeys;
    mapping(address => mapping(bytes32 => bytes32)) internal activeValidatorForKey;
    mapping(address => bytes32) public validatorOf;
    mapping(address => uint64) public lastReportedBlock;
    mapping(address => bool) private _hasReported;
    uint256 private _reentrancyLock;

    event Bound(address indexed operator, bytes32 indexed budlumValidator, bytes compressedKey);
    event Unbound(address indexed operator, bytes32 indexed budlumValidator);
    event AllocationReported(
        address indexed operator, bytes32 indexed budlumValidator, uint64 units, uint64 observedEpoch
    );
    event OperatorSlashed(address indexed operator, uint256 indexed slashId, uint256 strategyCount);

    error NotInOperatorSet(address operator);
    error KeyMismatch();
    error UntrustedGenerator();
    error BindingSignatureInvalid();
    error NotBound(address operator);
    error AlreadyReported(uint64 blockNumber);
    error OnlySlasher();
    error NoStrategies();
    error InvalidRegistrarConfig();
    error InvalidValidator();
    error InvalidStakeMatrix();
    error BlockNumberOverflow(uint256 blockNumber);
    error ReentrantCall();

    constructor(
        IAllocationManager allocationManager_,
        uint32 operatorSetId_,
        address[] memory strategies_,
        uint64 budlumChainId_,
        bytes32 g2GeneratorHash_,
        uint256 doubleVoteWad_
    ) {
        if (strategies_.length == 0 || strategies_.length > MAX_STRATEGIES) {
            revert NoStrategies();
        }
        if (
            address(allocationManager_) == address(0) || address(allocationManager_).code.length == 0
                || budlumChainId_ == 0 || g2GeneratorHash_ == bytes32(0) || doubleVoteWad_ == 0 || doubleVoteWad_ > MAX_WAD
        ) {
            revert InvalidRegistrarConfig();
        }
        for (uint256 i = 0; i < strategies_.length; i++) {
            address s = strategies_[i];
            if (s == address(0)) {
                revert InvalidRegistrarConfig();
            }
            for (uint256 j = i + 1; j < strategies_.length; j++) {
                if (strategies_[j] == s) {
                    revert InvalidRegistrarConfig();
                }
            }
        }
        allocationManager = allocationManager_;
        operatorSetId = operatorSetId_;
        strategies = strategies_;
        budlumChainId = budlumChainId_;
        g2GeneratorHash = g2GeneratorHash_;
        doubleVoteWad = doubleVoteWad_;
        _reentrancyLock = _NOT_ENTERED;
        slasher = new BudlumSlasher(address(this), budlumChainId_, g2GeneratorHash_);
    }

    modifier nonReentrant() {
        if (_reentrancyLock == _ENTERED) {
            revert ReentrantCall();
        }
        _reentrancyLock = _ENTERED;
        _;
        _reentrancyLock = _NOT_ENTERED;
    }

    function bindingMessage(address operator, bytes32 budlumValidator) public view returns (bytes memory) {
        return bytes.concat(
            bytes("BDLM_MIKORIZA_BIND_V1"),
            BudlumHash.le64(uint64(block.chainid)),
            bytes20(address(this)),
            bytes20(operator),
            budlumValidator,
            BudlumHash.le64(budlumChainId)
        );
    }

    function bind(
        bytes32 budlumValidator,
        bytes calldata compressedKey,
        bytes calldata uncompressedKey,
        bytes calldata negBindingSignature,
        bytes calldata g2Generator
    ) external nonReentrant {
        if (budlumValidator == bytes32(0)) {
            revert InvalidValidator();
        }
        if (keccak256(g2Generator) != g2GeneratorHash) {
            revert UntrustedGenerator();
        }
        if (!BudlumBls.g2Matches(compressedKey, uncompressedKey)) {
            revert KeyMismatch();
        }
        if (
            !BudlumBls.verify(
                uncompressedKey, bindingMessage(msg.sender, budlumValidator), negBindingSignature, g2Generator
            )
        ) {
            revert BindingSignatureInvalid();
        }
        OperatorSet memory set = OperatorSet({avs: address(this), id: operatorSetId});
        if (!allocationManager.isMemberOfOperatorSet(msg.sender, set)) {
            revert NotInOperatorSet(msg.sender);
        }
        _recordBinding(msg.sender, budlumValidator, compressedKey, uncompressedKey);
        emit Bound(msg.sender, budlumValidator, compressedKey);
    }

    function _recordBinding(
        address operator,
        bytes32 budlumValidator,
        bytes memory compressedKey,
        bytes memory uncompressedKey
    ) internal {
        _retireMovedRow(operator, budlumValidator, compressedKey);
        bytes32 row = bindingKey(budlumValidator, operator);
        bytes32 keyHash = keccak256(compressedKey);
        if (bindings[row].operator != address(0)) {
            bytes32 replacedKeyHash = keccak256(bindings[row].compressedKey);
            if (replacedKeyHash != keyHash && activeValidatorForKey[operator][replacedKeyHash] == budlumValidator) {
                delete activeValidatorForKey[operator][replacedKeyHash];
            }
        }
        boundKeys[row][keccak256(uncompressedKey)] = true;
        bindings[row] = Binding({operator: operator, compressedKey: compressedKey, uncompressedKey: uncompressedKey});
        activeValidatorForKey[operator][keyHash] = budlumValidator;
        validatorOf[operator] = budlumValidator;
    }

    function _retireMovedRow(address operator, bytes32 budlumValidator, bytes memory compressedKey) internal {
        bytes32 keyHash = keccak256(compressedKey);
        bytes32 tracked = activeValidatorForKey[operator][keyHash];
        if (tracked != bytes32(0) && tracked != budlumValidator) {
            bytes32 trackedRow = bindingKey(tracked, operator);
            if (
                bindings[trackedRow].operator != address(0)
                    && keccak256(bindings[trackedRow].compressedKey) == keyHash
            ) {
                delete bindings[trackedRow];
                delete activeValidatorForKey[operator][keyHash];
                emit Unbound(operator, tracked);
            }
        }
        bytes32 previous = validatorOf[operator];
        if (previous == bytes32(0) || previous == budlumValidator || previous == tracked) {
            return;
        }
        bytes32 previousRow = bindingKey(previous, operator);
        if (
            bindings[previousRow].operator != address(0)
                && keccak256(bindings[previousRow].compressedKey) == keyHash
        ) {
            delete bindings[previousRow];
            if (activeValidatorForKey[operator][keyHash] == previous) {
                delete activeValidatorForKey[operator][keyHash];
            }
            emit Unbound(operator, previous);
        }
    }

    function reportAllocation(address operator) external nonReentrant returns (uint64 units) {
        bytes32 validator = validatorOf[operator];
        if (validator == bytes32(0) || bindings[bindingKey(validator, operator)].operator == address(0)) {
            revert NotBound(operator);
        }
        if (block.number > type(uint64).max) {
            revert BlockNumberOverflow(block.number);
        }
        uint64 observedEpoch = uint64(block.number);
        if (_hasReported[operator] && lastReportedBlock[operator] == observedEpoch) {
            revert AlreadyReported(observedEpoch);
        }
        _hasReported[operator] = true;
        lastReportedBlock[operator] = observedEpoch;
        units = allocatedUnits(operator);
        bytes memory key = bindings[bindingKey(validator, operator)].compressedKey;
        emit AllocationReported(operator, validator, units, observedEpoch);
        _emitOutbound(
            ALLOCATION_KIND,
            validator,
            operatorCorrelation(operator),
            allocationPayloadHash(validator, operator, units, observedEpoch, key)
        );
    }

    function allocatedUnits(address operator) public view returns (uint64) {
        if (block.number > type(uint32).max) {
            revert BlockNumberOverflow(block.number);
        }
        OperatorSet memory set = OperatorSet({avs: address(this), id: operatorSetId});
        if (!allocationManager.isMemberOfOperatorSet(operator, set)) {
            return 0;
        }
        address[] memory operators = new address[](1);
        operators[0] = operator;
        uint256[][] memory stake =
            allocationManager.getMinimumSlashableStake(set, operators, strategies, uint32(block.number));
        if (stake.length != 1 || stake[0].length != strategies.length) {
            revert InvalidStakeMatrix();
        }
        uint256 total;
        for (uint256 i = 0; i < stake[0].length; i++) {
            total += stake[0][i];
        }
        uint256 gwei_ = total / UNIT;
        return gwei_ > type(uint64).max ? type(uint64).max : uint64(gwei_);
    }

    function operatorCorrelation(address operator) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](OPERATOR_CORR_FIELDS);
        fields[0] = "BDLM_MIKORIZA_OPERATOR_V1";
        fields[1] = bytes.concat(bytes20(operator));
        return BudlumHash.hashFields(fields);
    }

    function allocationPayloadHash(
        bytes32 validator,
        address operator,
        uint64 units,
        uint64 observedEpoch,
        bytes memory compressedKey
    ) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](ALLOCATION_PAYLOAD_FIELDS);
        fields[0] = "BDLM_MIKORIZA_ALLOCATION_V1";
        fields[1] = bytes.concat(bytes1(SOURCE_EIGENLAYER));
        fields[2] = bytes.concat(validator);
        fields[3] = bytes.concat(bytes20(operator));
        fields[4] = BudlumHash.le64(units);
        fields[5] = BudlumHash.le64(observedEpoch);
        fields[6] = compressedKey;
        return BudlumHash.hashFields(fields);
    }

    function uncompressedKeyOf(bytes32 budlumValidator, address operator) external view returns (bytes memory) {
        return bindings[bindingKey(budlumValidator, operator)].uncompressedKey;
    }

    function wasBound(bytes32 budlumValidator, address operator, bytes calldata uncompressedKey)
        external
        view
        returns (bool)
    {
        if (budlumValidator == bytes32(0) || operator == address(0) || uncompressedKey.length == 0) {
            return false;
        }
        return boundKeys[bindingKey(budlumValidator, operator)][keccak256(uncompressedKey)];
    }

    function compressedKeyOf(bytes32 budlumValidator, address operator) external view returns (bytes memory) {
        return bindings[bindingKey(budlumValidator, operator)].compressedKey;
    }

    function bindingKey(bytes32 budlumValidator, address operator) public pure returns (bytes32) {
        return keccak256(abi.encode(budlumValidator, operator));
    }

    function slashForDoubleVote(address operator, string calldata description) external nonReentrant {
        if (msg.sender != address(slasher)) {
            revert OnlySlasher();
        }
        if (operator == address(0) || bytes(description).length == 0) {
            revert InvalidStakeMatrix();
        }
        uint256[] memory wads = new uint256[](strategies.length);
        for (uint256 i = 0; i < wads.length; i++) {
            wads[i] = doubleVoteWad;
        }
        (uint256 slashId, uint256[] memory shares) = allocationManager.slashOperator(
            address(this),
            SlashingParams({
                operator: operator,
                operatorSetId: operatorSetId,
                strategies: strategies,
                wadsToSlash: wads,
                description: description
            })
        );
        if (shares.length != strategies.length) {
            revert InvalidStakeMatrix();
        }
        emit OperatorSlashed(operator, slashId, shares.length);
    }

    function supportsAVS(address avs) external view returns (bool) {
        return avs == address(this);
    }

    function registerOperator(address, address avs, uint32[] calldata, bytes calldata) external view {
        require(msg.sender == address(allocationManager) && avs == address(this), "registrar hook");
    }

    function deregisterOperator(address, address avs, uint32[] calldata) external view {
        require(msg.sender == address(allocationManager) && avs == address(this), "registrar hook");
    }
}
