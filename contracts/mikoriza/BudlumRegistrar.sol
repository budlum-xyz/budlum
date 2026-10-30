// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
pragma solidity ^0.8.24;

import {BudlumBls} from "../lib/BudlumBls.sol";
import {BudlumHash} from "../lib/BudlumHash.sol";
import {BudlumOutboundEmitter} from "../lib/BudlumOutbound.sol";
import {BudlumSlasher} from "./BudlumSlasher.sol";
import {IAllocationManager, OperatorSet, SlashingParams} from "./IAllocationManager.sol";

/// @title BudlumRegistrar
/// @notice The Mikoriza AVS on Ethereum (10.2): an
///         EigenLayer operator in the Budlum operator set binds a Budlum
///         validator address and its BLS key, and reports its allocation to
///         Budlum as an outbound message the `SharedSecurityTx::Observe` door
///         checks (src/settlement/shared_security.rs):
///
///         kind           budlum/mikoriza/allocation/v1
///         sender         this contract (the registrar the domain named)
///         recipient      the Budlum validator
///         correlation    H("BDLM_MIKORIZA_OPERATOR_V1", operator)
///         payload hash   H("BDLM_MIKORIZA_ALLOCATION_V1", source, validator,
///                        operator, units, observed_epoch, bls_key)
///
///         Both keys sign the binding: the operator by sending it, the BLS
///         key by a signature over the binding message. An Ethereum validator
///         key is never a Budlum key.
///
///         A binding is the operator's own claim, keyed by
///         (budlumValidator, operator), so it is neither a single slot one
///         member of the operator set can occupy for a validator it does not
///         run nor a permanent one: the operator may rebind, and a second
///         operator may bind the same validator. Which claim is true is decided
///         on Budlum, where the `SharedSecurityTx::Observe` door compares the
///         key with the validator's registered BLS key.
///
///         The registrar deploys its slasher and is the AVS EigenLayer
///         slashes for; the slasher is the only caller of
///         `slashForDoubleVote`. There is no owner, no pause and no upgrade.
contract BudlumRegistrar is BudlumOutboundEmitter {
    bytes internal constant ALLOCATION_KIND = "budlum/mikoriza/allocation/v1";
    /// `RestakeSource::EigenLayer` tag.
    uint8 internal constant SOURCE_EIGENLAYER = 1;
    /// Allocated magnitude is reported in gwei.
    uint256 internal constant UNIT = 1e9;

    IAllocationManager public immutable allocationManager;
    uint32 public immutable operatorSetId;
    uint64 public immutable budlumChainId;
    bytes32 public immutable g2GeneratorHash;
    BudlumSlasher public immutable slasher;
    /// wad slashed per strategy for a double vote (1e18 = all).
    uint256 public immutable doubleVoteWad;

    address[] internal strategies;

    struct Binding {
        address operator;
        bytes compressedKey;
        bytes uncompressedKey;
    }

    mapping(bytes32 => Binding) internal bindings;
    mapping(address => bytes32) public validatorOf;
    mapping(address => uint64) public lastReportedBlock;

    event Bound(address indexed operator, bytes32 indexed budlumValidator, bytes compressedKey);
    event AllocationReported(
        address indexed operator, bytes32 indexed budlumValidator, uint64 units, uint64 observedEpoch
    );

    error NotInOperatorSet(address operator);
    error KeyMismatch();
    error UntrustedGenerator();
    error BindingSignatureInvalid();
    error NotBound(address operator);
    error AlreadyReported(uint64 blockNumber);
    error OnlySlasher();
    error NoStrategies();

    constructor(
        IAllocationManager allocationManager_,
        uint32 operatorSetId_,
        address[] memory strategies_,
        uint64 budlumChainId_,
        bytes32 g2GeneratorHash_,
        uint256 doubleVoteWad_
    ) {
        if (strategies_.length == 0) {
            revert NoStrategies();
        }
        allocationManager = allocationManager_;
        operatorSetId = operatorSetId_;
        strategies = strategies_;
        budlumChainId = budlumChainId_;
        g2GeneratorHash = g2GeneratorHash_;
        doubleVoteWad = doubleVoteWad_;
        slasher = new BudlumSlasher(address(this), budlumChainId_, g2GeneratorHash_);
    }

    /// @notice The message the Budlum BLS key signs to bind itself to the
    ///         sender on this registrar.
    function bindingMessage(address operator, bytes32 budlumValidator)
        public
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            "BDLM_MIKORIZA_BIND_V1",
            BudlumHash.le64(uint64(block.chainid)),
            address(this),
            operator,
            budlumValidator,
            BudlumHash.le64(budlumChainId)
        );
    }

    /// @notice Bind the sender's operator to a Budlum validator.
    /// @param compressedKey The BLS key as Budlum registers it (96 bytes).
    /// @param uncompressedKey The same key in EIP-2537 form (256 bytes).
    /// @param negBindingSignature The key's signature over
    ///        `bindingMessage`, negated, uncompressed G1.
    function bind(
        bytes32 budlumValidator,
        bytes calldata compressedKey,
        bytes calldata uncompressedKey,
        bytes calldata negBindingSignature,
        bytes calldata g2Generator
    ) external {
        OperatorSet memory set = OperatorSet({avs: address(this), id: operatorSetId});
        if (!allocationManager.isMemberOfOperatorSet(msg.sender, set)) {
            revert NotInOperatorSet(msg.sender);
        }
        if (keccak256(g2Generator) != g2GeneratorHash) {
            revert UntrustedGenerator();
        }
        if (!BudlumBls.g2Matches(compressedKey, uncompressedKey)) {
            revert KeyMismatch();
        }
        if (!BudlumBls.verify(
            uncompressedKey, bindingMessage(msg.sender, budlumValidator), negBindingSignature, g2Generator
        )) {
            revert BindingSignatureInvalid();
        }
        // The row is this operator's own claim about this validator, so
        // re-binding replaces it instead of locking the validator address for
        // good: a key rotation or a move to another validator is the
        // operator's to make, and a claim that turns out false is refused on
        // Budlum by the Observe door, not made permanent here.
        bindings[bindingKey(budlumValidator, msg.sender)] = Binding({
            operator: msg.sender,
            compressedKey: compressedKey,
            uncompressedKey: uncompressedKey
        });
        validatorOf[msg.sender] = budlumValidator;
        emit Bound(msg.sender, budlumValidator, compressedKey);
    }

    /// @notice Report `operator`'s current allocation to Budlum. Anyone may
    ///         call it; the numbers come from the AllocationManager. A
    ///         report of zero units tells Budlum the operator exited.
    function reportAllocation(address operator) external returns (uint64 units) {
        bytes32 validator = validatorOf[operator];
        if (validator == bytes32(0) || bindings[bindingKey(validator, operator)].operator == address(0)) {
            revert NotBound(operator);
        }
        uint64 observedEpoch = uint64(block.number);
        if (lastReportedBlock[operator] == observedEpoch) {
            revert AlreadyReported(observedEpoch);
        }
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

    /// @notice The operator's slashable allocation to this operator set, in
    ///         gwei, saturated at u64.
    function allocatedUnits(address operator) public view returns (uint64) {
        OperatorSet memory set = OperatorSet({avs: address(this), id: operatorSetId});
        if (!allocationManager.isMemberOfOperatorSet(operator, set)) {
            return 0;
        }
        address[] memory operators = new address[](1);
        operators[0] = operator;
        uint256[][] memory stake = allocationManager.getMinimumSlashableStake(
            set, operators, strategies, uint32(block.number)
        );
        uint256 total;
        for (uint256 i = 0; i < stake[0].length; i++) {
            total += stake[0][i];
        }
        uint256 gwei_ = total / UNIT;
        return gwei_ > type(uint64).max ? type(uint64).max : uint64(gwei_);
    }

    /// @notice `operator_correlation` of src/settlement/shared_security.rs.
    function operatorCorrelation(address operator) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](2);
        fields[0] = "BDLM_MIKORIZA_OPERATOR_V1";
        fields[1] = abi.encodePacked(operator);
        return BudlumHash.hashFields(fields);
    }

    /// @notice `allocation_payload_hash` of src/settlement/shared_security.rs.
    function allocationPayloadHash(
        bytes32 validator,
        address operator,
        uint64 units,
        uint64 observedEpoch,
        bytes memory compressedKey
    ) public pure returns (bytes32) {
        bytes[] memory fields = new bytes[](7);
        fields[0] = "BDLM_MIKORIZA_ALLOCATION_V1";
        fields[1] = abi.encodePacked(SOURCE_EIGENLAYER);
        fields[2] = abi.encodePacked(validator);
        fields[3] = abi.encodePacked(operator);
        fields[4] = BudlumHash.le64(units);
        fields[5] = BudlumHash.le64(observedEpoch);
        fields[6] = compressedKey;
        return BudlumHash.hashFields(fields);
    }

    /// @notice The key `operator` bound for `budlumValidator`, as its own
    ///         claim. Empty when that operator has not bound the validator.
    function uncompressedKeyOf(bytes32 budlumValidator, address operator)
        external
        view
        returns (bytes memory)
    {
        return bindings[bindingKey(budlumValidator, operator)].uncompressedKey;
    }

    /// @notice The compressed key `operator` bound for `budlumValidator`.
    function compressedKeyOf(bytes32 budlumValidator, address operator)
        external
        view
        returns (bytes memory)
    {
        return bindings[bindingKey(budlumValidator, operator)].compressedKey;
    }

    /// @notice The storage key of one operator's claim about one validator.
    function bindingKey(bytes32 budlumValidator, address operator) public pure returns (bytes32) {
        return keccak256(abi.encode(budlumValidator, operator));
    }

    /// @notice Called by the slasher once it verified a double vote.
    function slashForDoubleVote(address operator, string calldata description) external {
        if (msg.sender != address(slasher)) {
            revert OnlySlasher();
        }
        uint256[] memory wads = new uint256[](strategies.length);
        for (uint256 i = 0; i < wads.length; i++) {
            wads[i] = doubleVoteWad;
        }
        allocationManager.slashOperator(
            address(this),
            SlashingParams({
                operator: operator,
                operatorSetId: operatorSetId,
                strategies: strategies,
                wadsToSlash: wads,
                description: description
            })
        );
    }

    /// @notice EigenLayer's AVS registrar hook: membership is decided by the
    ///         AllocationManager; the registrar keeps no list of its own.
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
