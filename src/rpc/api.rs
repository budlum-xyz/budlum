#![allow(clippy::too_many_arguments)]

use crate::core::transaction::Transaction;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::ErrorObjectOwned;

#[rpc(server)]
#[allow(clippy::too_many_arguments)]
pub trait BudlumApi {
    #[method(name = "bud_chainId")]
    async fn chain_id(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_blockNumber")]
    async fn block_number(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_getBlockByNumber")]
    async fn get_block_by_number(&self, number: u64)
        -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_getBlockByHash")]
    async fn get_block_by_hash(&self, hash: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_getBalance")]
    async fn get_balance(&self, address: String) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_getNonce")]
    async fn get_nonce(&self, address: String) -> Result<String, ErrorObjectOwned>;

    /// Inclusion or absence proof for one account.
    ///
    /// `bud_getBalance` returns what this node says; this returns what it can
    /// prove. The bundle carries its own root, which is the proof-bearing
    /// trie root and *not* the consensus state root.
    #[method(name = "bud_getAccountProof")]
    async fn get_account_proof(
        &self,
        address: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_sendRawTransaction")]
    async fn send_raw_transaction(&self, tx: Transaction) -> Result<String, ErrorObjectOwned>;

    /// Admit several transactions under one composite signature, all or none.
    ///
    /// A bundle carries up to [`crate::core::tx_bundle::MAX_BUNDLE_TXS`] V7
    /// transactions of one sender, nonces rising by one, each signed by the
    /// same key, and one witness over the root of the set. The node verifies
    /// the witness and every member before it admits anything, so a bundle the
    /// pool refuses leaves no member behind. Returns the hash of each member in
    /// execution order.
    #[method(name = "bud_sendTxBundle")]
    async fn send_tx_bundle(
        &self,
        bundle: crate::core::tx_bundle::TxBundle,
    ) -> Result<Vec<String>, ErrorObjectOwned>;

    #[method(name = "bud_getTransactionByHash")]
    async fn get_transaction_by_hash(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_getTransactionReceipt")]
    async fn get_transaction_receipt(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_gasPrice")]
    async fn gas_price(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_estimateGas")]
    async fn estimate_gas(&self, tx: Transaction) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_txPrecheck")]
    async fn tx_precheck(&self, tx: Transaction) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_syncing")]
    async fn syncing(&self) -> Result<bool, ErrorObjectOwned>;

    #[method(name = "bud_netVersion")]
    async fn net_version(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_netListening")]
    async fn net_listening(&self) -> Result<bool, ErrorObjectOwned>;

    #[method(name = "bud_netPeerCount")]
    async fn net_peer_count(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_getSettlementInfo")]
    async fn get_settlement_info(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// The committed global header at a global height, or null.
    #[method(name = "bud_getGlobalHeader")]
    async fn get_global_header(&self, height: u64) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// One named root of the committed global header at global height `key`
    ///, with what ties it to a finalized block: the checkpoint block
    /// hash and state root, and the state root opening. A light client
    /// checks `root_from_opening(stateRootBody, header.hash) == stateRoot`
    /// against a block its finality certificate covers. Null when the header
    /// is unknown.
    #[method(name = "bud_getGlobalHeaderProof")]
    async fn get_global_header_proof(
        &self,
        root: String,
        key: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_getDomainCommitments")]
    async fn get_domain_commitments(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_getConsensusDomains")]
    async fn get_consensus_domains(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Read one state-rooted Graft application by its canonical id. Writes
    /// still travel as signed `SettlementTx::Graft` transactions.
    #[method(name = "bud_getGraftApplication")]
    async fn get_graft_application(
        &self,
        graft_id_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// The Mikoriza restaked validators: the bound Ethereum operator,
    /// the allocated units, the source, the observed epoch, the status and
    /// the capped weight in force this epoch. Facts only, no score.
    #[method(name = "bud_getRestakedValidators")]
    async fn get_restaked_validators(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prove a Graft payment against the latest checkpoint header whose
    /// payment window holds it. An application checks the
    /// result with `settlement::graft::verify_graft_payment` and a finalized
    /// checkpoint it trusts. `null` when no recent header covers the payment.
    #[method(name = "bud_graftPaymentProof")]
    async fn graft_payment_proof(
        &self,
        payment_id_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: registration is a signed `ExternalDomain`
    /// transaction (`ExternalDomainTx::Register`) from the poster, which
    /// runs admission and escrows the bond in block. Operator-only, kept so a
    /// client is pointed at the transaction.
    #[method(name = "bud_registerExternalDomain")]
    async fn register_external_domain(
        &self,
        registration: serde_json::Value,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: evidence is a signed `ExternalDomainTx::SubmitEvidence`
    /// transaction from the submitter it names.
    #[method(name = "bud_submitExternalEvidence")]
    async fn submit_external_evidence(
        &self,
        evidence: serde_json::Value,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Reads one external domain's public profile: state, trust model, bond,
    /// accept/refuse history - the facts, with units, judgement left to the
    /// reader.
    #[method(name = "bud_getExternalDomainProfile")]
    async fn get_external_domain_profile(
        &self,
        domain_key_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Lists every registered external domain's profile, each with the
    /// one-line summary the profile module renders.
    #[method(name = "bud_getExternalDomains")]
    async fn get_external_domains(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// The deterministic digest of the external-intake state. Two nodes that
    /// applied the same registrations and attestations return the same value;
    /// this is the cross-node commitment until the header earns a root (see
    /// `cross_domain::external::intake`).
    #[method(name = "bud_getExternalIntakeDigest")]
    async fn get_external_intake_digest(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: readmission is a signed `ExternalDomainTx::Readmit`
    /// transaction from the domain's registrant.
    #[method(name = "bud_readmitExternalDomain")]
    async fn readmit_external_domain(
        &self,
        domain_key_hex: String,
        reason: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: a fork is a signed `ExternalDomainTx::ScheduleFork`
    /// transaction from the domain's registrant.
    #[method(name = "bud_scheduleExternalFork")]
    async fn schedule_external_fork(
        &self,
        domain_key_hex: String,
        old_version: u32,
        new_version: u32,
        fork_height: u64,
        grace_heights: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Closed: slashing an external prover needs a proof that an accepted
    /// attestation was false, and no such proof format exists yet. The
    /// method refuses every call and says so.
    #[method(name = "bud_slashExternalProver")]
    async fn slash_external_prover(
        &self,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: a prover bond is a signed
    /// `ExternalDomainTx::BondProver` transaction from the prover.
    #[method(name = "bud_bondExternalProver")]
    async fn bond_external_prover(
        &self,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: a quorum policy is a signed
    /// `ExternalDomainTx::SetQuorumPolicy` transaction from the domain's
    /// registrant. Once installed, submissions enter rounds keyed by
    /// external height and nothing commits until enough bonded provers carry
    /// the same claim.
    #[method(name = "bud_setExternalQuorumPolicy")]
    async fn set_external_quorum_policy(
        &self,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Reads the quorum round for one external height of one domain: its
    /// state, every recorded answer, and who gave it. This is where a
    /// submitter whose evidence returned "round pending" watches the round.
    #[method(name = "bud_getExternalQuorumRound")]
    async fn get_external_quorum_round(
        &self,
        domain_key_hex: String,
        height: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Lists every retained quorum round of one domain with the policy they
    /// run under, oldest external height first.
    #[method(name = "bud_getExternalQuorumRounds")]
    async fn get_external_quorum_rounds(
        &self,
        domain_key_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Assembles submission material for an external domain from its parts,
    /// without submitting anything. For the BudZKVM adapter it encodes a
    /// `ZkFinalityEvidence` (envelope + public inputs + program) into the
    /// adapter's payload and wraps the whole evidence into the raw finality
    /// carrier used by consensus domains bridged through the external
    /// framework. It also returns the starting version policy a registrar
    /// would declare (`single`, version pinned to the adapter's constant)
    /// and the payload cap the decoder enforces, so a registrar builds a
    /// registration from this response instead of guessing constants.
    #[method(name = "bud_encodeExternalEvidence")]
    async fn encode_external_evidence(
        &self,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// The full status of one external domain: the registration record
    /// (economics with the honesty arithmetic evaluated, version windows
    /// with their liveness at the current clock, every prover bond with its
    /// sufficiency and slashing history), the latest attestation, and the
    /// profile's derived ratios. Everything the profile's one-line summary
    /// compresses, uncompressed.
    #[method(name = "bud_getExternalDomainStatus")]
    async fn get_external_domain_status(
        &self,
        domain_key_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Re-runs one registered domain's fault probes against its stored
    /// golden sample, without touching the registry: a dry run of the same
    /// admission harness, reporting each probe's outcome by name. This is
    /// how an operator checks "would this domain still pass admission"
    /// before calling `bud_readmitExternalDomain`, which does mutate.
    #[method(name = "bud_replayExternalProbes")]
    async fn replay_external_probes(
        &self,
        domain_key_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Parses a sync-committee update payload without submitting it:
    /// the decoded fields, the participation arithmetic (count, threshold,
    /// supermajority verdict), the slot-to-epoch/period derivations and the
    /// byte layout the parser applied. This is the dry run an integrator
    /// uses to see exactly what the Ethereum adapter would see, with the
    /// same parser - not a lookalike.
    #[method(name = "bud_inspectEthereumUpdate")]
    async fn inspect_ethereum_update(
        &self,
        payload_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Plans verification of Budlum's hybrid finality proof on a target
    /// EVM: which precompiles the probes proved, which mode that allows
    /// (full cryptographic, half-challenge, optimistic), and the gas
    /// estimate split into crypto and calldata. The planner refuses
    /// malformed material and unbound message points; refusals name the
    /// rule. Deployment tooling reads this from the node so the plan and
    /// the node agree on the rules.
    #[method(name = "bud_planEvmVerification")]
    async fn plan_evm_verification(
        &self,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: a domain registers through a signed `Settlement`
    /// transaction (`SettlementTx::RegisterDomain`) from its operator.
    #[method(name = "bud_registerConsensusDomain")]
    async fn register_consensus_domain(
        &self,
        domain: crate::domain::ConsensusDomain,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: a template registers through a signed `Settlement`
    /// transaction (`SettlementTx::RegisterSovereignTemplate`).
    #[method(name = "bud_registerSovereignTemplate")]
    async fn register_sovereign_template(
        &self,
        template: crate::domain::SovereignDomainTemplate,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Read the state-rooted sovereign template for a consensus domain.
    #[method(name = "bud_getSovereignTemplate")]
    async fn get_sovereign_template(
        &self,
        domain_id: crate::domain::types::DomainId,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_validateSovereignAuditExport")]
    async fn validate_sovereign_audit_export(
        &self,
        bundle: crate::domain::sovereign::AuditExportBundle,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_submitDomainCommitment")]
    async fn submit_domain_commitment(
        &self,
        commitment: crate::domain::DomainCommitment,
    ) -> Result<String, ErrorObjectOwned>;

    /// Refused: a bonded RELAYER carries a commitment and its
    /// finality proof in a signed `Settlement` transaction
    /// (`SettlementTx::SubmitCommitment`).
    #[method(name = "bud_submitVerifiedDomainCommitment")]
    async fn submit_verified_domain_commitment(
        &self,
        payload: crate::domain::VerifiedDomainCommitment,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "bud_submitCrossDomainMessage")]
    async fn submit_cross_domain_message(
        &self,
        msg: crate::cross_domain::CrossDomainMessage,
    ) -> Result<String, ErrorObjectOwned>;

    /// Read a state-rooted cross-domain message by id. Registration remains a
    /// signed `RelayCrossDomainMessage` transaction, not an RPC write.
    #[method(name = "bud_getCrossDomainMessage")]
    async fn get_cross_domain_message(
        &self,
        message_id_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Read the state-rooted bridge transfer associated with a message id.
    /// Bridge lifecycle mutations remain signed transaction doors.
    #[method(name = "bud_getBridgeTransfer")]
    async fn get_bridge_transfer(
        &self,
        message_id_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Read the state-rooted relay queue and, when supplied, one relay record.
    /// `null` returns the bounded summary; relay mutations remain transaction
    /// doors.
    #[method(name = "bud_getRelayerStatus")]
    async fn get_relayer_status(
        &self,
        message_id_hex: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Read one state-rooted outbound relayer intent, its bids, escrow, and
    /// settlement row.
    #[method(name = "bud_getRelayerIntent")]
    async fn get_relayer_intent(
        &self,
        intent_id_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: the home domain's operator registers an asset with a
    /// signed `Bridge` transaction (`BridgeTx::RegisterAsset`).
    #[method(name = "bud_registerBridgeAsset")]
    async fn register_bridge_asset(
        &self,
        asset_id: crate::cross_domain::AssetId,
        domain: crate::domain::DomainId,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // Security review section 3: `bud_lockBridgeTransfer` was removed from
    // the RPC because it created locks without authentication. A lock is a
    // signed `Bridge` transaction from the owner it debits
    //.

    /// Refused: a bonded RELAYER mints with a signed `Bridge`
    /// transaction (`BridgeTx::Mint`) carrying the verified lock event.
    #[method(name = "bud_mintBridgeTransfer")]
    async fn mint_bridge_transfer(
        &self,
        source_domain: crate::domain::DomainId,
        source_height: u64,
        sequence: u64,
        expected_block_hash: Option<crate::domain::Hash32>,
        event: crate::cross_domain::DomainEvent,
        proof: crate::cross_domain::MerkleProof,
        relayer: crate::core::address::Address,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: raw burns are disabled.
    #[method(name = "bud_burnBridgeTransfer")]
    async fn burn_bridge_transfer(
        &self,
        message_id: crate::cross_domain::MessageId,
        domain: crate::domain::DomainId,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: the transfer's recipient burns with a signed `Bridge`
    /// transaction (`BridgeTx::BurnWithEvent`).
    #[method(name = "bud_burnBridgeTransferWithEvent")]
    async fn burn_bridge_transfer_with_event(
        &self,
        message_id: crate::cross_domain::MessageId,
        domain: crate::domain::DomainId,
        domain_height: u64,
        event_index: u32,
        expiry_height: u64,
        // The burner declares the Ethereum destination
        // at burn time.
        recipient_eth: [u8; 20],
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: raw unlocks are disabled.
    #[method(name = "bud_unlockBridgeTransfer")]
    async fn unlock_bridge_transfer(
        &self,
        message_id: crate::cross_domain::MessageId,
        source_domain: crate::domain::DomainId,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: a bonded RELAYER unlocks with a signed `Bridge`
    /// transaction (`BridgeTx::Unlock`) carrying the verified burn event.
    #[method(name = "bud_unlockBridgeTransferVerified")]
    async fn unlock_bridge_transfer_verified(
        &self,
        target_domain: crate::domain::DomainId,
        target_height: u64,
        sequence: u64,
        expected_block_hash: Option<crate::domain::Hash32>,
        event: crate::cross_domain::DomainEvent,
        proof: crate::cross_domain::MerkleProof,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: a bonded RELAYER relays with a signed `Bridge`
    /// transaction (`BridgeTx::RelayProof`).
    #[method(name = "bud_submitRelayProof")]
    async fn submit_relay_proof(
        &self,
        message_id: crate::cross_domain::message::MessageId,
        relayer: String,
        proof: crate::cross_domain::event_tree::MerkleProof,
        source_domain: crate::domain::types::DomainId,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: headers are built in block at every finality
    /// checkpoint.
    #[method(name = "bud_sealGlobalHeader")]
    async fn seal_global_header(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- Permissionless registry -------------------------------------------
    // These endpoints are permissionless by design: there is NO whitelist,
    // API-key allow-list or approval check gating participation. The only
    // Validation is economic (stake) / cryptographic (evidence).

    /// Register by submitting a signed `Stake` (validator) or
    /// `AiOperatorBond` (RoleId 8) transaction. Bonding == registration;
    /// There is no separate approval step. Returns the tx hash.
    #[method(name = "bud_registryRegister")]
    async fn registry_register(
        &self,
        tx: Transaction,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused. This helper bonded an address
    /// into the RELAYER role outside a block, without the address's
    /// signature. A relayer bonds itself with a signed `RoleBond`
    /// transaction (role 3) through `bud_sendRawTransaction`.
    #[method(name = "bud_registryBondRelayer")]
    async fn registry_bond_relayer(
        &self,
        address: String,
        amount: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused. A prover bonds itself with a signed
    /// `RoleBond` transaction (role 4) through `bud_sendRawTransaction`.
    #[method(name = "bud_registryBondProver")]
    async fn registry_bond_prover(
        &self,
        address: String,
        amount: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused. Unbonding a role bond is a signed
    /// `RoleUnbond` transaction from the bonded account, applied in block,
    /// so every node starts the unbonding window at the same height.
    #[method(name = "bud_registryBeginRoleBondUnbonding")]
    async fn registry_begin_role_bond_unbonding(
        &self,
        address: String,
        role_id: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused. Withdrawing a matured role bond is
    /// a signed `RoleWithdraw` transaction from the bonded account, applied
    /// in block.
    #[method(name = "bud_registryWithdrawRoleBond")]
    async fn registry_withdraw_role_bond(
        &self,
        address: String,
        role_id: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Refused: a ZK proof (chain ↔ BudZKVM bridge) rides a signed
    /// `Settlement` transaction (`SettlementTx::SubmitZkProof`) from the
    /// submitter the proof names. The door stays permissionless: a valid
    /// proof is accepted regardless of registration, registered provers earn
    /// a reward, and an invalid proof burns the fee.
    #[method(name = "bud_submitZkProof")]
    async fn submit_zk_proof(
        &self,
        submission: crate::prover::ZkProofSubmission,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query a participant's status for a role (roleId: 1=validator, 2=verifier,
    /// 3=relayer, 4=prover, or any custom id).
    #[method(name = "bud_registryQuery")]
    async fn registry_query(
        &self,
        address: String,
        role_id: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// List active members of a role.
    #[method(name = "bud_registryActiveMembers")]
    async fn registry_active_members(
        &self,
        role_id: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// The facts the chain holds about one validator: bond, delegation,
    /// commission, jail and slash record, missed checkpoints. No score.
    #[method(name = "bud_validatorProfile")]
    async fn validator_profile(
        &self,
        validator: crate::core::address::Address,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Every validator's profile, in address order (bounded list).
    #[method(name = "bud_validatorList")]
    async fn validator_list(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// List active delegation positions for a validator. Delegation state is
    /// rooted and read-only; exits remain visible through their signed
    /// transaction lifecycle rather than an operator-side mutation RPC.
    #[method(name = "bud_getValidatorDelegations")]
    async fn get_validator_delegations(
        &self,
        validator: crate::core::address::Address,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Submit a slashing evidence report. Permissionless: anyone may submit.
    /// The report is only actioned if structurally valid AND consensus-verified;
    /// Unverified reports are rejected without any state change.
    #[method(name = "bud_submitSlashingReport")]
    async fn submit_slashing_report(
        &self,
        report: crate::registry::SlashingReport,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// (security audit) submit a QC fault proof.
    ///
    /// Fail-closed: every reachable proof shape is refused with a
    /// named reason. A proof naming a signature that verifies targets a
    /// valid attestation; one naming a signature that does not verify is not
    /// evidence against the named validator - garbage bytes naming anyone
    /// are free to produce, and acting on them would make this permissionless
    /// surface a frame-up rail. A sound evidence form (two attested
    /// checkpoints at one height under one key) is the double-sign
    /// `SlashingEvidence` path, not this RPC.
    #[method(name = "bud_submitQcFaultProof")]
    async fn submit_qc_fault_proof(
        &self,
        proof: crate::consensus::qc::QcFaultProof,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_health")]
    async fn health(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_nodeInfo")]
    async fn node_info(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Operator-only: ban a peer by its libp2p PeerId. The public listener
    /// refuses with -32004 before any node state is touched.
    #[method(name = "bud_adminBanPeer")]
    async fn admin_ban_peer(&self, peer_id: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Operator-only: lift a ban on a peer by its libp2p PeerId.
    #[method(name = "bud_adminUnbanPeer")]
    async fn admin_unban_peer(
        &self,
        peer_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Operator-only: list currently banned peer IDs.
    #[method(name = "bud_adminListBannedPeers")]
    async fn admin_list_banned_peers(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    // === B.U.D. Storage RPC surface ============================
    // This temporary surface exposes grant and reveal operations. The legacy
    // B.U.D. 1.0 and 2.0 endpoints stay removed until their B.U.D. 3.0 doors
    // are implemented.

    /// Issue a view grant (key handle on-chain; key material off-chain).
    #[method(name = "bud_storageIssueViewGrant")]
    async fn storage_issue_view_grant(
        &self,
        content_id: String,
        authorization: Option<serde_json::Value>,
        grantee: Option<String>,
        key_id: String,
        policy: String,
        opened_epoch: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_storageRevokeViewGrant")]
    async fn storage_revoke_view_grant(
        &self,
        grant_id: u64,
        authorization: Option<serde_json::Value>,
        at_epoch: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Social/DM delete: owner-authorised; revokes every live view grant the
    /// owner issued for the content and rotates its payload key id.
    #[method(name = "bud_storageSocialDelete")]
    async fn storage_social_delete(
        &self,
        content_id: String,
        authorization: Option<serde_json::Value>,
        at_epoch: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Every view-grant row of a confidential object, with the count the node
    /// treats as live. `liveOnly` asks for the live rows alone.
    #[method(name = "bud_storageListViewGrants")]
    async fn storage_list_view_grants(
        &self,
        content_id: String,
        live_only: bool,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_storageMayView")]
    async fn storage_may_view(
        &self,
        content_id: String,
        viewer: String,
        key_id: String,
        owner: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Open a metered reveal session for a Three object. The node re-derives
    /// the view grant from chain state (the same path as
    /// `bud_storageMayView`), so a sealed recipe without a live grant is
    /// refused here, not at the viewer. The returned session id is served by
    /// `bud_storageRevealFrames`; sessions are capped at
    /// `MAX_REVEAL_SESSIONS` and expire after `REVEAL_SESSION_TTL_SECS`.
    ///
    /// The viewer is not a field: `viewer_claim` is
    /// `{viewerPublicKey, signature, issuedAt}`, an ML-DSA-87 signature by the
    /// viewer's own key over `view_claim_digest(content, viewer, key_id,
    /// owner, payload_commitment(packed), issuedAt)`. The viewer address is
    /// derived from the key, so a caller cannot name a grantee it is not; a
    /// claim older than `VIEW_CLAIM_MAX_AGE_SECS` is refused. `owner` is
    /// checked against the owner the chain recorded for `content_id` and a
    /// mismatch is refused by name (`-32006`) before any grant is looked up.
    #[method(name = "bud_storageOpenReveal")]
    async fn storage_open_reveal(
        &self,
        content_id: String,
        recipe: serde_json::Value,
        full_public: Option<serde_json::Value>,
        packed: String,
        viewer_claim: serde_json::Value,
        owner: String,
        key_id: String,
        meter_budget: Option<u64>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Serve `count` frames from `seq_start` of an open reveal session, under
    /// that session's meter budget and the per-call ceiling
    /// (`MAX_FRAMES_PER_CALL`).
    #[method(name = "bud_storageRevealFrames")]
    async fn storage_reveal_frames(
        &self,
        session_id: u64,
        seq_start: u32,
        count: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Close a reveal session early. Returns whether it existed.
    #[method(name = "bud_storageCloseReveal")]
    async fn storage_close_reveal(&self, session_id: u64) -> Result<bool, ErrorObjectOwned>;

    // --- B.U.D. Name Service (BNS) ---

    /// Resolve a human-readable name to an address.
    #[method(name = "bud_bnsResolve")]
    async fn bns_resolve(&self, name: String) -> Result<Option<String>, ErrorObjectOwned>;

    /// Resolve a name to full BNS record (address, storage_root, etc).
    #[method(name = "bud_bnsResolveFull")]
    async fn bns_resolve_full(&self, name: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Resolve a name to a B.U.D. Content ID (CID).
    #[method(name = "bud_bnsResolveContent")]
    async fn bns_resolve_content(&self, name: String) -> Result<Option<String>, ErrorObjectOwned>;

    /// Resolve a subdomain (e.g. photos.ayaz.bud).
    #[method(name = "bud_bnsResolveSubdomain")]
    async fn bns_resolve_subdomain(
        &self,
        parent_name: String,
        sub_label: String,
    ) -> Result<Option<String>, ErrorObjectOwned>;

    /// Prepare a registration transaction (offline helper).
    #[method(name = "bud_bnsPrepareRegister")]
    async fn bns_prepare_register(
        &self,
        name: String,
        owner: String,
        duration: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a subdomain registration transaction.
    #[method(name = "bud_bnsPrepareRegisterSubdomain")]
    async fn bns_prepare_register_subdomain(
        &self,
        parent_name: String,
        sub_label: String,
        sub_owner: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a transaction to link content (CID) to a name.
    #[method(name = "bud_bnsPrepareSetContent")]
    async fn bns_prepare_set_content(
        &self,
        name: String,
        owner: String,
        cid: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a signed renewal transaction. The caller must be the current
    /// owner; the executor rechecks ownership and liveness in the block.
    #[method(name = "bud_bnsPrepareRenew")]
    async fn bns_prepare_renew(
        &self,
        name: String,
        owner: String,
        duration: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a signed transfer transaction. The caller must be the current
    /// owner; the executor rechecks ownership and liveness in the block.
    #[method(name = "bud_bnsPrepareTransfer")]
    async fn bns_prepare_transfer(
        &self,
        name: String,
        owner: String,
        new_owner: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- B.U.D. SocialFi ---

    /// Get an NFT post by ID.
    #[method(name = "bud_socialGetPost")]
    async fn social_get_post(&self, id: u64) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get all posts by a user.
    #[method(name = "bud_socialGetProfile")]
    async fn social_get_profile(
        &self,
        address: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// B.U.D. SocialFi: Get global social feed.
    #[method(name = "bud_socialGetFeed")]
    async fn social_get_feed(&self, limit: usize) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare an NFT post transaction (Mint).
    #[method(name = "bud_socialPreparePost")]
    async fn social_prepare_post(
        &self,
        author: String,
        cid: String,
        author_name: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;
    /// B.U.D. Gateway: Fetch raw content by BNS name (D-Web entry).
    #[method(name = "bud_gatewayFetchContent")]
    async fn gateway_fetch_content(&self, name: String) -> Result<String, ErrorObjectOwned>;

    /// B.U.D. Gateway: render recipe-born content into a requested format.
    ///
    /// `format` is one of `svg`, `png:<size>`, `frame:<index>`. The reply
    /// carries the bytes and the render id, which commits to the format:
    /// the same recipe rendered as PNG is a different object from the same
    /// recipe rendered as SVG.
    #[method(name = "bud_gatewayRenderContent")]
    async fn gateway_render_content(
        &self,
        name: String,
        format: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// D-Web Passport profile bundle for budlum.xyz. Read-only and evidence-labelled.
    #[method(name = "bud_passportGetProfile")]
    async fn passport_get_profile(
        &self,
        name: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// D-Web Passport proof bundle for budlum.xyz. Read-only and evidence-only.
    #[method(name = "bud_passportGetProofBundle")]
    async fn passport_get_proof_bundle(
        &self,
        name: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Budlum Atlas wallet context for bud.scan/budlum.xyz. Read-only.
    #[method(name = "bud_atlasGetWalletContext")]
    async fn atlas_get_wallet_context(
        &self,
        address: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- B.U.D. SocialFi extended ---

    /// Prepare an NFT burn transaction.
    #[method(name = "bud_socialPrepareBurn")]
    async fn social_prepare_burn(
        &self,
        owner: String,
        nft_id: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare an NFT boost transaction.
    #[method(name = "bud_socialPrepareBoost")]
    async fn social_prepare_boost(
        &self,
        booster: String,
        nft_id: u64,
        amount: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- B.U.D. AI Data Marketplace ---

    /// List all active data offers.
    #[method(name = "bud_marketGetOffers")]
    async fn market_get_offers(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a data offer transaction.
    #[method(name = "bud_marketPrepareOffer")]
    async fn market_prepare_offer(
        &self,
        seller: String,
        cid: String,
        price: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a data purchase transaction.
    #[method(name = "bud_marketPreparePurchase")]
    async fn market_prepare_purchase(
        &self,
        buyer: String,
        offer_id: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// List Data Market DataAsset records visible in chain state.
    #[method(name = "bud_dataMarketGetDataAssets")]
    async fn pollen_get_data_assets(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// List Data Market AccessGrant records visible in chain state.
    #[method(name = "bud_dataMarketGetAccessGrants")]
    async fn pollen_get_access_grants(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// List Data Market SaleAuthorization records visible in chain state.
    #[method(name = "bud_dataMarketGetSaleAuthorizations")]
    async fn pollen_get_sale_authorizations(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// List Data Market purchase receipts visible in chain state.
    #[method(name = "bud_dataMarketGetPurchaseReceipts")]
    async fn pollen_get_purchase_receipts(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Build canonical AiInferenceRequest.input_ref for grant-gated data reads.
    #[method(name = "bud_dataMarketBuildAiInputRef")]
    async fn pollen_build_ai_input_ref(
        &self,
        asset_id: String,
        grant_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare unsigned owner/seller authorization for selling a DataAsset.
    #[method(name = "bud_dataMarketPrepareSaleAuthorization")]
    async fn pollen_prepare_sale_authorization(
        &self,
        seller: String,
        asset_id: String,
        unit_price: u64,
        expires_at_block: u64,
        max_grants: u32,
        terms_hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare an authorization-backed Data Market purchase without mutating state.
    ///
    /// `buyer_signature`: an ed25519 signature by the buyer bound to the whole
    /// purchase set (authorization, price, duration, max_reads,
    /// payment_commitment, expiry): an unsigned purchase is not accepted.
    #[method(name = "bud_dataMarketPreparePurchase")]
    async fn pollen_prepare_purchase(
        &self,
        authorization_id: String,
        buyer: String,
        grantee: String,
        grant_duration_blocks: u64,
        max_reads: u32,
        payment_commitment: String,
        buyer_signature: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- B.U.D. budlumxyz ---

    /// List all registered dApps.
    #[method(name = "bud_hubGetApps")]
    async fn budlumxyz_get_apps(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// List the Graft applications (apps on other chains usable with BUD).
    #[method(name = "bud_hubGetGraftApps")]
    async fn budlumxyz_get_graft_apps(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a dApp registration transaction.
    #[method(name = "bud_hubPrepareRegister")]
    async fn budlumxyz_prepare_register(
        &self,
        developer: String,
        name: String,
        category: crate::budlumxyz::types::AppCategory,
        website_url: String,
        manifest_id: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- B.U.D. Universal Relayer ---

    /// Prepare an external chain relay transaction.
    #[method(name = "bud_relayerPrepareExternalTx")]
    async fn relayer_prepare_external_tx(
        &self,
        from: String,
        chain: crate::core::transaction::ExternalChain,
        target_address: String,
        payload: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // --- Mobile/Snapshot Pruning API ---

    /// Get current snapshot/pruning status.
    #[method(name = "bud_pruneStatus")]
    async fn prune_status(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Read and verify a persisted state snapshot by block height.
    /// `null` selects the current chain height. Operator listener only: the
    /// response is the whole state.
    #[method(name = "bud_getStateSnapshot")]
    async fn get_state_snapshot(
        &self,
        height: Option<u64>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Manually trigger a pruning pass.
    #[method(name = "bud_requestPrune")]
    async fn request_prune(
        &self,
        min_blocks_to_keep: Option<u64>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    // ---: AI Inference & Verifier Layer ---

    /// Query registered AI model specification by model_id hex.
    #[method(name = "bud_aiGetModel")]
    async fn ai_get_model(&self, model_id: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare an AI model registration transaction template.
    ///
    /// The governance-tunable registration fee
    /// (`RegistryParams::ai_model_register_fee`) must be attached as
    /// `tx.amount`; the template sets amount 0 - the caller signs the final
    /// amount. Below-fee registrations are rejected atomically by the
    /// executor (`ai_model_register_fee_insufficient`).
    ///
    /// `modality_bits` carries the modality bits (`ModalitySet`). Absent
    /// means the old behaviour (`text_only`). 0 reads nothing (`none` - a
    /// deliberate refusal). 1 is text.
    #[method(name = "bud_aiRegisterModel")]
    async fn ai_register_model(
        &self,
        owner: String,
        model_hash: String,
        min_verifier_count: u32,
        agreement_threshold: u32,
        max_input_ref_bytes: u64,
        max_output_ref_bytes: u64,
        request_deadline_blocks: u64,
        result_deadline_blocks: u64,
        modality_bits: Option<u32>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare an AI inference request transaction.
    ///
    /// The perception declaration: the asset (32B hex), the content (32B hex),
    /// the kind tag (1=text, 2=image, 3=audio, 4=video) and the unit amount.
    /// If all four are given the request is built with a V3 declaration; if
    /// none are given it is built without one (and the executor refuses it,
    /// fail-closed).
    #[method(name = "bud_aiSubmitRequest")]
    async fn ai_submit_request(
        &self,
        requester: String,
        model_id: String,
        input_commitment: String,
        input_ref_hex: String,
        max_fee: u64,
        callback: Option<String>,
        deadline_block: u64,
        perception_asset_id: Option<String>,
        perception_content_id: Option<String>,
        perception_kind_tag: Option<u32>,
        perception_declared_units: Option<u32>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare an AI inference attestation result transaction.
    #[method(name = "bud_aiSubmitResult")]
    async fn ai_submit_result(
        &self,
        verifier: String,
        request_id: String,
        output_commitment: String,
        output_ref_hex: String,
        result_nonce: u64,
        signature_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Open AI requests: no outcome yet, deadline not passed (at most 256).
    #[method(name = "bud_aiOpenRequests")]
    async fn ai_open_requests(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query finalized AI inference outcome by request_id hex.
    #[method(name = "bud_aiGetOutcome")]
    async fn ai_get_outcome(
        &self,
        request_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query active AI verifiers (RoleId::AI_VERIFIER = RoleId(6)).
    #[method(name = "bud_aiGetActiveVerifiers")]
    async fn ai_get_active_verifiers(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Reclaim escrowed max_fee for expired unfinalized AI inference request.
    #[method(name = "bud_aiReclaimFee")]
    async fn ai_reclaim_fee(
        &self,
        request_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Check if a verifier has equivocated on a specific AI request.
    #[method(name = "bud_aiEquivocationStatus")]
    async fn ai_equivocation_status(
        &self,
        request_id: String,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Check if an AI request has been cancelled.
    #[method(name = "bud_aiCancelStatus")]
    async fn ai_cancel_status(
        &self,
        request_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prepare a dispute slash transaction for an equivocating verifier.
    /// This creates an AiDisputeSlash transaction template that must be signed
    /// And submitted via bud_sendRawTransaction.
    #[method(name = "bud_aiDisputeSlash")]
    async fn ai_dispute_slash(
        &self,
        submitter: String,
        request_id: String,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query dispute/slash status for a (request, verifier) pair.
    /// Returns equivocation status, dispute window info, and verifier stake details.
    #[method(name = "bud_aiSlashingStatus")]
    async fn ai_slashing_status(
        &self,
        request_id: String,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query verifier stake information.
    /// Returns stake amount, staking status, and equivocation history.
    #[method(name = "bud_aiVerifierStake")]
    async fn ai_verifier_stake(
        &self,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query pending callback events for an address.
    /// When an AI inference outcome is finalized with a callback address,
    /// The event is queued here for off-chain delivery.
    #[method(name = "bud_aiCallbackQueue")]
    async fn ai_callback_queue(
        &self,
        callback_address: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query ZKVM execution proof for a (request, verifier) pair.
    /// Results with execution proofs are "trustless", verified by ZKVM
    /// Mathematics rather than by verifier reputation alone. This is the
    /// Core primitive for the Agentic Economy paradigm shift.
    #[method(name = "bud_aiExecutionProof")]
    async fn ai_execution_proof(
        &self,
        request_id: String,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query QoS metrics for a verifier.
    /// Returns reliability score, finalization rate, equivocation count,
    /// And response time metrics. Enables QoS-aware verifier selection.
    #[method(name = "bud_aiVerifierQos")]
    async fn ai_verifier_qos(
        &self,
        verifier: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get all verifiers ranked by reliability score.
    /// Returns verifiers ordered from highest to lowest reliability,
    /// Enabling agents to select the most trustworthy verifiers.
    #[method(name = "bud_aiVerifierRanking")]
    async fn ai_verifier_ranking(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query an agent-to-agent payment by ID.
    #[method(name = "bud_aiAgentPayment")]
    async fn ai_agent_payment(
        &self,
        payment_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query payments for an agent (from or to).
    #[method(name = "bud_aiAgentPayments")]
    async fn ai_agent_payments(
        &self,
        agent: String,
        direction: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Query the verifier whitelist.
    /// Returns all whitelisted verifier addresses. If empty, the system
    /// Is in permissionless mode (any staked verifier can submit).
    #[method(name = "bud_aiVerifierWhitelist")]
    async fn ai_verifier_whitelist(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_aiAgentReputation")]
    async fn ai_agent_reputation(
        &self,
        agent: crate::core::address::Address,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    #[method(name = "bud_aiAgentRanking")]
    async fn ai_agent_ranking(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// A read-only status endpoint (independent of the relayer's decision).
    #[method(name = "bud_getStatus")]
    async fn get_status(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Active validator set snapshot.
    #[method(name = "bud_getValidatorSet")]
    async fn get_validator_set(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// One validator's directory record (class, operator key, quota, offers,
    /// pending changes), or null.
    #[method(name = "bud_getValidator")]
    async fn get_validator(&self, owner: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// A B.U.D. 3.0 object record by commitment (hex): header facts, symbol
    /// roots, references, expiry and due repairs; a deleted object shows its
    /// tombstone; unknown is null.
    #[method(name = "bud_storageGetObject")]
    async fn storage_get_object(
        &self,
        commitment: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// The B.U.D. 3.0 shares a validator holds and their audit state.
    #[method(name = "bud_storageGetCustody")]
    async fn storage_get_custody(
        &self,
        validator: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Validators that offer a relay.
    #[method(name = "bud_listRelays")]
    async fn list_relays(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Validators that offer an upload gateway.
    #[method(name = "bud_listGateways")]
    async fn list_gateways(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Domain info by ID.
    #[method(name = "bud_getDomainInfo")]
    async fn get_domain_info(&self, domain_id: u32) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Quantum alarm: level, breaks, solved canaries, pending commits,
    /// the rules the level sets, and the observed crypto facts and quantum
    /// class of every native domain.
    #[method(name = "bud_getQuantumAlarm")]
    async fn get_quantum_alarm(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Slashing history (audit trail).
    #[method(name = "bud_getSlashingHistory")]
    async fn get_slashing_history(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// AI inference layer readiness: chain-derived bonded operator count plus explicit
    /// Fail-closed flags for scheduler, worker, proof, and settlement wiring.
    #[method(name = "bud_aiInferenceStats")]
    async fn ai_stats(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// The DID document of a `did:bud:<hex>` subject, as the master registry
    /// holds it: methods with their revocation state AT THIS READ'S EPOCH,
    /// the credential root, guardians, and the recovery threshold.
    ///
    /// A malformed DID is a refused call, an absent document is `null`: the
    /// two answers must stay tellable apart or a consent screen cannot render
    /// "not registered yet" differently from "typo".
    #[method(name = "bud_identityResolve")]
    async fn identity_resolve(&self, did: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// One credential commitment by id, with the registry's own validity
    /// verdict at the current epoch. The commitment is what the chain holds;
    /// the values were never on it.
    #[method(name = "bud_identityCredential")]
    async fn identity_credential(
        &self,
        credential_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Re-verify a wallet's presentation receipt against the registry as it
    /// stands now: the receiving service's door, where a revocation turns
    /// yesterday's accepted document into today's refusal. `valid:false` is
    /// an answer, not a call error - only an ill-formed request errors.
    #[method(name = "bud_identityVerifyPresentation")]
    async fn identity_verify_presentation(
        &self,
        receipt: crate::registry::PresentationReceipt,
        requester: String,
        document: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Read a Universal Object Layer domain charter by settlement domain id.
    #[method(name = "bud_getCharter")]
    async fn get_charter(&self, domain_id: u32) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Read a Universal Object Layer asset class and its recorded custody by 32-byte hex id.
    #[method(name = "bud_getAssetClass")]
    async fn get_asset_class(
        &self,
        class_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Read a Universal Object Layer unique/record asset placement by 32-byte hex id.
    #[method(name = "bud_getAsset")]
    async fn get_asset(&self, asset_id: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// WebSocket subscriptions: `kind` is
    /// `newHeads`, `finalizedHeads` or `logs`; `logs` takes an optional
    /// address and yields the transactions that send to or from it.
    #[subscription(name = "bud_subscribe" => "bud_subscription", unsubscribe = "bud_unsubscribe", item = serde_json::Value)]
    async fn subscribe(
        &self,
        kind: String,
        address: Option<String>,
    ) -> jsonrpsee::core::SubscriptionResult;

    // ---- Ethereum JSON-RPC compatibility gateway (WP-28, 1/2) ----
    //
    // Section 8.11.2 names every method of this gateway. The table in
    // `src/rpc/compat/ethereum/opening.rs` says what each one answers, the class
    // rows in `src/rpc/method_class.rs` say on which listener, and
    // `docs/RPC_COMPAT.md` says why every EVM-state method refuses today: the
    // opening surface has no validated end-to-end EVM execution environment
    // (WP-27), so a balance read here would be a number no EVM account backs.

    /// `web3_clientVersion`: this node's name and version.
    #[method(name = "web3_clientVersion")]
    async fn web3_client_version(&self) -> Result<String, ErrorObjectOwned>;

    /// `net_version`: the chain id in decimal, as Ethereum tools expect.
    #[method(name = "net_version")]
    async fn compat_net_version(&self) -> Result<String, ErrorObjectOwned>;

    /// `net_listening`: whether this node accepts connections.
    #[method(name = "net_listening")]
    async fn compat_net_listening(&self) -> Result<bool, ErrorObjectOwned>;

    /// `eth_chainId`: the EIP-155 chain id as a quantity.
    #[method(name = "eth_chainId")]
    async fn eth_chain_id(&self) -> Result<String, ErrorObjectOwned>;

    /// `eth_syncing`: `false`, or the sync state while catching up.
    #[method(name = "eth_syncing")]
    async fn eth_syncing(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_blockNumber`: the head height as a quantity.
    #[method(name = "eth_blockNumber")]
    async fn eth_block_number(&self) -> Result<String, ErrorObjectOwned>;

    /// `eth_getBalance`: refuses until WP-27 (door: `bud_getBalance`).
    #[method(name = "eth_getBalance")]
    async fn eth_get_balance(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getCode`: refuses until WP-27 (door: `bud_getAccountProof`).
    #[method(name = "eth_getCode")]
    async fn eth_get_code(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getStorageAt`: refuses until WP-27 (door: `bud_getAccountProof`).
    #[method(name = "eth_getStorageAt")]
    async fn eth_get_storage_at(
        &self,
        address: String,
        position: String,
        block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getTransactionCount`: refuses until WP-27 (door: `bud_getNonce`).
    #[method(name = "eth_getTransactionCount")]
    async fn eth_get_transaction_count(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_call`: refuses until WP-27 (door: `bud_txPrecheck`).
    #[method(name = "eth_call")]
    async fn eth_call(
        &self,
        call: serde_json::Value,
        block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_estimateGas`: refuses until WP-27 (door: `bud_estimateGas`).
    #[method(name = "eth_estimateGas")]
    async fn eth_estimate_gas(
        &self,
        call: serde_json::Value,
        block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_createAccessList`: refuses until WP-27 (door: `bud_txPrecheck`).
    #[method(name = "eth_createAccessList")]
    async fn eth_create_access_list(
        &self,
        call: serde_json::Value,
        block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_gasPrice`: the base fee in wei per gas unit (Section 8.9.7).
    #[method(name = "eth_gasPrice")]
    async fn eth_gas_price(&self) -> Result<String, ErrorObjectOwned>;

    /// `eth_maxPriorityFeePerGas`: zero, because this chain charges none.
    #[method(name = "eth_maxPriorityFeePerGas")]
    async fn eth_max_priority_fee_per_gas(&self) -> Result<String, ErrorObjectOwned>;

    /// `eth_feeHistory`: refuses until WP-35 calibrates the series
    /// (door: `bud_gasPrice`).
    #[method(name = "eth_feeHistory")]
    async fn eth_fee_history(
        &self,
        block_count: String,
        newest_block: String,
        reward_percentiles: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_sendRawTransaction`: refuses until WP-27 accepts the envelope
    /// (door: `bud_sendRawTransaction`).
    #[method(name = "eth_sendRawTransaction")]
    async fn eth_send_raw_transaction(
        &self,
        raw: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getBlockByNumber`: refuses until WP-27 serves `execution_root`
    /// (door: `bud_getBlockByNumber`).
    #[method(name = "eth_getBlockByNumber")]
    async fn eth_get_block_by_number(
        &self,
        block: String,
        full: Option<bool>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getBlockByHash`: refuses until WP-27 (door: `bud_getBlockByHash`).
    #[method(name = "eth_getBlockByHash")]
    async fn eth_get_block_by_hash(
        &self,
        hash: String,
        full: Option<bool>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getBlockTransactionCountByNumber`: refuses until WP-27
    /// (door: `bud_getBlockByNumber`).
    #[method(name = "eth_getBlockTransactionCountByNumber")]
    async fn eth_get_block_transaction_count_by_number(
        &self,
        block: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getBlockTransactionCountByHash`: refuses until WP-27
    /// (door: `bud_getBlockByHash`).
    #[method(name = "eth_getBlockTransactionCountByHash")]
    async fn eth_get_block_transaction_count_by_hash(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getTransactionByHash`: refuses until WP-27
    /// (door: `bud_getTransactionByHash`).
    #[method(name = "eth_getTransactionByHash")]
    async fn eth_get_transaction_by_hash(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getTransactionByBlockNumberAndIndex`: refuses until WP-27
    /// (door: `bud_getBlockByNumber`).
    #[method(name = "eth_getTransactionByBlockNumberAndIndex")]
    async fn eth_get_transaction_by_block_number_and_index(
        &self,
        block: String,
        index: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getTransactionReceipt`: refuses until WP-27
    /// (door: `bud_getTransactionReceipt`).
    #[method(name = "eth_getTransactionReceipt")]
    async fn eth_get_transaction_receipt(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getBlockReceipts`: refuses until WP-27
    /// (door: `bud_getBlockByNumber`).
    #[method(name = "eth_getBlockReceipts")]
    async fn eth_get_block_receipts(
        &self,
        block: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getLogs`: refuses until WP-27
    /// (door: `bud_getTransactionReceipt`).
    #[method(name = "eth_getLogs")]
    async fn eth_get_logs(
        &self,
        filter: serde_json::Value,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_newFilter`: admits one record into the bounded filter table.
    /// `with_extensions` gives the handler the peer key for the quota.
    #[method(name = "eth_newFilter", with_extensions)]
    async fn eth_new_filter(
        &self,
        filter: serde_json::Value,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_newBlockFilter`: admits one block-head filter record.
    #[method(name = "eth_newBlockFilter", with_extensions)]
    async fn eth_new_block_filter(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getFilterChanges`: refuses log data until WP-27 (door: `bud_subscribe`).
    #[method(name = "eth_getFilterChanges", with_extensions)]
    async fn eth_get_filter_changes(
        &self,
        filter_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getFilterLogs`: refuses log data until WP-27 (door: `bud_subscribe`).
    #[method(name = "eth_getFilterLogs", with_extensions)]
    async fn eth_get_filter_logs(
        &self,
        filter_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_uninstallFilter`: releases the slot of one filter id.
    #[method(name = "eth_uninstallFilter", with_extensions)]
    async fn eth_uninstall_filter(
        &self,
        filter_id: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_accounts`: the empty list. This node holds no unlocked key.
    #[method(name = "eth_accounts")]
    async fn eth_accounts(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `debug_traceTransaction`: operator only; refuses until WP-27.
    #[method(name = "debug_traceTransaction")]
    async fn debug_trace_transaction(
        &self,
        hash: String,
        options: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `debug_traceCall`: operator only; refuses until WP-27.
    #[method(name = "debug_traceCall")]
    async fn debug_trace_call(
        &self,
        call: serde_json::Value,
        block: Option<String>,
        options: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// `eth_getProof`: `-32601` on purpose (Section 8.10.6). The Budlum
    /// native proof is `bud_getAccountProof`.
    #[method(name = "eth_getProof")]
    async fn eth_get_proof(
        &self,
        address: String,
        keys: serde_json::Value,
        block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;
}
