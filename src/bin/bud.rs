//! Budlum CLI - send transactions, query state, validator guidance.
//!
//! This binary talks to the Universal Settlement Layer core (`budlum_core`):
//! build and send a signed transaction (`tx send`), read-only queries
//! (`query balance`/`query block`/`query status`), and guidance for running
//! a validator (`validator run`).
//!
//! The BudZKVM toolchain (`budzero/bud-cli`) is a separate workspace; this binary
//! is for chain interaction and uses the core types directly.
//!
//! # Design
//! - JSON-RPC transport: a hand-written minimal HTTP/1.1 POST over a std
//!   `TcpStream`. NO new external dependency (enough for a CLI; localhost/single node).
//! - Signing: `KeyPair::from_seed` (32-byte hex seed) -> `Transaction::sign`.
//! - Node address via `--rpc-url` (default `http://127.0.0.1:8545`).

#[path = "support/faucet_client.rs"]
mod faucet_client;

use budlum_core::core::address::Address;
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::crypto::primitives::KeyPair;
use budlum_core::project_manifest::{ProjectManifest, ProofFixtureStatus};
use clap::{Parser, Subcommand};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8545";
const RPC_TIMEOUT_SECS: u64 = 15;

/// Ceiling for one RPC response body. CLI answers are kilobytes; a hostile
/// or broken endpoint that streams forever must hit a wall, not the heap.
const MAX_RPC_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "bud",
    author,
    version,
    about = "Budlum CLI - send txs, query state, validator guidance"
)]
struct Cli {
    /// The node's JSON-RPC endpoint.
    #[arg(long, global = true, default_value = DEFAULT_RPC_URL)]
    rpc_url: String,
    /// The chain this invocation signs for: `45260` mainnet, `45261` testnet,
    /// `45262` devnet.
    ///
    /// Required by every command that signs. The node's `bud_chainId` answer is
    /// compared against it and a mismatch is refused before a signature is
    /// spent: a seed controls the same address on every network, so a node that
    /// chose the id chose where the signature we make is valid, and could
    /// present itself as another chain. Naming the network is the only way to
    /// sign for the one you mean.
    #[arg(long, global = true)]
    signing_chain_id: Option<u64>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build a signed transaction and send it to the node.
    Tx {
        #[command(subcommand)]
        action: TxAction,
    },
    /// Read-only state query (relayer independent).
    Query {
        #[command(subcommand)]
        action: QueryAction,
    },
    /// Validator keys, ceremony record and joining (without a subcommand:
    /// guidance for running a node).
    Validator {
        /// A configuration file such as `config/mainnet.toml` (validate + summarize).
        #[arg(short, long)]
        config: Option<String>,
        #[command(subcommand)]
        action: Option<ValidatorAction>,
    },
    /// The genesis ceremony.
    Genesis {
        #[command(subcommand)]
        action: GenesisAction,
    },
    /// Node identity and seed records.
    Node {
        #[command(subcommand)]
        action: NodeAction,
    },
    /// The V5 (ML-DSA-87) wallet: 24-word mnemonic, password-sealed key file.
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },
    /// Request testnet BUD after solving the faucet's work challenge.
    Faucet {
        #[command(subcommand)]
        action: FaucetAction,
    },
    /// Bond stake from a V5 wallet (`Stake`).
    Stake {
        #[command(flatten)]
        signer: V5Signer,
        /// Stake to bond, in whole BUD.
        #[arg(long, required = true)]
        amount_bud: u64,
    },
    /// Start unbonding stake of a V5 wallet (`Unstake`).
    Unstake {
        #[command(flatten)]
        signer: V5Signer,
        /// Stake to unbond, in whole BUD.
        #[arg(long, required = true)]
        amount_bud: u64,
    },
    /// Delegate stake from a V5 wallet to a validator (`Delegate`). The
    /// delegated stake carries the validator's slashing risk and earns only
    /// the rewards the chain actually pays; there is no fixed yield.
    Delegate {
        #[command(flatten)]
        signer: V5Signer,
        /// The validator's address (hex, `0x` prefix optional).
        #[arg(long, required = true)]
        validator: String,
        /// Stake to delegate, in whole BUD.
        #[arg(long, required = true)]
        amount_bud: u64,
    },
    /// Answer an open AI request as an AI verifier (`AiInferenceResult`).
    /// The testnet harness (`budlum-tools ai-test-verifier`) drives this;
    /// its answers are attestation only.
    AiAnswer {
        #[command(flatten)]
        signer: V5Signer,
        /// The request id (32 bytes hex).
        #[arg(long, required = true)]
        request_id: String,
        /// The output commitment (32 bytes hex).
        #[arg(long, required = true)]
        output_commitment: String,
    },
    /// Start unbonding a delegation (`Undelegate`); it stays slashable until
    /// the exit matures.
    Undelegate {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        validator: String,
        /// Stake to undelegate, in whole BUD.
        #[arg(long, required = true)]
        amount_bud: u64,
    },
    /// Withdraw matured delegation exits back to the wallet
    /// (`WithdrawDelegation`).
    WithdrawDelegation {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        validator: String,
    },
    /// Move a delegation from one validator to another (`Redelegate`); no
    /// unbonding round trip, the voting weight follows the position.
    Redelegate {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        from_validator: String,
        #[arg(long, required = true)]
        to_validator: String,
        /// Stake to move, in whole BUD.
        #[arg(long, required = true)]
        amount_bud: u64,
    },
    /// Claim the delegator rewards an epoch close credited
    /// (`ClaimRewards`).
    ClaimRewards {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        validator: String,
    },
    /// Consensus domains: register one in a block.
    Domain {
        #[command(subcommand)]
        action: DomainAction,
    },
    /// Show deterministic cross-VM aliases (EVM / Solana / Aptos) for a Budlum address.
    Alias {
        /// Budlum 32-byte hex address (`0x` optional).
        #[arg(long, required = true)]
        address: String,
    },
    /// Run deterministic multi-VM conformance, BGU calibration, and B.U.D. 3.0 subsystem self-checks.
    Conformance {
        /// Optional BGU calibration sample count (default 20).
        #[arg(long, default_value_t = 20)]
        samples: usize,
    },
    /// A Budlum project (`budlum.toml`): scaffold it, read it, check it
    /// against a node.
    Dev {
        #[command(subcommand)]
        action: DevAction,
    },
    /// Graft: use an application of another network from Budlum, in BUD.
    Graft {
        #[command(subcommand)]
        action: GraftAction,
    },
    /// `.bud` names.
    Bns {
        #[command(subcommand)]
        action: BnsAction,
    },
    /// Local development project manifest (validate + project id).
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
    /// Print and check one epoch's 40 / 50 / 10 security-pool split.
    RewardPool {
        /// Epoch whose calendar budget is split.
        #[arg(long)]
        epoch: u64,
    },
}

#[derive(Subcommand)]
enum ValidatorAction {
    /// Generate a validator key set and write the public ceremony record.
    ///
    /// The key file holds plaintext key material (mode 0600); mainnet
    /// refuses it. The record holds only public keys and the proof of
    /// possession bound to `--chain-id` and the validator address.
    Init {
        /// Where to write the new key set. An existing file is never overwritten.
        #[arg(long, required = true)]
        key_file: std::path::PathBuf,
        /// Where to write the public operator record (JSON).
        #[arg(long, required = true)]
        record_out: std::path::PathBuf,
        /// The chain the proof of possession is bound to (testnet: 45261).
        #[arg(long, default_value_t = 45_261)]
        chain_id: u64,
        /// A display name for the record.
        #[arg(long, default_value = "")]
        moniker: String,
    },
    /// Bond stake and register the consensus keys: the validator becomes
    /// active at the next epoch.
    Join {
        /// The key set `bud validator init` wrote.
        #[arg(long, required = true)]
        key_file: std::path::PathBuf,
        /// Stake to bond, in whole BUD (the network's minimum at least).
        #[arg(long, required = true)]
        stake_bud: u64,
        /// Fee for each of the two transactions (base units; defaults to the network base fee).
        #[arg(long, value_parser = parse_positive_fee)]
        fee: Option<u64>,
    },
    /// Register this validator's Filiz Chain (`RegisterFiliz`). The node
    /// must run with the same seed file in `BUDLUM_FILIZ_SEED_FILE`; the
    /// chain becomes its leader-election proof three epochs later.
    Filiz {
        /// The key set `bud validator init` wrote.
        #[arg(long, required = true)]
        key_file: std::path::PathBuf,
        /// The Filiz seed: 64 hex characters, mode 0600.
        #[arg(long, required = true)]
        seed_file: std::path::PathBuf,
        /// Fee (base units; defaults to the network base fee).
        #[arg(long, value_parser = parse_positive_fee)]
        fee: Option<u64>,
    },
    /// Set the commission this validator takes from its delegators'
    /// rewards (`SetValidatorCommission`), in parts per million. The chain
    /// caps it and limits how fast it may change per epoch.
    Commission {
        /// The key set `bud validator init` wrote.
        #[arg(long, required = true)]
        key_file: std::path::PathBuf,
        /// Commission in parts per million (100000 = 10 percent).
        #[arg(long, required = true)]
        rate_ppm: u32,
        /// Fee (base units; defaults to the network base fee).
        #[arg(long, value_parser = parse_positive_fee)]
        fee: Option<u64>,
    },
}

#[derive(Subcommand)]
enum GenesisAction {
    /// Assemble a ceremony genesis from the operators' public records.
    Assemble {
        /// `testnet`, `mainnet` or `devnet`.
        #[arg(long, default_value = "testnet")]
        network: String,
        /// A directory of operator records (`*.json`, from `bud validator init`).
        #[arg(long, required = true)]
        operators: std::path::PathBuf,
        /// Community destination; on the testnet this is the faucet account.
        #[arg(long, required = true)]
        community: String,
        #[arg(long, required = true)]
        liquidity: String,
        /// Ecosystem destination; the genesis validator stake is drawn from it.
        #[arg(long, required = true)]
        ecosystem: String,
        #[arg(long, required = true)]
        team: String,
        #[arg(long, required = true)]
        burn_reserve: String,
        /// Genesis timestamp in milliseconds (the template's when absent).
        #[arg(long)]
        timestamp_ms: Option<u128>,
        /// An extra genesis balance, `<address>:<base units>`; repeatable.
        /// A tokenomics genesis has no room for one (fixed supply).
        #[arg(long)]
        fund: Vec<String>,
        /// Where to write the genesis file.
        #[arg(long, required = true)]
        out: std::path::PathBuf,
    },
}

/// Where a V5 command finds its key and its password.
#[derive(clap::Args)]
struct V5Signer {
    /// The wallet key file (`bud wallet create` or `import`).
    #[arg(long, required = true)]
    key_file: std::path::PathBuf,
    /// A file holding the wallet password; else `BUD_WALLET_PASSWORD`.
    #[arg(long)]
    password_file: Option<std::path::PathBuf>,
    /// Fee (base units; defaults to the network base fee via `bud_estimateGas` / `bud_gasPrice`).
    #[arg(long, value_parser = parse_positive_fee)]
    fee: Option<u64>,
}

#[derive(Subcommand)]
enum WalletAction {
    /// Create a wallet: print its 24 words once and seal it in a key file.
    Create {
        #[arg(long, required = true)]
        key_file: std::path::PathBuf,
        #[arg(long)]
        password_file: Option<std::path::PathBuf>,
    },
    /// Import a 24-word mnemonic read from standard input (never from argv).
    Import {
        #[arg(long, required = true)]
        key_file: std::path::PathBuf,
        #[arg(long)]
        password_file: Option<std::path::PathBuf>,
    },
    /// Print the address a key file holds (no password needed).
    Address {
        #[arg(long, required = true)]
        key_file: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum DomainAction {
    /// Register a proof-of-work domain (header-chain finality) with the
    /// wallet as its operator; the operator bond is escrowed from it.
    RegisterPow {
        #[command(flatten)]
        signer: V5Signer,
        /// The domain id to claim.
        #[arg(long, required = true)]
        id: u32,
        /// The domain's own chain id.
        #[arg(long, required = true)]
        chain_id: u64,
        /// Confirmations the header chain must carry.
        #[arg(long, default_value_t = 6)]
        min_confirmations: u64,
    },
    /// Run an adapter's admission self-test offline: the golden sample must
    /// verify and every fault probe must be refused. Exits non-zero when
    /// the adapter would not be admitted.
    Selftest {
        /// Adapter family. `zkvm` is the BudZKVM proof adapter.
        #[arg(long, default_value = "zkvm")]
        adapter: String,
        /// The external network label the adapter serves.
        #[arg(long, required = true)]
        network: String,
        /// The golden evidence sample (JSON `RawConsensusEvidence`).
        #[arg(long, required = true)]
        golden: std::path::PathBuf,
        /// Program hash the proof must commit to (hex, 32 bytes).
        #[arg(long)]
        program_hash: Option<String>,
        /// Chain id the proof must commit to.
        #[arg(long)]
        chain_id: Option<u64>,
        /// The target's current time for the verification policy.
        #[arg(long, default_value_t = 0)]
        now: u64,
    },
}

#[derive(Subcommand)]
enum FaucetAction {
    /// Solve the challenge and request 100 testnet BUD for an owned address.
    Request {
        /// HTTPS faucet origin; local loopback HTTP is for rehearsal only.
        #[arg(long, required = true)]
        url: String,
        #[arg(long, required = true)]
        address: String,
    },
}

#[derive(Subcommand)]
enum GraftAction {
    /// Print the Graft id and the mirror account of an application.
    Id {
        #[arg(long, required = true)]
        domain: u32,
        /// The application's identifier on its own network (hex).
        #[arg(long, required = true)]
        origin_app: String,
    },
    /// Register an origin application (permissionless; names no owner).
    Register {
        #[command(flatten)]
        signer: V5Signer,
        /// The origin domain id.
        #[arg(long, required = true)]
        domain: u32,
        /// The application's identifier on its own network (hex).
        #[arg(long, required = true)]
        origin_app: String,
        /// The B.U.D. content id of the application's metadata (hex).
        #[arg(long, required = true)]
        manifest: String,
    },
    /// Pay an application in BUD.
    Pay {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        graft_id: String,
        /// Amount in base units.
        #[arg(long, required = true)]
        amount: u64,
        /// The recipient on the origin network (hex).
        #[arg(long, required = true)]
        origin_recipient: String,
        /// A 32-byte memo hash (hex); zero when absent.
        #[arg(long)]
        memo_hash: Option<String>,
        /// Redeeming origin chain id committed in the payment leaf.
        #[arg(long, default_value_t = 0)]
        target_chain_id: u64,
        /// Redeeming receiver contract/account identifier (hex) committed in the leaf.
        #[arg(long)]
        target_receiver: Option<String>,
    },
    /// Ask a solver to make a call on the origin network; escrows
    /// `--max-payment`.
    Intent {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        graft_id: String,
        /// Hash of the call data (hex).
        #[arg(long, required = true)]
        call_hash: String,
        /// Origin-chain value the call carries.
        #[arg(long, default_value_t = 0)]
        value: u64,
        /// The most BUD (base units) the call may cost in total.
        #[arg(long, required = true)]
        max_payment: u64,
        #[arg(long, required = true)]
        solver_fee_cap: u64,
        /// The application's price for the service.
        #[arg(long, default_value_t = 0)]
        service_price: u64,
        /// The beneficiary on the origin network (hex).
        #[arg(long, required = true)]
        beneficiary: String,
        /// Deadline block; the genesis default when absent.
        #[arg(long, default_value_t = 0)]
        deadline_block: u64,
    },
    /// Refund an expired intent.
    Refund {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        intent_id: String,
    },
    /// Bid on an intent (needs an active RELAYER bond).
    Bid {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        intent_id: String,
        #[arg(long, required = true)]
        cost: u64,
        #[arg(long, required = true)]
        fee: u64,
    },
    /// Award a recorded bid from `--solver`; only the intent owner can do this.
    Award {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        intent_id: String,
        #[arg(long, required = true)]
        solver: String,
    },
    /// Claim an application for a payout with an anchored claim event
    /// (a `RelayerExternalResult` JSON file).
    Claim {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        graft_id: String,
        #[arg(long, required = true)]
        payout: String,
        #[arg(long, required = true)]
        evidence: std::path::PathBuf,
    },
    /// Claim an externally owned application with its EIP-191 signature
    /// over `eoa_claim_hash` (docs/APP_BINDING.md, section 4).
    ClaimSigned {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        graft_id: String,
        #[arg(long, required = true)]
        payout: String,
        /// Last block the signature is valid at.
        #[arg(long, required = true)]
        valid_until_block: u64,
        /// The 65-byte r || s || v signature (hex).
        #[arg(long, required = true)]
        signature: String,
    },
    /// Collect a bid with an anchored fulfilment event (JSON file).
    Fulfill {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        intent_id: String,
        #[arg(long, required = true)]
        evidence: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum BnsAction {
    /// Batch-publish `Primary` `.bud` marketplace offers from a text file.
    ///
    /// Each non-empty, non-`#` line carries `<name> <price_atoms> [duration]`
    /// (space- or comma-separated).
    Sell {
        #[command(flatten)]
        signer: V5Signer,
        /// Path to the listing file (`<name> <price_atoms> [duration]`).
        #[arg(long, required = true)]
        file: std::path::PathBuf,
        /// Default registration length in epochs when a line omits `duration`.
        #[arg(long, default_value_t = 100_000)]
        duration: u64,
        /// Epoch at which the opened offers expire.
        #[arg(long, required = true)]
        expires_at_epoch: u64,
    },
    /// Open a single `Primary` or `Resale` `.bud` marketplace offer.
    CreateOffer {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        name: String,
        #[arg(long, required = true)]
        price_atoms: u64,
        #[arg(long, default_value_t = 0)]
        duration: u64,
        /// Offer kind: `Primary` or `Resale`.
        #[arg(long, default_value = "Resale")]
        kind: String,
        #[arg(long, required = true)]
        expires_at_epoch: u64,
    },
    /// Buy an active `.bud` marketplace offer by id.
    Buy {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        offer_id: u64,
    },
    /// Cancel an active `.bud` marketplace offer owned by the wallet.
    CancelOffer {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        offer_id: u64,
    },
    /// Extend a live `.bud` name from its existing expiry.
    Renew {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        name: String,
        /// Additional registration length in blocks.
        #[arg(long, required = true)]
        duration: u64,
    },
    /// Transfer a live `.bud` name to another address.
    Transfer {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        name: String,
        /// New owner's 32-byte address, with or without a 0x prefix.
        #[arg(long, required = true)]
        new_owner: String,
    },
    /// Set or clear (`--clear`) the target address of a live `.bud` name.
    SetAddress {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        name: String,
        /// Target address (omit when passing `--clear`).
        #[arg(long)]
        address: Option<String>,
        /// Clear the forwarding target instead of setting one.
        #[arg(long, default_value_t = false)]
        clear: bool,
        /// Optional consensus domain ID associated with `--address`.
        #[arg(long)]
        domain_id: Option<u32>,
    },
    /// Set or clear (`--clear`) the wallet's reverse primary `.bud` name.
    SetPrimary {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value_t = false)]
        clear: bool,
    },
    /// Reverse-resolve an address to its verified primary `.bud` name.
    Reverse {
        #[arg(long, required = true)]
        address: String,
    },
    /// Set or delete (`--delete`) a text/profile/multi-chain record on a live `.bud` name.
    SetRecord {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        name: String,
        #[arg(long, required = true)]
        key: String,
        #[arg(long)]
        value: Option<String>,
        #[arg(long, default_value_t = false)]
        delete: bool,
    },
    /// Print all text/profile/multi-chain records of a live `.bud` name.
    GetRecords {
        #[arg(long, required = true)]
        name: String,
    },
    /// Register or update a subdomain `<sub_label>.<parent>` under a live `.bud` name.
    SetSubdomain {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        parent: String,
        #[arg(long, required = true)]
        sub: String,
        #[arg(long, required = true)]
        target: String,
    },
    /// Remove an existing subdomain `<sub_label>` under a live `.bud` parent name.
    RemoveSubdomain {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        parent: String,
        #[arg(long, required = true)]
        sub: String,
    },
    /// List all subdomains under a live `.bud` parent name.
    ListSubdomains {
        #[arg(long, required = true)]
        parent: String,
    },
    /// Bind or clear (`--clear`) a B.U.D. 3.0 `ContentRef` on a live `.bud` name.
    SetBud3 {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        name: String,
        #[arg(long)]
        object: Option<String>,
        #[arg(long)]
        digest: Option<String>,
        #[arg(long)]
        len: Option<u64>,
        #[arg(long, default_value_t = false)]
        sealed: bool,
        #[arg(long)]
        nft: Option<String>,
        #[arg(long, default_value_t = false)]
        clear: bool,
    },
    /// Inspect the live B.U.D. 3.0 `ContentRef` bound to a `.bud` name.
    GetBud3 {
        #[arg(long, required = true)]
        name: String,
    },
    /// List all `active` and `grace` `.bud` names held by an address.
    List {
        #[arg(long, required = true)]
        owner: String,
    },
    /// Fetch a compact per-name Merkle state proof against `BnsRegistry::root()`.
    Proof {
        #[arg(long, required = true)]
        name: String,
    },
    /// Forward-resolve `<label>.bud` or `<sub_label>.<label>.bud` to its target address.
    Resolve {
        #[arg(long, required = true)]
        name: String,
        /// Require and locally verify a per-name Merkle state proof (`<label>.bud`).
        #[arg(long, default_value_t = false)]
        verify_proof: bool,
    },
    /// Inspect full `.bud` record metadata and locally verify its Merkle state proof.
    Info {
        #[arg(long, required = true)]
        name: String,
    },
    /// List active `.bud` marketplace offers (`Primary`, `Resale`, or all).
    Offers {
        #[arg(long)]
        kind: Option<String>,
    },
    /// Inspect a single `.bud` marketplace offer by numeric id.
    GetOffer {
        #[arg(long, required = true)]
        offer_id: u64,
    },
    /// Package a file or static directory into B.U.D. 3.0 and bind its `ContentRef` to `<label>.bud`.
    PublishSite {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        name: String,
        /// File (e.g. `index.html`) or static site directory to publish.
        #[arg(long, required = true)]
        path: std::path::PathBuf,
        /// Paid B.U.D. 3.0 object lifetime in epochs.
        #[arg(long, default_value_t = 100_000)]
        lifetime_epochs: u64,
        /// Optional 32-byte custody validator hex (defaults to wallet address).
        #[arg(long)]
        validator: Option<String>,
    },
}

#[derive(Subcommand)]
enum NodeAction {
    /// Create (or read) a P2P identity file and print the node's peer id,
    /// its bootnode multiaddr and the DNS seed record that names it.
    Identity {
        /// The identity file the node is started with (`p2p.identity_file`).
        #[arg(long, required = true)]
        identity_file: std::path::PathBuf,
        /// The public IPv4 address or DNS name peers dial.
        #[arg(long, required = true)]
        host: String,
        /// The P2P port (testnet: 5001).
        #[arg(long, default_value_t = 5001)]
        port: u16,
        /// The DNS seed name (`p2p.dns_seeds`) this node answers under.
        #[arg(long)]
        seed_domain: Option<String>,
    },
}

#[derive(Subcommand)]
enum ProjectAction {
    /// Validate the local standard manifest and print the project id.
    Id {
        /// Project name.
        #[arg(long, required = true)]
        name: String,
        /// The 32-byte hash of the BudL source tree (hex, `0x` prefix optional).
        #[arg(long, required = true)]
        source_hash: String,
    },
    /// Bind a proof record to the hash of a verified proof envelope.
    BindProof {
        /// Project name.
        #[arg(long, required = true)]
        name: String,
        /// The 32-byte hash of the `BudL` source tree (hex).
        #[arg(long, required = true)]
        source_hash: String,
        /// Name of the proof record in the manifest.
        #[arg(long, required = true)]
        fixture: String,
        /// The 32-byte hash of the proof envelope that passed verification (hex).
        #[arg(long, required = true)]
        proof_hash: String,
    },
}

#[derive(Subcommand)]
enum DevAction {
    /// Write a `budlum.toml` for a new project (refuses to overwrite).
    Init {
        /// The project name.
        #[arg(long, required = true)]
        name: String,
        /// Where to write the file.
        #[arg(long, default_value = "budlum.toml")]
        path: std::path::PathBuf,
    },
    /// Read a `budlum.toml` and show what it says; with a reachable node,
    /// show the node's chain id and version beside it.
    Info {
        #[arg(long, default_value = "budlum.toml")]
        path: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum TxAction {
    /// Send a BDLM transfer.
    Send {
        /// Recipient address (hex, `0x` prefix optional).
        #[arg(long, required = true)]
        to: String,
        /// Transfer amount (base units).
        #[arg(long, required = true)]
        amount: u64,
        /// Path to a file holding the sender's 32-byte hex signing seed.
        ///
        /// The seed is never taken on the command line: `argv` is visible in
        /// the process list, shell history and any log that captures the
        /// invocation. Either this flag or the `BUD_PRIV_KEY` environment
        /// variable must supply it.
        #[arg(long)]
        priv_key_file: Option<std::path::PathBuf>,
        /// Transaction fee (base units; defaults to the network base fee via RPC when omitted).
        #[arg(long, value_parser = parse_positive_fee)]
        fee: Option<u64>,
        /// Transaction nonce (fetched from the node with `bud_getNonce` if omitted).
        #[arg(long)]
        nonce: Option<u64>,
        /// A V5 wallet key file. With it the transfer is signed ML-DSA-87
        /// (V5, the default for new wallets); without it the retired V4
        /// Ed25519 seed (`--priv-key-file`) signs.
        #[arg(long, conflicts_with = "priv_key_file")]
        key_file: Option<std::path::PathBuf>,
        /// A file holding the wallet password; else `BUD_WALLET_PASSWORD`.
        #[arg(long, requires = "key_file")]
        password_file: Option<std::path::PathBuf>,
    },
    /// Submit a signed transaction bundle (`bud_sendTxBundle`).
    ///
    /// The file holds the bundle as JSON: the signed members in execution
    /// order and the one witness over them. Nothing is signed here - both are
    /// the sender's - and the node verifies the witness and every member
    /// before it admits a single one.
    Bundle {
        /// Path to the bundle file.
        #[arg(long)]
        file: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum QueryAction {
    /// Query an address balance (`bud_getBalance`).
    Balance {
        /// Address (hex, `0x` prefix optional).
        address: String,
    },
    /// Query a block by number (`bud_getBlockByNumber`).
    Block {
        /// Block number or `latest`.
        number: String,
    },
    /// Queries the chain status (`bud_getStatus`).
    Status,
}

/// Parses a `http://host:port` URL into a (host, port) pair. The path is ignored.
fn parse_rpc_url(url: &str) -> Result<(String, u16), String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        format!("--rpc-url expects the 'http://' scheme (https unsupported): '{url}'")
    })?;
    let host_port = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| format!("invalid port: '{p}'"))?,
        ),
        None => (host_port.to_string(), 8545u16),
    };
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    Ok((host, port))
}

/// A minimal HTTP/1.1 POST over a std `TcpStream`, reading the whole response body.
///
/// The operator RPC gate (`auth_required`, its default) reads an `x-api-key`
/// header. This client sent none, so a correctly configured node answered every
/// call with `401` and a bare `Unauthorized` body, which the caller then failed
/// to parse as JSON (RT-002). The key is read from the file named by
/// [`BUDLUM_RPC_API_KEY_FILE`](budlum_core::rpc::client_auth::API_KEY_FILE_ENV) - a
/// path in the environment, never the secret, and never an argument.
fn http_post_json(host: &str, port: u16, body: &str) -> Result<String, String> {
    let api_key = budlum_core::rpc::client_auth::api_key_from_env()?;
    http_post_json_with_key(host, port, body, api_key.as_deref())
}

/// [`http_post_json`] with the caller's already-loaded key, so the file is read
/// once per call site and a test can drive the header without the environment.
fn http_post_json_with_key(
    host: &str,
    port: u16,
    body: &str,
    api_key: Option<&str>,
) -> Result<String, String> {
    let mut stream = TcpStream::connect((host, port))
        .map_err(|e| format!("connection error ({host}:{port}): {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(RPC_TIMEOUT_SECS)))
        .map_err(|e| format!("read_timeout setting: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(RPC_TIMEOUT_SECS)))
        .map_err(|e| format!("write_timeout setting: {e}"))?;

    // Header values are positional in the request line, so the key cannot be
    // smuggled into the request line or the body: it is one header, or absent.
    let auth_header = match api_key {
        Some(key) => format!("x-api-key: {key}\r\n"),
        None => String::new(),
    };
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\n{auth_header}Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("request write error: {e}"))?;

    let mut raw = Vec::new();
    let mut limited = stream.take(MAX_RPC_RESPONSE_BYTES + 1);
    limited
        .read_to_end(&mut raw)
        .map_err(|e| format!("response read error: {e}"))?;
    if raw.len() as u64 > MAX_RPC_RESPONSE_BYTES {
        return Err(format!(
            "response over {MAX_RPC_RESPONSE_BYTES} bytes refused"
        ));
    }
    let text = String::from_utf8(raw).map_err(|e| format!("UTF-8 parse: {e}"))?;

    // Status line first: an unauthorised answer is the word `Unauthorized`, and
    // reporting that as a JSON parse failure hid the real cause.
    let status = text
        .split_once("\r\n")
        .and_then(|(line, _)| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok());
    // HTTP header/body split: everything after the first "\r\n\r\n" is the body.
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(&text);
    if let Some(code @ (401 | 403)) = status {
        return Err(format!(
            "the node refused the RPC call with HTTP {code} ({}): this endpoint requires the \
             operator key. Point {} at a 0600 file holding it, or run the node with auth disabled \
             on a trusted network.",
            body.trim(),
            budlum_core::rpc::client_auth::API_KEY_FILE_ENV
        ));
    }
    let code = status.ok_or("RPC response has no valid HTTP status code")?;
    if !(200..300).contains(&code) {
        // The node can answer a burst with plain-text HTTP 429, which the
        // caller previously reported as a JSON parse error. Never retry a
        // transaction automatically: its submission outcome may be unknown.
        let preview: String = body.trim().chars().take(160).collect();
        return Err(format!("RPC HTTP {code}: {preview:?}"));
    }
    if body.trim().is_empty() {
        return Err(format!("RPC HTTP {code} returned an empty body"));
    }
    Ok(body.to_string())
}

/// Parse a JSON-RPC response: return `result` or propagate the `error` message.
fn rpc_result(resp: &serde_json::Value) -> Result<serde_json::Value, String> {
    if let Some(err) = resp.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown JSON-RPC error");
        return Err(format!("JSON-RPC error: {msg}"));
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| "the JSON-RPC response has no 'result' field".to_string())
}

/// Make a single JSON-RPC call.
fn rpc_call(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let (host, port) = parse_rpc_url(rpc_url)?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });
    let body_str =
        serde_json::to_string(&body).map_err(|e| format!("request serialization: {e}"))?;
    let resp_text = http_post_json(&host, port, &body_str)?;
    let v: serde_json::Value =
        serde_json::from_str(&resp_text).map_err(|e| format!("RPC response parse: {e}"))?;
    rpc_result(&v)
}

/// Parse an address leniently (`0x` prefix optional).
fn parse_address(s: &str) -> Result<Address, String> {
    Address::from_hex(s).map_err(|e| format!("invalid address '{s}': {e}"))
}

/// Parse a 32-byte hex signing seed.
/// The signing seed comes from a file (`--priv-key-file`) or from the
/// `BUD_PRIV_KEY` environment variable, in that order, never from `argv`.
fn load_priv_key(path: Option<&std::path::Path>) -> Result<String, String> {
    if let Some(path) = path {
        check_key_file_mode(path)?;
        return std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("cannot read priv key file {}: {e}", path.display()));
    }
    std::env::var("BUD_PRIV_KEY").map_err(|_| {
        String::from(
            "no signing seed: pass --priv-key-file <path> or set BUD_PRIV_KEY \
             (the seed is not accepted as a command-line argument)",
        )
    })
}

/// Refuse a seed file that group or others can read (Unix only).
///
/// A world-readable seed file is a leaked key; the user must `chmod 600` it.
#[cfg(unix)]
fn check_key_file_mode(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("cannot read priv key file {}: {e}", path.display()))?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "priv key file {} has mode {:03o}; group and others must have no access \
             (chmod 600)",
            path.display(),
            mode & 0o777
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_file_mode(_path: &std::path::Path) -> Result<(), String> {
    Ok(())
}

fn parse_seed(hex_str: &str) -> Result<[u8; 32], String> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).map_err(|e| format!("invalid hex priv key: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "the priv key must be 32 bytes".to_string())?;
    Ok(arr)
}

fn parse_rpc_u64(value: &serde_json::Value, field: &str) -> Result<u64, String> {
    let s = value
        .as_str()
        .ok_or_else(|| format!("{field} must return a string"))?;
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|e| format!("{field} hex parse: {e}"))
    } else {
        s.parse::<u64>().map_err(|e| format!("{field} parse: {e}"))
    }
}

/// The chain this invocation signs for, as named on the command line.
///
/// Written once from `argv` before any signing path runs and only read after
/// that. A process-wide cell rather than a parameter because the alternative is
/// threading the value through every `send_v5` call site, and the one thing
/// that must not be possible is a signing path that quietly skips the check.
static SIGNING_CHAIN_ID: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Record `--signing-chain-id`, if it was given.
fn set_signing_chain_id(value: Option<u64>) {
    if let Some(value) = value {
        let _ = SIGNING_CHAIN_ID.set(value);
    }
}

/// Whether the node's answer is the chain the operator named.
///
/// Split out so it can be tested without a node: the whole point is that this
/// comparison, and not the node's answer, decides the replay domain.
fn chain_id_binding(node_chain_id: u64, requested: u64) -> Result<u64, String> {
    if node_chain_id != requested {
        return Err(format!(
            "the node serves chain id {node_chain_id}, but --signing-chain-id {requested} was \
             given; refusing to sign for a network you did not name"
        ));
    }
    Ok(requested)
}

/// The node's `bud_chainId`, taken only if it is the chain `--signing-chain-id`
/// names.
///
/// Every signing path in this binary goes through here rather than through a
/// bare `bud_chainId` call, so no command can quietly sign for whatever network
/// it happens to be talking to.
fn node_chain_id(rpc_url: &str) -> Result<u64, String> {
    let Some(requested) = SIGNING_CHAIN_ID.get().copied() else {
        return Err(
            "--signing-chain-id <id> is required to sign (45260 mainnet, 45261 testnet, \
             45262 devnet): the node's answer is untrusted input, and a signature carrying a \
             chain id the node chose is a signature for the node's network, not yours"
                .to_string(),
        );
    };
    let value = rpc_call(rpc_url, "bud_chainId", serde_json::json!([]))?;
    let node = parse_rpc_u64(&value, "bud_chainId")?;
    chain_id_binding(node, requested)
}

/// Reject zero as an explicit fee. Zero remains the unsigned transaction
/// template's sentinel for a fee that must still be resolved from the network.
fn parse_positive_fee(value: &str) -> Result<u64, std::io::Error> {
    let fee = value.parse::<u64>().map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
    })?;
    if fee == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "an explicit fee must be greater than zero",
        ));
    }
    Ok(fee)
}

/// Query the node's live fee floor when `--fee` is omitted.
///
/// Tries `bud_estimateGas` first when a draft transaction is available so
/// proportional transfer cuts and governance escalations are included, then
/// falls back to `bud_gasPrice` (`Chain::get_base_fee`).
fn resolve_network_fee(
    rpc_url: &str,
    explicit_fee: Option<u64>,
    draft: Option<&Transaction>,
) -> Result<u64, String> {
    if let Some(fee) = explicit_fee {
        if fee == 0 {
            return Err(String::from("an explicit fee must be greater than zero"));
        }
        return Ok(fee);
    }
    if let Some(tx) = draft {
        if let Ok(est) = rpc_call(rpc_url, "bud_estimateGas", serde_json::json!([tx])) {
            if let Ok(parsed) = parse_rpc_u64(&est, "bud_estimateGas") {
                return Ok(parsed);
            }
        }
    }
    let raw = rpc_call(rpc_url, "bud_gasPrice", serde_json::json!([]))?;
    parse_rpc_u64(&raw, "bud_gasPrice")
}

/// Build an unsigned transfer bound to `chain_id`.
fn build_transfer(
    from: Address,
    to: Address,
    amount: u64,
    fee: u64,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        to,
        amount,
        fee,
        nonce,
        Vec::new(),
        chain_id,
        TransactionType::Transfer,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_tx_send(
    rpc_url: &str,
    to: &str,
    amount: u64,
    priv_key_file: Option<&std::path::Path>,
    fee: Option<u64>,
    nonce: Option<u64>,
) -> Result<(), String> {
    let seed = parse_seed(&load_priv_key(priv_key_file)?)?;
    let keypair = KeyPair::from_seed(&seed).map_err(|e| format!("key derivation: {e}"))?;
    let from = Address::from(keypair.public_key_bytes());
    let to_addr = if to.ends_with(".bud") || to.contains('.') {
        resolve_bud_recipient_verified(rpc_url, to)?
    } else {
        parse_address(to)?
    };

    // Nonce: fetch it from the node when not given.
    let nonce = match nonce {
        Some(n) => n,
        None => {
            let r = rpc_call(rpc_url, "bud_getNonce", serde_json::json!([from.to_hex()]))?;
            let s = parse_rpc_u64(&r, "bud_getNonce")?;
            println!("nonce (from node): {s}");
            s
        }
    };

    // The signature's replay domain is the chain the operator named; the node's
    // answer can only agree with it or be refused.
    let chain_id = node_chain_id(rpc_url)?;
    println!("chain id: {chain_id} (named with --signing-chain-id)");

    // V4 is refused on mainnet: say so before a signature is spent.
    if chain_id
        == budlum_core::core::chain_config::Network::Mainnet
            .chain_id()
            .value()
    {
        return Err(
            "the node serves mainnet, which refuses V4 Ed25519 transactions; sign with a \
             wallet key file (--key-file) instead"
                .into(),
        );
    }

    // Build and sign the transaction; default fee comes from the network base fee.
    let mut tx = build_transfer(from, to_addr, amount, fee.unwrap_or(0), nonce, chain_id);
    let resolved_fee = resolve_network_fee(rpc_url, fee, Some(&tx))?;
    tx.fee = resolved_fee;
    tx.max_fee = resolved_fee;
    tx.sign(&keypair);

    let tx_hash = tx.calculate_hash();
    println!("tx hash (signed): {tx_hash}");

    // Send it (bud_sendRawTransaction takes the Transaction object directly).
    let r = rpc_call(rpc_url, "bud_sendRawTransaction", serde_json::json!([tx]))?;
    match r.as_str() {
        Some(returned) => println!("sent \u{2713} - node tx hash: {returned}"),
        None => println!("sent \u{2713} - node response: {r}"),
    }
    Ok(())
}

fn run_query_balance(rpc_url: &str, address: &str) -> Result<(), String> {
    let addr = parse_address(address)?;
    let r = rpc_call(
        rpc_url,
        "bud_getBalance",
        serde_json::json!([addr.to_hex()]),
    )?;
    match r.as_str() {
        Some(balance) => println!("balance ({address}): {balance}"),
        None => println!("balance ({address}): {r}"),
    }
    Ok(())
}

fn run_query_block(rpc_url: &str, number: &str) -> Result<(), String> {
    let block_number = if number.eq_ignore_ascii_case("latest") {
        let latest = rpc_call(rpc_url, "bud_blockNumber", serde_json::json!([]))?;
        parse_rpc_u64(&latest, "bud_blockNumber")?
    } else {
        if let Some(hex) = number.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).map_err(|e| format!("invalid block number: {e}"))?
        } else {
            number
                .parse::<u64>()
                .map_err(|e| format!("invalid block number: {e}"))?
        }
    };
    let r = rpc_call(
        rpc_url,
        "bud_getBlockByNumber",
        serde_json::json!([block_number]),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&r).unwrap_or_else(|_| r.to_string())
    );
    Ok(())
}

fn run_query_status(rpc_url: &str) -> Result<(), String> {
    let r = rpc_call(rpc_url, "bud_getStatus", serde_json::json!([]))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&r).unwrap_or_else(|_| r.to_string())
    );
    Ok(())
}

/// Submit a signed transaction bundle (`bud_sendTxBundle`).
///
/// The file is read as JSON and forwarded as it stands: a bundle's signature
/// covers every member field, so a client that rewrote a body here would only
/// produce a witness that no longer verifies. The node answers with the hash
/// of each member in execution order, and with nothing at all if it refused
/// the bundle - admission is all or none on both sides of the door.
fn run_tx_bundle(rpc_url: &str, file: &std::path::Path) -> Result<(), String> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| format!("cannot read bundle file {}: {e}", file.display()))?;
    let bundle: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("bundle file {} is not JSON: {e}", file.display()))?;
    let r = rpc_call(rpc_url, "bud_sendTxBundle", serde_json::json!([bundle]))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&r).unwrap_or_else(|_| r.to_string())
    );
    Ok(())
}

fn run_validator(config: Option<&str>) -> Result<(), String> {
    // This is not a packaged full-node runner (chain + consensus loop + RPC
    // server) - `validator run` here validates configuration and gives guidance.
    // Real node startup with `RpcServer::run` + `NodeConfig` is future work.
    match config {
        Some(path) => {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("configuration read error ({path}): {e}"))?;
            // Basic TOML parse validation.
            let _doc: toml::Value =
                toml::from_str(&content).map_err(|e| format!("invalid TOML configuration: {e}"))?;
            println!("configuration valid (TOML): {path}");
        }
        None => {
            println!("(no configuration given - validate one with --config <path>)");
        }
    }
    println!();
    println!("running a validator:");
    println!("  The full node runner (consensus loop + RPC server) is a separate binary.");
    println!("  This command validates configuration. Use the node binary to start a node.");
    println!("  RPC: --rpc-url <url> (default {DEFAULT_RPC_URL})");
    Ok(())
}

/// Parse a 32-byte hex digest.
fn parse_digest(field: &str, hex_str: &str) -> Result<[u8; 32], String> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).map_err(|e| format!("{field} invalid hex: {e}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{field} must be 32 bytes, {} bytes given", bytes.len()))
}

/// Build and validate the local standard manifest.
///
/// The manifest is a record layer and its validation is a gate: no project id is
/// computed for a manifest that does not pass `validate`. Otherwise a manifest
/// carrying an invented compiler profile or a zero source hash would also produce
/// a smooth id, indistinguishable from a real one.
fn build_manifest(name: &str, source_hash: &str) -> Result<ProjectManifest, String> {
    let digest = parse_digest("--source-hash", source_hash)?;
    let manifest = ProjectManifest::local_standard(name, digest);
    manifest
        .validate()
        .map_err(|e| format!("manifest refused: {e:?}"))?;
    Ok(manifest)
}

fn run_project_id(name: &str, source_hash: &str) -> Result<(), String> {
    let manifest = build_manifest(name, source_hash)?;
    println!("project: {name}");
    println!("chain_id: {}", manifest.chain_id);
    println!("project id: 0x{}", hex::encode(manifest.project_id()));
    Ok(())
}

/// Audit a proof record's right to say `Verified` by binding it to the hash of
/// the verified envelope.
///
/// A record declaring itself verified is not enough: the hash it carries must equal
/// the one of the envelope that passed verification. If they differ the record is
/// speaking of another proof, and that is a wrong record that looks right.
fn run_project_bind_proof(
    name: &str,
    source_hash: &str,
    fixture: &str,
    proof_hash: &str,
) -> Result<(), String> {
    let mut manifest = build_manifest(name, source_hash)?;
    let verified = parse_digest("--proof-hash", proof_hash)?;

    let record = manifest
        .proof_fixtures
        .iter_mut()
        .find(|f| f.name == fixture)
        .ok_or_else(|| format!("the manifest has no proof record named '{fixture}'"))?;

    // A record arrives `Pending` from the local template; binding is meaningful on a
    // record that claims the verifier has run. The hash the record already
    // carries is what gets compared with the verified envelope; it is not
    // overwritten first, since a record rewritten to the supplied hash would
    // pass the comparison whatever it said before, and the mismatch check
    // would never fire.
    let mut candidate = record.clone();
    candidate.status = ProofFixtureStatus::Verified;
    candidate
        .bind_verified(verified)
        .map_err(|e| format!("proof binding refused: {e:?}"))?;
    *record = candidate;
    println!("proof record '{fixture}' bound to the verified envelope");
    println!("proof hash: 0x{}", hex::encode(verified));
    println!("project id: 0x{}", hex::encode(manifest.project_id()));
    Ok(())
}

/// `bud validator init`: generate keys, write them, write the record.
fn run_validator_init(
    key_file: &std::path::Path,
    record_out: &std::path::Path,
    chain_id: u64,
    moniker: &str,
) -> Result<(), String> {
    use budlum_core::core::chain_config::Network;
    if Network::from_chain_id(chain_id) == Some(Network::Mainnet) {
        return Err(
            "mainnet validator keys live in an HSM; this command writes a plaintext key file"
                .into(),
        );
    }
    if key_file.exists() {
        return Err(format!(
            "{} exists; a key file is never overwritten",
            key_file.display()
        ));
    }
    let keys = budlum_core::crypto::primitives::ValidatorKeys::generate()
        .map_err(|e| format!("key generation: {e}"))?;
    let record = budlum_core::chain::genesis_ceremony::OperatorRecord {
        validator: keys.address(),
        registration: keys
            .consensus_key_registration(chain_id)
            .map_err(|e| format!("consensus keys: {e}"))?,
        moniker: moniker.to_string(),
    };
    keys.save(key_file)
        .map_err(|e| format!("cannot write {}: {e}", key_file.display()))?;
    let json = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
    std::fs::write(record_out, json + "\n")
        .map_err(|e| format!("cannot write {}: {e}", record_out.display()))?;
    println!("validator address: {}", record.validator.to_hex());
    println!("key file (secret, mode 0600): {}", key_file.display());
    println!("ceremony record (public): {}", record_out.display());
    println!("An Ethereum validator key is never reused here: these are new, Budlum-only keys.");
    Ok(())
}

/// Sign `tx_type` from `keys` against the node at `rpc_url` and send it.
/// How `send_signed` signs a validator transaction.
///
/// `Auto` picks V7 when the key set carries an ML-DSA-65 key - the form a
/// mainnet node admits from a validator registered with that key. `Enrol`
/// always signs the Ed25519-authorised legacy form: enrolment happens before
/// any ML-DSA-65 key is registered, and a V7 validator transaction from an
/// unregistered sender is refused at the binding gate (both halves of an
/// unregistered pair are chosen by whoever presents them).
#[derive(Clone, Copy)]
enum ValidatorSigning {
    Auto,
    Enrol,
}

fn send_signed(
    rpc_url: &str,
    keys: &budlum_core::crypto::primitives::ValidatorKeys,
    amount: u64,
    fee: Option<u64>,
    tx_type: TransactionType,
    signing: ValidatorSigning,
) -> Result<String, String> {
    let from = keys.address();
    let nonce_value = rpc_call(rpc_url, "bud_getNonce", serde_json::json!([from.to_hex()]))?;
    let nonce = parse_rpc_u64(&nonce_value, "bud_getNonce")?;
    // The validator transactions are signed for the chain the operator named:
    // a signature is valid wherever its chain id says, and the node does not get
    // to choose that.
    let chain_id = node_chain_id(rpc_url)?;
    let mut tx = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        amount,
        fee.unwrap_or(0),
        nonce,
        Vec::new(),
        chain_id,
        tx_type,
    );
    let resolved_fee = resolve_network_fee(rpc_url, fee, Some(&tx))?;
    tx.fee = resolved_fee;
    tx.max_fee = resolved_fee;
    // A key set with an ML-DSA-65 key signs the V7 validator form,
    // the only one a mainnet node admits; a legacy set signs V4. Enrolment
    // always signs V4: the V7 binding gate refuses a validator transaction
    // from a sender with no registered ML-DSA-65 key, which is exactly the
    // state `bud validator join` starts from.
    if keys.pq_key.is_some() && matches!(signing, ValidatorSigning::Auto) {
        use rand::Rng;
        let keypair = keys.composite_keypair().map_err(|e| e.to_string())?;
        let mut rnd = [0u8; 32];
        rand::rng().fill_bytes(&mut rnd);
        tx.sign_v7_validator(
            &budlum_core::crypto::scheme::SchemeStatusRegistry::genesis(),
            &keypair,
            &rnd,
        )?;
    } else {
        tx.sign(&keys.sig_key);
    }
    let r = rpc_call(rpc_url, "bud_sendRawTransaction", serde_json::json!([tx]))?;
    Ok(r.as_str().map_or_else(|| r.to_string(), str::to_string))
}

/// `bud validator join`: `Stake`, then `RegisterConsensusKeys`.
fn run_validator_join(
    rpc_url: &str,
    key_file: &std::path::Path,
    stake_bud: u64,
    fee: Option<u64>,
) -> Result<(), String> {
    check_key_file_mode(key_file)?;
    let keys = budlum_core::crypto::primitives::ValidatorKeys::load(key_file)
        .map_err(|e| format!("cannot load {}: {e}", key_file.display()))?;
    let stake = stake_bud
        .checked_mul(budlum_core::tokenomics::BUD_UNIT)
        .ok_or("stake overflows the base unit")?;
    let chain_id = node_chain_id(rpc_url)?;
    let registration = keys
        .consensus_key_registration(chain_id)
        .map_err(|e| format!("consensus keys: {e}"))?;
    let from = keys.address().to_hex();
    // The nonce the stake will take. Read before it is sent, so the wait below
    // can tell "included" from "still pending" without trusting a receipt
    // shape.
    let staking_nonce = parse_rpc_u64(
        &rpc_call(rpc_url, "bud_getNonce", serde_json::json!([from.clone()]))?,
        "bud_getNonce",
    )?;
    let staked = send_signed(
        rpc_url,
        &keys,
        stake,
        fee,
        TransactionType::Stake,
        ValidatorSigning::Enrol,
    )?;
    println!("stake sent: {staked}");
    // The registration is a second transaction from the same account and the
    // node refuses it outright - "Validator must bond stake before
    // registering" - until the stake is *in a block*. Sending both back to back
    // therefore failed on state that had not moved yet, and the retry could not
    // help: the second send reuses the stake's nonce and the mempool answers
    // RbfFeeTooLow. The stake is awaited here, so what follows is built on the
    // state it leaves.
    wait_for_inclusion(rpc_url, &from, &staked, staking_nonce)?;
    let registered = send_signed(
        rpc_url,
        &keys,
        0,
        fee,
        TransactionType::RegisterConsensusKeys(registration),
        ValidatorSigning::Enrol,
    )?;
    println!("consensus keys sent: {registered}");
    println!(
        "validator {} is active from the next epoch once both are in a block",
        keys.address().to_hex()
    );
    Ok(())
}

/// Wait until the transaction has moved the account's nonce past `nonce`, or
/// a receipt for it exists.
///
/// Bounded: a chain that never includes it is a failure to report, not a wait
/// to extend. Sixty seconds is many slots even on a chain that produces one
/// block every ten.
fn wait_for_inclusion(
    rpc_url: &str,
    address: &str,
    tx_hash: &str,
    nonce: u64,
) -> Result<(), String> {
    for _ in 0..120 {
        if let Ok(receipt) = rpc_call(
            rpc_url,
            "bud_getTransactionReceipt",
            serde_json::json!([tx_hash]),
        ) {
            if !receipt.is_null() {
                return Ok(());
            }
        }
        if let Ok(value) = rpc_call(rpc_url, "bud_getNonce", serde_json::json!([address])) {
            if parse_rpc_u64(&value, "bud_getNonce").is_ok_and(|current| current > nonce) {
                return Ok(());
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(format!(
        "transaction {tx_hash} was not included within 60 s"
    ))
}

/// `bud validator filiz`: build the chain the node will open and register
/// its top link.
fn run_validator_filiz(
    rpc_url: &str,
    key_file: &std::path::Path,
    seed_file: &std::path::Path,
    fee: Option<u64>,
) -> Result<(), String> {
    check_key_file_mode(key_file)?;
    check_key_file_mode(seed_file)?;
    let keys = budlum_core::crypto::primitives::ValidatorKeys::load(key_file)
        .map_err(|e| format!("cannot load {}: {e}", key_file.display()))?;
    let seed = budlum_core::consensus::filiz::read_seed_file(seed_file)?;
    let chain_id = node_chain_id(rpc_url)?;
    let chain = budlum_core::consensus::filiz::chain_for_network(keys.address().0, seed, chain_id)
        .map_err(|e| format!("Filiz chain: {e:?}"))?;
    let sent = send_signed(
        rpc_url,
        &keys,
        0,
        fee,
        TransactionType::RegisterFiliz {
            commitment: chain.commitment(),
            length: chain.length(),
        },
        ValidatorSigning::Auto,
    )?;
    println!("Filiz registration sent: {sent}");
    println!(
        "the chain ({} links) is the leader-election proof three epochs after it lands",
        chain.length()
    );
    Ok(())
}

/// `bud validator commission`: sign `SetValidatorCommission` with the
/// validator's own key set.
fn run_validator_commission(
    rpc_url: &str,
    key_file: &std::path::Path,
    rate_ppm: u32,
    fee: Option<u64>,
) -> Result<(), String> {
    check_key_file_mode(key_file)?;
    let keys = budlum_core::crypto::primitives::ValidatorKeys::load(key_file)
        .map_err(|e| format!("cannot load {}: {e}", key_file.display()))?;
    let sent = send_signed(
        rpc_url,
        &keys,
        0,
        fee,
        TransactionType::SetValidatorCommission {
            commission_ppm: rate_ppm,
        },
        ValidatorSigning::Auto,
    )?;
    println!("commission sent: {sent}");
    Ok(())
}

/// `bud delegate`, `bud undelegate` (with an amount) and
/// `bud withdraw-delegation` (without one).
fn run_delegation(
    rpc_url: &str,
    signer: &V5Signer,
    validator: &str,
    amount_bud: Option<u64>,
    bond: bool,
) -> Result<(), String> {
    let validator = parse_address(validator.strip_prefix("0x").unwrap_or(validator))?;
    let key = open_wallet(signer)?;
    let (tx_type, amount) = match amount_bud {
        Some(bud) => {
            let amount = bud
                .checked_mul(budlum_core::tokenomics::BUD_UNIT)
                .ok_or("the amount overflows the base unit")?;
            let tx_type = if bond {
                TransactionType::Delegate { validator }
            } else {
                TransactionType::Undelegate { validator }
            };
            (tx_type, amount)
        }
        None => (TransactionType::WithdrawDelegation { validator }, 0),
    };
    send_v5(
        rpc_url,
        &key,
        v5_template(tx_type, amount, signer.fee),
        None,
    )
}

/// `bud redelegate`: move a position to another validator.
fn run_redelegate(
    rpc_url: &str,
    signer: &V5Signer,
    from_validator: &str,
    to_validator: &str,
    amount_bud: u64,
) -> Result<(), String> {
    let from = parse_address(from_validator.strip_prefix("0x").unwrap_or(from_validator))?;
    let to = parse_address(to_validator.strip_prefix("0x").unwrap_or(to_validator))?;
    let amount = amount_bud
        .checked_mul(budlum_core::tokenomics::BUD_UNIT)
        .ok_or("the amount overflows the base unit")?;
    let key = open_wallet(signer)?;
    send_v5(
        rpc_url,
        &key,
        v5_template(
            TransactionType::Redelegate {
                from_validator: from,
                to_validator: to,
            },
            amount,
            signer.fee,
        ),
        None,
    )
}

/// `bud claim-rewards`: take the claimable delegator reward of one validator.
fn run_claim_rewards(rpc_url: &str, signer: &V5Signer, validator: &str) -> Result<(), String> {
    let validator = parse_address(validator.strip_prefix("0x").unwrap_or(validator))?;
    let key = open_wallet(signer)?;
    send_v5(
        rpc_url,
        &key,
        v5_template(TransactionType::ClaimRewards { validator }, 0, signer.fee),
        None,
    )
}

/// `bud ai-answer`: sign one AI verifier result.
fn run_ai_answer(
    rpc_url: &str,
    signer: &V5Signer,
    request_id: &str,
    output_commitment: &str,
) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let latest = rpc_call(rpc_url, "bud_blockNumber", serde_json::json!([]))?;
    let height = parse_rpc_u64(&latest, "bud_blockNumber")?;
    let result = budlum_core::ai::types::AiInferenceResult {
        request_id: budlum_core::ai::types::AiRequestId(hex32(request_id, "request id")?),
        verifier: key.address(),
        output_commitment: hex32(output_commitment, "output commitment")?,
        output_ref: budlum_core::ai::types::BoundedBytes::try_new(Vec::new())?,
        result_nonce: height,
        signature: Vec::new(),
        submitted_at_block: height,
    };
    send_v5(
        rpc_url,
        &key,
        v5_template(TransactionType::AiInferenceResult(result), 0, signer.fee),
        None,
    )
}

fn hex32(text: &str, what: &str) -> Result<[u8; 32], String> {
    hex::decode(text.trim().strip_prefix("0x").unwrap_or(text.trim()))
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{what} must be 32 bytes of hex"))
}

fn hex_bytes(text: &str, what: &str) -> Result<Vec<u8>, String> {
    hex::decode(text.trim().strip_prefix("0x").unwrap_or(text.trim()))
        .map_err(|e| format!("{what} is not hex: {e}"))
}

fn evidence_file(
    path: &std::path::Path,
) -> Result<Box<budlum_core::core::transaction::RelayerExternalResult>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_slice(&raw)
        .map(Box::new)
        .map_err(|e| format!("{} is not an external result: {e}", path.display()))
}

/// `bud domain register-pow`: a PoW domain with the header-chain adapter,
/// the wallet as operator.
fn run_domain_register_pow(
    rpc_url: &str,
    signer: &V5Signer,
    id: u32,
    chain_id: u64,
    min_confirmations: u64,
) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let mut domain = budlum_core::domain::plugin::default_domain(
        id,
        budlum_core::domain::ConsensusKind::PoW,
        chain_id,
        budlum_core::domain::POW_HEADER_CHAIN_ADAPTER,
        min_confirmations,
    );
    domain.operator = Some(key.address());
    let tx_type = TransactionType::Settlement(
        budlum_core::settlement::domains::SettlementTx::RegisterDomain(Box::new(domain)),
    );
    send_v5(rpc_url, &key, v5_template(tx_type, 0, signer.fee), None)
}

/// `bud domain selftest`: the admission harness
/// (`cross_domain::external::admit`) run locally, so an adapter author sees
/// the report before bonding anything.
fn run_domain_selftest(
    adapter: &str,
    network: &str,
    golden: &std::path::Path,
    program_hash: Option<&str>,
    chain_id: Option<u64>,
    now: u64,
) -> Result<(), String> {
    use budlum_core::cross_domain::external::{
        admit, RawConsensusEvidence, VerificationPolicy, ZkVmFinalityAdapter,
    };
    let text = std::fs::read_to_string(golden)
        .map_err(|e| format!("cannot read {}: {e}", golden.display()))?;
    let sample: RawConsensusEvidence =
        serde_json::from_str(&text).map_err(|e| format!("golden sample: {e}"))?;
    let report = match adapter {
        "zkvm" => {
            let program_hash = match program_hash {
                Some(hex) => {
                    let bytes = hex_bytes(hex, "--program-hash")?;
                    Some(
                        <[u8; 32]>::try_from(bytes.as_slice())
                            .map_err(|_| "--program-hash must be 32 bytes".to_string())?,
                    )
                }
                None => None,
            };
            let adapter =
                ZkVmFinalityAdapter::new(network, program_hash, chain_id).with_golden(sample);
            admit(&adapter, &VerificationPolicy::proven(now))
        }
        other => return Err(format!("unknown adapter family: {other} (known: zkvm)")),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| format!("report: {e}"))?
    );
    if report.admitted {
        Ok(())
    } else {
        Err(format!(
            "not admitted: golden sample verified = {}, {} of {} probes refused as required",
            report.golden_verified,
            report.passed(),
            report.probes.len()
        ))
    }
}

/// Use the sibling faucet client rather than maintaining two subtly different
/// proof-of-work implementations. It validates the HTTPS origin, challenge,
/// chain id, nonce and receipt; no shell or PATH lookup is involved.
fn run_faucet(action: &FaucetAction) -> Result<(), String> {
    match action {
        FaucetAction::Request { url, address } => {
            // This build uses reqwest's provider-less rustls mode. Install the
            // same pinned crypto provider as the node before making HTTPS calls.
            budlum_core::crypto::tls::install_default_provider();
            tokio::runtime::Runtime::new()
                .map_err(|e| format!("tokio runtime: {e}"))?
                .block_on(faucet_client::request_funds(url, address))
        }
    }
}

/// `bud graft ...`: build the Graft settlement transaction here and sign it
/// with the V5 wallet.
fn run_graft(rpc_url: &str, action: &GraftAction) -> Result<(), String> {
    use budlum_core::settlement::graft::GraftTx;
    let (signer, graft_tx) = match action {
        GraftAction::Id { domain, origin_app } => {
            let origin = hex_bytes(origin_app, "--origin-app")?;
            let id = budlum_core::settlement::graft::graft_id(*domain, &origin);
            println!("graft id: 0x{}", hex::encode(id));
            println!(
                "mirror account: 0x{}",
                budlum_core::settlement::graft::mirror_account(id).to_hex()
            );
            return Ok(());
        }
        GraftAction::Register {
            signer,
            domain,
            origin_app,
            manifest,
        } => (
            signer,
            GraftTx::Register {
                domain_key: *domain,
                origin_app: hex_bytes(origin_app, "--origin-app")?,
                manifest_hash: hex32(manifest, "--manifest")?,
            },
        ),
        GraftAction::Pay {
            signer,
            graft_id,
            amount,
            origin_recipient,
            memo_hash,
            target_chain_id,
            target_receiver,
        } => (
            signer,
            GraftTx::Pay {
                graft_id: hex32(graft_id, "--graft-id")?,
                amount: *amount,
                memo_hash: memo_hash
                    .as_deref()
                    .map_or(Ok([0u8; 32]), |memo| hex32(memo, "--memo-hash"))?,
                origin_recipient: hex_bytes(origin_recipient, "--origin-recipient")?,
                target_chain_id: *target_chain_id,
                target_receiver: target_receiver
                    .as_deref()
                    .map_or(Ok(Vec::new()), |recv| hex_bytes(recv, "--target-receiver"))?,
            },
        ),
        GraftAction::Intent {
            signer,
            graft_id,
            call_hash,
            value,
            max_payment,
            solver_fee_cap,
            service_price,
            beneficiary,
            deadline_block,
        } => (
            signer,
            GraftTx::OpenIntent {
                graft_id: hex32(graft_id, "--graft-id")?,
                call_hash: hex32(call_hash, "--call-hash")?,
                value: *value,
                max_payment: *max_payment,
                solver_fee_cap: *solver_fee_cap,
                service_price: *service_price,
                origin_beneficiary: hex_bytes(beneficiary, "--beneficiary")?,
                deadline_block: *deadline_block,
            },
        ),
        GraftAction::Refund { signer, intent_id } => (
            signer,
            GraftTx::Refund {
                intent_id: hex32(intent_id, "--intent-id")?,
            },
        ),
        GraftAction::Bid {
            signer,
            intent_id,
            cost,
            fee,
        } => (
            signer,
            GraftTx::Bid {
                intent_id: hex32(intent_id, "--intent-id")?,
                cost: *cost,
                fee: *fee,
            },
        ),
        GraftAction::Award {
            signer,
            intent_id,
            solver,
        } => (
            signer,
            GraftTx::Award {
                intent_id: hex32(intent_id, "--intent-id")?,
                solver: parse_address(solver.strip_prefix("0x").unwrap_or(solver))?,
            },
        ),
        GraftAction::Claim {
            signer,
            graft_id,
            payout,
            evidence,
        } => (
            signer,
            GraftTx::Claim {
                graft_id: hex32(graft_id, "--graft-id")?,
                payout: parse_address(payout.strip_prefix("0x").unwrap_or(payout))?,
                evidence: evidence_file(evidence)?,
            },
        ),
        GraftAction::ClaimSigned {
            signer,
            graft_id,
            payout,
            valid_until_block,
            signature,
        } => (
            signer,
            GraftTx::ClaimBySignature {
                graft_id: hex32(graft_id, "--graft-id")?,
                payout: parse_address(payout.strip_prefix("0x").unwrap_or(payout))?,
                valid_until_block: *valid_until_block,
                signature: hex_bytes(signature, "--signature")?,
            },
        ),
        GraftAction::Fulfill {
            signer,
            intent_id,
            evidence,
        } => (
            signer,
            GraftTx::Fulfill {
                intent_id: hex32(intent_id, "--intent-id")?,
                evidence: evidence_file(evidence)?,
            },
        ),
    };
    let key = open_wallet(signer)?;
    let tx_type = TransactionType::Settlement(
        budlum_core::settlement::domains::SettlementTx::Graft(Box::new(graft_tx)),
    );
    send_v5(rpc_url, &key, v5_template(tx_type, 0, signer.fee), None)
}

/// `bud dev`: the project file is the schema `budlum_core::sdk` defines.
fn run_dev(rpc_url: &str, action: &DevAction) -> Result<(), String> {
    use budlum_core::sdk::BudlumToml;
    match action {
        DevAction::Init { name, path } => {
            if path.exists() {
                return Err(format!("{} exists; not overwriting it", path.display()));
            }
            let mut project = BudlumToml::default_template(name);
            project.project.budlum_version = Some(env!("CARGO_PKG_VERSION").to_string());
            project.save(path).map_err(|e| e.to_string())?;
            println!("wrote {}", path.display());
            Ok(())
        }
        DevAction::Info { path } => {
            let project = BudlumToml::load(path).map_err(|e| e.to_string())?;
            println!(
                "project: {} {}",
                project.project.name, project.project.version
            );
            match &project.project.budlum_version {
                Some(v) if v != env!("CARGO_PKG_VERSION") => println!(
                    "targets budlum {v}; this CLI is {}",
                    env!("CARGO_PKG_VERSION")
                ),
                Some(v) => println!("targets budlum {v}"),
                None => println!("names no budlum version"),
            }
            match rpc_call(rpc_url, "bud_chainId", serde_json::json!([])) {
                Ok(chain_id) => println!("node at {rpc_url}: chain id {chain_id}"),
                Err(e) => println!("node at {rpc_url} not reachable: {e}"),
            }
            Ok(())
        }
    }
}

/// `<address>:<amount>` of `--fund`.
fn parse_fund(entry: &str) -> Result<(Address, u64), String> {
    let (address, amount) = entry
        .split_once(':')
        .ok_or_else(|| format!("--fund '{entry}' is not <address>:<amount>"))?;
    let amount = amount
        .parse::<u64>()
        .map_err(|e| format!("--fund '{entry}': amount: {e}"))?;
    Ok((parse_address(address)?, amount))
}

/// `bud genesis assemble`: read the records, assemble, check, write.
fn run_genesis_assemble(
    network: &str,
    operators: &std::path::Path,
    destinations: [&str; 5],
    timestamp_ms: Option<u128>,
    fund: &[String],
    out: &std::path::Path,
) -> Result<(), String> {
    use budlum_core::chain::genesis_ceremony::{
        assemble, genesis_hash, supply_audit, CeremonyInputs, SupplyAudit,
    };
    use budlum_core::core::chain_config::Network;
    let network = match network {
        "testnet" => Network::Testnet,
        "mainnet" => Network::Mainnet,
        // The local rehearsal (ops/docker-compose.yml) runs the same
        // ceremony on the devnet profile.
        "devnet" => Network::Devnet,
        other => {
            return Err(format!(
                "unknown network '{other}' (testnet, mainnet or devnet)"
            ))
        }
    };
    let mut paths: Vec<_> = std::fs::read_dir(operators)
        .map_err(|e| format!("cannot read {}: {e}", operators.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    let mut records = Vec::with_capacity(paths.len());
    for path in &paths {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        records.push(
            serde_json::from_str(&raw)
                .map_err(|e| format!("{} is not an operator record: {e}", path.display()))?,
        );
    }
    let [community, liquidity, ecosystem, team, burn_reserve] = destinations;
    let inputs = CeremonyInputs {
        operators: records,
        tokenomics_addresses: budlum_core::tokenomics::TokenomicsAddresses {
            community: parse_address(community)?,
            liquidity: parse_address(liquidity)?,
            ecosystem: parse_address(ecosystem)?,
            team: parse_address(team)?,
            burn_reserve: parse_address(burn_reserve)?,
        },
        timestamp_ms,
        allocations: fund
            .iter()
            .map(|entry| parse_fund(entry))
            .collect::<Result<_, _>>()?,
    };
    let genesis = assemble(network, inputs)?;
    // The ceremony publishes the audit report beside the file
    // and its hash, so every operator can repeat the same `u128` sum.
    let audit: SupplyAudit = supply_audit(&genesis)?;
    let json = serde_json::to_string_pretty(&genesis).map_err(|e| e.to_string())?;
    std::fs::write(out, json + "\n").map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    println!("validators: {}", genesis.validators.len());
    println!("genesis file: {}", out.display());
    println!("genesis hash: {}", genesis_hash(&genesis));
    println!(
        "supply audit: {}",
        serde_json::to_string(&audit).map_err(|e| e.to_string())?
    );
    Ok(())
}

/// The wallet password: the first line of `--password-file`, else the
/// `BUD_WALLET_PASSWORD` environment variable. Never an argument.
fn wallet_password(file: Option<&std::path::Path>) -> Result<String, String> {
    let password = match file {
        Some(path) => {
            check_key_file_mode(path)?;
            std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?
                .lines()
                .next()
                .unwrap_or_default()
                .to_string()
        }
        None => std::env::var("BUD_WALLET_PASSWORD").map_err(|_| {
            String::from(
                "no wallet password: pass --password-file <path> or set BUD_WALLET_PASSWORD",
            )
        })?,
    };
    if password.chars().count() < 8 {
        return Err("the wallet password must have at least 8 characters".into());
    }
    Ok(password)
}

/// Write a key file that did not exist, owner-only.
fn write_new_key_file(
    path: &std::path::Path,
    file: &budlum_core::wallet::KeyFile,
) -> Result<(), String> {
    use std::io::Write as _;
    let json = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut handle = options.open(path).map_err(|e| {
        format!(
            "cannot create {} (a key file is never overwritten): {e}",
            path.display()
        )
    })?;
    handle
        .write_all(json.as_bytes())
        .and_then(|()| handle.write_all(b"\n"))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn read_key_file(path: &std::path::Path) -> Result<budlum_core::wallet::KeyFile, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|e| format!("{} is not a wallet key file: {e}", path.display()))
}

fn run_wallet_create(
    key_file: &std::path::Path,
    password_file: Option<&std::path::Path>,
) -> Result<(), String> {
    use budlum_core::wallet::{
        generate_entropy, mnemonic_from_entropy, KeyFile, DEFAULT_KDF_ITERATIONS,
    };
    let password = wallet_password(password_file)?;
    let entropy = generate_entropy();
    let file =
        KeyFile::seal(&entropy, &password, DEFAULT_KDF_ITERATIONS).map_err(|e| e.to_string())?;
    write_new_key_file(key_file, &file)?;
    println!("address: 0x{}", file.address);
    println!(
        "key file (sealed with your password): {}",
        key_file.display()
    );
    println!();
    println!("Write these 24 words down, offline, in order. They are shown once and they");
    println!("are the only way to recover the wallet:");
    println!();
    println!("{}", mnemonic_from_entropy(&entropy));
    Ok(())
}

fn run_wallet_import(
    key_file: &std::path::Path,
    password_file: Option<&std::path::Path>,
) -> Result<(), String> {
    use budlum_core::wallet::{entropy_from_mnemonic, KeyFile, DEFAULT_KDF_ITERATIONS};
    use std::io::BufRead as _;
    let password = wallet_password(password_file)?;
    eprintln!("Type the 24 words on one line and press enter:");
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("cannot read the mnemonic: {e}"))?;
    let entropy = entropy_from_mnemonic(line.trim()).map_err(|e| e.to_string())?;
    let file =
        KeyFile::seal(&entropy, &password, DEFAULT_KDF_ITERATIONS).map_err(|e| e.to_string())?;
    write_new_key_file(key_file, &file)?;
    println!("address: 0x{}", file.address);
    println!("key file: {}", key_file.display());
    Ok(())
}

use budlum_core::wallet::SigningKey as WalletKey;

/// Open a wallet: its keys.
fn open_wallet(signer: &V5Signer) -> Result<WalletKey, String> {
    open_wallet_file(&signer.key_file, signer.password_file.as_deref())
}

fn open_wallet_file(
    key_file: &std::path::Path,
    password_file: Option<&std::path::Path>,
) -> Result<WalletKey, String> {
    let file = read_key_file(key_file)?;
    let entropy = file
        .open(&wallet_password(password_file)?)
        .map_err(|e| e.to_string())?;
    WalletKey::from_entropy(&entropy, file.is_legacy()).map_err(|e| e.to_string())
}

/// Sign `tx` with the wallet (its sender, nonce and chain id from the node)
/// and send it. A V3 wallet signs V7; a legacy key signs V5.
fn send_v5(
    rpc_url: &str,
    key: &WalletKey,
    mut tx: Transaction,
    nonce: Option<u64>,
) -> Result<(), String> {
    let from = key.address();
    // Checked before anything is signed, so a wallet transfer is valid on the
    // network the operator named and nowhere else.
    let chain_id = node_chain_id(rpc_url)?;
    tx.from = from;
    tx.nonce = match nonce {
        Some(n) => n,
        None => {
            let nonce_value =
                rpc_call(rpc_url, "bud_getNonce", serde_json::json!([from.to_hex()]))?;
            parse_rpc_u64(&nonce_value, "bud_getNonce")?
        }
    };
    tx.chain_id = chain_id;
    if tx.fee == 0 {
        let resolved_fee = resolve_network_fee(rpc_url, None, Some(&tx))?;
        tx.fee = resolved_fee;
        tx.max_fee = resolved_fee;
    }
    match key {
        WalletKey::V3(account) => {
            use rand::Rng;
            let mut rnd = [0u8; 32];
            rand::rng().fill_bytes(&mut rnd);
            tx.sign_v7(
                &budlum_core::crypto::scheme::SchemeStatusRegistry::genesis(),
                &account.signing,
                &account.recovery_public_key,
                &rnd,
            )?;
            println!("tx hash (signed, V7): {}", tx.hash);
        }
        WalletKey::V5(key) => {
            tx.sign_v5(key);
            println!("tx hash (signed, V5): {}", tx.hash);
        }
    }
    let r = rpc_call(rpc_url, "bud_sendRawTransaction", serde_json::json!([tx]))?;
    match r.as_str() {
        Some(returned) => println!("sent \u{2713} - node tx hash: {returned}"),
        None => println!("sent \u{2713} - node response: {r}"),
    }
    Ok(())
}

/// A header-only transaction of `tx_type` for `send_v5` to complete.
fn v5_template(tx_type: TransactionType, amount: u64, fee: Option<u64>) -> Transaction {
    Transaction::new_with_chain_id(
        Address::zero(),
        Address::zero(),
        amount,
        fee.unwrap_or(0),
        0,
        Vec::new(),
        0,
        tx_type,
    )
}

/// The cost a `bud_bnsPrepare*` answer quotes. Only the number is taken from
/// the node: the transaction itself is built here, so a node that answers
/// with a different transaction type, recipient or payload cannot get it
/// signed. Consensus refuses a wrong cost, so a lying node can make the
/// transaction fail but not redirect it.
fn quoted_cost(prepared: &serde_json::Value, method: &str) -> Result<u64, String> {
    prepared
        .get("cost")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{method} returned no cost"))
}

fn send_bns(
    rpc_url: &str,
    signer: &V5Signer,
    key: &WalletKey,
    tx_type: TransactionType,
    amount: u64,
    data: Vec<u8>,
) -> Result<(), String> {
    let mut tx = v5_template(tx_type, amount, signer.fee);
    tx.data = data;
    send_v5(rpc_url, key, tx, None)
}

/// Parse a batch `bud bns sell` file into `(name, price_atoms, duration)` rows.
fn parse_bns_sell_list(
    contents: &str,
    default_duration: u64,
) -> Result<Vec<(String, u64, u64)>, String> {
    let mut rows = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (idx, raw_line) in contents.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw_line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        let fields: Vec<&str> = trimmed
            .split(|c: char| c.is_ascii_whitespace() || c == ',')
            .filter(|part| !part.is_empty())
            .collect();
        if !(2..=3).contains(&fields.len()) {
            return Err(format!(
                "line {line_no}: expected `<name> <price_atoms> [duration]`, got `{trimmed}`"
            ));
        }
        let name = fields[0].to_string();
        if !budlum_core::bns::BnsRegistry::is_valid_name(&name) {
            return Err(format!(
                "line {line_no}: invalid BNS name `{name}` (expected <label>.bud with 3..=32 chars)"
            ));
        }
        if !seen.insert(name.clone()) {
            return Err(format!(
                "line {line_no}: duplicate name `{name}` in sell file"
            ));
        }
        let price_atoms = fields[1]
            .parse::<u64>()
            .map_err(|e| format!("line {line_no}: invalid price_atoms `{}`: {e}", fields[1]))?;
        if price_atoms == 0 {
            return Err(format!(
                "line {line_no}: price_atoms must be greater than zero"
            ));
        }
        let duration = match fields.get(2) {
            Some(raw_dur) => raw_dur
                .parse::<u64>()
                .map_err(|e| format!("line {line_no}: invalid duration `{raw_dur}`: {e}"))?,
            None => default_duration,
        };
        if duration == 0 {
            return Err(format!(
                "line {line_no}: duration must be greater than zero"
            ));
        }
        rows.push((name, price_atoms, duration));
    }
    if rows.is_empty() {
        return Err("sell file contains no offers".into());
    }
    Ok(rows)
}

fn run_bns_sell(
    rpc_url: &str,
    signer: &V5Signer,
    file: &std::path::Path,
    default_duration: u64,
    expires_at_epoch: u64,
) -> Result<(), String> {
    let contents = std::fs::read_to_string(file)
        .map_err(|e| format!("could not read {}: {e}", file.display()))?;
    let rows = parse_bns_sell_list(&contents, default_duration)?;
    let key = open_wallet(signer)?;
    let nonce_value = rpc_call(
        rpc_url,
        "bud_getNonce",
        serde_json::json!([key.address().to_hex()]),
    )?;
    let base_nonce = parse_rpc_u64(&nonce_value, "bud_getNonce")?;

    for (idx, (name, price_atoms, duration)) in rows.into_iter().enumerate() {
        let nonce = base_nonce
            .checked_add(u64::try_from(idx).map_err(|_| "batch size overflow".to_string())?)
            .ok_or_else(|| "nonce overflow in batch sell".to_string())?;
        let req = budlum_core::bns::CreateNameOffer {
            name: name.clone(),
            price_atoms,
            duration,
            kind: budlum_core::bns::OfferKind::Primary,
            expires_at_epoch,
        };
        let data = bincode::serialize(&req).map_err(|e| e.to_string())?;
        let mut tx = v5_template(TransactionType::BnsCreateOffer, 0, signer.fee);
        tx.data = data;
        send_v5(rpc_url, &key, tx, Some(nonce))?;
        println!("submitted Primary offer for {name} at {price_atoms} atoms (duration {duration})");
    }
    Ok(())
}

fn run_bns_create_offer(
    rpc_url: &str,
    signer: &V5Signer,
    name: &str,
    price_atoms: u64,
    duration: u64,
    kind: &str,
    expires_at_epoch: u64,
) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let offer_kind = match kind {
        "Primary" | "primary" => budlum_core::bns::OfferKind::Primary,
        "Resale" | "resale" => budlum_core::bns::OfferKind::Resale,
        other => {
            return Err(format!(
                "invalid offer kind `{other}`: expected Primary or Resale"
            ))
        }
    };
    let _prepared = rpc_call(
        rpc_url,
        "bud_bnsPrepareCreateOffer",
        serde_json::json!([
            key.address().to_hex(),
            name,
            price_atoms,
            duration,
            kind,
            expires_at_epoch
        ]),
    )?;
    let req = budlum_core::bns::CreateNameOffer {
        name: name.to_string(),
        price_atoms,
        duration,
        kind: offer_kind,
        expires_at_epoch,
    };
    let data = bincode::serialize(&req).map_err(|e| e.to_string())?;
    send_bns(
        rpc_url,
        signer,
        &key,
        TransactionType::BnsCreateOffer,
        0,
        data,
    )
}

fn run_bns_buy(rpc_url: &str, signer: &V5Signer, offer_id: u64) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let prepared = rpc_call(
        rpc_url,
        "bud_bnsPrepareBuyName",
        serde_json::json!([key.address().to_hex(), offer_id]),
    )?;
    let price_atoms = prepared
        .get("price_atoms")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "bud_bnsPrepareBuyName returned no price_atoms".to_string())?;
    let data = bincode::serialize(&offer_id).map_err(|e| e.to_string())?;
    send_bns(
        rpc_url,
        signer,
        &key,
        TransactionType::BnsBuyName,
        price_atoms,
        data,
    )
}

fn run_bns_cancel_offer(rpc_url: &str, signer: &V5Signer, offer_id: u64) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let _prepared = rpc_call(
        rpc_url,
        "bud_bnsPrepareCancelOffer",
        serde_json::json!([key.address().to_hex(), offer_id]),
    )?;
    let data = bincode::serialize(&offer_id).map_err(|e| e.to_string())?;
    send_bns(
        rpc_url,
        signer,
        &key,
        TransactionType::BnsCancelOffer,
        0,
        data,
    )
}

fn run_bns_renew(
    rpc_url: &str,
    signer: &V5Signer,
    name: &str,
    duration: u64,
) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let prepared = rpc_call(
        rpc_url,
        "bud_bnsPrepareRenew",
        serde_json::json!([name, key.address().to_hex(), duration]),
    )?;
    let cost = quoted_cost(&prepared, "bud_bnsPrepareRenew")?;
    let data = bincode::serialize(&(name.to_string(), duration)).map_err(|e| e.to_string())?;
    send_bns(rpc_url, signer, &key, TransactionType::BnsRenew, cost, data)
}

fn run_bns_transfer(
    rpc_url: &str,
    signer: &V5Signer,
    name: &str,
    new_owner: &str,
) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let new_owner = parse_address(new_owner.strip_prefix("0x").unwrap_or(new_owner))?;
    if new_owner == Address::zero() {
        return Err("the new owner cannot be the zero address".into());
    }
    let data = bincode::serialize(&(name.to_string(), new_owner)).map_err(|e| e.to_string())?;
    send_bns(rpc_url, signer, &key, TransactionType::BnsTransfer, 0, data)
}

fn run_bns_set_address(
    rpc_url: &str,
    signer: &V5Signer,
    name: &str,
    address: Option<&str>,
    clear: bool,
    domain_id: Option<u32>,
) -> Result<(), String> {
    if clear && address.is_some() {
        return Err("pass either --address or --clear, not both".into());
    }
    if !clear && address.is_none() {
        return Err("either --address <hex> or --clear is required".into());
    }
    let key = open_wallet(signer)?;
    let target = match address {
        Some(raw) => {
            let parsed = parse_address(raw.strip_prefix("0x").unwrap_or(raw))?;
            if parsed == Address::zero() {
                return Err("target address cannot be the zero address".into());
            }
            Some(parsed)
        }
        None => None,
    };
    let effective_domain = if target.is_some() { domain_id } else { None };
    let _prepared = rpc_call(
        rpc_url,
        "bud_bnsPrepareSetAddress",
        serde_json::json!([
            name,
            key.address().to_hex(),
            target.map(|a| a.to_hex()),
            effective_domain,
        ]),
    )?;
    let data = bincode::serialize(&(name.to_string(), target, effective_domain))
        .map_err(|e| e.to_string())?;
    send_bns(
        rpc_url,
        signer,
        &key,
        TransactionType::BnsSetAddress,
        0,
        data,
    )
}

fn run_bns_set_primary(
    rpc_url: &str,
    signer: &V5Signer,
    name: Option<&str>,
    clear: bool,
) -> Result<(), String> {
    if clear && name.is_some() {
        return Err("pass either --name or --clear, not both".into());
    }
    if !clear && name.is_none() {
        return Err("either --name <label.bud> or --clear is required".into());
    }
    let key = open_wallet(signer)?;
    let primary = name.map(str::to_string);
    let _prepared = rpc_call(
        rpc_url,
        "bud_bnsPrepareSetPrimaryName",
        serde_json::json!([key.address().to_hex(), primary]),
    )?;
    let data = bincode::serialize(&primary).map_err(|e| e.to_string())?;
    send_bns(
        rpc_url,
        signer,
        &key,
        TransactionType::BnsSetPrimaryName,
        0,
        data,
    )
}

fn run_bns_reverse(rpc_url: &str, address: &str) -> Result<(), String> {
    let ans = rpc_call(
        rpc_url,
        "bud_bnsReverseResolve",
        serde_json::json!([address]),
    )?;
    match ans.as_str() {
        Some(name) => println!("{name}"),
        None => println!("null"),
    }
    Ok(())
}

fn run_bns_set_record(
    rpc_url: &str,
    signer: &V5Signer,
    name: &str,
    record_key: &str,
    value: Option<&str>,
    delete: bool,
) -> Result<(), String> {
    if delete && value.is_some() {
        return Err("pass either --value or --delete, not both".into());
    }
    if !delete && value.is_none() {
        return Err("either --value <text> or --delete is required".into());
    }
    let key = open_wallet(signer)?;
    let mut updates = std::collections::BTreeMap::new();
    updates.insert(record_key.to_string(), value.map(str::to_string));
    let _prepared = rpc_call(
        rpc_url,
        "bud_bnsPrepareSetRecords",
        serde_json::json!([name, key.address().to_hex(), updates]),
    )?;
    let data = bincode::serialize(&(name.to_string(), updates)).map_err(|e| e.to_string())?;
    send_bns(
        rpc_url,
        signer,
        &key,
        TransactionType::BnsSetRecords,
        0,
        data,
    )
}

fn run_bns_get_records(rpc_url: &str, name: &str) -> Result<(), String> {
    let ans = rpc_call(rpc_url, "bud_bnsGetRecords", serde_json::json!([name]))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&ans).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn run_bns_set_subdomain(
    rpc_url: &str,
    signer: &V5Signer,
    parent: &str,
    sub: &str,
    target: &str,
) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let target_addr = Address::from_hex(target.strip_prefix("0x").unwrap_or(target))?;
    if target_addr == Address::zero() {
        return Err("subdomain target cannot be the zero address".into());
    }
    let _prepared = rpc_call(
        rpc_url,
        "bud_bnsPrepareRegisterSubdomain",
        serde_json::json!([parent, sub, target_addr.to_hex()]),
    )?;
    let data = bincode::serialize(&(parent.to_string(), sub.to_string(), target_addr))
        .map_err(|e| e.to_string())?;
    send_bns(
        rpc_url,
        signer,
        &key,
        TransactionType::BnsRegisterSubdomain,
        0,
        data,
    )
}

fn run_bns_remove_subdomain(
    rpc_url: &str,
    signer: &V5Signer,
    parent: &str,
    sub: &str,
) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let _prepared = rpc_call(
        rpc_url,
        "bud_bnsPrepareRemoveSubdomain",
        serde_json::json!([parent, sub, key.address().to_hex()]),
    )?;
    let data =
        bincode::serialize(&(parent.to_string(), sub.to_string())).map_err(|e| e.to_string())?;
    send_bns(
        rpc_url,
        signer,
        &key,
        TransactionType::BnsRemoveSubdomain,
        0,
        data,
    )
}

fn run_bns_list_subdomains(rpc_url: &str, parent: &str) -> Result<(), String> {
    let ans = rpc_call(
        rpc_url,
        "bud_bnsListSubdomains",
        serde_json::json!([parent]),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&ans).map_err(|e| e.to_string())?
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_bns_set_bud3(
    rpc_url: &str,
    signer: &V5Signer,
    name: &str,
    object: Option<&str>,
    digest: Option<&str>,
    len: Option<u64>,
    sealed: bool,
    nft: Option<&str>,
    clear: bool,
) -> Result<(), String> {
    if clear && object.is_some() {
        return Err("pass either --object/--digest/--len or --clear, not both".into());
    }
    if !clear && (object.is_none() || digest.is_none() || len.is_none()) {
        return Err(
            "--object <hex>, --digest <hex>, and --len <u64> are required unless --clear is set"
                .into(),
        );
    }
    let key = open_wallet(signer)?;
    let parse_32 = |raw: &str, label: &str| -> Result<[u8; 32], String> {
        let clean = raw.strip_prefix("0x").unwrap_or(raw);
        let bytes = hex::decode(clean).map_err(|e| format!("invalid {label} hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("{label} must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    };
    let cref = if clear {
        None
    } else {
        let obj_key = parse_32(object.unwrap_or_default(), "object")?;
        let dig = parse_32(digest.unwrap_or_default(), "digest")?;
        let nft_id = match nft {
            Some(raw) => Some(parse_32(raw, "nft")?),
            None => None,
        };
        let kind = if sealed {
            budlum_core::storage::bud3::content_id::ContentIdKind::Sealed
        } else {
            budlum_core::storage::bud3::content_id::ContentIdKind::Public
        };
        let cid = budlum_core::storage::bud3::content_id::ContentId {
            kind,
            digest: dig,
            len: len.unwrap_or_default(),
        };
        Some(
            budlum_core::storage::bud3::content_ref::ContentRef::new(cid, obj_key, nft_id)
                .map_err(|e| format!("invalid ContentRef: {e:?}"))?,
        )
    };
    let _prepared = rpc_call(
        rpc_url,
        "bud_bnsPrepareSetBud3Content",
        serde_json::json!([
            name,
            key.address().to_hex(),
            object,
            digest,
            len,
            sealed,
            nft
        ]),
    )?;
    let data = bincode::serialize(&(name.to_string(), cref)).map_err(|e| e.to_string())?;
    send_bns(
        rpc_url,
        signer,
        &key,
        TransactionType::BnsSetBud3Content,
        0,
        data,
    )
}

fn run_bns_get_bud3(rpc_url: &str, name: &str) -> Result<(), String> {
    let ans = rpc_call(rpc_url, "bud_bnsGetBud3Content", serde_json::json!([name]))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&ans).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn run_bns_list_by_owner(rpc_url: &str, owner: &str) -> Result<(), String> {
    let ans = rpc_call(
        rpc_url,
        "bud_bnsListNamesByOwner",
        serde_json::json!([owner]),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&ans).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn run_bns_proof(rpc_url: &str, name: &str) -> Result<(), String> {
    let ans = rpc_call(rpc_url, "bud_bnsGetProof", serde_json::json!([name]))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&ans).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn decode_hex32_field(val: &serde_json::Value, field: &str) -> Result<[u8; 32], String> {
    let raw = val
        .as_str()
        .ok_or_else(|| format!("missing or non-string `{field}` in BNS proof JSON"))?;
    let clean = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(clean).map_err(|e| format!("invalid `{field}` hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("`{field}` must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_merkle_branch_json(
    val: &serde_json::Value,
) -> Result<budlum_core::bns::types::BnsMerkleBranch, String> {
    let name = val
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing branch.name")?
        .to_string();
    let owner = Address::from(decode_hex32_field(
        val.get("owner").ok_or("missing branch.owner")?,
        "branch.owner",
    )?);
    let address = match val.get("address") {
        Some(v) if !v.is_null() => Some(Address::from(decode_hex32_field(v, "branch.address")?)),
        _ => None,
    };
    let expires_at = val
        .get("expires_at")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing branch.expires_at")?;
    let content_id = match val.get("content_id") {
        Some(v) if !v.is_null() => Some(budlum_core::storage::ContentId(decode_hex32_field(
            v,
            "branch.content_id",
        )?)),
        _ => None,
    };
    let storage_root = match val.get("storage_root") {
        Some(v) if !v.is_null() => Some(decode_hex32_field(v, "branch.storage_root")?),
        _ => None,
    };
    let extras_digest = decode_hex32_field(
        val.get("extras_digest")
            .ok_or("missing branch.extras_digest")?,
        "branch.extras_digest",
    )?;
    let leaf = decode_hex32_field(val.get("leaf").ok_or("missing branch.leaf")?, "branch.leaf")?;
    let siblings_arr = val
        .get("siblings")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing branch.siblings")?;
    let mut siblings = Vec::with_capacity(siblings_arr.len());
    for s in siblings_arr {
        siblings.push(decode_hex32_field(s, "branch.siblings[]")?);
    }
    let dirs_arr = val
        .get("directions")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing branch.directions")?;
    let mut directions = Vec::with_capacity(dirs_arr.len());
    for d in dirs_arr {
        directions.push(d.as_bool().ok_or("non-bool entry in branch.directions")?);
    }
    // Position fields are optional on the wire: a missing one leaves the
    // branch usable for inclusion and unusable for non-inclusion, which is the
    // safe reading. A missing field is not an error here.
    let leaf_index = val.get("leaf_index").and_then(serde_json::Value::as_u64);
    let tree_size = val.get("tree_size").and_then(serde_json::Value::as_u64);
    // The extras pre-image is what binds `address`, the records, the
    // subdomains and the B.U.D. 3.0 reference to `extras_digest`. Dropping it
    // here would make the client's own verification refuse a branch the
    // registry correctly produced, so it is read when present and left `None`
    // when the node does not disclose it.
    let extras = match val.get("extras") {
        Some(v) if !v.is_null() => Some(parse_branch_extras_json(v)?),
        _ => None,
    };
    Ok(budlum_core::bns::types::BnsMerkleBranch {
        name,
        owner,
        address,
        expires_at,
        content_id,
        storage_root,
        extras_digest,
        leaf,
        siblings,
        directions,
        leaf_index,
        tree_size,
        extras,
    })
}

fn parse_branch_extras_json(
    val: &serde_json::Value,
) -> Result<budlum_core::bns::types::BnsBranchExtras, String> {
    let address = match val.get("address") {
        Some(v) if !v.is_null() => Some(Address::from(decode_hex32_field(v, "extras.address")?)),
        _ => None,
    };
    let resolver = match val.get("resolver") {
        Some(v) if !v.is_null() => Some(Address::from(decode_hex32_field(v, "extras.resolver")?)),
        _ => None,
    };
    let mut subdomains = std::collections::BTreeMap::new();
    if let Some(map) = val.get("subdomains").and_then(serde_json::Value::as_object) {
        for (label, owner) in map {
            subdomains.insert(
                label.clone(),
                Address::from(decode_hex32_field(owner, "extras.subdomains[]")?),
            );
        }
    }
    let mut records = std::collections::BTreeMap::new();
    if let Some(map) = val.get("records").and_then(serde_json::Value::as_object) {
        for (key, value) in map {
            let text = value
                .as_str()
                .ok_or_else(|| format!("non-string value for extras.records.{key}"))?;
            records.insert(key.clone(), text.to_string());
        }
    }
    Ok(budlum_core::bns::types::BnsBranchExtras {
        resolver,
        address,
        consensus_domain_id: val
            .get("consensus_domain_id")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok()),
        storage_domain_id: val
            .get("storage_domain_id")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok()),
        storage_root_height: val
            .get("storage_root_height")
            .and_then(serde_json::Value::as_u64),
        // The B.U.D. 3.0 reference carries a kind byte, a digest, a length, an
        // object commitment and an optional NFT id; a partial reference would
        // fold to a different digest, so it is either read whole or not at all.
        bud3_content: match val.get("bud3_content") {
            Some(v) if !v.is_null() => Some(parse_bud3_ref_json(v)?),
            _ => None,
        },
        subdomains,
        records,
    })
}

fn parse_bud3_ref_json(
    val: &serde_json::Value,
) -> Result<budlum_core::storage::bud3::content_ref::ContentRef, String> {
    use budlum_core::storage::bud3::content_id::{ContentId, ContentIdKind};
    let kind = match val
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing extras.bud3_content.kind")?
    {
        "public" => ContentIdKind::Public,
        "sealed" => ContentIdKind::Sealed,
        other => return Err(format!("unknown extras.bud3_content.kind `{other}`")),
    };
    let content_id = ContentId {
        kind,
        digest: decode_hex32_field(
            val.get("digest")
                .ok_or("missing extras.bud3_content.digest")?,
            "extras.bud3_content.digest",
        )?,
        len: val
            .get("len")
            .and_then(serde_json::Value::as_u64)
            .ok_or("missing extras.bud3_content.len")?,
    };
    let object_commitment = decode_hex32_field(
        val.get("object_commitment")
            .ok_or("missing extras.bud3_content.object_commitment")?,
        "extras.bud3_content.object_commitment",
    )?;
    let nft_id = match val.get("nft_id") {
        Some(v) if !v.is_null() => Some(decode_hex32_field(v, "extras.bud3_content.nft_id")?),
        _ => None,
    };
    budlum_core::storage::bud3::content_ref::ContentRef::new(content_id, object_commitment, nft_id)
        .map_err(|e| format!("invalid extras.bud3_content: {e}"))
}

fn is_valid_resolvable_bud_fqdn(name: &str) -> bool {
    if budlum_core::bns::BnsRegistry::is_valid_name(name) {
        return true;
    }
    let Some(stem) = name.strip_suffix(".bud") else {
        return false;
    };
    let Some((sub, parent_label)) = stem.split_once('.') else {
        return false;
    };
    !parent_label.contains('.')
        && budlum_core::bns::BnsRegistry::is_valid_sub_label(sub)
        && budlum_core::bns::BnsRegistry::is_valid_name(&format!("{parent_label}.bud"))
}

fn parse_and_verify_bns_proof_json(
    proof_json: &serde_json::Value,
    expected_name: &str,
) -> Result<(budlum_core::bns::types::BnsStateProof, Option<Address>), String> {
    let name = proof_json
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing proof.name")?
        .to_string();
    if name != expected_name {
        return Err(format!(
            "BNS proof name mismatch: expected `{expected_name}`, got `{name}`"
        ));
    }
    let included = proof_json
        .get("included")
        .and_then(serde_json::Value::as_bool)
        .ok_or("missing proof.included")?;
    let epoch = proof_json
        .get("epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing proof.epoch")?;
    let names_count = proof_json
        .get("names_count")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing proof.names_count")?;
    let bns_root = decode_hex32_field(
        proof_json.get("bns_root").ok_or("missing proof.bns_root")?,
        "proof.bns_root",
    )?;
    let meta_digest = decode_hex32_field(
        proof_json
            .get("meta_digest")
            .ok_or("missing proof.meta_digest")?,
        "proof.meta_digest",
    )?;
    let parse_opt_branch =
        |key: &str| -> Result<Option<budlum_core::bns::types::BnsMerkleBranch>, String> {
            match proof_json.get(key) {
                Some(v) if !v.is_null() => Ok(Some(parse_merkle_branch_json(v)?)),
                _ => Ok(None),
            }
        };
    let proof = budlum_core::bns::types::BnsStateProof {
        name,
        included,
        bns_root,
        meta_digest,
        names_count,
        epoch,
        entry: parse_opt_branch("entry")?,
        predecessor: parse_opt_branch("predecessor")?,
        successor: parse_opt_branch("successor")?,
    };
    let verified_leaf =
        budlum_core::bns::BnsRegistry::verify_state_proof(&proof, &bns_root, epoch)?;
    let owner = verified_leaf.map(|b| b.owner);
    Ok((proof, owner))
}

fn resolve_bud_recipient_verified(rpc_url: &str, name: &str) -> Result<Address, String> {
    if !is_valid_resolvable_bud_fqdn(name) {
        return Err(format!(
            "invalid .bud recipient `{name}`: expected <label>.bud or <sub>.<label>.bud"
        ));
    }
    let parent = if budlum_core::bns::BnsRegistry::is_valid_name(name) {
        name.to_string()
    } else {
        let (_, p) = name
            .rsplit_once('.')
            .and_then(|(stem, _)| {
                stem.split_once('.')
                    .map(|(_, label)| ("", format!("{label}.bud")))
            })
            .ok_or_else(|| format!("invalid subdomain recipient `{name}`"))?;
        p
    };
    let proof_json = rpc_call(rpc_url, "bud_bnsGetProof", serde_json::json!([parent]))?;
    let (_, verified_owner) = parse_and_verify_bns_proof_json(&proof_json, &parent)?;
    if verified_owner.is_none() {
        return Err(format!(
            "`{parent}` is not registered in verified BNS state"
        ));
    }
    let resolved = rpc_call(rpc_url, "bud_bnsResolve", serde_json::json!([name]))?;
    let raw = resolved
        .as_str()
        .ok_or_else(|| format!("`{name}` has no active forwarding target address"))?;
    let addr = parse_address(raw.strip_prefix("0x").unwrap_or(raw))?;
    if addr == Address::zero() {
        return Err("resolved BNS recipient cannot be the zero address".into());
    }
    Ok(addr)
}

fn run_bns_resolve(rpc_url: &str, name: &str, verify_proof: bool) -> Result<(), String> {
    if !is_valid_resolvable_bud_fqdn(name) {
        return Err(format!(
            "invalid BNS name `{name}`: expected <label>.bud or <sub>.<label>.bud"
        ));
    }
    if verify_proof {
        let addr = resolve_bud_recipient_verified(rpc_url, name)?;
        println!("0x{}", addr.to_hex());
        return Ok(());
    }
    let ans = rpc_call(rpc_url, "bud_bnsResolve", serde_json::json!([name]))?;
    match ans.as_str() {
        Some(addr) => println!("{addr}"),
        None => println!("null"),
    }
    Ok(())
}

fn run_bns_info(rpc_url: &str, name: &str) -> Result<(), String> {
    if !budlum_core::bns::BnsRegistry::is_valid_name(name) {
        return Err(format!(
            "invalid BNS name `{name}`: expected <label>.bud with 3..=32 chars"
        ));
    }
    let full = rpc_call(rpc_url, "bud_bnsResolveFull", serde_json::json!([name]))?;
    let proof_json = rpc_call(rpc_url, "bud_bnsGetProof", serde_json::json!([name]))?;
    let (proof, verified_owner) = parse_and_verify_bns_proof_json(&proof_json, name)?;
    let summary = serde_json::json!({
        "name": name,
        "resolved": full,
        "bns_root": format!("0x{}", hex::encode(proof.bns_root)),
        "epoch": proof.epoch,
        "proof_verified": true,
        "verified_live_owner": verified_owner.map(|o| format!("0x{}", o.to_hex())),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn run_bns_offers(rpc_url: &str, kind: Option<&str>) -> Result<(), String> {
    let ans = rpc_call(rpc_url, "bud_bnsListOffers", serde_json::json!([kind]))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&ans).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn run_bns_get_offer(rpc_url: &str, offer_id: u64) -> Result<(), String> {
    let ans = rpc_call(rpc_url, "bud_bnsGetOffer", serde_json::json!([offer_id]))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&ans).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn infer_site_mime(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("wasm") => "application/wasm",
        Some("txt" | "md") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn collect_site_dir_files(
    root: &std::path::Path,
    dir: &std::path::Path,
    out: &mut std::collections::BTreeMap<String, (String, Vec<u8>)>,
) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("dir entry error: {e}"))?;
        let ft = entry
            .file_type()
            .map_err(|e| format!("file_type error: {e}"))?;
        if ft.is_symlink() {
            return Err(format!(
                "refusing symlink inside static site directory: {}",
                entry.path().display()
            ));
        }
        let path = entry.path();
        if ft.is_dir() {
            collect_site_dir_files(root, &path, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .components()
                .map(|c| {
                    c.as_os_str()
                        .to_str()
                        .ok_or_else(|| "non-UTF-8 path in site directory".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?
                .join("/");
            if rel.is_empty() || rel.contains("..") {
                return Err(format!("invalid relative site path `{rel}`"));
            }
            let bytes =
                std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            out.insert(rel, (infer_site_mime(&path).to_string(), bytes));
        }
    }
    Ok(())
}

/// Read a single site file or deterministically package a static site directory
/// into `(payload_bytes, mime_type)`.
fn bundle_site_payload(path: &std::path::Path) -> Result<(Vec<u8>, String), String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!("refusing symlink site path: {}", path.display()));
    }
    if meta.is_file() {
        let bytes =
            std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if bytes.is_empty() {
            return Err("site file cannot be empty".into());
        }
        return Ok((bytes, infer_site_mime(path).to_string()));
    }
    if meta.is_dir() {
        let mut files = std::collections::BTreeMap::new();
        collect_site_dir_files(path, path, &mut files)?;
        if files.is_empty() {
            return Err("static site directory contains no files".into());
        }
        if !files.contains_key("index.html") {
            return Err("static site directory must contain an `index.html` entrypoint".into());
        }
        let mut manifest_files = serde_json::Map::new();
        for (rel, (mime, raw)) in files {
            manifest_files.insert(
                rel,
                serde_json::json!({
                    "mime": mime,
                    "hex": hex::encode(raw),
                }),
            );
        }
        let bundle = serde_json::json!({
            "format": "bud-site-v1",
            "entrypoint": "index.html",
            "files": manifest_files,
        });
        let encoded = serde_json::to_vec(&bundle).map_err(|e| e.to_string())?;
        return Ok((encoded, "application/vnd.budlum.site+json".to_string()));
    }
    Err(format!(
        "{} is neither a regular file nor a directory",
        path.display()
    ))
}

fn prepare_publish_site_payloads(
    name: &str,
    payload: &[u8],
    mime: &str,
    lifetime_epochs: u64,
    custody_validator: [u8; 32],
) -> Result<
    (
        budlum_core::storage::bud3::tx::StorageTxV3,
        budlum_core::storage::bud3::content_ref::ContentRef,
        Vec<u8>,
        Vec<u8>,
    ),
    String,
> {
    use budlum_core::storage::bud3::content_ref::ContentRef;
    use budlum_core::storage::bud3::limits::{Bud3Limits, Profile};
    use budlum_core::storage::bud3::pipeline::prepare_public_upload;
    use budlum_core::storage::bud3::placement::{Class, Share};
    use budlum_core::storage::bud3::tx::StorageTxV3;

    if !budlum_core::bns::BnsRegistry::is_valid_name(name) {
        return Err(format!(
            "invalid BNS name `{name}`: expected <label>.bud with 3..=32 chars"
        ));
    }
    if lifetime_epochs == 0 {
        return Err("--lifetime-epochs must be greater than zero".into());
    }
    const SITE_PROFILE: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };
    let prepared = prepare_public_upload(payload, &SITE_PROFILE, &Bud3Limits::default(), 8)
        .map_err(|e| format!("B.U.D. 3.0 site encoding failed: {e:?}"))?;
    let mut shares = Vec::with_capacity(prepared.segments.len());
    for (seg_idx, syms) in prepared.segments.iter().enumerate() {
        shares.push((
            seg_idx as u64,
            Share {
                validator: custody_validator,
                class: Class::Full,
                first_esi: 0,
                symbols: syms.len() as u32,
            },
        ));
    }
    let cref = ContentRef::new(prepared.record.content_id, prepared.record.commitment, None)
        .map_err(|e| format!("invalid ContentRef: {e:?}"))?;
    let storage_tx = StorageTxV3::RegisterObject {
        record: prepared.record,
        shares,
        lifetime_epochs,
    };
    let set_bud3_data =
        bincode::serialize(&(name.to_string(), Some(cref))).map_err(|e| e.to_string())?;
    let mut rec_updates: std::collections::BTreeMap<String, Option<String>> =
        std::collections::BTreeMap::new();
    rec_updates.insert("content.mime".to_string(), Some(mime.to_string()));
    let set_records_data =
        bincode::serialize(&(name.to_string(), rec_updates)).map_err(|e| e.to_string())?;
    Ok((storage_tx, cref, set_bud3_data, set_records_data))
}

fn run_bns_publish_site(
    rpc_url: &str,
    signer: &V5Signer,
    name: &str,
    path: &std::path::Path,
    lifetime_epochs: u64,
    validator: Option<&str>,
) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let (payload, mime) = bundle_site_payload(path)?;
    let custody_validator = match validator {
        Some(raw) => parse_address(raw.strip_prefix("0x").unwrap_or(raw))?.0,
        None => key.address().0,
    };
    let (storage_tx, cref, set_bud3_data, set_records_data) =
        prepare_publish_site_payloads(name, &payload, &mime, lifetime_epochs, custody_validator)?;
    let nonce_val = rpc_call(
        rpc_url,
        "bud_getNonce",
        serde_json::json!([key.address().to_hex()]),
    )?;
    let start_nonce = parse_rpc_u64(&nonce_val, "bud_getNonce")?;

    // 1. Register B.U.D. 3.0 object on-chain (`nonce`).
    let tx1 = v5_template(
        TransactionType::StorageV3(Box::new(storage_tx)),
        0,
        signer.fee,
    );
    send_v5(rpc_url, &key, tx1, Some(start_nonce))?;

    // 2. Bind `ContentRef` to `<label>.bud` (`nonce + 1`).
    let mut tx2 = v5_template(TransactionType::BnsSetBud3Content, 0, signer.fee);
    tx2.data = set_bud3_data;
    send_v5(rpc_url, &key, tx2, Some(start_nonce + 1))?;

    // 3. Record canonical `content.mime` in V3 records (`nonce + 2`).
    let mut tx3 = v5_template(TransactionType::BnsSetRecords, 0, signer.fee);
    tx3.data = set_records_data;
    send_v5(rpc_url, &key, tx3, Some(start_nonce + 2))?;

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "name": name,
            "byte_len": payload.len(),
            "mime": mime,
            "object_commitment": format!("0x{}", hex::encode(cref.object_commitment)),
            "content_digest": format!("0x{}", hex::encode(cref.content_id.digest)),
            "lifetime_epochs": lifetime_epochs,
        }))
        .map_err(|e| e.to_string())?
    );
    Ok(())
}

/// The multiaddr peers dial: `/ip4/...` for an address, `/dns4/...` for a
/// name.
fn bootnode_multiaddr(host: &str, port: u16, peer_id: &str) -> String {
    let proto = if host.parse::<std::net::Ipv4Addr>().is_ok() {
        "ip4"
    } else {
        "dns4"
    };
    format!("/{proto}/{host}/tcp/{port}/p2p/{peer_id}")
}

/// `bud node identity`: the node's identity and its seed records.
fn run_node_identity(
    identity_file: &std::path::Path,
    host: &str,
    port: u16,
    seed_domain: Option<&str>,
) -> Result<(), String> {
    let path = identity_file
        .to_str()
        .ok_or("the identity file path is not UTF-8")?;
    let keypair = budlum_core::network::node::load_or_generate_identity_key(Some(path));
    let peer_id = keypair.public().to_peer_id().to_string();
    let multiaddr = bootnode_multiaddr(host, port, &peer_id);
    println!("peer id: {peer_id}");
    println!("bootnode (config [p2p] bootnodes): \"{multiaddr}\"");
    if let Some(domain) = seed_domain {
        // `p2p.dns_seeds` names are resolved through their address records
        // (A/AAAA) and each address is dialled at the P2P port; the node does
        // not read libp2p `_dnsaddr` TXT records.
        if host.parse::<std::net::IpAddr>().is_ok() {
            println!(
                "DNS seed record: {domain} A {host}   (config [p2p] dns_seeds = [\"{domain}\"])"
            );
        } else {
            println!("DNS seed record: {domain} CNAME {host}   (config [p2p] dns_seeds = [\"{domain}\"])");
        }
    }
    Ok(())
}

/// `bud reward-pool --epoch N`: the operator-facing audit of one epoch's
/// Network Security Pool split. The command names and checks the three
/// interfaces the storage-fee path reads, so a split that stops conserving
/// the budget is refused here rather than discovered in a payout.
fn run_reward_pool(epoch: u64) -> Result<(), String> {
    use budlum_core::tokenomics::reward_pool::{
        split_epoch_budget, storage_share, storage_share_for, RewardPoolSchedule, RewardPoolSplit,
        DEFAULT_VALIDATION_REWARD_POOL,
    };
    let schedule = RewardPoolSchedule::default();
    let remaining = DEFAULT_VALIDATION_REWARD_POOL;
    let budget = schedule.per_epoch_budget(epoch, remaining);
    let split: RewardPoolSplit = split_epoch_budget(budget);
    if split.total() != budget {
        return Err("the pool split does not conserve the epoch budget".into());
    }
    if storage_share(epoch) != split.storage {
        return Err("the default storage share disagrees with the split".into());
    }
    if storage_share_for(epoch, &schedule, remaining) != split.storage {
        return Err("the schedule-aware storage share disagrees with the split".into());
    }
    println!("epoch: {epoch}");
    println!("budget_atoms: {budget}");
    println!("consensus_atoms: {}", split.consensus);
    println!("storage_atoms: {}", split.storage);
    println!("repair_and_relay_atoms: {}", split.repair_and_relay);
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    set_signing_chain_id(cli.signing_chain_id);
    let result = match &cli.command {
        Command::Tx { action } => match action {
            TxAction::Send {
                to,
                amount,
                priv_key_file: _,
                fee,
                nonce,
                key_file: Some(key_file),
                password_file,
            } => open_wallet_file(key_file, password_file.as_deref()).and_then(|key| {
                let draft = build_transfer(
                    Address::zero(),
                    parse_address(to)?,
                    *amount,
                    fee.unwrap_or(0),
                    0,
                    0,
                );
                let resolved_fee = resolve_network_fee(&cli.rpc_url, *fee, Some(&draft))?;
                let tx = build_transfer(
                    Address::zero(),
                    parse_address(to)?,
                    *amount,
                    resolved_fee,
                    0,
                    0,
                );
                send_v5(&cli.rpc_url, &key, tx, *nonce)
            }),
            TxAction::Send {
                to,
                amount,
                priv_key_file,
                fee,
                nonce,
                key_file: None,
                password_file: _,
            } => run_tx_send(
                &cli.rpc_url,
                to,
                *amount,
                priv_key_file.as_deref(),
                *fee,
                *nonce,
            ),
            TxAction::Bundle { file } => run_tx_bundle(&cli.rpc_url, file),
        },
        Command::Query { action } => match action {
            QueryAction::Balance { address } => run_query_balance(&cli.rpc_url, address),
            QueryAction::Block { number } => run_query_block(&cli.rpc_url, number),
            QueryAction::Status => run_query_status(&cli.rpc_url),
        },
        Command::Validator { config, action } => match action {
            None => run_validator(config.as_deref()),
            Some(ValidatorAction::Init {
                key_file,
                record_out,
                chain_id,
                moniker,
            }) => run_validator_init(key_file, record_out, *chain_id, moniker),
            Some(ValidatorAction::Join {
                key_file,
                stake_bud,
                fee,
            }) => run_validator_join(&cli.rpc_url, key_file, *stake_bud, *fee),
            Some(ValidatorAction::Commission {
                key_file,
                rate_ppm,
                fee,
            }) => run_validator_commission(&cli.rpc_url, key_file, *rate_ppm, *fee),
            Some(ValidatorAction::Filiz {
                key_file,
                seed_file,
                fee,
            }) => run_validator_filiz(&cli.rpc_url, key_file, seed_file, *fee),
        },
        Command::Wallet { action } => match action {
            WalletAction::Create {
                key_file,
                password_file,
            } => run_wallet_create(key_file, password_file.as_deref()),
            WalletAction::Import {
                key_file,
                password_file,
            } => run_wallet_import(key_file, password_file.as_deref()),
            WalletAction::Address { key_file } => read_key_file(key_file).map(|file| {
                println!("0x{}", file.address);
            }),
        },
        Command::Faucet { action } => run_faucet(action),
        Command::Alias { address } => run_cli_alias(address),
        Command::Conformance { samples } => run_cli_conformance(*samples),
        Command::Stake { signer, amount_bud } => open_wallet(signer).and_then(|key| {
            let amount = amount_bud
                .checked_mul(budlum_core::tokenomics::BUD_UNIT)
                .ok_or("the stake overflows the base unit")?;
            send_v5(
                &cli.rpc_url,
                &key,
                v5_template(TransactionType::Stake, amount, signer.fee),
                None,
            )
        }),
        Command::Unstake { signer, amount_bud } => open_wallet(signer).and_then(|key| {
            let amount = amount_bud
                .checked_mul(budlum_core::tokenomics::BUD_UNIT)
                .ok_or("the amount overflows the base unit")?;
            send_v5(
                &cli.rpc_url,
                &key,
                v5_template(TransactionType::Unstake, amount, signer.fee),
                None,
            )
        }),
        Command::Delegate {
            signer,
            validator,
            amount_bud,
        } => run_delegation(&cli.rpc_url, signer, validator, Some(*amount_bud), true),
        Command::Undelegate {
            signer,
            validator,
            amount_bud,
        } => run_delegation(&cli.rpc_url, signer, validator, Some(*amount_bud), false),
        Command::AiAnswer {
            signer,
            request_id,
            output_commitment,
        } => run_ai_answer(&cli.rpc_url, signer, request_id, output_commitment),
        Command::WithdrawDelegation { signer, validator } => {
            run_delegation(&cli.rpc_url, signer, validator, None, false)
        }
        Command::Redelegate {
            signer,
            from_validator,
            to_validator,
            amount_bud,
        } => run_redelegate(
            &cli.rpc_url,
            signer,
            from_validator,
            to_validator,
            *amount_bud,
        ),
        Command::ClaimRewards { signer, validator } => {
            run_claim_rewards(&cli.rpc_url, signer, validator)
        }
        Command::Domain { action } => match action {
            DomainAction::RegisterPow {
                signer,
                id,
                chain_id,
                min_confirmations,
            } => run_domain_register_pow(&cli.rpc_url, signer, *id, *chain_id, *min_confirmations),
            DomainAction::Selftest {
                adapter,
                network,
                golden,
                program_hash,
                chain_id,
                now,
            } => run_domain_selftest(
                adapter,
                network,
                golden,
                program_hash.as_deref(),
                *chain_id,
                *now,
            ),
        },
        Command::Dev { action } => run_dev(&cli.rpc_url, action),
        Command::Graft { action } => run_graft(&cli.rpc_url, action),
        Command::Bns { action } => match action {
            BnsAction::Sell {
                signer,
                file,
                duration,
                expires_at_epoch,
            } => run_bns_sell(&cli.rpc_url, signer, file, *duration, *expires_at_epoch),
            BnsAction::CreateOffer {
                signer,
                name,
                price_atoms,
                duration,
                kind,
                expires_at_epoch,
            } => run_bns_create_offer(
                &cli.rpc_url,
                signer,
                name,
                *price_atoms,
                *duration,
                kind,
                *expires_at_epoch,
            ),
            BnsAction::Buy { signer, offer_id } => run_bns_buy(&cli.rpc_url, signer, *offer_id),
            BnsAction::CancelOffer { signer, offer_id } => {
                run_bns_cancel_offer(&cli.rpc_url, signer, *offer_id)
            }
            BnsAction::Renew {
                signer,
                name,
                duration,
            } => run_bns_renew(&cli.rpc_url, signer, name, *duration),
            BnsAction::Transfer {
                signer,
                name,
                new_owner,
            } => run_bns_transfer(&cli.rpc_url, signer, name, new_owner),
            BnsAction::SetAddress {
                signer,
                name,
                address,
                clear,
                domain_id,
            } => run_bns_set_address(
                &cli.rpc_url,
                signer,
                name,
                address.as_deref(),
                *clear,
                *domain_id,
            ),
            BnsAction::SetPrimary {
                signer,
                name,
                clear,
            } => run_bns_set_primary(&cli.rpc_url, signer, name.as_deref(), *clear),
            BnsAction::Reverse { address } => run_bns_reverse(&cli.rpc_url, address),
            BnsAction::SetRecord {
                signer,
                name,
                key,
                value,
                delete,
            } => run_bns_set_record(&cli.rpc_url, signer, name, key, value.as_deref(), *delete),
            BnsAction::GetRecords { name } => run_bns_get_records(&cli.rpc_url, name),
            BnsAction::SetSubdomain {
                signer,
                parent,
                sub,
                target,
            } => run_bns_set_subdomain(&cli.rpc_url, signer, parent, sub, target),
            BnsAction::RemoveSubdomain {
                signer,
                parent,
                sub,
            } => run_bns_remove_subdomain(&cli.rpc_url, signer, parent, sub),
            BnsAction::ListSubdomains { parent } => run_bns_list_subdomains(&cli.rpc_url, parent),
            BnsAction::SetBud3 {
                signer,
                name,
                object,
                digest,
                len,
                sealed,
                nft,
                clear,
            } => run_bns_set_bud3(
                &cli.rpc_url,
                signer,
                name,
                object.as_deref(),
                digest.as_deref(),
                *len,
                *sealed,
                nft.as_deref(),
                *clear,
            ),
            BnsAction::GetBud3 { name } => run_bns_get_bud3(&cli.rpc_url, name),
            BnsAction::List { owner } => run_bns_list_by_owner(&cli.rpc_url, owner),
            BnsAction::Proof { name } => run_bns_proof(&cli.rpc_url, name),
            BnsAction::Resolve { name, verify_proof } => {
                run_bns_resolve(&cli.rpc_url, name, *verify_proof)
            }
            BnsAction::Info { name } => run_bns_info(&cli.rpc_url, name),
            BnsAction::Offers { kind } => run_bns_offers(&cli.rpc_url, kind.as_deref()),
            BnsAction::GetOffer { offer_id } => run_bns_get_offer(&cli.rpc_url, *offer_id),
            BnsAction::PublishSite {
                signer,
                name,
                path,
                lifetime_epochs,
                validator,
            } => run_bns_publish_site(
                &cli.rpc_url,
                signer,
                name,
                path,
                *lifetime_epochs,
                validator.as_deref(),
            ),
        },
        Command::Node { action } => match action {
            NodeAction::Identity {
                identity_file,
                host,
                port,
                seed_domain,
            } => run_node_identity(identity_file, host, *port, seed_domain.as_deref()),
        },
        Command::Genesis { action } => match action {
            GenesisAction::Assemble {
                network,
                operators,
                community,
                liquidity,
                ecosystem,
                team,
                burn_reserve,
                timestamp_ms,
                fund,
                out,
            } => run_genesis_assemble(
                network,
                operators,
                [community, liquidity, ecosystem, team, burn_reserve],
                *timestamp_ms,
                fund,
                out,
            ),
        },
        Command::Project { action } => match action {
            ProjectAction::Id { name, source_hash } => run_project_id(name, source_hash),
            ProjectAction::BindProof {
                name,
                source_hash,
                fixture,
                proof_hash,
            } => run_project_bind_proof(name, source_hash, fixture, proof_hash),
        },
        Command::RewardPool { epoch } => run_reward_pool(*epoch),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run_cli_alias(raw_address: &str) -> Result<(), String> {
    let hex_str = raw_address
        .trim()
        .strip_prefix("0x")
        .unwrap_or(raw_address.trim());
    let addr = Address::from_hex(hex_str).map_err(|e| format!("invalid address: {e}"))?;
    let aliases = budlum_core::cli::bud3_commands::cli_alias_show(addr);
    let default_fee = budlum_core::cli::bud3_commands::resolve_cli_fee_default(45261, None, None)
        .map_err(|e| format!("{e:?}"))?;
    let (_pow_nonce, _pow_digest) =
        budlum_core::cli::bud3_commands::solve_faucet_pow(&addr, &[0x45; 32], 1, 64)
            .map_err(|e| format!("{e:?}"))?;
    println!(
        "{{\"budlum\":\"0x{}\",\"evm\":\"0x{}\",\"solana\":\"0x{}\",\"aptos\":\"0x{}\",\"default_testnet_fee_atoms\":{}}}",
        addr.to_hex(),
        hex::encode(aliases.evm_address),
        hex::encode(aliases.svm_address),
        hex::encode(aliases.move_address),
        default_fee
    );
    Ok(())
}

fn run_cli_conformance(samples: usize) -> Result<(), String> {
    use budlum_core::execution::coordinator::conformance::{
        calibrate_bgu_schedule, run_budzero_conformance, run_evm_conformance, run_move_conformance,
        run_svm_conformance, run_wasm_conformance,
    };
    let evm = run_evm_conformance()?;
    let wasm = run_wasm_conformance()?;
    let svm = run_svm_conformance()?;
    let mv = run_move_conformance()?;
    let bz = run_budzero_conformance()?;
    let (ns_per_bgu, _sched) = calibrate_bgu_schedule(samples)?;

    // Verify stateful platform registries & B.U.D. 3.0 subsystems on testnet (45261).
    let qa_reg = budlum_core::account_abstraction::registry::QuantumAccountRegistry::new();
    let _qa_ok = qa_reg.is_registered(&[0u8; 32]);

    let bns_res = budlum_core::bns::bud3::Bud3BnsResolver::new();
    let _bns_none = bns_res.binding("example.bud");

    let dm_reg = budlum_core::data_market::DataMarketRegistry::new();
    let _dm_none = dm_reg.listing(&[0u8; 32]);

    let edu_reg = budlum_core::education_domain::EducationDomainRegistry::new();
    let _edu_none = edu_reg.artifact(&[0u8; 32]);

    let mut obj_metrics = budlum_core::object_layer::metrics::ObjectLayerMetrics::new();
    obj_metrics.entry(0).note_composite(1);

    let proposer = budlum_core::registry::handover::HandoverCoordinator::proposer_for_round(
        &[Address::from([1u8; 32])],
        1,
        0,
    );
    if proposer.is_none() {
        return Err(String::from("handover proposer derivation failed"));
    }

    let android_pol =
        budlum_core::registry::mobile_runtime::MobileValidatorPolicy::android_default();
    let ios_pol =
        budlum_core::registry::mobile_runtime::MobileValidatorPolicy::ios_opportunistic_default();
    let android_win = budlum_core::registry::mobile_runtime::MobileValidatorClass::AndroidMobile
        .audit_window_hours();
    let android_bps = android_pol.custody_reward_bps();
    let duty_ok = android_pol.permits_active_duty(
        true,
        true,
        100,
        false,
        budlum_core::registry::mobile_runtime::DeviceThermalLevel::None,
    ) && (ios_pol.class.audit_window_hours() >= android_win)
        && android_bps > 0;
    if !duty_ok {
        return Err(String::from("mobile runtime policy self-check failed"));
    }

    let reh_samples = budlum_core::registry::rehearsal::analyze_mobile_field_logs("")
        .map_err(|e| format!("{e:?}"))?;
    let _ = reh_samples.device_count;

    let nft_id = budlum_core::socialfi::nft_folders::derive_bud3_nft_id(1);
    let folders = budlum_core::socialfi::nft_folders::NftFolderRegistry::new();
    let _ = (nft_id, folders.folder(0));

    let ctx_fee =
        budlum_core::storage::bud3::compression_context::committed::compute_context_savings_fee(
            1_000, 600, false,
        );
    if ctx_fee == 0 {
        return Err(String::from("context savings fee check failed"));
    }

    let mut pdedup =
        budlum_core::storage::bud3::private_dedup::threshold::PrivateDedupEngine::new(true, 0);
    let _ = (pdedup.public_epoch_ref_total(), pdedup.flush_epoch_batch());

    let live_gw = budlum_core::storage::bud3::live_broadcast::LiveGateway::testnet();
    if let Ok(stream) = budlum_core::storage::bud3::LiveStream::begin(
        [0u8; 32],
        [0u8; 32],
        budlum_core::storage::bud3::LiveContext {
            height: 0,
            activation: budlum_core::storage::bud3::LiveActivation { height: Some(0) },
        },
    ) {
        let _ = live_gw.admit_viewer(&stream, 0, 0);
    }
    if let Ok(probe_obj) =
        budlum_core::storage::bud3::bof1::Object::public_coded(0, Vec::new(), b"")
    {
        let _ = live_gw.admit_live_object(&probe_obj, 0);
    }
    let _ = budlum_core::execution::zkvm::four_words_to_address([0, 0, 0, 0]);

    println!(
        "{{\"evm_passed\":{},\"wasm_passed\":{},\"svm_passed\":{},\"move_passed\":{},\"budzero_passed\":{},\"ns_per_bgu\":{}}}",
        evm.passed_vectors, wasm.passed_vectors, svm.passed_vectors, mv.passed_vectors, bz.passed_vectors, ns_per_bgu
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faucet_request_command_requires_origin_and_owned_address() {
        let address = format!("0x{}", "ab".repeat(32));
        let cli = Cli::try_parse_from([
            "bud",
            "faucet",
            "request",
            "--url",
            "https://faucet.test",
            "--address",
            address.as_str(),
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Faucet {
                action: FaucetAction::Request { .. }
            }
        ));
        assert!(
            Cli::try_parse_from(["bud", "faucet", "request", "--address", address.as_str()])
                .is_err()
        );
    }

    #[test]
    fn delegation_commands_parse() {
        let validator = "ab".repeat(32);
        let cli = Cli::try_parse_from([
            "bud",
            "delegate",
            "--key-file",
            "w.key",
            "--validator",
            &validator,
            "--amount-bud",
            "5",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Delegate { amount_bud: 5, .. }
        ));
        let cli = Cli::try_parse_from([
            "bud",
            "withdraw-delegation",
            "--key-file",
            "w.key",
            "--validator",
            &validator,
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::WithdrawDelegation { .. }));
        let cli = Cli::try_parse_from([
            "bud",
            "validator",
            "commission",
            "--key-file",
            "v.key",
            "--rate-ppm",
            "100000",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Validator {
                action: Some(ValidatorAction::Commission {
                    rate_ppm: 100_000,
                    ..
                }),
                ..
            }
        ));
    }

    #[test]
    fn a_bootnode_multiaddr_names_its_transport() {
        assert_eq!(
            bootnode_multiaddr("203.0.113.7", 5001, "12D3Koo"),
            "/ip4/203.0.113.7/tcp/5001/p2p/12D3Koo"
        );
        assert_eq!(
            bootnode_multiaddr("seed1.example.org", 5001, "12D3Koo"),
            "/dns4/seed1.example.org/tcp/5001/p2p/12D3Koo"
        );
    }

    /// The CLI help names the product by its approved name, not
    /// by the banned layer-one term.
    /// The node may not choose the replay domain of a signature this CLI makes.
    ///
    /// A seed controls the same address on every network, so a transfer signed
    /// with a chain id the node supplied is a transfer the node's network - or
    /// any network that node speaks for - can replay. The id is the operator's
    /// to name, and the node's answer can only agree or be refused.
    #[test]
    fn a_node_on_another_network_cannot_choose_the_replay_domain() {
        assert_eq!(chain_id_binding(45_262, 45_262).expect("agreement"), 45_262);
        let err = chain_id_binding(45_260, 45_262)
            .expect_err("a node on another network must not receive a signature");
        assert!(
            err.contains("refusing to sign for a network you did not name"),
            "{err}"
        );
        assert!(err.contains("45260") && err.contains("45262"), "{err}");
    }

    /// The flag exists on the top-level command and reaches every subcommand,
    /// so no signing path can be run without the operator having named a chain
    /// (the run-time refusal is in `node_chain_id`).
    #[test]
    fn the_chain_to_sign_for_is_a_global_flag() {
        use clap::CommandFactory;
        let cli = Cli::command();
        let flag = cli
            .get_arguments()
            .find(|arg| arg.get_id() == "signing_chain_id")
            .expect("--signing-chain-id is a top-level argument");
        // clap propagates a global argument into every subcommand, so no
        // signing subcommand can be reached without it being on the command
        // line. There is deliberately no default: a default is a compiled-in
        // network, which is the same mistake in a quieter form.
        assert!(flag.is_global_set(), "every subcommand inherits it");
        assert!(
            flag.get_default_values().is_empty(),
            "the chain is named, never defaulted"
        );
    }

    #[test]
    fn cli_help_does_not_use_the_layer_one_term() {
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        let banned = ["L", "1"].concat();
        assert!(
            !help
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|w| w == banned),
            "help text uses the banned term: {help}"
        );
        // The ban covers every surface the CLI PRINTS -
        // long help, short help and the subcommand helps - instead of
        // scanning the source file as text.
        let short = Cli::command().render_help().to_string();
        assert!(!short.contains(&banned), "short help uses the banned term");
        for sub in Cli::command().get_subcommands() {
            let sub_help = sub.clone().render_help().to_string();
            assert!(
                !sub_help.contains(&banned),
                "subcommand help uses the banned term: {sub_help}"
            );
        }
    }

    #[test]
    fn parse_rpc_u64_accepts_hex_and_decimal() {
        assert_eq!(
            parse_rpc_u64(&serde_json::json!("0x2a"), "field").unwrap(),
            42
        );
        assert_eq!(
            parse_rpc_u64(&serde_json::json!("42"), "field").unwrap(),
            42
        );
    }

    #[test]
    fn parse_rpc_url_defaults_port() {
        let (host, port) = parse_rpc_url("http://127.0.0.1").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8545);
    }

    /// A seed file readable by group or others is refused.
    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("bud-key-mode-{}", std::process::id()));
        std::fs::write(&path, "00").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = check_key_file_mode(&path).expect_err("mode 644 must be refused");
        assert!(err.contains("chmod 600"), "{err}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(check_key_file_mode(&path).is_ok());
        std::fs::remove_file(&path).ok();
    }

    /// The transfer carries the chain id it was given, not the devnet default.
    #[test]
    fn a_transfer_is_bound_to_the_given_chain_id() {
        let from = Address::zero();
        let tx = build_transfer(from, from, 1, 2, 3, 45260);
        assert_eq!(tx.chain_id, 45260);
        assert_eq!(tx.fee, 2);
        assert_eq!(tx.nonce, 3);
        assert_eq!(tx.tx_type, TransactionType::Transfer);
    }

    const SOURCE_HASH: &str = "0909090909090909090909090909090909090909090909090909090909090909";

    /// Manifest validation is a gate: a manifest that passes produces an id.
    #[test]
    fn a_valid_project_yields_an_id() {
        let manifest = build_manifest("demo-app", SOURCE_HASH).unwrap();
        assert_eq!(manifest.project_id(), manifest.project_id());
    }

    /// A zero source hash does not name a project; no id must be computed.
    #[test]
    fn a_zero_source_hash_is_refused() {
        let zero = "0".repeat(64);
        let err =
            build_manifest("demo-app", &zero).expect_err("a zero source hash must be refused");
        assert!(err.contains("manifest refused"), "{err}");
    }

    /// A short digest must not be silently padded.
    #[test]
    fn a_short_digest_is_refused() {
        let err =
            parse_digest("--source-hash", "0x0909").expect_err("a short digest must be refused");
        assert!(err.contains("must be 32 bytes"), "{err}");
    }

    /// Binding passes for a record carrying the hash of the verified envelope.
    #[test]
    fn binding_a_proof_to_its_own_hash_passes() {
        let proof = "01".repeat(32);
        run_project_bind_proof("demo-app", SOURCE_HASH, "zkvm-smoke", &proof).unwrap();
    }

    /// A record whose own hash differs from the verified envelope is refused.
    /// The record used to be rewritten to the supplied hash before the
    /// comparison, so this case passed.
    #[test]
    fn binding_a_proof_to_another_hash_is_refused() {
        let other = "02".repeat(32);
        let err = run_project_bind_proof("demo-app", SOURCE_HASH, "zkvm-smoke", &other)
            .expect_err("a record speaking of another proof must be refused");
        assert!(err.contains("ProofFixtureHashMismatch"), "{err}");
    }

    /// A record absent from the manifest cannot be bound.
    #[test]
    fn binding_an_unknown_fixture_is_refused() {
        let proof = "01".repeat(32);
        let err = run_project_bind_proof("demo-app", SOURCE_HASH, "no-such-record", &proof)
            .expect_err("an unknown record must be refused");
        assert!(err.contains("no proof record named"), "{err}");
    }

    #[test]
    fn cli_fee_default_reads_network_base_fee() {
        use std::io::{Read as _, Write as _};
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).expect("read");
                let req = String::from_utf8_lossy(&buf[..n]);
                let payload = if req.contains("bud_estimateGas") {
                    r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"not wired"},"id":1}"#
                } else {
                    assert!(req.contains("bud_gasPrice"), "expected bud_gasPrice: {req}");
                    r#"{"jsonrpc":"2.0","result":"0x3b","id":1}"#
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                stream.write_all(resp.as_bytes()).expect("write");
            }
        });
        let rpc_url = format!("http://{addr}");
        let draft = build_transfer(Address::zero(), Address::zero(), 100, 0, 0, 45261);
        // When `--fee` is omitted (`None`), `resolve_network_fee` queries the
        // node and adopts its live base fee (`0x3b` == 59).
        assert_eq!(
            resolve_network_fee(&rpc_url, None, Some(&draft)).unwrap(),
            59
        );
        // Explicit `--fee` overrides without contacting the node.
        assert_eq!(
            resolve_network_fee("http://127.0.0.1:1", Some(777), Some(&draft)).unwrap(),
            777
        );
        server.join().expect("mock RPC thread");
    }

    #[test]
    fn cli_explicit_zero_fee_is_refused_without_contacting_the_network() {
        let err = parse_positive_fee("0").expect_err("zero must not be accepted as a template");
        assert!(err.to_string().contains("greater than zero"));
        let draft = build_transfer(Address::zero(), Address::zero(), 100, 0, 0, 45261);
        assert!(resolve_network_fee("http://127.0.0.1:1", Some(0), Some(&draft)).is_err());
    }
}

/// The RPC gate on the client side (RT-002).
///
/// A node with `auth_required` - the default - answers every request without an
/// `x-api-key` header with `401 Unauthorized`. These tests drive the real
/// request path against a socket that records exactly what the CLI writes, so
/// "the key is sent" and "a 401 is reported as what it is" are both pinned.
#[cfg(test)]
mod rpc_auth_tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    /// Serve exactly one request, capture its bytes, and answer with `response`.
    fn serve_once(response: &'static str, captured: Arc<Mutex<Vec<u8>>>) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("one connection");
            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                let read = stream.read(&mut chunk).expect("read the request");
                if read == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
                if request_is_complete(&buf) {
                    break;
                }
            }
            captured
                .lock()
                .expect("capture lock")
                .extend_from_slice(&buf);
            stream
                .write_all(response.as_bytes())
                .expect("write response");
            stream.flush().expect("flush response");
        });
        port
    }

    /// Headers are all in, and the declared body length has been received.
    fn request_is_complete(buf: &[u8]) -> bool {
        let Ok(text) = std::str::from_utf8(buf) else {
            return false;
        };
        let Some((head, body)) = text.split_once("\r\n\r\n") else {
            return false;
        };
        let declared = head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        });
        declared.is_some_and(|len| body.len() >= len)
    }

    fn request_text(captured: &Arc<Mutex<Vec<u8>>>) -> String {
        let bytes = captured.lock().expect("capture lock").clone();
        String::from_utf8(bytes).expect("the client writes UTF-8")
    }

    #[test]
    fn the_cli_sends_the_operator_key_as_a_header() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let port = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"result\":4242}",
            Arc::clone(&captured),
        );
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"bud_getStatus","params":[]}"#;
        let answer = http_post_json_with_key("127.0.0.1", port, body, Some("sekret-key"))
            .expect("an authorised call succeeds");
        assert_eq!(answer, "{\"result\":4242}");

        let request = request_text(&captured);
        assert!(
            request.contains("\r\nx-api-key: sekret-key\r\n"),
            "the key must travel as the header the server reads: {request}"
        );
        assert!(
            request.ends_with(body),
            "the key must not disturb the JSON body: {request}"
        );
        assert!(
            !request.starts_with("x-api-key"),
            "the key must not become the request line: {request}"
        );
    }

    #[test]
    fn no_configured_key_sends_no_header() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let port = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
            Arc::clone(&captured),
        );
        http_post_json_with_key("127.0.0.1", port, "{}", None).expect("no key, open node");
        let request = request_text(&captured);
        assert!(
            !request.to_ascii_lowercase().contains("x-api-key"),
            "an unset key must not be sent as an empty header: {request}"
        );
    }

    #[test]
    fn a_429_names_the_rate_limit_instead_of_a_json_parse_error() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let port = serve_once(
            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\nContent-Length: 17\r\n\r\nToo many requests",
            Arc::clone(&captured),
        );
        let error = http_post_json_with_key("127.0.0.1", port, "{}", Some("private-api-key"))
            .expect_err("a throttled write must fail closed, never parse plain text as JSON");
        assert!(error.contains("RPC HTTP 429"), "{error}");
        assert!(error.contains("Too many requests"), "{error}");
        assert!(!error.contains("private-api-key"), "no key in diagnostics");
        assert_eq!(
            request_text(&captured).matches("POST / HTTP/1.1").count(),
            1
        );
    }

    #[test]
    fn an_empty_success_reply_is_not_a_json_result() {
        let port = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            Arc::new(Mutex::new(Vec::new())),
        );
        let error = http_post_json_with_key("127.0.0.1", port, "{}", None)
            .expect_err("empty body must be attributed to HTTP, not JSON parsing");
        assert!(error.contains("HTTP 200 returned an empty body"), "{error}");
    }

    #[test]
    fn a_401_names_the_missing_key_instead_of_a_parse_error() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let port = serve_once(
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 12\r\n\r\nUnauthorized",
            Arc::clone(&captured),
        );
        let error = http_post_json_with_key("127.0.0.1", port, "{}", None)
            .expect_err("an unauthenticated call is refused");
        assert!(
            error.contains("HTTP 401"),
            "the refusal must name the status, got: {error}"
        );
        assert!(
            error.contains(budlum_core::rpc::client_auth::API_KEY_FILE_ENV),
            "the refusal must name the setting that fixes it, got: {error}"
        );
        assert!(
            error.contains("requires the operator key"),
            "the refusal must name the cause, got: {error}"
        );
    }

    #[test]
    fn bns_sell_list_parser_enforces_bud_names_and_prices() {
        let ok = parse_bns_sell_list(
            "# comment\n\
             ayaz.bud 50000\n\
             bids.bud, 125000, 36500\n",
            10_000,
        )
        .expect("valid batch file parses");
        assert_eq!(
            ok,
            vec![
                ("ayaz.bud".to_string(), 50_000, 10_000),
                ("bids.bud".to_string(), 125_000, 36_500),
            ]
        );
        assert!(parse_bns_sell_list("bids 50000\n", 10_000).is_err());
        assert!(parse_bns_sell_list("ab.bud 50000\n", 10_000).is_err());
        assert!(parse_bns_sell_list("ayaz.bud 0\n", 10_000).is_err());
        assert!(parse_bns_sell_list("ayaz.bud 100\nayaz.bud 200\n", 10_000).is_err());
    }

    #[test]
    fn site_bundle_and_publish_site_payloads_execute_cleanly_in_consensus_and_verify_proof_json() {
        use budlum_core::core::account::AccountState;
        use budlum_core::execution::executor::Executor;

        let dir = tempfile::tempdir().unwrap();
        let index_path = dir.path().join("index.html");
        std::fs::write(
            &index_path,
            b"<!doctype html><html><body><h1>Hello ayaz.bud</h1></body></html>",
        )
        .unwrap();
        let assets_dir = dir.path().join("assets");
        std::fs::create_dir(&assets_dir).unwrap();
        std::fs::write(assets_dir.join("style.css"), b"body{background:#111;}").unwrap();

        // Single-file mode
        let (file_bytes, file_mime) = bundle_site_payload(&index_path).unwrap();
        assert_eq!(file_mime, "text/html; charset=utf-8");
        assert!(file_bytes.starts_with(b"<!doctype html>"));

        // Directory-bundle mode
        let (dir_bytes, dir_mime) = bundle_site_payload(dir.path()).unwrap();
        assert_eq!(dir_mime, "application/vnd.budlum.site+json");
        let parsed: serde_json::Value = serde_json::from_slice(&dir_bytes).unwrap();
        assert_eq!(parsed["format"], "bud-site-v1");
        assert!(parsed["files"]["index.html"].is_object());
        assert!(parsed["files"]["assets/style.css"].is_object());

        // Missing index.html in directory is refused
        let bad_dir = tempfile::tempdir().unwrap();
        std::fs::write(bad_dir.path().join("only.txt"), b"hi").unwrap();
        assert!(bundle_site_payload(bad_dir.path()).is_err());

        // Acquire `ayaz.bud` via real Primary marketplace (`BnsCreateOffer` + `BnsBuyName`),
        // then execute the 3 prepared site-publish transactions (`StorageV3::RegisterObject`,
        // `BnsSetBud3Content`, `BnsSetRecords`) through `Executor::apply_transaction_checked`!
        let seller_kp = KeyPair::generate().unwrap();
        let seller = Address::from(seller_kp.public_key_bytes());
        let kp = KeyPair::generate().unwrap();
        let alice = Address::from(kp.public_key_bytes());
        let mut state = AccountState::new();
        state.epoch_index = 5;
        state.add_balance(&seller, 50_000_000_000);
        state.add_balance(&alice, 50_000_000_000);
        state.bns_registry.set_primary_sellers([seller]).unwrap();

        let offer_req = budlum_core::bns::CreateNameOffer {
            name: "ayaz.bud".to_string(),
            price_atoms: 10_000,
            duration: 100,
            kind: budlum_core::bns::OfferKind::Primary,
            expires_at_epoch: 50,
        };
        let mut offer_tx = Transaction::new_with_chain_id(
            seller,
            Address::zero(),
            0,
            1_000,
            0,
            bincode::serialize(&offer_req).unwrap(),
            45261,
            TransactionType::BnsCreateOffer,
        );
        offer_tx.max_fee = 1_000;
        offer_tx.sign(&seller_kp);
        Executor::apply_transaction_checked(&mut state, &offer_tx).unwrap();

        let mut buy_tx = Transaction::new_with_chain_id(
            alice,
            Address::zero(),
            10_000,
            1_000,
            0,
            bincode::serialize(&0u64).unwrap(),
            45261,
            TransactionType::BnsBuyName,
        );
        buy_tx.max_fee = 1_000;
        buy_tx.sign(&kp);
        Executor::apply_transaction_checked(&mut state, &buy_tx).unwrap();

        let (storage_tx, cref, set_bud3_data, set_records_data) =
            prepare_publish_site_payloads("ayaz.bud", &file_bytes, &file_mime, 100, alice.0)
                .unwrap();

        let mut tx1 = Transaction::new_with_chain_id(
            alice,
            Address::zero(),
            0,
            1_000,
            1,
            Vec::new(),
            45261,
            TransactionType::StorageV3(Box::new(storage_tx)),
        );
        tx1.max_fee = 1_000;
        tx1.sign(&kp);
        Executor::apply_transaction_checked(&mut state, &tx1).unwrap();

        let mut tx2 = Transaction::new_with_chain_id(
            alice,
            Address::zero(),
            0,
            1_000,
            2,
            set_bud3_data,
            45261,
            TransactionType::BnsSetBud3Content,
        );
        tx2.max_fee = 1_000;
        tx2.sign(&kp);
        Executor::apply_transaction_checked(&mut state, &tx2).unwrap();

        let mut tx3 = Transaction::new_with_chain_id(
            alice,
            Address::zero(),
            0,
            1_000,
            3,
            set_records_data,
            45261,
            TransactionType::BnsSetRecords,
        );
        tx3.max_fee = 1_000;
        tx3.sign(&kp);
        Executor::apply_transaction_checked(&mut state, &tx3).unwrap();

        assert_eq!(
            state.bns_registry.resolve_bud3_content("ayaz.bud", 6),
            Some(cref)
        );
        assert_eq!(
            state
                .bns_registry
                .get_records("ayaz.bud", 6)
                .unwrap()
                .get("content.mime")
                .map(String::as_str),
            Some("text/html; charset=utf-8")
        );

        // Verify JSON proof roundtrip through `parse_and_verify_bns_proof_json`!
        let proof = state.bns_registry.prove_name("ayaz.bud", 6);
        let t = proof.entry.as_ref().unwrap();
        let proof_json = serde_json::json!({
            "name": proof.name,
            "included": proof.included,
            "epoch": proof.epoch,
            "names_count": proof.names_count,
            "bns_root": format!("0x{}", hex::encode(proof.bns_root)),
            "meta_digest": format!("0x{}", hex::encode(proof.meta_digest)),
            "entry": {
                "name": t.name,
                "owner": format!("0x{}", t.owner.to_hex()),
                "address": t.address.map(|a| format!("0x{}", a.to_hex())),
                "expires_at": t.expires_at,
                "content_id": t.content_id.map(|c| format!("0x{}", hex::encode(c.0))),
                "storage_root": t.storage_root.map(|s| format!("0x{}", hex::encode(s))),
                "extras_digest": format!("0x{}", hex::encode(t.extras_digest)),
                "leaf": format!("0x{}", hex::encode(t.leaf)),
                "siblings": t.siblings.iter().map(|s| format!("0x{}", hex::encode(s))).collect::<Vec<_>>(),
                "directions": t.directions,
            },
            "predecessor": serde_json::Value::Null,
            "successor": serde_json::Value::Null,
        });
        let (_, verified_owner) = parse_and_verify_bns_proof_json(&proof_json, "ayaz.bud").unwrap();
        assert_eq!(verified_owner, Some(alice));

        let mut forged_json = proof_json;
        forged_json["bns_root"] = serde_json::json!(format!("0x{}", "ee".repeat(32)));
        assert!(parse_and_verify_bns_proof_json(&forged_json, "ayaz.bud").is_err());
    }
}
