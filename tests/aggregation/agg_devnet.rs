//! The phase 1 exit of the aggregation layer, on real nodes.
//!
//! A `budlum-core` process built with the native backend runs a devnet
//! whose genesis turns the layer on. It produces blocks and runs the
//! aggregator. Signed ML-DSA-87 transactions go in through its JSON-RPC,
//! and what the chain ends up with is read back the same way: blocks that
//! carry a claim frame, transactions without a signature byte, and the
//! balances the transactions and the claim fees leave behind.
//!
//! One node, not two: the public RPC of a node also opens two
//! compatibility listeners on fixed ports and the process exits when they
//! are taken, so a second node with an RPC cannot share the host. Blocks
//! with frames crossing the network between nodes are covered in process
//! by `tests::aggregation_network` and the block rules by
//! `aggregation::tests::chain`.
//!
//! Needs the `agg-native-backend` feature: a build without a backend
//! refuses a genesis with the layer on.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use budlum_core::aggregation::params::{AggMode, AggParams};
use budlum_core::chain::genesis::GenesisConfig;
use budlum_core::core::address::Address;
use budlum_core::core::transaction::Transaction;
use budlum_core::crypto::primitives::WalletKeyPair;
use serde_json::{json, Value};

const CHAIN: u64 = 45262;
const FEE: u64 = 100_000;
const AMOUNT: u64 = 10;
/// Fee of one signature claim under the default parameters: 64 per byte
/// over 67 bytes.
const SIG_CLAIM_FEE: u64 = 4288;
const SENDERS: usize = 8;
const TIMEOUT: Duration = Duration::from_secs(180);

/// Four distinct free ports. The listeners are held until all four are
/// known: a port asked for on its own can be handed out twice.
fn free_ports() -> Result<[u16; 4], String> {
    let listeners = (0..4)
        .map(|_| TcpListener::bind("127.0.0.1:0"))
        .collect::<Result<Vec<TcpListener>, _>>()
        .map_err(|e| e.to_string())?;
    let mut ports = [0u16; 4];
    for (port, listener) in ports.iter_mut().zip(&listeners) {
        *port = listener.local_addr().map_err(|e| e.to_string())?.port();
    }
    Ok(ports)
}

/// The operator listener serves 120 requests a minute to one address; the
/// calls keep under that instead of lifting it.
const CALL_SPACING: Duration = Duration::from_millis(550);

/// One JSON-RPC call over a fresh HTTP connection.
fn call(port: u16, method: &str, params: &Value) -> Result<Value, String> {
    std::thread::sleep(CALL_SPACING);
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|e| e.to_string())?;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&raw);
    let (_, payload) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("{method}: no HTTP body in {text:?}"))?;
    let start = payload
        .find('{')
        .ok_or_else(|| format!("{method}: no JSON in {payload:?}"))?;
    let end = payload
        .rfind('}')
        .ok_or_else(|| format!("{method}: no JSON in {payload:?}"))?;
    let answer: Value =
        serde_json::from_str(&payload[start..=end]).map_err(|e| format!("{method}: {e}"))?;
    if let Some(error) = answer.get("error") {
        return Err(format!("{method}: {error}"));
    }
    answer
        .get("result")
        .cloned()
        .ok_or_else(|| format!("{method}: answer has no result: {answer}"))
}

fn wait_for<T>(what: &str, mut probe: impl FnMut() -> Result<Option<T>, String>) -> T {
    let started = Instant::now();
    let mut last = String::from("condition not met");
    loop {
        match probe() {
            Ok(Some(value)) => return value,
            Ok(None) => {}
            Err(e) => last = e,
        }
        assert!(
            started.elapsed() < TIMEOUT,
            "timed out waiting for {what}: {last}"
        );
    }
}

/// A number the RPC answers as `0x..` hex or as a JSON number.
fn number(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        let text = value.as_str()?;
        text.strip_prefix("0x").map_or_else(
            || text.parse().ok(),
            |hex| u64::from_str_radix(hex, 16).ok(),
        )
    })
}

struct Node {
    child: Child,
    dir: tempfile::TempDir,
    /// The operator listener. The public one also opens two compatibility
    /// listeners on fixed ports, so only one node of a host can have it.
    rpc_port: u16,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Node {
    /// Start a devnet node on `genesis` that builds blocks and runs the
    /// aggregator for `producer`.
    ///
    /// # Errors
    ///
    /// When the process cannot be set up or started, or never answers.
    fn start(genesis: &str, producer: Address) -> Result<Self, String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let genesis_path = dir.path().join("genesis.json");
        std::fs::write(&genesis_path, genesis).map_err(|e| e.to_string())?;
        let [public_port, rpc_port, p2p_port, metrics_port] = free_ports()?;
        let log = std::fs::File::create(dir.path().join("node.log")).map_err(|e| e.to_string())?;
        let errors = log.try_clone().map_err(|e| e.to_string())?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_budlum-core"));
        command
            .arg("--network=devnet")
            .arg("--consensus=pow")
            .arg("--difficulty=0")
            .arg(format!("--genesis-file={}", genesis_path.display()))
            .arg(format!("--db-path={}", dir.path().join("db").display()))
            .arg(format!("--port={p2p_port}"))
            .arg("--rpc-host=127.0.0.1")
            .arg(format!("--rpc-port={public_port}"))
            .arg(format!("--rpc-public-listener=127.0.0.1:{public_port}"))
            .arg(format!("--rpc-operator-listener=127.0.0.1:{rpc_port}"))
            .arg(format!("--metrics-port={metrics_port}"))
            .arg(format!("--metrics-listener=127.0.0.1:{metrics_port}"))
            .arg("--mdns-enabled=false");
        command.arg(format!("--validator-address={}", producer.to_hex()));
        let child = command
            .env("BUDLUM_RPC_AUTH_REQUIRED", "0")
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(errors))
            .spawn()
            .map_err(|e| format!("budlum-core did not start: {e}"))?;
        let node = Self {
            child,
            dir,
            rpc_port,
        };
        let started = Instant::now();
        while node.rpc("bud_blockNumber", &json!([])).is_err() {
            if started.elapsed() >= TIMEOUT {
                return Err(format!("the node never answered:\n{}", node.log_tail(60)));
            }
        }
        Ok(node)
    }

    fn rpc(&self, method: &str, params: &Value) -> Result<Value, String> {
        call(self.rpc_port, method, params)
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("node.log")).unwrap_or_default()
    }

    fn log_tail(&self, lines: usize) -> String {
        let log = self.log();
        let all: Vec<&str> = log.lines().collect();
        all[all.len().saturating_sub(lines)..].join("\n")
    }

    fn height(&self) -> Result<u64, String> {
        let answer = self.rpc("bud_blockNumber", &json!([]))?;
        number(&answer).ok_or_else(|| format!("no height in {answer}"))
    }

    fn balance(&self, address: &Address) -> Result<u64, String> {
        let answer = self.rpc("bud_getBalance", &json!([address.to_hex()]))?;
        number(&answer).ok_or_else(|| format!("no balance in {answer}"))
    }
}

fn is_empty(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty(),
        Some(Value::Array(items)) => items.is_empty(),
        Some(_) => false,
    }
}

#[test]
fn a_devnet_with_the_native_backend_builds_blocks_without_signature_bytes() {
    let wallets: Vec<WalletKeyPair> = (0..SENDERS)
        .map(|n| WalletKeyPair::from_seed(&[u8::try_from(n + 1).expect("small"); 32]))
        .collect();
    let producer = Address::from([0xB7; 32]);
    let recipient = Address::from([0x44; 32]);
    let mut genesis = GenesisConfig::new(CHAIN);
    for wallet in &wallets {
        genesis = genesis.with_allocation(wallet.address(), 10_000_000);
    }
    genesis.aggregation = Some(AggParams {
        mode: AggMode::On,
        ..AggParams::default()
    });
    let genesis = serde_json::to_string(&genesis).expect("genesis json");

    let node = Node::start(&genesis, producer).expect("the node starts");
    assert!(
        node.log().contains("Aggregator active"),
        "the node runs its aggregation side:\n{}",
        node.log_tail(40)
    );

    // The signed transactions go in the way a wallet sends them.
    for wallet in &wallets {
        let mut tx = Transaction::new_with_fee(wallet.address(), recipient, AMOUNT, FEE, 0, vec![]);
        tx.chain_id = CHAIN;
        tx.sign_v5(wallet);
        assert!(tx.verify(), "the wallet signs a valid V5 transaction");
        let payload = serde_json::to_value(&tx).expect("transaction json");
        node.rpc("bud_sendRawTransaction", &json!([payload]))
            .unwrap_or_else(|e| {
                panic!("the node refused a transaction: {e}\n{}", node.log_tail(40))
            });
    }

    // The tick timer proves the objects and the producer carries them.
    let sent = u64::try_from(SENDERS).expect("small") * AMOUNT;
    wait_for("the transfers", || {
        Ok((node.balance(&recipient)? == sent).then_some(()))
    });

    // Read the chain back: every transfer sits in a block that carries a
    // frame, and none of them carries a signature byte.
    let height = node.height().expect("height");
    let mut claimed = 0usize;
    let mut frames = 0usize;
    for index in 1..=height {
        if claimed == SENDERS {
            break;
        }
        let block = node
            .rpc("bud_getBlockByNumber", &json!([index]))
            .expect("block");
        let transactions = block
            .get("transactions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let frame = block.get("claimFrame").filter(|frame| !frame.is_null());
        assert_eq!(
            frame.is_some(),
            block.get("frameHash").is_some_and(|hash| !hash.is_null()),
            "a frame and its hash go together: block {index}"
        );
        let Some(frame) = frame else {
            assert!(
                transactions.is_empty(),
                "block {index} holds transactions and no frame"
            );
            continue;
        };
        frames += 1;
        assert_eq!(
            frame.get("claims").and_then(Value::as_u64),
            u64::try_from(transactions.len()).ok(),
            "one claim per transaction in block {index}"
        );
        assert!(frame.get("proofBytes").and_then(Value::as_u64) > Some(0));
        for segment in frame
            .get("segments")
            .and_then(Value::as_array)
            .expect("segments")
        {
            assert_eq!(
                segment.get("aggregator").and_then(Value::as_str),
                Some(producer.to_string().as_str()),
                "the node proved for its producer address"
            );
        }
        for tx in &transactions {
            assert!(
                is_empty(tx.get("signature")),
                "signature bytes in block {index}: {tx}"
            );
            assert!(
                tx.get("authClaim").is_some_and(|claim| !claim.is_null()),
                "no claim on a transaction of block {index}: {tx}"
            );
            claimed += 1;
        }
    }
    assert_eq!(claimed, SENDERS, "every transfer was carried as a claim");
    assert!(frames >= 1);

    // What the claims cost and who was paid: every sender paid its amount
    // and its fee, and the claim fees went to the aggregator and the
    // producer, which are the same address here.
    let fees = u64::try_from(SENDERS).expect("small") * SIG_CLAIM_FEE;
    for wallet in &wallets {
        assert_eq!(
            node.balance(&wallet.address()).expect("balance"),
            10_000_000 - AMOUNT - FEE
        );
    }
    assert!(node.balance(&producer).expect("balance") >= fees);
    println!(
        "agg_devnet: {claimed} claimed transactions in {frames} block(s) with a frame, \
         chain height {height}"
    );
}
