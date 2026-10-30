//! The local testnet rehearsal.
//!
//! Without `--compose` the tool is a dependency-free preflight: it checks the
//! ceremony, the four-validator `PoS` topology, the public services, the
//! monitoring files and the documented endpoints. CI runs it on every pull
//! request.
//!
//! With `--compose` it builds the images, starts `ops/testnet-local.yml`
//! (four validators, an RPC node, the faucet, the explorer API, Prometheus,
//! Grafana) and runs the module scenarios against it, the way a stranger
//! would: every write is a signed transaction that the `bud` CLI builds
//! inside the RPC container and the chain applies in a block; every check
//! reads public RPC or the explorer API.
//!
//! 1. The chain is live: the tip grows.
//! 2. Four distinct validators produce blocks (VRF leadership).
//! 3. Finality advances.
//! 4. A checkpoint global header is committed and readable.
//! 5. A new V5 wallet receives BUD from the faucet.
//! 6. A transfer between two wallets lands and the explorer API serves it.
//! 7. A delegation to a genesis validator appears in its delegations.
//! 8. A `.bud` name is registered and resolves to its owner.
//! 9. A `PoW` domain is registered; a Graft application on it is registered
//!    and paid; the payment sits in the application's mirror account.
//!
//! Each scenario's verdict and measurements go to the report file (default
//! `target/testnet-rehearsal.md`). The first failure stops the run; the
//! report still records what passed before it.

use crate::{checked_repo_root, has_program, run_checked};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::rpc;

const COMPOSE_FILE: &str = "ops/testnet-local.yml";
/// Loopback ports `ops/testnet-local.yml` publishes.
const RPC_PORT: u16 = 28545;
const FAUCET_PORT: u16 = 28600;
const INDEXER_PORT: u16 = 28700;
/// A throwaway password for the rehearsal's throwaway wallets.
const WALLET_PASSWORD: &str = "rehearsal-only-password";
const PAUSE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
struct Options {
    compose: bool,
    keep_running: bool,
    report: Option<PathBuf>,
}

impl Options {
    fn parse(args: &[&str]) -> Result<Self, String> {
        let mut options = Self {
            compose: false,
            keep_running: false,
            report: None,
        };
        let mut index = 0;
        while let Some(arg) = args.get(index) {
            match *arg {
                "--compose" => options.compose = true,
                "--keep" => options.keep_running = true,
                "--report" => {
                    index += 1;
                    let path = args.get(index).ok_or("--report needs a path")?;
                    options.report = Some(PathBuf::from(path));
                }
                "--help" | "-h" => {
                    return Err(
                        "usage: testnet-rehearsal [--compose [--keep] [--report <path>]]".into(),
                    )
                }
                unknown => return Err(format!("unknown testnet-rehearsal option `{unknown}`")),
            }
            index += 1;
        }
        if options.report.is_some() && !options.compose {
            return Err("--report needs --compose: the preflight runs no scenario".into());
        }
        Ok(options)
    }
}

fn required_file(root: &Path, relative: &str, checks: &mut Vec<String>) -> Result<String, String> {
    let path = root.join(relative);
    let contents = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    checks.push(format!("present: {relative}"));
    Ok(contents)
}

fn require_text(contents: &str, needle: &str, label: &str) -> Result<(), String> {
    if contents.contains(needle) {
        Ok(())
    } else {
        Err(format!("{label} is missing `{needle}`"))
    }
}

fn count_text(contents: &str, needle: &str) -> usize {
    contents.matches(needle).count()
}

fn preflight(root: &Path) -> Result<Vec<String>, String> {
    let mut checks = Vec::new();
    let genesis = required_file(root, "config/testnet-genesis.json", &mut checks)?;
    require_text(&genesis, "\"chain_id\": 45261", "testnet genesis")?;
    require_text(&genesis, "\"block_reward\": 0", "testnet genesis")?;
    require_text(&genesis, "\"bud_tokenomics\"", "testnet genesis")?;

    let profile = required_file(root, "config/testnet.toml", &mut checks)?;
    require_text(&profile, "chain_id = 45261", "testnet profile")?;
    // The profile is the file an operator copies, so it keeps the reviewed
    // posture: the RPC key is required whatever the bind address. The
    // rehearsal's own compose opts out through the environment (asserted two
    // checks below) rather than by weakening the file everyone else copies.
    // This canary asserted the opposite and stayed green only because an
    // earlier formatting failure in this same job ended the run before it.
    require_text(&profile, "auth_required = true", "testnet profile")?;

    let compose = required_file(root, COMPOSE_FILE, &mut checks)?;
    for service in [
        "validator1:",
        "validator2:",
        "validator3:",
        "validator4:",
        "rpc:",
        "faucet:",
        "indexer:",
        "prometheus:",
        "grafana:",
    ] {
        require_text(&compose, service, "local testnet compose")?;
    }
    if count_text(&compose, "--consensus=pos") < 5 {
        return Err(
            "local testnet compose must start four validators and one RPC node with PoS".into(),
        );
    }
    if compose.contains("--consensus=pow") {
        return Err("local testnet compose must not silently fall back to PoW".into());
    }
    require_text(
        &compose,
        "BUDLUM_RPC_AUTH_REQUIRED=0",
        "local testnet compose",
    )?;
    for port in [RPC_PORT, FAUCET_PORT, INDEXER_PORT] {
        require_text(
            &compose,
            &format!("127.0.0.1:{port}:"),
            "local testnet compose",
        )?;
    }

    let testnet_doc = required_file(root, "docs/TESTNET.md", &mut checks)?;
    for endpoint in ["budlum-faucet", "budlum-indexer", "bud_sendRawTransaction"] {
        require_text(&testnet_doc, endpoint, "testnet guide")?;
    }
    required_file(
        root,
        "ops/monitoring/testnet-local-prometheus.yml",
        &mut checks,
    )?;
    required_file(root, "ops/monitoring/alerts.yml", &mut checks)?;
    required_file(
        root,
        "ops/monitoring/grafana/budlum-testnet.json",
        &mut checks,
    )?;
    required_file(root, "docs/explorer-api.openapi.yaml", &mut checks)?;
    checks.push("four-validator PoS topology: present".into());
    checks.push("faucet and finalized-chain indexer: present".into());
    checks.push("Prometheus, Grafana, and explorer contract: present".into());
    Ok(checks)
}

// ---------------------------------------------------------------- scenarios

/// One scenario's verdict for the report.
struct Verdict {
    name: &'static str,
    result: Result<String, String>,
}

/// How many scenarios a full rehearsal runs.
const SCENARIOS: usize = 11;

fn compose(root: &Path, extra: &[&str]) -> Result<String, String> {
    let out = Command::new("docker")
        .arg("compose")
        .args(["-f", COMPOSE_FILE])
        .args(extra)
        .current_dir(root)
        .output()
        .map_err(|e| format!("docker could not be run: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "`docker compose {}` failed: {}{}",
            extra.join(" "),
            stdout,
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// Run `bud` inside the RPC container, against its own public listener,
/// with the rehearsal wallet password in the environment.
fn bud(root: &Path, args: &[&str]) -> Result<String, String> {
    let mut full = vec![
        "exec",
        "-T",
        "-e",
        "BUD_WALLET_PASSWORD",
        "rpc",
        "bud",
        "--rpc-url",
        "http://127.0.0.1:8545",
    ];
    full.extend_from_slice(args);
    let out = Command::new("docker")
        .arg("compose")
        .args(["-f", COMPOSE_FILE])
        .args(&full)
        .env("BUD_WALLET_PASSWORD", WALLET_PASSWORD)
        .current_dir(root)
        .output()
        .map_err(|e| format!("docker could not be run: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "`bud {}` failed: {}{}",
            args.join(" "),
            stdout,
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn call(method: &str, params: &str) -> Option<crate::json::Value> {
    let body = rpc::call(RPC_PORT, method, params, Duration::from_secs(5)).ok()?;
    let value = crate::json::parse(&body).ok()?;
    value.get("result").cloned()
}

fn quantity(value: &crate::json::Value) -> Option<u64> {
    match value {
        crate::json::Value::String(text) => {
            rpc::parse_hex_quantity(text).or_else(|| text.parse().ok())
        }
        crate::json::Value::Number(text) => text.parse().ok(),
        _ => None,
    }
}

fn tip() -> u64 {
    call("bud_blockNumber", "[]")
        .as_ref()
        .and_then(quantity)
        .unwrap_or(0)
}

fn balance(address: &str) -> u64 {
    call("bud_getBalance", &format!("[\"{address}\"]"))
        .as_ref()
        .and_then(quantity)
        .unwrap_or(0)
}

/// Poll `check` every two seconds for up to `tries` rounds.
fn wait_for<T>(tries: u32, mut check: impl FnMut() -> Option<T>) -> Option<T> {
    for _ in 0..tries {
        if let Some(found) = check() {
            return Some(found);
        }
        std::thread::sleep(PAUSE);
    }
    None
}

/// The text after `prefix` on the first line that starts with it.
#[must_use]
pub fn line_value(output: &str, prefix: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix))
        .map(|rest| rest.trim().to_string())
}

/// The address `bud wallet create` printed, without its `0x`.
fn wallet(root: &Path, file: &str) -> Result<String, String> {
    let output = bud(root, &["wallet", "create", "--key-file", file])?;
    line_value(&output, "address: 0x").ok_or_else(|| "wallet create printed no address".into())
}

fn scenario_live() -> Result<String, String> {
    let start = wait_for(90, || {
        let height = tip();
        (height > 0).then_some(height)
    })
    .ok_or("the RPC node reported no block within 180 s")?;
    let later = wait_for(30, || {
        let height = tip();
        (height > start).then_some(height)
    })
    .ok_or_else(|| format!("the tip stayed at {start} for 60 s"))?;
    Ok(format!("tip {start} -> {later}"))
}

fn scenario_producers() -> Result<String, String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut scanned = 0u64;
    let found = wait_for(120, || {
        let height = tip();
        while scanned < height {
            scanned += 1;
            if let Some(producer) = call("bud_getBlockByNumber", &format!("[{scanned}]"))
                .as_ref()
                .and_then(|block| block.get("producer"))
                .and_then(crate::json::Value::as_str)
            {
                seen.insert(producer.to_string());
            }
        }
        (seen.len() >= 4).then_some(())
    });
    match found {
        Some(()) => Ok(format!("{} producers in blocks 1..={scanned}", seen.len())),
        None => Err(format!(
            "only {} producers in blocks 1..={scanned}",
            seen.len()
        )),
    }
}

fn finalized() -> u64 {
    call("bud_getStatus", "[]")
        .as_ref()
        .and_then(|status| status.get("finalizedHeight"))
        .and_then(quantity)
        .unwrap_or(0)
}

fn scenario_finality() -> Result<String, String> {
    let first = wait_for(120, || {
        let height = finalized();
        (height > 0).then_some(height)
    })
    .ok_or("nothing finalized within 240 s")?;
    let later = wait_for(60, || {
        let height = finalized();
        (height > first).then_some(height)
    })
    .ok_or_else(|| format!("finality stayed at {first}"))?;
    Ok(format!("finalized {first} -> {later}"))
}

fn scenario_global_header() -> Result<String, String> {
    let header = wait_for(60, || {
        call("bud_getGlobalHeader", "[0]").filter(|value| *value != crate::json::Value::Null)
    })
    .ok_or("no committed global header at global height 0")?;
    let hash = header
        .get("hash")
        .and_then(crate::json::Value::as_str)
        .unwrap_or("?")
        .to_string();
    Ok(format!("global header 0: {hash}"))
}

struct Wallets {
    alice: String,
    bob: String,
}

fn scenario_faucet(root: &Path) -> Result<(Wallets, String), String> {
    let alice = wallet(root, "/tmp/rehearsal-alice.key")?;
    let bob = wallet(root, "/tmp/rehearsal-bob.key")?;
    let body = format!("{{\"address\":\"0x{alice}\"}}");
    let reply = rpc::request(
        "POST",
        FAUCET_PORT,
        "/request",
        Some(&body),
        Duration::from_secs(30),
    )?;
    if !reply.is_success() {
        return Err(format!(
            "faucet answered HTTP {}: {}",
            reply.status, reply.body
        ));
    }
    let funded = wait_for(60, || {
        let amount = balance(&alice);
        (amount > 0).then_some(amount)
    })
    .ok_or("the faucet grant did not land within 120 s")?;
    let detail = format!("alice 0x{alice} holds {funded}");
    Ok((Wallets { alice, bob }, detail))
}

fn scenario_transfer(root: &Path, wallets: &Wallets) -> Result<String, String> {
    const AMOUNT: u64 = 1_000_000;
    let output = bud(
        root,
        &[
            "tx",
            "send",
            "--key-file",
            "/tmp/rehearsal-alice.key",
            "--to",
            &wallets.bob,
            "--amount",
            &AMOUNT.to_string(),
            "--fee",
            "1000",
        ],
    )?;
    // A V3 wallet (`bud wallet create`) signs V7; a legacy file signs V5.
    let hash = line_value(&output, "tx hash (signed, V7):")
        .or_else(|| line_value(&output, "tx hash (signed, V5):"))
        .ok_or("tx send printed no hash")?;
    wait_for(60, || (balance(&wallets.bob) >= AMOUNT).then_some(()))
        .ok_or("the transfer did not land within 120 s")?;
    let path = format!("/v1/txs/{}", hash.trim_start_matches("0x"));
    wait_for(60, || {
        rpc::request("GET", INDEXER_PORT, &path, None, Duration::from_secs(5))
            .ok()
            .filter(rpc::Reply::is_success)
    })
    .ok_or_else(|| format!("the explorer API did not serve {path} within 120 s"))?;
    Ok(format!("transfer {hash} landed and the explorer serves it"))
}

fn genesis_validator(root: &Path) -> Result<String, String> {
    let record = compose(
        root,
        &[
            "exec",
            "-T",
            "rpc",
            "cat",
            "/home/budlum/ceremony/operators/validator1.json",
        ],
    )?;
    crate::json::parse(&record)?
        .get("validator")
        .and_then(crate::json::Value::as_str)
        .map(|address| address.trim_start_matches("0x").to_string())
        .ok_or_else(|| "validator1.json names no validator".into())
}

fn scenario_delegation(root: &Path) -> Result<String, String> {
    let validator = genesis_validator(root)?;
    bud(
        root,
        &[
            "delegate",
            "--key-file",
            "/tmp/rehearsal-alice.key",
            "--validator",
            &validator,
            "--amount-bud",
            "10",
        ],
    )?;
    let delegated = wait_for(60, || {
        call("bud_getValidatorDelegations", &format!("[\"{validator}\"]"))
            .as_ref()
            .and_then(|value| value.get("activeDelegatedStake"))
            .and_then(quantity)
            .filter(|stake| *stake > 0)
    })
    .ok_or("the delegation did not appear within 120 s")?;
    Ok(format!(
        "validator {validator} carries {delegated} delegated"
    ))
}

fn scenario_bns(root: &Path, wallets: &Wallets) -> Result<String, String> {
    let name = "rehearsal.bud";
    bud(
        root,
        &[
            "bns",
            "register",
            "--key-file",
            "/tmp/rehearsal-alice.key",
            "--name",
            name,
            "--duration",
            "1000",
        ],
    )?;
    let owner = wait_for(60, || {
        call("bud_bnsResolve", &format!("[\"{name}\"]"))
            .as_ref()
            .and_then(crate::json::Value::as_str)
            .map(str::to_string)
    })
    .ok_or("the name did not resolve within 120 s")?;
    if owner.trim_start_matches("0x") != wallets.alice {
        return Err(format!("{name} resolves to {owner}, not to its registrant"));
    }
    Ok(format!("{name} -> {owner}"))
}

fn scenario_graft(root: &Path) -> Result<String, String> {
    const DOMAIN: &str = "4242";
    const ORIGIN: &str = "00000000000000000000000000000000000000aa";
    bud(
        root,
        &[
            "domain",
            "register-pow",
            "--key-file",
            "/tmp/rehearsal-alice.key",
            "--id",
            DOMAIN,
            "--chain-id",
            "4242",
        ],
    )?;
    wait_for(60, || {
        call("bud_getDomainInfo", &format!("[{DOMAIN}]"))
            .as_ref()
            .and_then(|info| info.get("registered"))
            .filter(|registered| **registered == crate::json::Value::Bool(true))
            .map(|_| ())
    })
    .ok_or("the PoW domain did not register within 120 s")?;
    let ids = bud(
        root,
        &["graft", "id", "--domain", DOMAIN, "--origin-app", ORIGIN],
    )?;
    let graft_id = line_value(&ids, "graft id: ").ok_or("graft id printed nothing")?;
    let mirror = line_value(&ids, "mirror account: 0x").ok_or("graft id printed no mirror")?;
    bud(
        root,
        &[
            "graft",
            "register",
            "--key-file",
            "/tmp/rehearsal-alice.key",
            "--domain",
            DOMAIN,
            "--origin-app",
            ORIGIN,
            "--manifest",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ],
    )?;
    wait_for(60, || {
        call("bud_getGraftApplication", &format!("[\"{graft_id}\"]"))
            .filter(|value| *value != crate::json::Value::Null)
    })
    .ok_or("the Graft application did not register within 120 s")?;
    bud(
        root,
        &[
            "graft",
            "pay",
            "--key-file",
            "/tmp/rehearsal-alice.key",
            "--graft-id",
            &graft_id,
            "--amount",
            "5000",
            "--origin-recipient",
            "01",
        ],
    )?;
    let held = wait_for(60, || {
        let amount = balance(&mirror);
        (amount >= 5000).then_some(amount)
    })
    .ok_or("the Graft payment did not reach the mirror within 120 s")?;
    Ok(format!(
        "application {graft_id}: mirror 0x{mirror} holds {held}"
    ))
}

fn run_scenarios(root: &Path) -> Vec<Verdict> {
    let mut verdicts = Vec::new();
    let mut push = |name: &'static str, result: Result<String, String>| -> bool {
        let ok = result.is_ok();
        verdicts.push(Verdict { name, result });
        ok
    };
    if !push("1. chain is live", scenario_live())
        || !push("2. four PoS producers", scenario_producers())
        || !push("3. finality advances", scenario_finality())
        || !push("4. global header committed", scenario_global_header())
    {
        return verdicts;
    }
    let wallets = match scenario_faucet(root) {
        Ok((wallets, detail)) => {
            push("5. faucet grant", Ok(detail));
            wallets
        }
        Err(error) => {
            push("5. faucet grant", Err(error));
            return verdicts;
        }
    };
    let _ = push(
        "6. transfer and explorer",
        scenario_transfer(root, &wallets),
    ) && push("7. delegation", scenario_delegation(root))
        && push("8. BNS name", scenario_bns(root, &wallets))
        && push("9. Graft register and pay", scenario_graft(root))
        && push("10. load", scenario_load(root, &wallets))
        && push("11. validator loss and rejoin", scenario_chaos(root));
    verdicts
}

fn nonce(address: &str) -> u64 {
    call("bud_getNonce", &format!("[\"{address}\"]"))
        .as_ref()
        .and_then(quantity)
        .unwrap_or(0)
}

/// item 4: send `LOAD_TXS` transfers with consecutive nonces and
/// measure how long the chain takes to include all of them. The number is a
/// measurement of this local topology and a sequential submitter, and the
/// report says so; it is not a capacity claim.
fn scenario_load(root: &Path, wallets: &Wallets) -> Result<String, String> {
    const LOAD_TXS: u64 = 40;
    const AMOUNT: u64 = 1_000;
    let first = nonce(&wallets.alice);
    let before = balance(&wallets.bob);
    let started = std::time::Instant::now();
    for offset in 0..LOAD_TXS {
        bud(
            root,
            &[
                "tx",
                "send",
                "--key-file",
                "/tmp/rehearsal-alice.key",
                "--to",
                &wallets.bob,
                "--amount",
                &AMOUNT.to_string(),
                "--fee",
                "1000",
                "--nonce",
                &(first + offset).to_string(),
            ],
        )?;
    }
    let submitted = started.elapsed();
    let target = before.saturating_add(LOAD_TXS * AMOUNT);
    wait_for(150, || (balance(&wallets.bob) >= target).then_some(()))
        .ok_or("the load did not land within 300 s")?;
    let included = started.elapsed();
    let rate = f64::from(u32::try_from(LOAD_TXS).unwrap_or(u32::MAX)) / included.as_secs_f64();
    Ok(format!(
        "{LOAD_TXS} transfers submitted in {:.1} s, all included after {:.1} s: {rate:.2} tx/s end to end (local four-validator topology, one sequential submitter)",
        submitted.as_secs_f64(),
        included.as_secs_f64()
    ))
}

/// item 5 (node loss): stop one of four validators, check finality
/// still advances on the remaining three (above two thirds), bring it back
/// and check it produces again, which it can only do once it has synced.
fn scenario_chaos(root: &Path) -> Result<String, String> {
    let validator4 = validator4_address(root).ok_or("validator4.json names no validator")?;
    compose(root, &["stop", "validator4"])?;
    let stopped_at = finalized();
    let advanced = wait_for(90, || {
        let height = finalized();
        (height > stopped_at).then_some(height)
    });
    let restart = compose(root, &["start", "validator4"]);
    let advanced = advanced
        .ok_or_else(|| format!("finality stayed at {stopped_at} with one validator down"))?;
    restart?;
    let rejoined_from = tip();
    let rejoined = wait_for(150, || {
        let height = tip();
        (rejoined_from + 1..=height).find(|h| {
            call("bud_getBlockByNumber", &format!("[{h}]"))
                .as_ref()
                .and_then(|block| block.get("producer"))
                .and_then(crate::json::Value::as_str)
                .is_some_and(|producer| {
                    producer
                        .trim_start_matches("0x")
                        .eq_ignore_ascii_case(&validator4)
                })
        })
    });
    match rejoined {
        Some(height) => Ok(format!(
            "finality {stopped_at} -> {advanced} with validator4 down; validator4 produced block {height} after restart"
        )),
        None => Err("validator4 did not produce a block within 300 s of its restart".into()),
    }
}

fn validator4_address(root: &Path) -> Option<String> {
    let record = compose(
        root,
        &[
            "exec",
            "-T",
            "rpc",
            "cat",
            "/home/budlum/ceremony/operators/validator4.json",
        ],
    )
    .ok()?;
    crate::json::parse(&record)
        .ok()?
        .get("validator")
        .and_then(crate::json::Value::as_str)
        .map(|address| address.trim_start_matches("0x").to_string())
}

fn report_text(verdicts: &[Verdict]) -> String {
    let mut text = String::from(
        "# Testnet rehearsal report\n\n| Scenario | Result | Detail |\n|---|---|---|\n",
    );
    for verdict in verdicts {
        let (result, detail) = match &verdict.result {
            Ok(detail) => ("pass", detail.as_str()),
            Err(error) => ("FAIL", error.as_str()),
        };
        let detail = detail.replace('|', "\\|").replace('\n', " ");
        let _ = writeln!(text, "| {} | {result} | {detail} |", verdict.name);
    }
    text
}

/// Run the preflight, and with `--compose` the local rehearsal.
///
/// # Errors
///
/// A preflight refusal, a docker failure, or any failed scenario (after the
/// report is written).
pub fn run(root: &Path, args: &[&str]) -> Result<String, String> {
    let options = Options::parse(args)?;
    let checks = preflight(root)?;
    if !options.compose {
        return Ok(format!(
            "testnet rehearsal preflight passed ({} checks); run with --compose for the scenarios",
            checks.len()
        ));
    }
    if !has_program("docker") {
        return Err("--compose requires docker on PATH".into());
    }
    run_checked(
        "docker",
        &["compose", "-f", COMPOSE_FILE, "config", "--quiet"],
        root,
    )?;
    run_checked(
        "docker",
        &["compose", "-f", COMPOSE_FILE, "up", "-d", "--build"],
        root,
    )?;
    let verdicts = run_scenarios(root);
    let report = report_text(&verdicts);
    let path = options
        .report
        .unwrap_or_else(|| root.join("target/testnet-rehearsal.md"));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, &report).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    print!("{report}");
    if !options.keep_running {
        run_checked(
            "docker",
            &["compose", "-f", COMPOSE_FILE, "down", "-v"],
            root,
        )?;
    }
    let failed: Vec<&str> = verdicts
        .iter()
        .filter(|verdict| verdict.result.is_err())
        .map(|verdict| verdict.name)
        .collect();
    if failed.is_empty() && verdicts.len() == SCENARIOS {
        Ok(format!(
            "testnet rehearsal passed: {SCENARIOS} of {SCENARIOS} scenarios; report at {}",
            path.display()
        ))
    } else {
        Err(format!(
            "testnet rehearsal failed at {:?}; report at {}",
            failed,
            path.display()
        ))
    }
}

/// The tool canary used by `budlum-tools --self-test`.
///
/// # Errors
///
/// Returns the checked-repository or preflight failure unchanged.
pub fn self_test() -> Result<String, String> {
    let root = checked_repo_root()?;
    let checks = preflight(&root)?;
    Ok(format!(
        "testnet-rehearsal: {} preflight checks passed",
        checks.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_requires_four_pos_validators() {
        let compose = "validator1: validator2: validator3: validator4: --consensus=pos";
        assert_eq!(count_text(compose, "--consensus=pos"), 1);
        assert!(require_text(compose, "validator4:", "compose").is_ok());
    }

    #[test]
    fn options_parse_the_report_path_only_with_compose() {
        let options = Options::parse(&[]).expect("default options");
        assert!(!options.compose);
        assert!(!options.keep_running);
        assert!(Options::parse(&["--report", "out.md"]).is_err());
        let options = Options::parse(&["--compose", "--report", "out.md"]).expect("compose");
        assert_eq!(options.report, Some(PathBuf::from("out.md")));
        assert!(Options::parse(&["--compose", "--report"]).is_err());
    }

    #[test]
    fn reads_cli_output_lines() {
        let output = "address: 0xabc\nkey file: /tmp/x\n";
        assert_eq!(line_value(output, "address: 0x"), Some("abc".into()));
        assert_eq!(line_value(output, "missing"), None);
    }

    #[test]
    fn the_report_marks_failures() {
        let verdicts = vec![
            Verdict {
                name: "1. chain is live",
                result: Ok("tip 1 -> 2".into()),
            },
            Verdict {
                name: "2. four PoS producers",
                result: Err("only 3 | producers".into()),
            },
        ];
        let text = report_text(&verdicts);
        assert!(text.contains("| 1. chain is live | pass | tip 1 -> 2 |"));
        assert!(text.contains("| 2. four PoS producers | FAIL | only 3 \\| producers |"));
    }
}
