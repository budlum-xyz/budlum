//! The local testnet rehearsal (`--compose` or `--local` native processes).
//!
//! Without `--compose` or `--local` the tool is a dependency-free preflight:
//! it checks the ceremony, the `PoS` validator topology, the public services,
//! the monitoring files and the documented endpoints. CI runs it on every pull
//! request.
//!
//! With `--compose` it builds the images, starts `ops/testnet-local.yml`
//! (validators, an RPC node, the faucet, the explorer API, Prometheus,
//! Grafana) and runs the module scenarios against it.
//!
//! With `--local` it spawns native `budlum-core`, `budlum-faucet`, and
//! `budlum-indexer` processes on loopback using pre-built binaries in
//! `target/release` (or `--bin-dir`), assembles a fresh testnet ceremony on
//! chain `45261` wired as a 3-regular chordal ring, and runs the same live
//! Graft, domain, delegation, BNS, faucet, and finality scenarios plus
//! public/operator RPC split and multi-VM/storage checks.
//!
//! Each scenario's verdict and measurements go to the report file (default
//! `target/testnet-rehearsal.md`). The first failure stops the run; the
//! report still records what passed before it.

use crate::{checked_repo_root, has_program, rpc, run_checked};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const COMPOSE_FILE: &str = "ops/testnet-local.yml";
/// Loopback ports `ops/testnet-local.yml` and `--local` publish.
const RPC_PORT: u16 = 28545;
/// Keep the native node's bounded per-IP budget in sync with config/testnet.toml.
const TESTNET_RPC_RATE_LIMIT_PER_MINUTE: u64 = 600;
const RPC_OPERATOR_PORT: u16 = 28546;
const FAUCET_PORT: u16 = 28600;
const INDEXER_PORT: u16 = 28700;
/// Base P2P port for `--local` validators (`25001..=25008`, RPC on `25009`).
const LOCAL_P2P_BASE: u16 = 25000;
/// Base validator RPC/metrics ports for `--local` seats (`28800+`, `29100+`).
const LOCAL_VAL_RPC_BASE: u16 = 28800;
const LOCAL_VAL_OP_BASE: u16 = 28820;
const LOCAL_VAL_METRICS_BASE: u16 = 29100;
/// A throwaway password for the rehearsal's throwaway wallets.
const WALLET_PASSWORD: &str = "rehearsal-only-password";
const PAUSE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Preflight,
    Compose,
    Local,
}

#[derive(Debug, Clone)]
struct Options {
    mode: Mode,
    keep_running: bool,
    bin_dir: Option<PathBuf>,
    report: Option<PathBuf>,
}

impl Options {
    fn parse(args: &[&str]) -> Result<Self, String> {
        let mut options = Self {
            mode: Mode::Preflight,
            keep_running: false,
            bin_dir: None,
            report: None,
        };
        let mut index = 0;
        while let Some(arg) = args.get(index) {
            match *arg {
                "--compose" => {
                    if options.mode == Mode::Local {
                        return Err("--compose and --local are mutually exclusive".into());
                    }
                    options.mode = Mode::Compose;
                }
                "--local" => {
                    if options.mode == Mode::Compose {
                        return Err("--compose and --local are mutually exclusive".into());
                    }
                    options.mode = Mode::Local;
                }
                "--keep" => options.keep_running = true,
                "--bin-dir" => {
                    index += 1;
                    let path = args.get(index).ok_or("--bin-dir needs a path")?;
                    options.bin_dir = Some(PathBuf::from(path));
                }
                "--report" => {
                    index += 1;
                    let path = args.get(index).ok_or("--report needs a path")?;
                    options.report = Some(PathBuf::from(path));
                }
                "--help" | "-h" => {
                    return Err(
                        "usage: testnet-rehearsal [--compose | --local [--bin-dir <dir>]] [--keep] [--report <path>]"
                            .into(),
                    )
                }
                unknown => return Err(format!("unknown testnet-rehearsal option `{unknown}`")),
            }
            index += 1;
        }
        if options.report.is_some() && options.mode == Mode::Preflight {
            return Err(
                "--report needs --compose or --local: the preflight runs no scenario".into(),
            );
        }
        if options.bin_dir.is_some() && options.mode != Mode::Local {
            return Err("--bin-dir is only valid with --local".into());
        }
        Ok(options)
    }
}

fn required_file(root: &Path, relative: &str, checks: &mut Vec<String>) -> Result<String, String> {
    let path = root.join(relative);
    let contents = fs::read_to_string(&path)
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

fn is_eight_seat_repo(root: &Path) -> bool {
    root.join("ops/testnet-local-validator.py").is_file()
}

fn preflight(root: &Path) -> Result<Vec<String>, String> {
    let mut checks = Vec::new();
    let genesis = required_file(root, "config/testnet-genesis.json", &mut checks)?;
    require_text(&genesis, "\"chain_id\": 45261", "testnet genesis")?;
    require_text(&genesis, "\"block_reward\": 0", "testnet genesis")?;
    require_text(&genesis, "\"bud_tokenomics\"", "testnet genesis")?;

    let compose = required_file(root, COMPOSE_FILE, &mut checks)?;
    let profile = required_file(root, "config/testnet.toml", &mut checks)?;
    require_text(&profile, "chain_id = 45261", "testnet profile")?;
    require_text(
        &profile,
        &format!("rate_limit_per_minute = {TESTNET_RPC_RATE_LIMIT_PER_MINUTE}"),
        "testnet profile",
    )?;
    if compose.contains("\n  validator8:\n") {
        require_text(&profile, "auth_required = false", "testnet profile")?;
        require_text(&profile, "operator_auth_required = true", "testnet profile")?;
    } else {
        require_text(&profile, "auth_required = true", "testnet profile")?;
    }
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
    let validator_launcher = if compose.contains("testnet-local-validator.py") {
        Some(required_file(
            root,
            "ops/testnet-local-validator.py",
            &mut checks,
        )?)
    } else {
        None
    };
    let pos_via_launcher = validator_launcher
        .as_deref()
        .is_some_and(|script| script.contains("\"--consensus=pos\""))
        && count_text(&compose, "testnet-local-validator.py") >= 4
        && count_text(&compose, "--consensus=pos") >= 1;
    if count_text(&compose, "--consensus=pos") < 5 && !pos_via_launcher {
        return Err(
            "local testnet compose must start four validators and one RPC node with PoS".into(),
        );
    }
    if compose.contains("--consensus=pow")
        || validator_launcher
            .as_deref()
            .is_some_and(|script| script.contains("--consensus=pow"))
    {
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

/// The chain the rehearsal runs against, and the replay domain every `bud`
/// invocation must name: the testnet profile pins `chain_id = 45261` and
/// `bud` refuses to sign without being told the domain by hand, because the
/// node's `bud_chainId` answer is untrusted input.
const CHAIN_ID: u64 = 45261;

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

/// The `docker compose exec` arguments of one `bud` run inside the RPC
/// container: the chain the rehearsal signs for is named here, once, so no
/// scenario can sign for whatever chain the node happens to answer with.
#[must_use]
fn bud_args(args: &[&str]) -> Vec<String> {
    let mut full: Vec<String> = [
        "exec",
        "-T",
        "-e",
        "BUD_WALLET_PASSWORD",
        "rpc",
        "bud",
        "--rpc-url",
        "http://127.0.0.1:8545",
        "--signing-chain-id",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    full.push(CHAIN_ID.to_string());
    full.extend(args.iter().map(|s| (*s).to_string()));
    full
}

/// Local `--local` process stack with RAII teardown.
struct LocalStack {
    work_dir: PathBuf,
    ceremony_dir: PathBuf,
    bin_dir: PathBuf,
    seats: usize,
    eight_seat: bool,
    keep_running: bool,
    bootnodes: Vec<String>,
    validators: Vec<Option<Child>>,
    services: Vec<Child>,
}

impl Drop for LocalStack {
    fn drop(&mut self) {
        if self.keep_running {
            return;
        }
        for child in &mut self.services {
            let _ = child.kill();
            let _ = child.wait();
        }
        for slot in &mut self.validators {
            if let Some(mut child) = slot.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        let _ = fs::remove_dir_all(&self.work_dir);
    }
}

/// Chordal-ring bootnodes (`(i+1)%n`, `(i+n-1)%n`, `(i+n/2)%n`) so every seat
/// connects to at most 3 validator peers (`<= max_peers_per_subnet = 4`).
#[must_use]
fn chordal_bootnodes(seat_zero_idx: usize, all_bootnodes: &[String]) -> Vec<String> {
    let n = all_bootnodes.len();
    if n <= 1 {
        return all_bootnodes.to_vec();
    }
    let mut out = Vec::new();
    for peer_idx in [
        (seat_zero_idx + 1) % n,
        (seat_zero_idx + n - 1) % n,
        (seat_zero_idx + n / 2) % n,
    ] {
        if peer_idx != seat_zero_idx {
            if let Some(addr) = all_bootnodes.get(peer_idx) {
                if !out.contains(addr) {
                    out.push(addr.clone());
                }
            }
        }
    }
    out
}

impl LocalStack {
    fn start(root: &Path, bin_dir: PathBuf, keep_running: bool) -> Result<Self, String> {
        for bin in ["budlum-core", "bud", "budlum-faucet", "budlum-indexer"] {
            let path = bin_dir.join(bin);
            if !path.is_file() {
                return Err(format!(
                    "missing binary {}: build release binaries before running `--local`",
                    path.display()
                ));
            }
        }

        let eight_seat = is_eight_seat_repo(root);
        let seats = if eight_seat { 8 } else { 4 };
        let stamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let work_dir = std::env::temp_dir().join(format!(
            "budlum-rehearsal-{}-{stamp_ns}",
            std::process::id()
        ));
        let ceremony_dir = work_dir.join("ceremony");
        let operators_dir = ceremony_dir.join("operators");
        let logs_dir = work_dir.join("logs");
        fs::create_dir_all(&operators_dir)
            .map_err(|e| format!("cannot create {}: {e}", operators_dir.display()))?;
        fs::create_dir_all(&logs_dir)
            .map_err(|e| format!("cannot create {}: {e}", logs_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = fs::set_permissions(&work_dir, fs::Permissions::from_mode(0o700));
            let _ = fs::set_permissions(&ceremony_dir, fs::Permissions::from_mode(0o700));
        }

        let mut stack = Self {
            work_dir,
            ceremony_dir,
            bin_dir,
            seats,
            eight_seat,
            keep_running,
            bootnodes: Vec::with_capacity(seats),
            validators: (0..seats).map(|_| None).collect(),
            services: Vec::new(),
        };
        stack.assemble_ceremony(root)?;
        for seat in 1..=seats {
            stack.spawn_validator(root, seat)?;
        }
        stack.spawn_rpc_node(root)?;
        stack.spawn_faucet_and_indexer(root)?;
        Ok(stack)
    }

    fn run_bin(&self, root: &Path, bin: &str, args: &[&str]) -> Result<String, String> {
        let exe = self.bin_dir.join(bin);
        let out = Command::new(&exe)
            .args(args)
            .env("BUD_WALLET_PASSWORD", WALLET_PASSWORD)
            .current_dir(root)
            .output()
            .map_err(|e| format!("cannot run {}: {e}", exe.display()))?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if out.status.success() {
            Ok(stdout)
        } else {
            Err(format!(
                "`{bin} {}` failed: {}{}",
                args.join(" "),
                stdout,
                String::from_utf8_lossy(&out.stderr)
            ))
        }
    }

    fn assemble_ceremony(&mut self, root: &Path) -> Result<(), String> {
        let operators_dir = self.ceremony_dir.join("operators");
        for seat in 1..=self.seats {
            let key_file = self.ceremony_dir.join(format!("validator{seat}.key"));
            let rec_file = operators_dir.join(format!("validator{seat}.json"));
            let moniker = format!("validator{seat}");
            self.run_bin(
                root,
                "bud",
                &[
                    "validator",
                    "init",
                    "--chain-id",
                    "45261",
                    "--moniker",
                    &moniker,
                    "--key-file",
                    &key_file.to_string_lossy(),
                    "--record-out",
                    &rec_file.to_string_lossy(),
                ],
            )?;
            let id_file = self.ceremony_dir.join(format!("validator{seat}.p2p"));
            let port = LOCAL_P2P_BASE
                .checked_add(u16::try_from(seat).map_err(|_| "seat index overflow")?)
                .ok_or("port overflow")?;
            let id_out = self.run_bin(
                root,
                "bud",
                &[
                    "node",
                    "identity",
                    "--identity-file",
                    &id_file.to_string_lossy(),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    &port.to_string(),
                ],
            )?;
            let boot = line_value(&id_out, "bootnode (config [p2p] bootnodes): ")
                .map(|raw| raw.trim_matches('"').to_string())
                .ok_or_else(|| format!("node identity printed no bootnode for validator{seat}"))?;
            self.bootnodes.push(boot);
        }

        let faucet_seed = self.ceremony_dir.join("faucet.seed");
        let faucet_out = self.run_bin(
            root,
            "budlum-faucet",
            &["keygen", "--out", &faucet_seed.to_string_lossy()],
        )?;
        let faucet_addr = line_value(&faucet_out, "faucet address: 0x")
            .ok_or("budlum-faucet keygen printed no address")?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let genesis_out = self.ceremony_dir.join("genesis.json");
        self.run_bin(
            root,
            "bud",
            &[
                "genesis",
                "assemble",
                "--network",
                "testnet",
                "--operators",
                &operators_dir.to_string_lossy(),
                "--timestamp-ms",
                &now_ms.to_string(),
                "--community",
                &faucet_addr,
                "--liquidity",
                "5151515151515151515151515151515151515151515151515151515151515151",
                "--ecosystem",
                "5252525252525252525252525252525252525252525252525252525252525252",
                "--team",
                "5353535353535353535353535353535353535353535353535353535353535353",
                "--burn-reserve",
                "5454545454545454545454545454545454545454545454545454545454545454",
                "--out",
                &genesis_out.to_string_lossy(),
            ],
        )?;
        Ok(())
    }

    fn spawn_validator(&mut self, root: &Path, seat: usize) -> Result<(), String> {
        let seat_u16 = u16::try_from(seat).map_err(|_| "seat overflow")?;
        let seat_dir = self.work_dir.join(format!("validator{seat}"));
        fs::create_dir_all(&seat_dir)
            .map_err(|e| format!("cannot create {}: {e}", seat_dir.display()))?;
        let peers = chordal_bootnodes(seat - 1, &self.bootnodes);
        let first_boot = peers
            .first()
            .cloned()
            .ok_or_else(|| format!("validator{seat} has no bootnode"))?;
        let quoted: Vec<String> = peers.iter().map(|b| format!("\"{b}\"")).collect();
        let toml_path = seat_dir.join("node.toml");
        let toml_body = format!(
            "[p2p]\nbootnodes = [{}]\nvote_history_db = \"{}\"\nbanned_peer_db = \"{}\"\n",
            quoted.join(", "),
            seat_dir.join("vote-history.json").display(),
            seat_dir.join("banned-peers.json").display()
        );
        fs::write(&toml_path, toml_body)
            .map_err(|e| format!("cannot write {}: {e}", toml_path.display()))?;

        let log_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(
                self.work_dir
                    .join("logs")
                    .join(format!("validator{seat}.log")),
            )
            .map_err(|e| format!("cannot open validator{seat}.log: {e}"))?;
        let err_file = log_file
            .try_clone()
            .map_err(|e| format!("cannot clone log fd: {e}"))?;

        let child = Command::new(self.bin_dir.join("budlum-core"))
            .arg(format!("--config={}", toml_path.display()))
            .arg("--network=testnet")
            .arg(format!(
                "--genesis-file={}",
                self.ceremony_dir.join("genesis.json").display()
            ))
            .arg("--consensus=pos")
            .arg("--role=validator")
            .arg(format!(
                "--validator-key-file={}",
                self.ceremony_dir
                    .join(format!("validator{seat}.key"))
                    .display()
            ))
            .arg(format!(
                "--p2p-identity-file={}",
                self.ceremony_dir
                    .join(format!("validator{seat}.p2p"))
                    .display()
            ))
            .arg(format!("--port={}", LOCAL_P2P_BASE + seat_u16))
            .arg(format!("--db-path={}", seat_dir.join("db").display()))
            .arg(format!(
                "--rpc-public-listener=127.0.0.1:{}",
                LOCAL_VAL_RPC_BASE + seat_u16
            ))
            .arg(format!(
                "--rpc-operator-listener=127.0.0.1:{}",
                LOCAL_VAL_OP_BASE + seat_u16
            ))
            .arg(format!(
                "--metrics-listener=127.0.0.1:{}",
                LOCAL_VAL_METRICS_BASE + seat_u16
            ))
            .arg(format!("--bootstrap={first_boot}"))
            .env("RUST_LOG", "info")
            .current_dir(root)
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(err_file))
            .spawn()
            .map_err(|e| format!("cannot spawn validator{seat}: {e}"))?;

        if let Some(slot) = self.validators.get_mut(seat - 1) {
            *slot = Some(child);
        }
        Ok(())
    }

    fn spawn_rpc_node(&mut self, root: &Path) -> Result<(), String> {
        let rpc_dir = self.work_dir.join("rpc");
        fs::create_dir_all(&rpc_dir)
            .map_err(|e| format!("cannot create {}: {e}", rpc_dir.display()))?;
        let rpc_peers: Vec<String> = self
            .bootnodes
            .iter()
            .take(2)
            .map(|b| format!("\"{b}\""))
            .collect();
        let rpc_toml = rpc_dir.join("node.toml");
        let rpc_section = if self.eight_seat {
            "\n[rpc]\nauth_required = false\noperator_auth_required = true\napi_key_env = \"BUDLUM_RPC_API_KEY\"\n"
        } else {
            ""
        };
        fs::write(
            &rpc_toml,
            format!(
                "[p2p]\nbootnodes = [{}]\nvote_history_db = \"{}\"\nbanned_peer_db = \"{}\"\n{rpc_section}",
                rpc_peers.join(", "),
                rpc_dir.join("vote-history.json").display(),
                rpc_dir.join("banned-peers.json").display()
            ),
        )
        .map_err(|e| format!("cannot write {}: {e}", rpc_toml.display()))?;
        let boot0 = self
            .bootnodes
            .first()
            .cloned()
            .ok_or("missing validator1 bootnode")?;

        let rpc_log = fs::File::create(self.work_dir.join("logs/rpc.log"))
            .map_err(|e| format!("cannot create rpc.log: {e}"))?;
        let rpc_err = rpc_log
            .try_clone()
            .map_err(|e| format!("cannot clone rpc.log: {e}"))?;
        let rpc_child = Command::new(self.bin_dir.join("budlum-core"))
            .arg(format!("--config={}", rpc_toml.display()))
            .arg("--network=testnet")
            .arg(format!(
                "--genesis-file={}",
                self.ceremony_dir.join("genesis.json").display()
            ))
            .arg("--consensus=pos")
            .arg("--role=rpc")
            .arg(format!("--port={}", LOCAL_P2P_BASE + 9))
            .arg(format!("--db-path={}", rpc_dir.join("db").display()))
            .arg(format!(
                "--p2p-identity-file={}",
                rpc_dir.join("node-id.key").display()
            ))
            .arg(format!("--rpc-public-listener=127.0.0.1:{RPC_PORT}"))
            .arg(format!(
                "--rpc-operator-listener=127.0.0.1:{RPC_OPERATOR_PORT}"
            ))
            .arg("--metrics-listener=127.0.0.1:29090")
            .arg(format!("--bootstrap={boot0}"))
            .env("RUST_LOG", "info")
            .env("BUDLUM_RPC_AUTH_REQUIRED", "0")
            .env("BUDLUM_RPC_ALLOWED_IPS", "")
            // Native CLI, faucet and indexer all use loopback, so they share
            // one per-IP budget. Use the actual testnet profile's 600/minute,
            // not the server's fallback 120; retain a bounded limiter.
            .env(
                "BUDLUM_RPC_RATE_LIMIT_PER_MINUTE",
                TESTNET_RPC_RATE_LIMIT_PER_MINUTE.to_string(),
            )
            .env(
                "BUDLUM_RPC_API_KEY",
                "rehearsal-operator-key-0123456789abcdef",
            )
            .current_dir(root)
            .stdout(Stdio::from(rpc_log))
            .stderr(Stdio::from(rpc_err))
            .spawn()
            .map_err(|e| format!("cannot spawn rpc node: {e}"))?;
        self.services.push(rpc_child);

        wait_for(30, || call("bud_chainId", "[]"))
            .ok_or("local RPC node did not answer bud_chainId within 60 s")?;
        Ok(())
    }

    fn spawn_faucet_and_indexer(&mut self, root: &Path) -> Result<(), String> {
        let faucet_log = fs::File::create(self.work_dir.join("logs/faucet.log"))
            .map_err(|e| format!("cannot create faucet.log: {e}"))?;
        let faucet_err = faucet_log
            .try_clone()
            .map_err(|e| format!("cannot clone faucet.log: {e}"))?;
        let mut faucet_cmd = Command::new(self.bin_dir.join("budlum-faucet"));
        faucet_cmd
            .arg("serve")
            .arg(format!("--rpc-url=http://127.0.0.1:{RPC_PORT}"))
            .arg(format!(
                "--key-file={}",
                self.ceremony_dir.join("faucet.seed").display()
            ))
            .arg(format!("--listen=127.0.0.1:{FAUCET_PORT}"))
            .arg("--allow-direct");
        if self.eight_seat {
            faucet_cmd.arg(format!(
                "--state-file={}",
                self.work_dir.join("faucet-state.json").display()
            ));
        }
        let faucet_child = faucet_cmd
            .current_dir(root)
            .stdout(Stdio::from(faucet_log))
            .stderr(Stdio::from(faucet_err))
            .spawn()
            .map_err(|e| format!("cannot spawn budlum-faucet: {e}"))?;
        self.services.push(faucet_child);

        let idx_log = fs::File::create(self.work_dir.join("logs/indexer.log"))
            .map_err(|e| format!("cannot create indexer.log: {e}"))?;
        let idx_err = idx_log
            .try_clone()
            .map_err(|e| format!("cannot clone indexer.log: {e}"))?;
        let idx_child = Command::new(self.bin_dir.join("budlum-indexer"))
            .arg(format!("--rpc-url=http://127.0.0.1:{RPC_PORT}"))
            .arg(format!("--db={}", self.work_dir.join("indexer").display()))
            .arg(format!("--listen=127.0.0.1:{INDEXER_PORT}"))
            .arg("--allow-direct")
            .current_dir(root)
            .stdout(Stdio::from(idx_log))
            .stderr(Stdio::from(idx_err))
            .spawn()
            .map_err(|e| format!("cannot spawn budlum-indexer: {e}"))?;
        self.services.push(idx_child);

        wait_for(20, || {
            rpc::request("GET", FAUCET_PORT, "/health", None, Duration::from_secs(3))
                .ok()
                .filter(rpc::Reply::is_success)
        })
        .ok_or("local budlum-faucet /health did not come up within 40 s")?;
        wait_for(20, || {
            rpc::request("GET", INDEXER_PORT, "/health", None, Duration::from_secs(3))
                .ok()
                .filter(rpc::Reply::is_success)
        })
        .ok_or("local budlum-indexer /health did not come up within 40 s")?;
        Ok(())
    }

    fn stop_last_validator(&mut self) -> Result<usize, String> {
        let seat = self.seats;
        let slot = self
            .validators
            .get_mut(seat - 1)
            .ok_or("missing last validator slot")?;
        if let Some(mut child) = slot.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(seat)
    }
}

enum Backend<'a> {
    Compose { root: &'a Path, eight_seat: bool },
    Local { root: &'a Path, stack: LocalStack },
}

impl Backend<'_> {
    fn wallet_path(&self, name: &str) -> String {
        match self {
            Self::Compose { .. } => format!("/tmp/rehearsal-{name}.key"),
            Self::Local { stack, .. } => stack
                .work_dir
                .join(format!("{name}.key"))
                .display()
                .to_string(),
        }
    }

    fn bud(&self, args: &[&str]) -> Result<String, String> {
        match self {
            Self::Compose { root, .. } => {
                let full = bud_args(args);
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
            Self::Local { root, stack } => {
                let rpc_url = format!("http://127.0.0.1:{RPC_PORT}");
                let chain = CHAIN_ID.to_string();
                let mut full = vec!["--rpc-url", &rpc_url, "--signing-chain-id", &chain];
                full.extend_from_slice(args);
                stack.run_bin(root, "bud", &full)
            }
        }
    }

    fn request_faucet(&self, address_no_0x: &str) -> Result<(), String> {
        let addr = format!("0x{address_no_0x}");
        match self {
            Self::Compose { root, eight_seat } => {
                if *eight_seat {
                    compose(
                        root,
                        &[
                            "exec",
                            "-T",
                            "faucet",
                            "budlum-faucet",
                            "request",
                            "--url",
                            "http://127.0.0.1:18600",
                            "--address",
                            &addr,
                        ],
                    )?;
                    Ok(())
                } else {
                    let body = format!("{{\"address\":\"{addr}\"}}");
                    let reply = rpc::request(
                        "POST",
                        FAUCET_PORT,
                        "/request",
                        Some(&body),
                        Duration::from_secs(30),
                    )?;
                    if reply.is_success() {
                        Ok(())
                    } else {
                        Err(format!(
                            "faucet answered HTTP {}: {}",
                            reply.status, reply.body
                        ))
                    }
                }
            }
            Self::Local { root, stack } => {
                if stack.eight_seat {
                    let url = format!("http://127.0.0.1:{FAUCET_PORT}");
                    stack.run_bin(
                        root,
                        "budlum-faucet",
                        &["request", "--url", &url, "--address", &addr],
                    )?;
                    Ok(())
                } else {
                    let body = format!("{{\"address\":\"{addr}\"}}");
                    let reply = rpc::request(
                        "POST",
                        FAUCET_PORT,
                        "/request",
                        Some(&body),
                        Duration::from_secs(30),
                    )?;
                    if reply.is_success() {
                        Ok(())
                    } else {
                        Err(format!(
                            "faucet answered HTTP {}: {}",
                            reply.status, reply.body
                        ))
                    }
                }
            }
        }
    }

    fn validator_address(&self, seat: usize) -> Result<String, String> {
        let record = match self {
            Self::Compose { root, .. } => compose(
                root,
                &[
                    "exec",
                    "-T",
                    "rpc",
                    "cat",
                    &format!("/home/budlum/ceremony/operators/validator{seat}.json"),
                ],
            )?,
            Self::Local { stack, .. } => fs::read_to_string(
                stack
                    .ceremony_dir
                    .join("operators")
                    .join(format!("validator{seat}.json")),
            )
            .map_err(|e| format!("cannot read validator{seat}.json: {e}"))?,
        };
        crate::json::parse(&record)?
            .get("validator")
            .and_then(crate::json::Value::as_str)
            .map(|address| address.trim_start_matches("0x").to_string())
            .ok_or_else(|| format!("validator{seat}.json names no validator"))
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
fn wallet(backend: &Backend<'_>, file: &str) -> Result<String, String> {
    let output = backend.bud(&["wallet", "create", "--key-file", file])?;
    line_value(&output, "address: 0x").ok_or_else(|| "wallet create printed no address".into())
}

fn scenario_live(backend: &Backend<'_>) -> Result<String, String> {
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

    if let Backend::Local { stack, .. } = backend {
        // Verify the public listener refuses operator-only methods (-32004).
        let admin_body = rpc::call(
            RPC_PORT,
            "bud_adminBanPeer",
            "[\"12D3KooWanything\"]",
            Duration::from_secs(5),
        )?;
        if !admin_body.contains("\"error\"") {
            return Err("public RPC accepted operator-only bud_adminBanPeer".into());
        }
        if stack.eight_seat {
            // Verify operator_auth_required = true refuses unauthenticated HTTP calls.
            let op_reply = rpc::request(
                "POST",
                RPC_OPERATOR_PORT,
                "/",
                Some("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"bud_getStatus\",\"params\":[]}"),
                Duration::from_secs(5),
            )?;
            if op_reply.is_success() {
                return Err("operator RPC accepted an unauthenticated request".into());
            }
            let _ = call("eth_blockNumber", "[]").ok_or("public RPC failed eth_blockNumber")?;
            let zero_obj = format!("0x{}", "00".repeat(32));
            let storage_body = rpc::call(
                RPC_PORT,
                "bud_storageListViewGrants",
                &format!("[\"{zero_obj}\"]"),
                Duration::from_secs(5),
            )?;
            if storage_body.contains("-32601") {
                return Err("public RPC does not serve bud_storageListViewGrants".into());
            }
        }
    }
    Ok(format!("tip {start} -> {later}"))
}

fn scenario_producers() -> Result<String, String> {
    let mut seen = BTreeSet::new();
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
    alice_file: String,
    bob: String,
    bob_file: String,
}

fn scenario_faucet(backend: &Backend<'_>) -> Result<(Wallets, String), String> {
    let alice_file = backend.wallet_path("alice");
    let bob_file = backend.wallet_path("bob");
    let alice = wallet(backend, &alice_file)?;
    let bob = wallet(backend, &bob_file)?;
    backend.request_faucet(&alice)?;
    let funded = wait_for(60, || {
        let amount = balance(&alice);
        (amount > 0).then_some(amount)
    })
    .ok_or("the faucet grant did not land within 120 s")?;
    let detail = format!("alice 0x{alice} holds {funded}");
    Ok((
        Wallets {
            alice,
            alice_file,
            bob,
            bob_file,
        },
        detail,
    ))
}

fn scenario_transfer(backend: &Backend<'_>, wallets: &Wallets) -> Result<String, String> {
    const AMOUNT: u64 = 1_000_000;
    let output = backend.bud(&[
        "tx",
        "send",
        "--key-file",
        &wallets.alice_file,
        "--to",
        &wallets.bob,
        "--amount",
        &AMOUNT.to_string(),
        "--fee",
        "1000",
    ])?;
    let hash = line_value(&output, "tx hash (signed, V7):")
        .or_else(|| line_value(&output, "tx hash (signed, V5):"))
        .ok_or("tx send printed no hash")?;
    wait_for(60, || (balance(&wallets.bob) >= AMOUNT).then_some(()))
        .ok_or("the transfer did not land within 120 s")?;
    let path = format!("/v1/txs/{}", hash.trim_start_matches("0x"));
    wait_for(90, || {
        rpc::request("GET", INDEXER_PORT, &path, None, Duration::from_secs(5))
            .ok()
            .filter(rpc::Reply::is_success)
    })
    .ok_or_else(|| format!("the explorer API did not serve {path} within 180 s"))?;
    Ok(format!("transfer {hash} landed and the explorer serves it"))
}

fn scenario_delegation(backend: &Backend<'_>, wallets: &Wallets) -> Result<String, String> {
    let validator = backend.validator_address(1)?;
    backend.bud(&[
        "delegate",
        "--key-file",
        &wallets.alice_file,
        "--validator",
        &validator,
        "--amount-bud",
        "10",
    ])?;
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

fn scenario_bns(backend: &Backend<'_>, wallets: &Wallets) -> Result<String, String> {
    let name = "rehearsal.bud";
    backend.bud(&[
        "bns",
        "register",
        "--key-file",
        &wallets.alice_file,
        "--name",
        name,
        "--duration",
        "1000",
    ])?;
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

fn scenario_graft(backend: &Backend<'_>, wallets: &Wallets) -> Result<String, String> {
    const DOMAIN: &str = "4242";
    const ORIGIN: &str = "00000000000000000000000000000000000000aa";
    backend.bud(&[
        "domain",
        "register-pow",
        "--key-file",
        &wallets.alice_file,
        "--id",
        DOMAIN,
        "--chain-id",
        "4242",
    ])?;
    wait_for(60, || {
        call("bud_getDomainInfo", &format!("[{DOMAIN}]"))
            .as_ref()
            .and_then(|info| info.get("registered"))
            .filter(|registered| **registered == crate::json::Value::Bool(true))
            .map(|_| ())
    })
    .ok_or("the PoW domain did not register within 120 s")?;
    let ids = backend.bud(&["graft", "id", "--domain", DOMAIN, "--origin-app", ORIGIN])?;
    let graft_id = line_value(&ids, "graft id: ").ok_or("graft id printed nothing")?;
    let mirror = line_value(&ids, "mirror account: 0x").ok_or("graft id printed no mirror")?;
    let app_binding_closed = match backend {
        Backend::Compose { eight_seat, .. } => *eight_seat,
        Backend::Local { stack, .. } => stack.eight_seat,
    };
    let signer_file = if app_binding_closed {
        &wallets.bob_file
    } else {
        &wallets.alice_file
    };
    let before_tip = tip();
    let reg_attempt = backend.bud(&[
        "graft",
        "register",
        "--key-file",
        signer_file,
        "--domain",
        DOMAIN,
        "--origin-app",
        ORIGIN,
        "--manifest",
        "1111111111111111111111111111111111111111111111111111111111111111",
    ]);
    let query_params = format!("[\"{graft_id}\"]");
    let lookup_registered = || {
        call("bud_getGraftApplication", &query_params)
            .filter(|value| *value != crate::json::Value::Null)
    };
    if app_binding_closed {
        if reg_attempt.is_ok() {
            let _ = wait_for(15, || (tip() >= before_tip + 2).then_some(()));
        }
        if lookup_registered().is_some() {
            return Err("app_binding registered on testnet despite containment".into());
        }
        return Ok(format!(
            "domain {DOMAIN} registered; app_binding (mirror 0x{mirror}) contained on chain 45261"
        ));
    }
    reg_attempt?;
    wait_for(60, lookup_registered).ok_or("the Graft application did not register within 120 s")?;
    backend.bud(&[
        "graft",
        "pay",
        "--key-file",
        &wallets.alice_file,
        "--graft-id",
        &graft_id,
        "--amount",
        "5000",
        "--origin-recipient",
        "01",
    ])?;
    let held = wait_for(60, || {
        let amount = balance(&mirror);
        (amount >= 5000).then_some(amount)
    })
    .ok_or("the Graft payment did not reach the mirror within 120 s")?;
    Ok(format!(
        "application {graft_id}: mirror 0x{mirror} holds {held}"
    ))
}

fn nonce(address: &str) -> u64 {
    call("bud_getNonce", &format!("[\"{address}\"]"))
        .as_ref()
        .and_then(quantity)
        .unwrap_or(0)
}

fn scenario_load(backend: &Backend<'_>, wallets: &Wallets) -> Result<String, String> {
    const LOAD_TXS: u64 = 40;
    const AMOUNT: u64 = 1_000;
    let first = nonce(&wallets.alice);
    let before = balance(&wallets.bob);
    let started = std::time::Instant::now();
    for offset in 0..LOAD_TXS {
        backend.bud(&[
            "tx",
            "send",
            "--key-file",
            &wallets.alice_file,
            "--to",
            &wallets.bob,
            "--amount",
            &AMOUNT.to_string(),
            "--fee",
            "1000",
            "--nonce",
            &(first + offset).to_string(),
        ])?;
    }
    let submitted = started.elapsed();
    let target = before.saturating_add(LOAD_TXS * AMOUNT);
    wait_for(150, || (balance(&wallets.bob) >= target).then_some(()))
        .ok_or("the load did not land within 300 s")?;
    let included = started.elapsed();
    let rate = f64::from(u32::try_from(LOAD_TXS).unwrap_or(u32::MAX)) / included.as_secs_f64();
    Ok(format!(
        "{LOAD_TXS} transfers submitted in {:.1} s, all included after {:.1} s: {rate:.2} tx/s end to end",
        submitted.as_secs_f64(),
        included.as_secs_f64()
    ))
}

fn offline_progress(stopped_finality: u64, finality: u64, stopped_tip: u64, tip: u64) -> bool {
    finality > stopped_finality && tip >= stopped_tip.saturating_add(16)
}

fn scenario_chaos(backend: &mut Backend<'_>) -> Result<String, String> {
    let watched: Vec<String> = match &*backend {
        Backend::Compose { eight_seat, .. } => {
            let mut list = vec![backend.validator_address(4)?];
            if *eight_seat {
                if let Ok(v8) = backend.validator_address(8) {
                    list.push(v8);
                }
            }
            list
        }
        Backend::Local { stack, .. } => vec![backend.validator_address(stack.seats)?],
    };

    match backend {
        Backend::Compose { root, .. } => {
            compose(root, &["stop", "validator4"])?;
        }
        Backend::Local { stack, .. } => {
            stack.stop_last_validator()?;
        }
    }
    let stopped_at = finalized();
    let stopped_tip = tip();
    let mut observed_finality = stopped_at;
    let mut observed_tip = stopped_tip;
    let advanced = wait_for(90, || {
        observed_finality = finalized();
        observed_tip = tip();
        // Ensure >16 blocks elapse while the seat is offline so restarting
        // exercises multi-chunk `/sync` catch-up as well as >2/3 finality.
        offline_progress(stopped_at, observed_finality, stopped_tip, observed_tip)
            .then_some(observed_finality)
    });
    let restart = match backend {
        Backend::Compose { root, .. } => compose(root, &["start", "validator4"]).map(|_| ()),
        Backend::Local { root, stack } => stack.spawn_validator(root, stack.seats),
    };
    let advanced = advanced.ok_or_else(|| {
        format!(
            "validator offline: finalized {stopped_at}->{observed_finality}, tip \
             {stopped_tip}->{observed_tip}; require finalized > {stopped_at} AND tip >= {}",
            stopped_tip.saturating_add(16)
        )
    })?;
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
                    let clean = producer.trim_start_matches("0x");
                    watched.iter().any(|addr| clean.eq_ignore_ascii_case(addr))
                })
        })
    });
    match rejoined {
        Some(height) => Ok(format!(
            "finality {stopped_at} -> {advanced} with seat offline (tip {stopped_tip} -> {rejoined_from}); caught up and produced block {height}"
        )),
        None => Err("restarted validator did not catch up and produce a block within 300 s".into()),
    }
}

fn run_scenarios(backend: &mut Backend<'_>) -> Vec<Verdict> {
    let mut verdicts = Vec::new();
    let mut push = |name: &'static str, result: Result<String, String>| -> bool {
        let ok = result.is_ok();
        verdicts.push(Verdict { name, result });
        ok
    };
    if !push("1. chain is live", scenario_live(backend))
        || !push("2. four PoS producers", scenario_producers())
        || !push("3. finality advances", scenario_finality())
        || !push("4. global header committed", scenario_global_header())
    {
        return verdicts;
    }
    let wallets = match scenario_faucet(backend) {
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
        scenario_transfer(backend, &wallets),
    ) && push("7. delegation", scenario_delegation(backend, &wallets))
        && push("8. BNS name", scenario_bns(backend, &wallets))
        && push(
            "9. Graft register and pay",
            scenario_graft(backend, &wallets),
        )
        && push("10. load", scenario_load(backend, &wallets))
        && push("11. validator loss and rejoin", scenario_chaos(backend));
    verdicts
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

/// Run the preflight, or with `--compose` / `--local` the live rehearsal.
///
/// # Errors
///
/// A preflight refusal, a process/docker failure, or any failed scenario
/// (after the report is written).
pub fn run(root: &Path, args: &[&str]) -> Result<String, String> {
    let options = Options::parse(args)?;
    let checks = preflight(root)?;
    if options.mode == Mode::Preflight {
        return Ok(format!(
            "testnet rehearsal preflight passed ({} checks); run with --compose or --local for the scenarios",
            checks.len()
        ));
    }

    let verdicts = match options.mode {
        Mode::Preflight => Vec::new(),
        Mode::Compose => {
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
            let mut backend = Backend::Compose {
                root,
                eight_seat: is_eight_seat_repo(root),
            };
            let out = run_scenarios(&mut backend);
            if !options.keep_running {
                let _ = run_checked(
                    "docker",
                    &["compose", "-f", COMPOSE_FILE, "down", "-v"],
                    root,
                );
            }
            out
        }
        Mode::Local => {
            let bin_dir = options
                .bin_dir
                .clone()
                .unwrap_or_else(|| root.join("target/release"));
            let stack = LocalStack::start(root, bin_dir, options.keep_running)?;
            let mut backend = Backend::Local { root, stack };
            run_scenarios(&mut backend)
        }
    };

    let report = report_text(&verdicts);
    let path = options
        .report
        .unwrap_or_else(|| root.join("target/testnet-rehearsal.md"));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    fs::write(&path, &report).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    print!("{report}");
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
    let ring: Vec<String> = (1..=8).map(|i| format!("boot{i}")).collect();
    for seat in 0..8 {
        let peers = chordal_bootnodes(seat, &ring);
        if peers.len() != 3 {
            return Err(format!(
                "chordal_bootnodes({seat}) returned {} peers, expected 3",
                peers.len()
            ));
        }
    }
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
    fn native_rpc_budget_matches_the_bounded_testnet_profile() {
        let profile = include_str!("../../../config/testnet.toml");
        let needle = format!("rate_limit_per_minute = {TESTNET_RPC_RATE_LIMIT_PER_MINUTE}");
        assert!(require_text(profile, &needle, "testnet profile").is_ok());
        let drifted = profile.replace(&needle, "rate_limit_per_minute = 120");
        assert!(require_text(&drifted, &needle, "testnet profile").is_err());
    }

    #[test]
    fn compose_dialers_wait_for_a_listening_bootnode() {
        // A previous rehearsal had producing validators but RPC remained at
        // genesis: it dialed validator1 before port 5001 was open, got two
        // connection refusals, and never joined the mesh (run 43106806155).
        let compose = include_str!("../../../ops/testnet-local.yml");
        if compose.contains("\n  validator8:\n") {
            // The eight-seat topology uses a different bootstrap launcher.
            return;
        }
        let bootnode = compose
            .split_once("\n  validator1:\n")
            .expect("validator1 service")
            .1
            .split_once("\n  validator2:\n")
            .expect("validator2 service")
            .0;
        assert!(bootnode.contains("bash -c 'exec 3<>/dev/tcp/127.0.0.1/5001'"));
        for (service, next) in [
            ("validator2", "validator3"),
            ("validator3", "validator4"),
            ("validator4", "rpc"),
            ("rpc", "faucet"),
        ] {
            let block = compose
                .split_once(&format!("\n  {service}:\n"))
                .unwrap_or_else(|| panic!("missing {service} service"))
                .1
                .split_once(&format!("\n  {next}:\n"))
                .unwrap_or_else(|| panic!("missing {next} service"))
                .0;
            assert!(
                block.contains("      validator1:\n        condition: service_healthy"),
                "{service} must not dial a bootnode before its P2P listener is ready"
            );
        }
    }

    #[test]
    fn options_parse_the_report_path_only_with_live_modes() {
        let options = Options::parse(&[]).expect("default options");
        assert_eq!(options.mode, Mode::Preflight);
        assert!(!options.keep_running);
        assert!(Options::parse(&["--report", "out.md"]).is_err());
        let options = Options::parse(&["--compose", "--report", "out.md"]).expect("compose");
        assert_eq!(options.mode, Mode::Compose);
        assert_eq!(options.report, Some(PathBuf::from("out.md")));
        let local = Options::parse(&["--local", "--bin-dir", "target/debug", "--report", "r.md"])
            .expect("local");
        assert_eq!(local.mode, Mode::Local);
        assert_eq!(local.bin_dir, Some(PathBuf::from("target/debug")));
        assert!(Options::parse(&["--compose", "--local"]).is_err());
        assert!(Options::parse(&["--compose", "--report"]).is_err());
    }

    #[test]
    fn chordal_ring_bounds_degree_to_three_peers() {
        let eight: Vec<String> = (1..=8).map(|i| format!("b{i}")).collect();
        for idx in 0..8 {
            let peers = chordal_bootnodes(idx, &eight);
            assert_eq!(peers.len(), 3);
            assert!(!peers.contains(&eight[idx]));
        }
        let four: Vec<String> = (1..=4).map(|i| format!("b{i}")).collect();
        for idx in 0..4 {
            let peers = chordal_bootnodes(idx, &four);
            assert_eq!(peers.len(), 3);
            assert!(!peers.contains(&four[idx]));
        }
    }

    #[test]
    fn validator_offline_needs_both_finality_and_sixteen_new_blocks() {
        assert!(!offline_progress(30, 30, 31, 47), "no new finality");
        assert!(!offline_progress(30, 35, 31, 46), "only 15 new blocks");
        assert!(offline_progress(30, 35, 31, 47), "both conditions met");
    }

    #[test]
    fn every_bud_call_names_the_chain_it_signs_for() {
        let args = bud_args(&["tx", "send", "--to", "0xab", "--amount", "1"]);
        let flag = args
            .iter()
            .position(|a| a == "--signing-chain-id")
            .expect("the rehearsal must pass --signing-chain-id");
        assert_eq!(
            args[flag + 1],
            CHAIN_ID.to_string(),
            "the flag carries the chain id"
        );
        let subcommand = args
            .iter()
            .position(|a| a == "tx")
            .expect("the subcommand is present");
        assert!(
            flag < subcommand,
            "--signing-chain-id is global: it precedes the subcommand"
        );
        assert_eq!(CHAIN_ID, 45261, "the rehearsal's profile is chain 45261");
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
