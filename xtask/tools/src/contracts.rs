//! `contracts`: the Rust wrapper around Foundry for the Ethereum-side
//! contracts. No script: this module runs
//! `forge` and `cast` and reads `config/testnet-ethereum.toml`.
//!
//! ```text
//! contracts build             forge build in contracts/
//! contracts test [args...]    forge test in contracts/ (args pass through)
//! contracts deploy            deploy every contract whose parameters are set
//! ```
//!
//! `deploy` reads the RPC endpoint from `BUDLUM_ETH_RPC_URL` and the deployer
//! keystore path from `BUDLUM_ETH_KEYSTORE`; `forge` reads the keystore
//! password from `ETH_PASSWORD` itself. None of the three is printed or
//! written. The addresses go into the `[addresses]` section of the
//! config file.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;
use std::process::Command;

const CONFIG: &str = "config/testnet-ethereum.toml";

/// Run the subcommand in `args`.
///
/// # Errors
///
/// A missing tool, a failed forge run, or a config that cannot be read.
pub fn run(root: &Path, args: &[&str]) -> Result<String, String> {
    match args.split_first() {
        Some((&"build", rest)) => forge(root, "build", rest),
        Some((&"test", rest)) => forge(root, "test", rest),
        Some((&"deploy", _)) => deploy(root),
        Some((other, _)) => Err(format!("contracts: unknown subcommand `{other}`")),
        None => Err("contracts: name a subcommand: build, test or deploy".into()),
    }
}

fn forge(root: &Path, action: &str, rest: &[&str]) -> Result<String, String> {
    let status = Command::new("forge")
        .arg(action)
        .arg("--root")
        .arg(root.join("contracts"))
        .args(rest)
        .status()
        .map_err(|e| format!("cannot run forge (is Foundry installed?): {e}"))?;
    if status.success() {
        Ok(format!("forge {action}: ok"))
    } else {
        Err(format!("forge {action} failed: {status}"))
    }
}

/// One `[section] key = value` view of the config file. Values are the raw
/// right-hand sides with surrounding quotes removed.
#[derive(Debug, Default)]
pub struct Config {
    values: BTreeMap<String, String>,
}

impl Config {
    /// Parse the subset of TOML the config uses: sections, `key = value`
    /// lines, `#` comments.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut values = BTreeMap::new();
        let mut section = String::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name.trim().to_string();
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let value = value.trim().trim_matches('"').to_string();
                values.insert(format!("{section}.{}", key.trim()), value);
            }
        }
        Self { values }
    }

    /// The value at `section.key`, when set and not empty.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }
}

/// Rewrite `key = "..."` lines of `[addresses]` in `text` with `written`.
#[must_use]
pub fn write_addresses(text: &str, written: &BTreeMap<&str, String>) -> String {
    let mut out = String::new();
    let mut in_addresses = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_addresses = line == "[addresses]";
        }
        let replaced = in_addresses
            .then(|| line.split_once('='))
            .flatten()
            .and_then(|(key, _)| written.get(key.trim()).map(|v| (key.trim(), v)));
        match replaced {
            Some((key, value)) => {
                let _ = write!(out, "{key} = \"{value}\"");
            }
            None => out.push_str(raw),
        }
        out.push('\n');
    }
    out
}

struct Plan {
    key: &'static str,
    contract: &'static str,
    args: Vec<String>,
}

fn plans(config: &Config, verifier: Option<&str>) -> Vec<Plan> {
    let mut plans = vec![Plan {
        key: "graft_executor",
        contract: "graft/GraftExecutor.sol:GraftExecutor",
        args: Vec::new(),
    }];
    let budlum_chain = config.get("network.budlum_chain_id").unwrap_or("45261");
    if let (Some(window), Some(fraud), Some(committee), Some(generator), Some(ml_dsa)) = (
        config.get("verifier.challenge_window_blocks"),
        config.get("verifier.fraud_proof_verifier"),
        config.get("verifier.committee_pubkey_hash"),
        config.get("verifier.g2_generator_hash"),
        config.get("verifier.ml_dsa_pubkey_hash"),
    ) {
        plans.push(Plan {
            key: "budlum_finality_verifier",
            contract: "external-domain/BudlumFinalityVerifier.sol:BudlumFinalityVerifier",
            args: [budlum_chain, window, fraud, committee, generator, ml_dsa]
                .iter()
                .map(ToString::to_string)
                .collect(),
        });
    }
    if let Some(verifier) = verifier {
        plans.push(Plan {
            key: "budlum_remote_account_factory",
            contract: "graft/BudlumRemoteAccountFactory.sol:BudlumRemoteAccountFactory",
            args: vec![verifier.to_string()],
        });
    }
    if let (Some(manager), Some(set), Some(strategies), Some(generator), Some(wad)) = (
        config.get("mikoriza.allocation_manager"),
        config.get("mikoriza.operator_set_id"),
        config.get("mikoriza.strategies"),
        config.get("verifier.g2_generator_hash"),
        config.get("mikoriza.double_vote_wad"),
    ) {
        plans.push(Plan {
            key: "budlum_registrar",
            contract: "mikoriza/BudlumRegistrar.sol:BudlumRegistrar",
            args: vec![
                manager.to_string(),
                set.to_string(),
                format!("[{strategies}]"),
                budlum_chain.to_string(),
                generator.to_string(),
                wad.to_string(),
            ],
        });
    }
    plans
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{name} is not set"))
}

fn create(root: &Path, rpc: &str, keystore: &str, plan: &Plan) -> Result<String, String> {
    let output = Command::new("forge")
        .arg("create")
        .arg("--root")
        .arg(root.join("contracts"))
        .arg(plan.contract)
        .args([
            "--rpc-url",
            rpc,
            "--keystore",
            keystore,
            "--broadcast",
            "--json",
        ])
        .args(if plan.args.is_empty() {
            Vec::new()
        } else {
            std::iter::once("--constructor-args".to_string())
                .chain(plan.args.iter().cloned())
                .collect()
        })
        .output()
        .map_err(|e| format!("cannot run forge create: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "forge create {} failed: {}",
            plan.contract,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    deployed_to(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| format!("forge create {} printed no deployedTo", plan.contract))
}

/// The `deployedTo` address of `forge create --json` output.
#[must_use]
pub fn deployed_to(json: &str) -> Option<String> {
    let at = json.find("\"deployedTo\"")?;
    let rest = &json[at + "\"deployedTo\"".len()..];
    let start = rest.find("0x")?;
    let address: String = rest[start..]
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    (address.len() == 42).then_some(address)
}

fn deploy(root: &Path) -> Result<String, String> {
    let rpc = required_env("BUDLUM_ETH_RPC_URL")?;
    let keystore = required_env("BUDLUM_ETH_KEYSTORE")?;
    let path = root.join(CONFIG);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {CONFIG}: {e}"))?;
    let config = Config::parse(&text);
    let mut written: BTreeMap<&str, String> = BTreeMap::new();
    let mut verifier = config
        .get("addresses.budlum_finality_verifier")
        .map(ToString::to_string);
    // Two rounds: the factory needs the verifier's address.
    for _ in 0..2 {
        for plan in plans(&config, verifier.as_deref()) {
            if written.contains_key(plan.key)
                || config.get(&format!("addresses.{}", plan.key)).is_some()
            {
                continue;
            }
            let address = create(root, &rpc, &keystore, &plan)?;
            if plan.key == "budlum_finality_verifier" {
                verifier = Some(address.clone());
            }
            written.insert(plan.key, address);
        }
    }
    if let Some(registrar) = written.get("budlum_registrar").cloned() {
        let output = Command::new("cast")
            .args(["call", &registrar, "slasher()(address)", "--rpc-url", &rpc])
            .output()
            .map_err(|e| format!("cannot run cast: {e}"))?;
        let slasher = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if slasher.len() == 42 {
            written.insert("budlum_slasher", slasher);
        }
    }
    std::fs::write(&path, write_addresses(&text, &written))
        .map_err(|e| format!("cannot write {CONFIG}: {e}"))?;
    Ok(format!(
        "deployed {} contract(s); addresses written to {CONFIG}",
        written.len()
    ))
}

/// The canary: the config parser, the address writer and the forge output
/// reader agree on a fixed sample.
///
/// # Errors
///
/// The first disagreement.
pub fn self_test() -> Result<String, String> {
    let sample = "[verifier]\nfraud_proof_verifier = \"\"\n[addresses]\ngraft_executor = \"\"\n";
    let config = Config::parse(sample);
    if config.get("verifier.fraud_proof_verifier").is_some() {
        return Err("an empty value read as set".into());
    }
    let mut written = BTreeMap::new();
    written.insert(
        "graft_executor",
        "0x00000000000000000000000000000000000000aa".to_string(),
    );
    let rewritten = write_addresses(sample, &written);
    if Config::parse(&rewritten).get("addresses.graft_executor")
        != Some("0x00000000000000000000000000000000000000aa")
    {
        return Err("the address writer lost the address".into());
    }
    if deployed_to(r#"{"deployer":"0x1","deployedTo":"0x00000000000000000000000000000000000000bb","transactionHash":"0x2"}"#)
        .as_deref()
        != Some("0x00000000000000000000000000000000000000bb")
    {
        return Err("deployedTo was not read".into());
    }
    if !plans(&config, None)
        .iter()
        .any(|p| p.key == "graft_executor")
    {
        return Err("the executor needs no parameter and is always planned".into());
    }
    Ok("contracts: config parser, address writer and forge output reader agree".into())
}
