#![allow(clippy::pedantic, clippy::nursery)]

//! F10.4 Budlum Relayer Binary — off-chain cross-chain relay servisi.
//!
//! RFC `docs/RFC_F10_EVM_CHAIN_ADAPTER.md` §4-5. Relayer:
//! - Ethereum RPC'ye bağlanır, deposit event'leri gözlemler.
//! - F10.1/F10.2 proof paketi üretir (MPT + header chain + receipt).
//! - Budlum'a `submit_relay_proof` ile submit eder (registry kapısı, stake).
//! - Bud→ETH yönü: Budlum burn event + finality proof → Ethereum bridge kontratına tx.
//!
//! Bu binary **mainnet sonrası** öncelik (F10.4). Şimdilik iskelet + CLI yapısı.
//! Production Ethereum RPC client (reqwest/alloy) + Budlum RPC client ayrı.
//!
//! # Çalıştırma (skelet)
//!
//! ```bash
//! # Relayer (Ethereum → Budlum yönü):
//! budlum-relayer --eth-rpc https://mainnet.infura.io/v3/... \
//!                --budlum-rpc http://localhost:8545 \
//!                --bridge-address 0x... \
//!                --direction eth-to-bud
//!
//! # Relayer (Budlum → Ethereum yönü, F10.5):
//! budlum-relayer --eth-rpc ... --budlum-rpc ... --direction bud-to-eth
//! ```

use std::env;
use std::process::ExitCode;

/// Relayer CLI konfigürasyonu.
#[derive(Debug, Clone)]
pub struct RelayerConfig {
    /// Ethereum RPC endpoint (eth_sendRawTransaction, eth_getTransactionReceipt).
    pub eth_rpc_url: String,
    /// Budlum RPC endpoint (bud_submitRelayProof, bud_getBridgeEvents).
    pub budlum_rpc_url: String,
    /// Ethereum bridge kontrat adresi (deposit event emitter + claim handler).
    pub bridge_address: String,
    /// Relay yönü: "eth-to-bud" (F10.2) | "bud-to-eth" (F10.5).
    pub direction: RelayDirection,
    /// N-confirmation eşiği (reorg penceresi; Ethereum mainnet ≈64).
    pub required_confirmations: u32,
}

/// Relay yönü.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayDirection {
    /// Ethereum → Budlum: deposit event gözle → proof üret → Budlum mint.
    EthToBud,
    /// Budlum → Ethereum: burn event gözle → Budlum finality proof → ETH claim.
    BudToEth,
}

impl RelayDirection {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "eth-to-bud" | "eth" => Ok(RelayDirection::EthToBud),
            "bud-to-eth" | "bud" => Ok(RelayDirection::BudToEth),
            _ => Err(format!(
                "Unknown direction '{s}'; expected 'eth-to-bud' or 'bud-to-eth'"
            )),
        }
    }
}

impl Default for RelayerConfig {
    fn default() -> Self {
        Self {
            eth_rpc_url: "http://localhost:8546".to_string(),
            budlum_rpc_url: "http://localhost:8545".to_string(),
            bridge_address: "0x0".to_string(),
            direction: RelayDirection::EthToBud,
            required_confirmations: 64,
        }
    }
}

/// CLI argümanları parse et (minimal — production clap kullanılabilir).
pub fn parse_args(args: &[String]) -> Result<RelayerConfig, String> {
    let mut config = RelayerConfig::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--eth-rpc" => {
                i += 1;
                config.eth_rpc_url = args.get(i).ok_or("--eth-rpc requires a value")?.clone();
            }
            "--budlum-rpc" => {
                i += 1;
                config.budlum_rpc_url = args.get(i).ok_or("--budlum-rpc requires a value")?.clone();
            }
            "--bridge-address" => {
                i += 1;
                config.bridge_address = args
                    .get(i)
                    .ok_or("--bridge-address requires a value")?
                    .clone();
            }
            "--direction" => {
                i += 1;
                config.direction =
                    RelayDirection::parse(args.get(i).ok_or("--direction requires a value")?)?;
            }
            "--confirmations" => {
                i += 1;
                config.required_confirmations = args
                    .get(i)
                    .ok_or("--confirmations requires a value")?
                    .parse()
                    .map_err(|e| format!("Invalid --confirmations value: {e}"))?;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            _ => {
                return Err(format!("Unknown argument: {}", args[i]));
            }
        }
        i += 1;
    }
    Ok(config)
}

fn print_usage() {
    eprintln!("budlum-relayer — F10 Universal Relayer service (EVM ↔ Budlum)");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  budlum-relayer --eth-rpc <URL> --budlum-rpc <URL> --bridge-address <ADDR>");
    eprintln!("                 --direction <eth-to-bud|bud-to-eth> [--confirmations N]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --eth-rpc <URL>          Ethereum RPC endpoint");
    eprintln!("  --budlum-rpc <URL>       Budlum RPC endpoint");
    eprintln!("  --bridge-address <ADDR>  Ethereum bridge contract address");
    eprintln!("  --direction <DIR>        eth-to-bud (F10.2) | bud-to-eth (F10.5)");
    eprintln!("  --confirmations <N>      N-confirmation threshold (default: 64)");
    eprintln!("  -h, --help               Show this help");
}

/// F10.4 ana relayer loop (skelet). Production: poll → proof üret → submit.
///
/// Bu versiyon config validate edip bekler (mainnet sonrası tam impl).
pub fn run_relayer(config: &RelayerConfig) -> Result<(), String> {
    eprintln!("budlum-relayer starting (F10.4 skeleton):");
    eprintln!("  direction: {:?}", config.direction);
    eprintln!("  eth-rpc: {}", config.eth_rpc_url);
    eprintln!("  budlum-rpc: {}", config.budlum_rpc_url);
    eprintln!("  bridge: {}", config.bridge_address);
    eprintln!("  confirmations: {}", config.required_confirmations);
    eprintln!();
    eprintln!("NOTE: F10.4 skeleton — production relay loop requires:");
    eprintln!("  - Ethereum RPC client (eth_getLogs / eth_getTransactionReceipt)");
    eprintln!("  - Budlum RPC client (bud_submitRelayProof)");
    eprintln!("  - F10.1/F10.2 proof assembly (MPT + header chain + receipt)");
    eprintln!("  - F10.5 Bud→ETH: Budlum light-client proof + Ethereum bridge tx");
    eprintln!();
    match config.direction {
        RelayDirection::EthToBud => {
            eprintln!("EthToBud: watching Ethereum deposit events → Budlum mint")
        }
        RelayDirection::BudToEth => {
            eprintln!("BudToEth: watching Budlum burn events → Ethereum claim (F10.5)")
        }
    }
    // Skeleton: validate config + return. Mainnet sonrası: tokio spawn poll loop.
    if config.bridge_address == "0x0" {
        return Err(
            "bridge-address is placeholder (0x0); set real Ethereum bridge contract".into(),
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let config = match parse_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            print_usage();
            return ExitCode::from(1);
        }
    };
    match run_relayer(&config) {
        Ok(()) => {
            eprintln!("budlum-relayer: skeleton complete (no relay loop — mainnet sonrası)");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("budlum-relayer error: {e}");
            ExitCode::from(1)
        }
    }
}
