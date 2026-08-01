use budlum_core::chain::blockchain::Blockchain;
use budlum_core::chain::chain_actor::ChainActor;
use budlum_core::chain::snapshot::PruningManager;
use budlum_core::cli::{ConsensusType, NodeConfig};
use budlum_core::consensus::poa::{PoAConfig, PoAEngine};
use budlum_core::consensus::pos::{PoSConfig, PoSEngine};
use budlum_core::consensus::pow::PoWEngine;
use budlum_core::consensus::ConsensusEngine;
use budlum_core::core::address::Address;
use budlum_core::core::transaction::Transaction;
use budlum_core::crypto::primitives::{KeyPair, ValidatorKeys};
use budlum_core::crypto::signer::ConsensusSigner;
use budlum_core::domain::{
    BftDomainPlugin, ConsensusKind, DomainStatus, PoADomainPlugin, PoSDomainPlugin, PoWDomainPlugin,
};
use budlum_core::network::node::Node;
use budlum_core::network::protocol::NetworkMessage;
use budlum_core::rpc::{RpcMode, RpcSecurityConfig, RpcServer};
use budlum_core::storage::db::Storage;

use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

fn load_signing_key(path: &str) -> Option<KeyPair> {
    ValidatorKeys::load(path)
        .map(|keys| keys.sig_key)
        .or_else(|_| KeyPair::load(path))
        .ok()
}

fn write_database_backup(
    storage: &Storage,
    backup_dir: &Path,
    retention_count: usize,
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(backup_dir)?;
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_millis();
    let path = backup_dir.join(format!("budlum-{timestamp_ms}.budbak"));
    storage.create_snapshot(&path)?;
    Storage::verify_snapshot(&path)?;

    let mut backups: Vec<PathBuf> = std::fs::read_dir(backup_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|candidate| {
            candidate
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("budlum-") && name.ends_with(".budbak"))
        })
        .collect();
    backups.sort();
    let remove_count = backups.len().saturating_sub(retention_count);
    for expired in backups.into_iter().take(remove_count) {
        std::fs::remove_file(expired)?;
    }
    Ok(path)
}

#[tokio::main]
async fn main() {
    // Semgrep `rust.lang.security.args.args` kuralı argv[0]'ın (saldırgan
    // Tarafından serbestçe ayarlanabilen çalıştırılabilir yolu) bir güvenlik
    // Kararına dayanak yapılmasını hedefler. Burada argv[0] hiç okunmaz:
    // Alt-komut ayrıştırma index 1'den, bayrak döngüsü index 3'ten başlar ve
    // Hiçbir yetki/kimlik kararı bu vektöre bağlı değildir.
    // Nosemgrep: rust.lang.security.args.args
    let args: Vec<String> = std::env::args().collect(); // nosemgrep: rust.lang.security.args.args
    if args.len() >= 3 && args[1] == "genesis" && args[2] == "build" {
        let mut output_path = "./genesis.json".to_string();
        let mut chain_id = 1337u64;
        let mut validators = Vec::new();
        let mut allocations = Vec::new();
        let mut block_reward = 50u64;
        let mut base_fee = 1u64;
        let mut dev_key_output = None;

        let mut i = 3;
        while i < args.len() {
            match args[i].as_str() {
                "--output" | "-o" => {
                    if i + 1 < args.len() {
                        output_path = args[i + 1].clone();
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --output");
                        std::process::exit(1);
                    }
                }
                "--chain-id" | "-c" => {
                    if i + 1 < args.len() {
                        chain_id = args[i + 1].parse().expect("Invalid chain-id");
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --chain-id");
                        std::process::exit(1);
                    }
                }
                "--validators" | "-v" => {
                    if i + 1 < args.len() {
                        let addrs = &args[i + 1];
                        for addr_str in addrs.split(',') {
                            if let Ok(addr) = Address::from_hex(addr_str.trim()) {
                                validators.push(addr);
                            } else {
                                eprintln!("Error: Invalid validator address '{addr_str}'");
                                std::process::exit(1);
                            }
                        }
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --validators");
                        std::process::exit(1);
                    }
                }
                "--allocations" | "-a" => {
                    if i + 1 < args.len() {
                        let allocs_str = &args[i + 1];
                        for item in allocs_str.split(',') {
                            let parts: Vec<&str> = item.split(':').collect();
                            if parts.len() == 2 {
                                let addr = Address::from_hex(parts[0].trim())
                                    .expect("Invalid allocation address");
                                let amount: u64 =
                                    parts[1].trim().parse().expect("Invalid allocation amount");
                                allocations.push((addr, amount));
                            } else {
                                eprintln!("Error: Invalid allocation format '{item}' (expected address:amount)");
                                std::process::exit(1);
                            }
                        }
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --allocations");
                        std::process::exit(1);
                    }
                }
                "--block-reward" => {
                    if i + 1 < args.len() {
                        block_reward = args[i + 1].parse().expect("Invalid block-reward");
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --block-reward");
                        std::process::exit(1);
                    }
                }
                "--base-fee" => {
                    if i + 1 < args.len() {
                        base_fee = args[i + 1].parse().expect("Invalid base-fee");
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --base-fee");
                        std::process::exit(1);
                    }
                }
                "--dev-key-output" => {
                    if i + 1 < args.len() {
                        dev_key_output = Some(args[i + 1].clone());
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --dev-key-output");
                        std::process::exit(1);
                    }
                }
                other => {
                    eprintln!("Unknown argument: {other}");
                    std::process::exit(1);
                }
            }
        }

        // Dev convenience path: never print generated private key material.
        if allocations.is_empty() {
            if chain_id
                != budlum_core::core::chain_config::Network::Devnet
                    .chain_id()
                    .value()
            {
                eprintln!(
                    "Error: automatic allocation key generation is only allowed for the devnet chain ID"
                );
                std::process::exit(1);
            }
            let key_output = dev_key_output.unwrap_or_else(|| {
                eprintln!(
                    "Error: --allocations is required unless --dev-key-output is provided for a generated dev key"
                );
                std::process::exit(1);
            });
            let dev_key = KeyPair::generate().unwrap();
            let dev_addr = Address::from(dev_key.public_key_bytes());
            dev_key
                .save(&key_output)
                .expect("Failed to save generated dev key");
            allocations.push((dev_addr, 1_000_000_000));
            validators.push(dev_addr);
            println!("No allocations/validators provided. Generated default devnet keypair:");
            println!("Address: {dev_addr}");
            println!("Private key saved to: {key_output}");
        }
        let network_defaults = budlum_core::core::chain_config::Network::from_chain_id(chain_id)
            .map(budlum_core::chain::genesis::GenesisConfig::for_network)
            .unwrap_or_else(|| budlum_core::chain::genesis::GenesisConfig::new(chain_id));

        if allocations.is_empty() {
            allocations = network_defaults.allocations.clone();
        }
        if validators.is_empty() {
            validators = network_defaults.validators.clone();
        }
        if chain_id
            != budlum_core::core::chain_config::Network::Devnet
                .chain_id()
                .value()
            && validators.is_empty()
            && !network_defaults.validators.is_empty()
        {
            eprintln!("Error: this network genesis requires an explicit or default validator set");
            std::process::exit(1);
        }

        let genesis_config = budlum_core::chain::genesis::GenesisConfig {
            chain_id,
            allocations,
            validators,
            validator_consensus_keys: network_defaults.validator_consensus_keys.clone(),
            block_reward,
            base_fee,
            gas_schedule: network_defaults.gas_schedule,
            timestamp: network_defaults.timestamp,
            bud_tokenomics: network_defaults.bud_tokenomics,
            tokenomics_addresses: network_defaults.tokenomics_addresses,
            // Record which PQ backend produced this file, so a node built with
            // the other one refuses the chain at startup instead of joining it
            // and rejecting every peer's validator registration.
            pq_scheme: network_defaults.pq_scheme.clone(),
            bootstrap_domains: network_defaults.bootstrap_domains.clone(),
        };

        let data = serde_json::to_string_pretty(&genesis_config)
            .expect("Failed to serialize genesis config");
        std::fs::write(&output_path, data).expect("Failed to write genesis file");
        println!("Genesis configuration file built and saved to: {output_path}");
        return;
    }

    //.1 tooling: `budlum-core keygen --type ed25519 --output <path>`
    // Ceremony dokümanı adımın karşılığı (önceden dokümanda olan ama
    // Binary'de OLMAYAN bir komuttu - iddia-vs-kanıt matrisi kapanışı).
    if args.len() >= 2 && args[1] == "keygen" {
        let mut key_type = "ed25519".to_string();
        let mut output: Option<String> = None;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--type" | "-t" => {
                    if i + 1 < args.len() {
                        key_type = args[i + 1].clone();
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --type");
                        std::process::exit(1);
                    }
                }
                "--output" | "-o" => {
                    if i + 1 < args.len() {
                        output = Some(args[i + 1].clone());
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --output");
                        std::process::exit(1);
                    }
                }
                other => {
                    eprintln!("Error: unknown keygen argument '{other}'");
                    eprintln!(
                        "Usage: budlum-core keygen --type ed25519 --output <secret-key-path>"
                    );
                    std::process::exit(1);
                }
            }
        }
        let Some(output) = output else {
            eprintln!("Error: keygen requires --output <secret-key-path>");
            eprintln!("Usage: budlum-core keygen --type ed25519 --output <secret-key-path>");
            std::process::exit(1);
        };
        // Mainnet anahtar politikası (crypto/primitives.rs
        // PlaintextDiskKeysForbiddenOnMainnet): BLS/PQ disk'te ÜRETİLMEZ,
        // Yalnızca PKCS#11 HSM içinde üretilir.
        if key_type != "ed25519" {
            eprintln!(
                "CRITICAL: '{key_type}' anahtarları disk üzerinde üretilemez - BLS/PQ yalnızca PKCS#11 HSM içinde üretilir (mainnet politikası)."
            );
            std::process::exit(1);
        }
        let keypair = KeyPair::generate().expect("keypair generation failed");
        keypair.save(&output).unwrap_or_else(|e| {
            eprintln!("Error: cannot write secret key to {output}: {e:?}");
            std::process::exit(1);
        });
        let pub_path = format!("{output}.pub");
        let pub_hex = keypair.public_key_hex();
        std::fs::write(&pub_path, format!("{pub_hex}\n")).unwrap_or_else(|e| {
            eprintln!("Error: cannot write public key file {pub_path}: {e}");
            std::process::exit(1);
        });
        // NOT (karşı-dengesi): node çalışırken pubkey stdout'a
        // Yazılmaz; burada operatörün açıkça çağırdığı ayrı keygen CLI'si
        // Sanctioned kanaldır - pubkey ve adres ceremony tabloları için
        // Bilinçli yazdırılır. Secret key ve dosya yolu ASLA loglanmaz.
        let address = Address::from(keypair.public_key_bytes());
        println!("Ed25519 keypair generated (secret key written with 0600 permissions).");
        println!("Public key:  {pub_hex}");
        println!("Address:     {address}");
        println!("Pubkey file: {pub_path}");
        return;
    }

    let mut config = NodeConfig::parse();
    config.load_with_file();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    if let Some(ref backup_path) = config.restore_backup {
        Storage::restore_snapshot(backup_path, &config.db_path).unwrap_or_else(|error| {
            eprintln!("CRITICAL: backup restore failed: {error}");
            std::process::exit(1);
        });
        println!(
            "Backup {} restored and integrity-checked at {}",
            backup_path, config.db_path
        );
        return;
    }

    if let Some(ref db_path) = config.migrate_v2 {
        let storage = Storage::new(db_path).unwrap_or_else(|error| {
            eprintln!("CRITICAL: failed to open database for V2 migration at {db_path}: {error}");
            std::process::exit(1);
        });
        println!("🚀 Starting offline ConsensusStateV2 schema migration check on: {db_path}");
        let backup_dir = config.backup_dir.as_deref().unwrap_or("./data/backups");
        let backup_path = write_database_backup(
            &storage,
            Path::new(backup_dir),
            config.backup_retention_count,
        )
        .unwrap_or_else(|error| {
            eprintln!(
                "CRITICAL: mandatory pre-migration backup failed: {error}. Aborting migration."
            );
            std::process::exit(1);
        });
        println!(
            "✅ Mandatory pre-migration backup verified at: {}",
            backup_path.display()
        );
        println!(
            "✅ ConsensusStateV2 schema migration ready and compatible. Supported schema window: {}..={}.",
            budlum_core::chain::snapshot::MIN_SUPPORTED_STATE_SNAPSHOT_SCHEMA_VERSION,
            budlum_core::chain::snapshot::CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION
        );
        return;
    }

    if config.backup_now {
        let storage = Storage::new(&config.db_path).unwrap_or_else(|error| {
            eprintln!("CRITICAL: failed to open database for backup: {error}");
            std::process::exit(1);
        });
        let backup_dir = config.backup_dir.as_deref().unwrap_or("./data/backups");
        let backup = write_database_backup(
            &storage,
            Path::new(backup_dir),
            config.backup_retention_count,
        )
        .unwrap_or_else(|error| {
            eprintln!("CRITICAL: database backup failed: {error}");
            std::process::exit(1);
        });
        println!("Verified database backup written to {}", backup.display());
        return;
    }

    if let Some(ref path) = config.gen_key {
        match budlum_core::crypto::primitives::ValidatorKeys::generate() {
            Ok(keys) => {
                keys.save(path).expect("Failed to save key");
                println!("Validator key generated and saved to: {path}");
                println!(
                    "Address: {}",
                    Address::from(keys.sig_key.public_key_bytes())
                );
            }
            Err(e) => eprintln!("Error generating key: {e}"),
        }
        return;
    }

    if config.check_db {
        let storage = Storage::new(&config.db_path).expect("Failed to open DB");
        println!(
            "🔍 Starting Database Integrity Audit on: {}",
            config.db_path
        );
        match storage.check_integrity() {
            Ok(errors) => {
                if errors.is_empty() {
                    println!("✅ Integrity Audit PASSED. No corruptions found.");
                } else {
                    println!("❌ Integrity Audit FAILED! Found {} errors.", errors.len());
                    for err in errors {
                        println!("   - {err}");
                    }
                    if config.repair_db {
                        println!("🔧 Attempting automatic repair...");
                        if let Err(e) = storage.repair_index() {
                            eprintln!("❌ Repair failed: {e}");
                        } else {
                            println!(
                                "✅ Repair successful. Please run --check-db again to verify."
                            );
                        }
                    } else {
                        println!("💡 Tip: Run with --repair-db to attempt index reconstruction.");
                    }
                }
            }
            Err(e) => eprintln!("System error during audit: {e}"),
        }
        return;
    }

    if config.repair_db {
        let storage = Storage::new(&config.db_path).expect("Failed to open DB");
        println!("🔧 Starting manual Database Repair on: {}", config.db_path);
        if let Err(e) = storage.repair_index() {
            eprintln!("Repair failed: {e}");
        } else {
            println!("Repair complete. Re-indexing finished.");
        }
        return;
    }

    let network = config.network;
    let port = config.port.unwrap_or(network.default_port());
    let chain_id = config.chain_id.unwrap_or(network.chain_id().value());
    let network_params = network.consensus_params();
    if config.min_stake == 1000 {
        config.min_stake = network_params.min_stake;
    }
    let consensus_type = config.consensus.unwrap_or(match network {
        budlum_core::core::chain_config::Network::Mainnet => ConsensusType::PoS,
        budlum_core::core::chain_config::Network::Testnet => ConsensusType::PoS,
        budlum_core::core::chain_config::Network::Devnet => ConsensusType::PoW,
    });
    let poa_validators = if consensus_type == ConsensusType::PoA {
        config.load_validator_addresses()
    } else {
        Vec::new()
    };
    let local_signer_address = config
        .validator_key_file
        .as_ref()
        .and_then(|s| load_signing_key(s))
        .map(|key| Address::from(key.public_key_bytes()));

    // F2 config-driven: set env var for VM VerifyMerkle gate from TOML [features] verify_merkle
    std::env::set_var(
        "BUDLUM_VERIFY_MERKLE",
        config.features_verify_merkle.to_string(),
    );
    println!(
        "   VerifyMerkle: {} (config-driven F2, MainnetActivation)",
        if config.features_verify_merkle {
            "enabled (full)"
        } else {
            "disabled (staged rollout)"
        }
    );

    println!("Budlum Node - v0.2.0 (Framework Edition)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Configuration:");
    println!("   Network: {network}");
    println!("   Chain ID: {chain_id}");
    println!("   Port: {port}");
    println!("   Consensus: {:?}", consensus_type);
    println!("   Privacy: {:?}", config.privacy);
    println!("   DB Path: {}", config.db_path);
    println!(
        "   Metrics: http://127.0.0.1:{}/metrics",
        config.metrics_port
    );
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let hsm_signer: Option<Arc<dyn ConsensusSigner>> = if matches!(
        config.signer_backend.as_deref(),
        Some("pkcs11") | Some("softhsm")
    ) {
        let module_path = config.pkcs11_module_path.as_deref().unwrap_or("");
        let slot_id = config.pkcs11_slot_id.unwrap_or(0);
        let pin_env = config.pkcs11_token_pin_env.as_deref().unwrap_or("");
        if module_path.is_empty() || pin_env.is_empty() {
            eprintln!(
                "ERROR: PKCS#11 backend requires --pkcs11-module-path and --pkcs11-token-pin-env"
            );
            std::process::exit(1);
        }
        let strict_vendor_native = config.network
            == budlum_core::core::chain_config::Network::Mainnet
            && config.role == "validator";
        if strict_vendor_native {
            let Some(bls_raw) = config.pkcs11_bls_mechanism.as_deref() else {
                eprintln!(
                    "CRITICAL: mainnet validators require an explicit PKCS#11 vendor-native BLS mechanism id"
                );
                std::process::exit(1);
            };
            let Some(pq_raw) = config.pkcs11_pq_mechanism.as_deref() else {
                eprintln!(
                    "CRITICAL: mainnet validators require an explicit PKCS#11 vendor-native PQ mechanism id"
                );
                std::process::exit(1);
            };
            if let Err(e) =
                budlum_core::crypto::pkcs11::Pkcs11Signer::validate_vendor_mechanism_id(bls_raw)
            {
                eprintln!("CRITICAL: invalid PKCS#11 BLS mechanism id: {e}");
                std::process::exit(1);
            }
            if let Err(e) =
                budlum_core::crypto::pkcs11::Pkcs11Signer::validate_vendor_mechanism_id(pq_raw)
            {
                eprintln!("CRITICAL: invalid PKCS#11 PQ mechanism id: {e}");
                std::process::exit(1);
            }
        }
        let signer_result = if strict_vendor_native {
            budlum_core::crypto::pkcs11::Pkcs11Signer::new_without_software_fallback(
                module_path.to_string(),
                slot_id,
                pin_env.to_string(),
            )
        } else {
            budlum_core::crypto::pkcs11::Pkcs11Signer::new(
                module_path.to_string(),
                slot_id,
                pin_env.to_string(),
            )
        };
        match signer_result.map(|s| {
            let signer = s.with_vendor_mechanisms(
                config.pkcs11_bls_mechanism.clone(),
                config.pkcs11_pq_mechanism.clone(),
            );
            if strict_vendor_native {
                signer.require_vendor_native_signing()
            } else {
                signer
            }
        }) {
            Ok(signer) => {
                if strict_vendor_native {
                    let caps = signer.vendor_capabilities();
                    if !caps.vendor_native_signing_configured() {
                        eprintln!(
                            "CRITICAL: mainnet validators require vendor-native PKCS#11 BLS and PQ signing; software fallback is forbidden"
                        );
                        std::process::exit(1);
                    }
                }
                // In strict mainnet mode BLS/PQ secrets must be
                // Non-extractable vendor-native objects. `has_bls_key` and
                // `has_pq_key` intentionally report only software fallback
                // Material, so using them as an admission check would reject
                // The secure configuration we just required above. The
                // Vendor-capability gate is the sole mainnet admission check.
                println!("PKCS#11 HSM initialized (slot: {slot_id})");
                Some(Arc::new(signer))
            }
            Err(e) => {
                eprintln!("CRITICAL: Failed to initialize PKCS#11 signer: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let consensus: Arc<dyn ConsensusEngine> = match consensus_type {
        ConsensusType::PoW => {
            println!(" PoW mode - difficulty: {}", config.difficulty);
            Arc::new(PoWEngine::new(config.difficulty))
        }
        ConsensusType::PoS => {
            println!("PoS mode - min stake: {}", config.min_stake);
            if config.network == budlum_core::core::chain_config::Network::Mainnet
                && config.role == "validator"
            {
                eprintln!(
                    "CRITICAL: mainnet PoS validators require native HSM VRF signing; this startup path has no PKCS#11 VRF backend yet"
                );
                std::process::exit(1);
            }
            let pos_config = PoSConfig {
                min_stake: config.min_stake,
                slot_duration: (network_params.slot_ms / 1000).max(1),
                epoch_length: network_params.epoch_len,
                ..Default::default()
            };
            // Mainnet forbids disk-backed ValidatorKeys
            // (BLS + Dilithium secrets stay plaintext on disk today).
            let keys = if config.network == budlum_core::core::chain_config::Network::Mainnet {
                if config.validator_key_file.is_some() {
                    eprintln!(
                        "CRITICAL: refusing to load ValidatorKeys from disk on mainnet (BLS/PQ plaintext)"
                    );
                    std::process::exit(1);
                }
                None
            } else if let Some(ref path) = config.validator_key_file {
                match budlum_core::crypto::primitives::ValidatorKeys::load(path) {
                    Ok(k) => Some(k),
                    Err(e) => {
                        println!("Failed to load validator keys from {path}: {e}");
                        None
                    }
                }
            } else {
                None
            };
            if let Some(signer) = hsm_signer {
                Arc::new(PoSEngine::with_signer(pos_config, keys, signer))
            } else {
                Arc::new(PoSEngine::new(pos_config, keys))
            }
        }
        ConsensusType::PoA => {
            println!("PoA mode");
            let poa_keypair = config
                .validator_key_file
                .as_ref()
                .and_then(|s| load_signing_key(s));
            if let Some(signer) = hsm_signer {
                Arc::new(PoAEngine::with_signer(
                    PoAConfig {
                        validators_file: Some(config.validators_file.clone()),
                        ..Default::default()
                    },
                    poa_keypair,
                    signer,
                ))
            } else {
                Arc::new(PoAEngine::new(
                    PoAConfig {
                        validators_file: Some(config.validators_file.clone()),
                        ..Default::default()
                    },
                    poa_keypair,
                ))
            }
        }
    };

    let storage_instance = Storage::new(&config.db_path).unwrap_or_else(|e| {
        eprintln!(
            "CRITICAL: Failed to initialize storage at {}: {}",
            config.db_path, e
        );
        std::process::exit(1);
    });

    let backup_schedule = (config.backups_enabled == Some(true)).then(|| {
        (
            storage_instance.clone(),
            PathBuf::from(
                config
                    .backup_dir
                    .clone()
                    .unwrap_or_else(|| "./data/backups".to_string()),
            ),
            config.backup_interval_secs,
            config.backup_retention_count,
        )
    });
    let storage = Some(storage_instance);

    if config.network == budlum_core::core::chain_config::Network::Mainnet
        && config.genesis_file.is_none()
    {
        eprintln!(
            "CRITICAL: mainnet startup requires an explicit, ceremony-validated genesis file"
        );
        std::process::exit(1);
    }

    let genesis_config = if let Some(ref path) = config.genesis_file {
        let data = std::fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("CRITICAL: Failed to read genesis file {path}: {e}");
            std::process::exit(1);
        });
        let custom_genesis: budlum_core::chain::genesis::GenesisConfig =
            serde_json::from_str(&data).unwrap_or_else(|e| {
                eprintln!("CRITICAL: Failed to parse genesis JSON {path}: {e}");
                std::process::exit(1);
            });
        if custom_genesis.chain_id != chain_id {
            eprintln!(
                "CRITICAL: Genesis chain ID {} does not match configured chain ID {}",
                custom_genesis.chain_id, chain_id
            );
            std::process::exit(1);
        }
        if let Err(error) = custom_genesis.validate_consensus_ceremony(config.network) {
            eprintln!("CRITICAL: Invalid genesis consensus ceremony: {error}");
            std::process::exit(1);
        }
        println!("Loaded custom genesis configuration from: {path}");
        Some(custom_genesis)
    } else {
        None
    };

    let pruning_manager = config.features_pruning.then(|| {
        PruningManager::new(
            1000,
            100,
            config
                .snapshot_dir
                .clone()
                .unwrap_or_else(|| "./data/snapshots".to_string()),
        )
    });

    let metrics = Arc::new(budlum_core::core::metrics::Metrics::new());

    let mut blockchain = Blockchain::new_with_genesis(
        consensus.clone(),
        storage,
        chain_id,
        pruning_manager,
        genesis_config,
    )
    .with_metrics(metrics.clone());

    if let Some((backup_storage, backup_dir, backup_interval, retention_count)) = backup_schedule {
        tokio::spawn(async move {
            // Blockchain initialization (including genesis) completed before
            // This task is created, so the first backup is restorable.
            loop {
                match write_database_backup(&backup_storage, &backup_dir, retention_count) {
                    Ok(path) => tracing::info!("Verified database backup: {}", path.display()),
                    Err(error) => tracing::error!("Database backup failed: {error}"),
                }
                tokio::time::sleep(std::time::Duration::from_secs(backup_interval)).await;
            }
        });
    }

    let bootstrap_domains = blockchain.domain_registry.domains();
    for domain in bootstrap_domains {
        // BFT domains are now activated
        // At bootstrap instead of being frozen. The BftDomainPlugin provides
        // Basic quorum-based finality via BftFinalityAdapter. If the BFT
        // Engine is not yet wired for a specific domain, it will operate
        // In fail-closed mode (blocks require valid BFT commit signatures).
        if domain.kind == ConsensusKind::Bft {
            if let Some(existing) = blockchain.domain_registry.get_mut(domain.id) {
                existing.status = DomainStatus::Active;
                if let Some(store) = blockchain.storage.as_ref() {
                    let _ = store.save_consensus_domain(existing);
                }
            }
            tracing::info!(
                "BFT bootstrap domain {} activated - BFT finality adapter engaged",
                domain.id
            );
            continue;
        }
        if domain.kind == ConsensusKind::PoA {
            if let Some(existing) = blockchain.domain_registry.get_mut(domain.id) {
                existing.status = DomainStatus::Frozen;
                if let Some(store) = blockchain.storage.as_ref() {
                    let _ = store.save_consensus_domain(existing);
                }
            }
            tracing::warn!(
                "PoA bootstrap domain {} kept registered but frozen until domain-local validator state exists",
                domain.id
            );
            continue;
        }

        let plugin_engine: Arc<dyn ConsensusEngine> = match &domain.kind {
            ConsensusKind::PoW => {
                if consensus_type == ConsensusType::PoW {
                    consensus.clone()
                } else {
                    Arc::new(PoWEngine::new(config.difficulty))
                }
            }
            ConsensusKind::PoS => {
                if consensus_type == ConsensusType::PoS {
                    consensus.clone()
                } else {
                    Arc::new(PoSEngine::new(
                        PoSConfig {
                            min_stake: config.min_stake,
                            slot_duration: (network_params.slot_ms / 1000).max(1),
                            epoch_length: network_params.epoch_len,
                            ..Default::default()
                        },
                        None,
                    ))
                }
            }
            ConsensusKind::PoA => {
                if consensus_type == ConsensusType::PoA {
                    consensus.clone()
                } else {
                    Arc::new(PoAEngine::new(
                        PoAConfig {
                            validators_file: Some(config.validators_file.clone()),
                            ..Default::default()
                        },
                        None,
                    ))
                }
            }
            _ => continue,
        };

        let plugin: std::sync::Arc<dyn budlum_core::domain::ConsensusDomainPlugin> =
            match &domain.kind {
                ConsensusKind::PoW => std::sync::Arc::new(PoWDomainPlugin::new(plugin_engine)),
                ConsensusKind::PoS => std::sync::Arc::new(PoSDomainPlugin::new(plugin_engine)),
                ConsensusKind::PoA => std::sync::Arc::new(PoADomainPlugin::new(plugin_engine)),
                ConsensusKind::Bft => std::sync::Arc::new(BftDomainPlugin::new(plugin_engine)),
                _ => continue,
            };
        if let Err(e) = blockchain.plugin_registry.register(domain.id, plugin) {
            println!("Plugin kaydi basarisiz (domain {}): {}", domain.id, e);
        }
    }

    for validator in &poa_validators {
        blockchain.state.add_validator(*validator, 1);
    }

    let (chain_actor, chain) = ChainActor::new(blockchain);
    tokio::spawn(async move {
        chain_actor.run().await;
    });

    // (2026-07-18,) ölü `_keys` bootstrap'ı gerçeğe bağlandı -
    // Yüklenen validator anahtarının ADRESİ producer-aday zincirine düşer.
    // Davranış değişikliği yalnızca şu: anahtar yüklemesi başarılıysa adresi
    // Artık bir değişkende tutulur; imza/devnet'lik doğrulama kuralları aynı.
    // (combinator biçimi: clippy pedantic/nursery ratchet'i için)
    let validator_keys_address: Option<Address> = (consensus_type == ConsensusType::PoS)
        .then_some(config.validator_key_file.clone())
        .flatten()
        .and_then(|v_path| {
            budlum_core::crypto::primitives::ValidatorKeys::load(&v_path)
                .map_err(|e| {
                    tracing::warn!(
                        "Validator key load failed ({v_path}): {e} - producersuz devam."
                    );
                })
                .ok()
        })
        .map(|keys| {
            let addr = Address::from(keys.sig_key.public_key_bytes());
            println!("Auto-bootstrapping validator: {addr}");
            addr
        });

    if consensus_type == ConsensusType::PoA {
        if !poa_validators.is_empty() {
            println!("Initializing PoA validators: {:?}", poa_validators);
        } else {
            println!(" No validators configured!");
        }
    }

    let mut bootstraps = Vec::new();
    if let Some(ref addr) = config.bootstrap {
        bootstraps.push(addr.clone());
    } else if !config.bootnodes.is_empty() {
        bootstraps.extend(config.bootnodes.clone());
    } else {
        bootstraps.extend(network.bootnodes());
        bootstraps.extend(network.fallback_bootnodes());
    }

    if network == budlum_core::core::chain_config::Network::Mainnet {
        if bootstraps.is_empty() {
            eprintln!("Refusing to start mainnet without at least one configured bootnode.");
            eprintln!("Set p2p.bootnodes in config/mainnet.toml or pass --bootstrap.");
            std::process::exit(1);
        }
        // Genesis placeholder reddiyle (cli/commands.rs Rule 4)
        // Simetrik fail-closed - dummy/placeholder marker içeren peer mainnet'te
        // DİAL EDİLMEZ. ceremony gerçek multiaddr'ları yazınca geçer.
        if let Some(bad) = budlum_core::core::chain_config::first_placeholder_peer(&bootstraps) {
            eprintln!("CRITICAL SECURITY FAILURE: Mainnet placeholder bootnode detected: {bad}");
            eprintln!(
                "Dummy peer'lar production'da dial edilemez - ceremony ile gerçek multiaddr'lar yazılmalı."
            );
            std::process::exit(1);
        }
        let effective_dns_seeds: Vec<String> = if config.dns_seeds.is_empty() {
            network.dns_seeds()
        } else {
            config.dns_seeds.clone()
        };
        if let Some(bad) =
            budlum_core::core::chain_config::first_placeholder_peer(&effective_dns_seeds)
        {
            eprintln!("CRITICAL SECURITY FAILURE: Mainnet placeholder DNS seed detected: {bad}");
            eprintln!("Ceremony ile gerçek _dnsaddr kayıtları yayınlanmalı.");
            std::process::exit(1);
        }
    }

    // Load or generate persistent P2P identity
    let identity_key = budlum_core::network::node::load_or_generate_identity_key(
        config.p2p_identity_file.as_deref(),
    );

    // B.U.D. Storage Node Initialization (Monolithic Architecture)
    let (storage_node, sharding_config) = if config.storage_enabled {
        let store = Arc::new(bud_node::MemoryContentStore::with_default_capacity());
        let bitswap = Arc::new(bud_node::BudBitswap::new(store));

        let mut s_config = if config.mobile_mode {
            bud_node::ShardingConfig::mobile_default()
        } else {
            bud_node::ShardingConfig::default()
        };

        s_config.replication_factor = config.storage_replication_factor;
        s_config.mandatory = config.storage_mandatory_sharding;

        (Some(bitswap), Some(s_config))
    } else {
        (None, None)
    };

    let mut node = Node::with_key(
        chain.clone(),
        identity_key,
        config
            .mdns_enabled
            .unwrap_or(network.security_config().mdns_enabled),
        storage_node,
        sharding_config,
    )
    .unwrap()
    .with_identity(config.p2p_identity_file.clone())
    .with_dns_seeds(config.dns_seeds.clone(), network.default_port())
    .with_banned_peer_db(config.banned_peer_db.clone())
    .with_vote_history_db(config.vote_history_db.clone())
    .with_bootstrap_peers(bootstraps.clone())
    .with_metrics(metrics.clone());
    node.apply_network_security(network);
    let profile_peer_cap = node.max_peers;
    let effective_max_peers = config.effective_max_peers();
    node.max_peers = effective_max_peers;
    if let Some(requested) = config.max_peers {
        if requested > profile_peer_cap {
            tracing::warn!(
                requested,
                profile_peer_cap,
                effective_max_peers,
                "P2P max_peers request capped by network security profile"
            );
        } else {
            tracing::info!(
                effective_max_peers,
                "P2P max_peers lower override applied from config/CLI"
            );
        }
    }

    for addr in &bootstraps {
        if let Err(e) = node.bootstrap(addr) {
            eprintln!("Failed to bootstrap from {addr}: {e}");
        }
    }

    node.listen(port).unwrap();
    if let Some(ref addr) = config.dial {
        node.dial(addr).expect("Failed to dial");
    }
    let client = node.get_client();
    let peer_id = node.peer_id.to_string();
    println!("Node PeerID: {peer_id}");
    let cli_producer_address = config
        .validator_address
        .as_ref()
        .and_then(|addr_str| Address::from_hex(addr_str).ok())
        .or(local_signer_address)
        .or(validator_keys_address);

    if config.rpc_enabled {
        let rpc_security = match RpcSecurityConfig::from_env(
            config.rpc_auth_required,
            config.rpc_api_key_env.as_deref(),
            config.rpc_allowed_ips.clone(),
            config.rpc_cors_origins.clone(),
            config.rpc_rate_limit_per_minute,
        ) {
            Ok(mut security) => {
                security.trusted_proxies = config.rpc_trusted_proxies.clone();
                security.max_request_body_size = Some(10 * 1024 * 1024);
                security.max_connections = Some(500);
                security
            }
            Err(e) => {
                eprintln!("RPC configuration error: {e}");
                return;
            }
        };

        // (security audit §5 wiring) emit a prominent startup
        // Warning if the *resolved* `auth_required` is false. This block
        // Runs regardless of which constructor
        // (`RpcSecurityConfig::default`, `operator_default`,
        // `from_env`) produced the config - the check is on the
        // Resolved value, not the code path. Without this, an operator
        // Who set `[rpc] auth_required = false` in their TOML (or
        // Relied on the prior NodeConfig default) would silently ship
        // An unauthenticated node.
        if !rpc_security.auth_required {
            tracing::warn!(
                "[GUVENLIK] Public RPC auth_required=false calisiyor - tum state-degistiren metodlar kimlik dogrulamasiz aga acik! --rpc-auth-required=true (veya esdeger config) ile kapatin."
            );
        }
        // Same reasoning for an unrestricted IP allow-list. The runtime
        // Treats an empty list as "allow all", so a non-empty list
        // Outside localhost is a strong signal that this is an
        // Intentional public deployment.
        let has_localhost_only = !rpc_security.allowed_ips.is_empty()
            && rpc_security
                .allowed_ips
                .iter()
                .all(|ip| ip == "127.0.0.1" || ip == "::1");
        if !has_localhost_only && !rpc_security.allowed_ips.is_empty() {
            tracing::warn!(
                "[GUVENLIK] Public RPC allowed_ips genisletildi: {:?} - sadece guvenilir / ozel ag uzerinde calistirin.",
                rpc_security.allowed_ips
            );
        }

        // Public RPC listener
        let public_addr = config
            .rpc_public_listener
            .clone()
            .unwrap_or_else(|| format!("{}:{}", config.rpc_host, config.rpc_port));
        let pub_server = RpcServer::with_security_and_mode(
            chain.clone(),
            node.get_client(),
            rpc_security.clone(),
            RpcMode::Public,
        )
        .with_metrics(metrics.clone());
        let pub_addr = public_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = pub_server.run(pub_addr.clone()).await {
                eprintln!("Public RPC Server Error on {pub_addr}: {e}");
            } else {
                println!("Public JSON-RPC Server running on {pub_addr}");
            }
        });

        // Operator RPC listener (localhost-only, no auth by default)
        if let Some(operator_addr) = config.rpc_operator_listener.as_ref() {
            let op_security = RpcSecurityConfig::operator_default();
            let op_server = RpcServer::with_security_and_mode(
                chain.clone(),
                node.get_client(),
                op_security,
                RpcMode::Operator,
            )
            .with_metrics(metrics.clone());
            let op_addr = operator_addr.clone();
            tokio::spawn(async move {
                if let Err(e) = op_server.run(op_addr.clone()).await {
                    eprintln!("Operator RPC Server Error on {op_addr}: {e}");
                } else {
                    println!("Operator JSON-RPC Server running on {op_addr}");
                }
            });
        }
    } else {
        println!("JSON-RPC Server disabled by config");
    }

    let metrics_clone = metrics.clone();
    let metrics_bind = config
        .metrics_listener
        .clone()
        .unwrap_or_else(|| format!("0.0.0.0:{}", config.metrics_port));
    tokio::spawn(async move {
        use http_body_util::Full;
        use hyper::service::service_fn;
        use hyper::{body::Bytes, Request, Response};
        use hyper_util::rt::TokioIo;

        let listener = match tokio::net::TcpListener::bind(metrics_bind.clone()).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Metrics server bind error: {e}");
                return;
            }
        };
        println!("Prometheus metrics on {metrics_bind}/metrics");
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let m = metrics_clone.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            io,
                            service_fn(move |req: Request<hyper::body::Incoming>| {
                                let body = m.encode();
                                async move {
                                    if req.uri().path() != "/metrics" {
                                        return Ok::<_, std::convert::Infallible>(
                                            Response::builder()
                                                .status(404)
                                                .body(Full::new(Bytes::from("404 Not Found\n")))
                                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("404")))),
                                        );
                                    }
                                    if let Ok(key) = std::env::var("BUDLUM_METRICS_API_KEY") {
                                        if !key.is_empty() {
                                            let auth_hdr = req
                                                .headers()
                                                .get("authorization")
                                                .and_then(|v| v.to_str().ok())
                                                .unwrap_or("");
                                            let api_key_hdr = req
                                                .headers()
                                                .get("x-api-key")
                                                .and_then(|v| v.to_str().ok())
                                                .unwrap_or("");
                                            let bearer = format!("Bearer {key}");
                                            if auth_hdr != bearer && api_key_hdr != key {
                                                return Ok(
                                                    Response::builder()
                                                        .status(401)
                                                        .body(Full::new(Bytes::from("401 Unauthorized: metrics require valid BUDLUM_METRICS_API_KEY\n")))
                                                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("401")))),
                                                );
                                            }
                                        }
                                    }
                                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                        Bytes::from(body),
                                    )))
                                }
                            }),
                        )
                        .await;
                });
            }
        }
    });

    // Start Relayer Worker if configured
    if config.role == "relayer" || config.role == "validator" {
        let relayer_addr = cli_producer_address.unwrap_or(Address::zero());
        // Persist the relay cursor next to the chain database. Without a path
        // The worker resumes from `get_finalized_height()` at boot, so every
        // Request that finalized while it was down is skipped: the user has
        // Paid the fee and nothing ever acts on the request. `with_cursor_path`
        // Existed and was never called, which left the fix inert in
        // Production.
        let cursor_path = std::path::Path::new(&config.db_path).join("relayer-cursor");
        let relayer = budlum_core::relayer::RelayerWorker::new(chain.clone(), relayer_addr)
            .with_cursor_path(Some(cursor_path));
        tokio::spawn(async move {
            relayer.run().await;
        });
    }

    // (2026-07-18,) Daemon blok-üretim döngüsü (PoS + PoW).
    // Kök neden (CI kanıtlı, multinode smoke job 87990206239): binary yalnız
    // Interaktif stdin "mine" komutuyla blok üretiyordu - daemon/compose
    // Ağları genesis'te (height=0x0) donuyordu. Döngü, producer adresi
    // Yapılandırılmışsa PoS ve PoW'da çalışır. Üretici-uygunluk tek otorite
    // Olarak motor katmanında kalır: PoS'ta `preview_common` (aktif-validator
    // + VRF liderlik - bunun için daemon'un PoSEngine'e enjekte edilmiş
    // Validator_keys'e ihtiyacı vardır; adres-only 0x02 ile PoS üretimi
    // YAPAMAZ, bakınız STATUS_ONLINE backlog), PoW'da `mine` (difficulty
    // CLI bayrağından; smoke difficulty=0). Yayın gossipsub "blocks"
    // Kanalından; eşler aynı deterministik commit yolunu koşar.
    if consensus_type == ConsensusType::PoS || consensus_type == ConsensusType::PoW {
        if let Some(producer) = cli_producer_address {
            let chain_p = chain.clone();
            let client_p = client.clone();
            let interval_ms = network_params
                .slot_ms
                .max(u64::try_from(budlum_core::consensus::MIN_BLOCK_INTERVAL_MS).unwrap_or(1_000));
            tracing::info!("Daemon block producer aktif: {producer}");
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_millis(interval_ms));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tick.tick().await;
                    if let Some((block, _pruned_cids)) = chain_p.produce_block(producer).await {
                        tracing::info!("Produced block #{}", block.index);
                        client_p
                            .broadcast("blocks".to_string(), NetworkMessage::Block(block))
                            .await;
                    }
                }
            });
        } else {
            tracing::warn!(
                "Daemon: producer adresi yapılandırılmadı (--validator-address / validator key) - node yalnızca doğrular ve senkronize olur."
            );
        }
    }

    tokio::select! {
        _ = node.run() => {},
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutdown signal received");
            match chain.flush_storage().await {
                Ok(bytes) => tracing::info!("Storage flushed: {bytes} bytes"),
                Err(e) => tracing::error!("Storage flush failed during shutdown: {e}"),
            }
        },
        _ = async {
            let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
            let mut line = String::new();
            client.subscribe("blocks".to_string()).await;
            client.subscribe("transactions".to_string()).await;
            loop {
                line.clear();
                use tokio::io::AsyncBufReadExt;
                if stdin.read_line(&mut line).await.is_ok() {
                    let cmd = line.trim();
                    match cmd {
                        "tx" => {
                            let alice = Address::from_hex(&"01".repeat(32)).unwrap();
                            let bob = Address::from_hex(&"02".repeat(32)).unwrap();
                            let tx = Transaction::new(
                                alice,
                                bob,
                                10,
                                b"demo tx".to_vec(),
                            );
                            client.broadcast("transactions".to_string(), NetworkMessage::Transaction(tx)).await;
                        }
                        "block" | "mine" => {
                            let producer = cli_producer_address.unwrap_or(Address::zero());
                            if let Some((block, pruned_cids)) = chain.produce_block(producer).await {
                                println!("Produced block #{} with {} txs", block.index, block.transactions.len());
                                for cid in pruned_cids {
                                    client.storage_prune_sync(cid);
                                }
                            }
                        }
                        "chain" => {
                            let info = chain.get_chain_info().await;
                            println!("{info}");
                        }
                        "peers" => {
                            client.list_peers().await;
                        }
                        "sync" => {
                            let msg = NetworkMessage::GetHeaders {
                                locator: Vec::new(),
                                limit: 2000,
                            };
                            client.broadcast("blocks".to_string(), msg).await;
                        }
                        "help" => {
                            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                            println!("Commands:");
                            println!("   tx    - Send demo transaction");
                            println!("   mine  - Produce new block");
                            println!("   chain - Show blockchain info");
                            println!("   peers - List connected peers");
                            println!("   sync  - Request chain sync");
                            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                        }
                        _ => {}
                    }
                }
            }
        } => {}
    }
}
