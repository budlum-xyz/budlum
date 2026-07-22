//! Budlum L1 CLI — işlem gönderme, state sorgulama, validator kılavuzu.
//!
//! Task 11.3 Görev 5. Bu binary L1 çekirdeği (`budlum_core`) ile konuşur:
//! imzalı işlem oluştur + gönder (`tx send`), salt-okunur sorgu
//! (`query balance`/`query block`/`query status`), validator çalıştırma
//! kılavuzu (`validator run`).
//!
//! BudZKVM toolchain (`budzero/bud-cli`) ayrı bir workspace'tir; bu binary
//! L1 zincir etkileşimi içindir ve doğrudan çekirdek tiplerini kullanır.
//!
//! # Tasarım
//! - JSON-RPC taşıması: std `TcpStream` üzerinden elle yazılmış minimal HTTP/1.1
//!   POST. Yeni dış bağımlılık YOK (CLI için yeterli; localhost/tek-düğüm).
//! - İmzalama: `KeyPair::from_seed` (32-byte hex tohum) → `Transaction::sign`.
//! - Düğüm adrese `--rpc-url` (varsayılan `http://127.0.0.1:8545`).

use budlum_core::core::address::Address;
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::crypto::primitives::KeyPair;
use clap::{Parser, Subcommand};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8545";
const RPC_TIMEOUT_SECS: u64 = 15;

#[derive(Parser)]
#[command(
    name = "bud",
    author,
    version,
    about = "Budlum L1 CLI — tx gönder, state sorgula, validator kılavuzu"
)]
struct Cli {
    /// Düğüm JSON-RPC uç noktası.
    #[arg(long, global = true, default_value = DEFAULT_RPC_URL)]
    rpc_url: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// İmzalı işlem oluştur ve düğüme gönder.
    Tx {
        #[command(subcommand)]
        action: TxAction,
    },
    /// Salt-okunur state sorgusu (relayer-bağımsız).
    Query {
        #[command(subcommand)]
        action: QueryAction,
    },
    /// Validator/node çalıştırma kılavuzu (tam node runner ayrı konu).
    Validator {
        /// `config/mainnet.toml` gibi yapılandırma dosyası (doğrula + özetle).
        #[arg(short, long)]
        config: Option<String>,
    },
}

#[derive(Subcommand)]
enum TxAction {
    /// BDLM transfer gönder.
    Send {
        /// Alıcı adres (hex, 0x öneki opsiyonel).
        #[arg(long, required = true)]
        to: String,
        /// Transfer miktarı (base units).
        #[arg(long, required = true)]
        amount: u64,
        /// Gönderenin 32-byte hex imzalama tohumu (private key).
        #[arg(long, required = true)]
        priv_key: String,
        /// İşlem ücreti (base units).
        #[arg(long, default_value_t = 0)]
        fee: u64,
        /// İşlem nonce'u (verilmezse düğümden `bud_getNonce` ile alınır).
        #[arg(long)]
        nonce: Option<u64>,
    },
}

#[derive(Subcommand)]
enum QueryAction {
    /// Adres bakiyesini sorgula (`bud_getBalance`).
    Balance {
        /// Adres (hex, 0x öneki opsiyonel).
        address: String,
    },
    /// Bloğu numara ile sorgula (`bud_getBlockByNumber`).
    Block {
        /// Blok numarası veya `latest`.
        number: String,
    },
    /// Zincir durumunu sorgula (`bud_getStatus`).
    Status,
}

/// `http://host:port` URL'sini (host, port) çiftine ayrıştırır. Path yok sayılır.
fn parse_rpc_url(url: &str) -> Result<(String, u16), String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        format!("--rpc-url 'http://' şeması bekler (https desteklenmiyor): '{url}'")
    })?;
    let host_port = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| format!("geçersiz port: '{p}'"))?,
        ),
        None => (host_port.to_string(), 8545u16),
    };
    if host.is_empty() {
        return Err("boş host".to_string());
    }
    Ok((host, port))
}

/// std TcpStream üzerinden minimal HTTP/1.1 POST + tam cevap gövdesi oku.
fn http_post_json(host: &str, port: u16, body: &str) -> Result<String, String> {
    let mut stream = TcpStream::connect((host, port))
        .map_err(|e| format!("bağlantı hatası ({host}:{port}): {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(RPC_TIMEOUT_SECS)))
        .map_err(|e| format!("read_timeout ayarı: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(RPC_TIMEOUT_SECS)))
        .map_err(|e| format!("write_timeout ayarı: {e}"))?;

    let request = format!(
        "POST / HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("istek yazma hatası: {e}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("cevap okuma hatası: {e}"))?;
    let text = String::from_utf8(raw).map_err(|e| format!("UTF-8 ayrıştırma: {e}"))?;

    // HTTP başlık/gövde ayrımı: ilk "\r\n\r\n" sonrası gövdedir.
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(&text);
    Ok(body.to_string())
}

/// JSON-RPC cevabını ayrıştır: `result` döndür veya `error` mesajını yay.
fn rpc_result(resp: &serde_json::Value) -> Result<serde_json::Value, String> {
    if let Some(err) = resp.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("bilinmeyen JSON-RPC hatası");
        return Err(format!("JSON-RPC hata: {msg}"));
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| "JSON-RPC cevap 'result' alanı yok".to_string())
}

/// Tek bir JSON-RPC çağrısı yap.
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
    let body_str = serde_json::to_string(&body).map_err(|e| format!("istek serileştirme: {e}"))?;
    let resp_text = http_post_json(&host, port, &body_str)?;
    let v: serde_json::Value =
        serde_json::from_str(&resp_text).map_err(|e| format!("RPC cevap ayrıştırma: {e}"))?;
    rpc_result(&v)
}

/// Adresi esnek ayrıştır (0x öneki opsiyonel).
fn parse_address(s: &str) -> Result<Address, String> {
    Address::from_hex(s).map_err(|e| format!("geçersiz adres '{s}': {e}"))
}

/// 32-byte hex imzalama tohumunu ayrıştır.
fn parse_seed(hex_str: &str) -> Result<[u8; 32], String> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).map_err(|e| format!("geçersiz hex priv key: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "priv key 32 byte olmalı".to_string())?;
    Ok(arr)
}

#[allow(clippy::too_many_arguments)]
fn run_tx_send(
    rpc_url: &str,
    to: &str,
    amount: u64,
    priv_key: &str,
    fee: u64,
    nonce: Option<u64>,
) -> Result<(), String> {
    let seed = parse_seed(priv_key)?;
    let keypair = KeyPair::from_seed(&seed).map_err(|e| format!("anahtar türetme: {e}"))?;
    let from = Address::from(keypair.public_key_bytes());
    let to_addr = parse_address(to)?;

    // Nonce: verilmezse düğümden al.
    let nonce = match nonce {
        Some(n) => n,
        None => {
            let r = rpc_call(rpc_url, "bud_getNonce", serde_json::json!([from.to_hex()]))?;
            let s = r
                .as_str()
                .ok_or("bud_getNonce string döndürmeli")?
                .parse::<u64>()
                .map_err(|e| format!("nonce ayrıştırma: {e}"))?;
            println!("nonce (düğümden): {s}");
            s
        }
    };

    // İşlemi kur + imzala.
    let mut tx = Transaction::new(from, to_addr, amount, Vec::new());
    tx.fee = fee;
    tx.nonce = nonce;
    tx.tx_type = TransactionType::Transfer;
    tx.sign(&keypair);

    let tx_hash = tx.calculate_hash();
    println!("tx hash (imzalı): {tx_hash}");

    // Gönder (bud_sendRawTransaction Transaction nesnesini doğrudan alır).
    let r = rpc_call(rpc_url, "bud_sendRawTransaction", serde_json::json!([tx]))?;
    match r.as_str() {
        Some(returned) => println!("gönderildi \u{2713} — düğüm tx hash: {returned}"),
        None => println!("gönderildi \u{2713} — düğüm cevap: {r}"),
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
        Some(balance) => println!("bakiye ({address}): {balance}"),
        None => println!("bakiye ({address}): {r}"),
    }
    Ok(())
}

fn run_query_block(rpc_url: &str, number: &str) -> Result<(), String> {
    let r = rpc_call(rpc_url, "bud_getBlockByNumber", serde_json::json!([number]))?;
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

fn run_validator(config: Option<&str>) -> Result<(), String> {
    // Tam node runner (chain + consensus loop + RPC sunucu) paketli bir binary
    // değildir — `validator run` burada yapılandırma doğrulama + kılavuz verir.
    // `RpcServer::run` + `NodeConfig` ile gerçek node başlatma gelecek görev.
    match config {
        Some(path) => {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("yapılandırma okuma hatası ({path}): {e}"))?;
            // Temel TOML ayrıştırma doğrulaması.
            let _doc: toml::Value =
                toml::from_str(&content).map_err(|e| format!("geçersiz TOML yapılandırma: {e}"))?;
            println!("yapılandırma geçerli (TOML): {path}");
        }
        None => {
            println!("(yapılandırma belirtilmedi — --config <path> ile doğrulanabilir)");
        }
    }
    println!();
    println!("validator çalıştırma:");
    println!("  Tam node runner (konsensüs döngüsü + RPC sunucu) ayrı bir binary'dir.");
    println!("  Bu komut yapılandırma doğrular. Node başlatma için node binary'ini kullanın.");
    println!("  RPC: --rpc-url <url> (varsayılan {DEFAULT_RPC_URL})");
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Tx { action } => match action {
            TxAction::Send {
                to,
                amount,
                priv_key,
                fee,
                nonce,
            } => run_tx_send(&cli.rpc_url, to, *amount, priv_key, *fee, *nonce),
        },
        Command::Query { action } => match action {
            QueryAction::Balance { address } => run_query_balance(&cli.rpc_url, address),
            QueryAction::Block { number } => run_query_block(&cli.rpc_url, number),
            QueryAction::Status => run_query_status(&cli.rpc_url),
        },
        Command::Validator { config } => run_validator(config.as_deref()),
    };
    if let Err(e) = result {
        eprintln!("hata: {e}");
        std::process::exit(1);
    }
}
