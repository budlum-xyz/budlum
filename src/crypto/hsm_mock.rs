//! Tur 15.1 / MAINNET_READINESS §2.2 (Ayaz Karar = Seçenek A & B):
//! BLS-PQ HSM Mock Backend (UNIX Domain Socket / JSON-RPC in-process simulation).
//!
//! Allows developers and auditors to test external BLS/PQ key protection and
//! out-of-process/in-process socket signing (`ConsensusSigner`) without requiring
//! physical PKCS#11 hardware tokens.

use crate::core::address::Address;
use crate::crypto::primitives::{BlsKeypair, CryptoError, KeyPair, PqKeyPair};
use crate::crypto::signer::ConsensusSigner;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

/// DTO for requests over the HSM mock UNIX socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmRequest {
    pub op: String, // "pubkey" | "sign_block" | "bls_sign" | "pq_sign" | "ping"
    #[serde(default)]
    pub payload: String, // hex encoded message
}

/// DTO for responses over the HSM mock UNIX socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmResponse {
    pub status: String, // "ok" | "error"
    #[serde(default)]
    pub result: String, // hex encoded signature / pubkey
    #[serde(default)]
    pub error: String,
}

/// In-process background thread server simulating an external BLS/PQ HSM backend.
pub struct HsmMockServer {
    socket_path: PathBuf,
    _listener_thread: Option<thread::JoinHandle<()>>,
}

impl HsmMockServer {
    /// Start the HSM mock server in an in-process background thread listening on `socket_path`.
    pub fn spawn_inprocess<P: AsRef<Path>>(
        socket_path: P,
        sig_key: Option<KeyPair>,
        bls_key: Option<BlsKeypair>,
        pq_key: Option<PqKeyPair>,
    ) -> Result<Self, String> {
        let path = socket_path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }

        let listener = UnixListener::bind(&path)
            .map_err(|e| format!("Failed to bind HSM mock UNIX socket at {:?}: {}", path, e))?;

        let sig_key_arc = Arc::new(Mutex::new(sig_key));
        let bls_key_arc = Arc::new(Mutex::new(bls_key));
        let pq_key_arc = Arc::new(Mutex::new(pq_key));

        let handle = thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let sig_k = Arc::clone(&sig_key_arc);
                let bls_k = Arc::clone(&bls_key_arc);
                let pq_k = Arc::clone(&pq_key_arc);
                thread::spawn(move || {
                    if let Err(e) = Self::handle_client(&mut stream, sig_k, bls_k, pq_k) {
                        tracing::debug!("HSM mock client connection error: {}", e);
                    }
                });
            }
        });

        Ok(Self {
            socket_path: path,
            _listener_thread: Some(handle),
        })
    }

    fn handle_client(
        stream: &mut UnixStream,
        sig_key: Arc<Mutex<Option<KeyPair>>>,
        bls_key: Arc<Mutex<Option<BlsKeypair>>>,
        pq_key: Arc<Mutex<Option<PqKeyPair>>>,
    ) -> Result<(), String> {
        let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
        let mut line = String::new();
        while reader
            .read_line(&mut line)
            .map_err(|e| e.to_string())?
            > 0
        {
            if line.trim().is_empty() {
                continue;
            }
            let req: HsmRequest = serde_json::from_str(&line).map_err(|e| e.to_string())?;
            let resp = match req.op.as_str() {
                "ping" => HsmResponse {
                    status: "ok".into(),
                    result: "pong".into(),
                    error: "".into(),
                },
                "pubkey" => {
                    if let Ok(guard) = sig_key.lock() {
                        if let Some(ref k) = *guard {
                            HsmResponse {
                                status: "ok".into(),
                                result: hex::encode(k.public_key_bytes()),
                                error: "".into(),
                            }
                        } else {
                            HsmResponse {
                                status: "error".into(),
                                result: "".into(),
                                error: "No signing key in HSM mock".into(),
                            }
                        }
                    } else {
                        HsmResponse {
                            status: "error".into(),
                            result: "".into(),
                            error: "Key lock poisoned".into(),
                        }
                    }
                }
                "sign_block" => {
                    if let Ok(guard) = sig_key.lock() {
                        if let Some(ref k) = *guard {
                            if let Ok(msg_bytes) = hex::decode(req.payload.trim()) {
                                let mut arr = [0u8; 32];
                                if msg_bytes.len() == 32 {
                                    arr.copy_from_slice(&msg_bytes);
                                    let sig = k.sign(&arr);
                                    HsmResponse {
                                        status: "ok".into(),
                                        result: hex::encode(sig),
                                        error: "".into(),
                                    }
                                } else {
                                    HsmResponse {
                                        status: "error".into(),
                                        result: "".into(),
                                        error: "sign_block payload must be 32 bytes hex".into(),
                                    }
                                }
                            } else {
                                HsmResponse {
                                    status: "error".into(),
                                    result: "".into(),
                                    error: "invalid hex payload".into(),
                                }
                            }
                        } else {
                            HsmResponse {
                                status: "error".into(),
                                result: "".into(),
                                error: "No signing key in HSM mock".into(),
                            }
                        }
                    } else {
                        HsmResponse {
                            status: "error".into(),
                            result: "".into(),
                            error: "Key lock poisoned".into(),
                        }
                    }
                }
                "bls_sign" => {
                    if let Ok(guard) = bls_key.lock() {
                        if let Some(ref bls) = *guard {
                            if let Ok(msg_bytes) = hex::decode(req.payload.trim()) {
                                let sig = crate::chain::finality::sign_bls(&bls.secret_key, &msg_bytes);
                                HsmResponse {
                                    status: "ok".into(),
                                    result: hex::encode(sig),
                                    error: "".into(),
                                }
                            } else {
                                HsmResponse {
                                    status: "error".into(),
                                    result: "".into(),
                                    error: "invalid hex payload".into(),
                                }
                            }
                        } else {
                            HsmResponse {
                                status: "error".into(),
                                result: "".into(),
                                error: "No BLS key in HSM mock".into(),
                            }
                        }
                    } else {
                        HsmResponse {
                            status: "error".into(),
                            result: "".into(),
                            error: "BLS key lock poisoned".into(),
                        }
                    }
                }
                "pq_sign" => {
                    if let Ok(guard) = pq_key.lock() {
                        if let Some(ref pq) = *guard {
                            if let Ok(msg_bytes) = hex::decode(req.payload.trim()) {
                                match pq.sign(&msg_bytes) {
                                    Ok(sig) => HsmResponse {
                                        status: "ok".into(),
                                        result: hex::encode(sig),
                                        error: "".into(),
                                    },
                                    Err(e) => HsmResponse {
                                        status: "error".into(),
                                        result: "".into(),
                                        error: e.to_string(),
                                    },
                                }
                            } else {
                                HsmResponse {
                                    status: "error".into(),
                                    result: "".into(),
                                    error: "invalid hex payload".into(),
                                }
                            }
                        } else {
                            HsmResponse {
                                status: "error".into(),
                                result: "".into(),
                                error: "No PQ key in HSM mock".into(),
                            }
                        }
                    } else {
                        HsmResponse {
                            status: "error".into(),
                            result: "".into(),
                            error: "PQ key lock poisoned".into(),
                        }
                    }
                }
                _ => HsmResponse {
                    status: "error".into(),
                    result: "".into(),
                    error: format!("Unknown HSM op: {}", req.op),
                },
            };

            let mut out = serde_json::to_string(&resp).map_err(|e| e.to_string())?;
            out.push('\n');
            stream.write_all(out.as_bytes()).map_err(|e| e.to_string())?;
            stream.flush().map_err(|e| e.to_string())?;
            line.clear();
        }
        Ok(())
    }
}

impl Drop for HsmMockServer {
    fn drop(&mut self) {
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

/// ConsensusSigner implementation connecting via UNIX Domain Socket to `HsmMockServer`.
pub struct HsmMockSigner {
    socket_path: PathBuf,
    pubkey: [u8; 32],
}

impl HsmMockSigner {
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Result<Self, CryptoError> {
        let path = socket_path.as_ref().to_path_buf();
        let resp = Self::rpc_call(&path, "pubkey", "")?;
        if resp.status != "ok" {
            return Err(CryptoError::InvalidKey(format!(
                "HSM mock pubkey check failed: {}",
                resp.error
            )));
        }
        let pk_bytes = hex::decode(resp.result.trim())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        if pk_bytes.len() != 32 {
            return Err(CryptoError::InvalidKey("HSM pubkey must be 32 bytes".into()));
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&pk_bytes);
        Ok(Self {
            socket_path: path,
            pubkey,
        })
    }

    fn rpc_call(path: &Path, op: &str, payload: &str) -> Result<HsmResponse, CryptoError> {
        let mut stream = UnixStream::connect(path).map_err(|e| {
            CryptoError::Io(format!("Failed to connect to HSM socket {:?}: {}", path, e))
        })?;
        let req = HsmRequest {
            op: op.to_string(),
            payload: payload.to_string(),
        };
        let mut out = serde_json::to_string(&req)
            .map_err(|e| CryptoError::Io(e.to_string()))?;
        out.push('\n');
        stream
            .write_all(out.as_bytes())
            .map_err(|e| CryptoError::Io(e.to_string()))?;
        stream
            .flush()
            .map_err(|e| CryptoError::Io(e.to_string()))?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| CryptoError::Io(e.to_string()))?;
        serde_json::from_str(&line).map_err(|e| CryptoError::Io(e.to_string()))
    }
}

impl ConsensusSigner for HsmMockSigner {
    fn public_key_bytes(&self) -> [u8; 32] {
        self.pubkey
    }

    fn address(&self) -> Address {
        Address::from(self.pubkey)
    }

    fn sign_block(&self, block_hash: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        let resp = Self::rpc_call(&self.socket_path, "sign_block", &hex::encode(block_hash))?;
        if resp.status != "ok" {
            return Err(CryptoError::Signing(resp.error));
        }
        hex::decode(resp.result.trim()).map_err(|e| CryptoError::Signing(e.to_string()))
    }

    fn bls_sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let resp = Self::rpc_call(&self.socket_path, "bls_sign", &hex::encode(msg))?;
        if resp.status != "ok" {
            return Err(CryptoError::Signing(resp.error));
        }
        hex::decode(resp.result.trim()).map_err(|e| CryptoError::Signing(e.to_string()))
    }

    fn pq_sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let resp = Self::rpc_call(&self.socket_path, "pq_sign", &hex::encode(msg))?;
        if resp.status != "ok" {
            return Err(CryptoError::Signing(resp.error));
        }
        hex::decode(resp.result.trim()).map_err(|e| CryptoError::Signing(e.to_string()))
    }

    fn backend_name(&self) -> &'static str {
        "hsm_mock_unix_socket"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_hsm_mock_backend_inprocess_thread_bls_pq_signing() {
        let dir = tempdir().unwrap();
        let sock = dir.path().join("mock.sock");

        let kp = KeyPair::generate().unwrap();
        let bls = BlsKeypair::generate().unwrap();
        let pq = PqKeyPair::generate();

        let _server = HsmMockServer::spawn_inprocess(&sock, Some(kp.clone()), Some(bls.clone()), Some(pq.clone())).unwrap();

        // Give the background thread 50ms to bind socket
        std::thread::sleep(std::time::Duration::from_millis(50));

        let signer = HsmMockSigner::new(&sock).unwrap();
        assert_eq!(signer.public_key_bytes(), kp.public_key_bytes());
        assert_eq!(signer.backend_name(), "hsm_mock_unix_socket");

        // Test sign_block
        let hash = [42u8; 32];
        let sig = signer.sign_block(&hash).unwrap();
        assert!(kp.verify(&hash, &sig).is_ok());

        // Test bls_sign
        let bls_sig = signer.bls_sign(b"test bls").unwrap();
        assert!(!bls_sig.is_empty());

        // Test pq_sign
        let pq_sig = signer.pq_sign(b"test pq").unwrap();
        assert!(!pq_sig.is_empty());
    }
}
