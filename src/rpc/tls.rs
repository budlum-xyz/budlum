//! In-process TLS for the RPC listener.
//!
//! The acceptor takes its configuration from [`crate::crypto::tls`]: TLS 1.3
//! with X25519MLKEM768 as the only key-exchange group. A client that offers
//! X25519 alone cannot connect.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

/// Builds the acceptor from a PEM certificate chain and a PEM private key.
///
/// # Errors
///
/// Returns a message naming the file when it is missing, holds no
/// certificate or key, or the pair does not form a usable server identity.
pub fn acceptor_from_files(cert_file: &Path, key_file: &Path) -> Result<TlsAcceptor, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_file)
        .map_err(|e| format!("RPC TLS certificate {}: {e}", cert_file.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("RPC TLS certificate {}: {e}", cert_file.display()))?;
    if chain.is_empty() {
        return Err(format!(
            "RPC TLS certificate {} holds no certificate",
            cert_file.display()
        ));
    }
    let key = PrivateKeyDer::from_pem_file(key_file)
        .map_err(|e| format!("RPC TLS key {}: {e}", key_file.display()))?;
    let config = crate::crypto::tls::server_config(chain, key)
        .map_err(|e| format!("RPC TLS identity is unusable: {e}"))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_files_are_named() {
        let err = acceptor_from_files(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
        )
        .map(|_| ())
        .unwrap_err();
        assert!(err.contains("/nonexistent/cert.pem"), "{err}");
    }

    #[test]
    fn certificate_file_without_a_certificate_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, "not a pem\n").unwrap();
        std::fs::write(&key, "not a pem\n").unwrap();
        assert!(acceptor_from_files(&cert, &key).is_err());
    }

    #[test]
    fn generated_identity_loads() {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, generated.cert.pem()).unwrap();
        std::fs::write(&key, generated.key_pair.serialize_pem()).unwrap();
        assert!(acceptor_from_files(&cert, &key).is_ok());
    }
}
