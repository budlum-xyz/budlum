//! In-process TLS for the RPC listener.
//!
//! The acceptor takes its configuration from [`crate::crypto::tls`]: TLS 1.3
//! with X25519MLKEM768 as the only key-exchange group. A client that offers
//! X25519 alone cannot connect.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

/// The longest TLS private key file this listener will read.
///
/// A misconfigured path (a disk image, a log file) would otherwise be read
/// into memory before the PEM parser rejected it.
const MAX_PRIVATE_KEY_BYTES: u64 = 64 * 1024;

/// Refuse a private key path that is a symlink, is not a regular file, is
/// readable by group or others, or is larger than [`MAX_PRIVATE_KEY_BYTES`].
///
/// The key is read through this handle, so the file that was checked is the
/// file that is parsed. The previous code let the PEM reader open the path a
/// second time, and nothing checked the mode at all, so a `0644` identity key
/// loaded without complaint, and a `serverAuth` private key readable by every
/// local user is the whole of that identity.
fn read_private_key_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let link = std::fs::symlink_metadata(path)
        .map_err(|e| format!("RPC TLS key {}: {e}", path.display()))?;
    if link.file_type().is_symlink() {
        return Err(format!(
            "RPC TLS key {} is a symlink; the identity key must sit in a regular file of its own",
            path.display()
        ));
    }
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("RPC TLS key {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("RPC TLS key {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "RPC TLS key {} is not a regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "RPC TLS key {} is readable by group or world (mode {:o}); run: chmod 600 {}",
                path.display(),
                mode & 0o777,
                path.display()
            ));
        }
    }
    if metadata.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(format!(
            "RPC TLS key {} is larger than {MAX_PRIVATE_KEY_BYTES} bytes; it does not hold one key",
            path.display()
        ));
    }
    let mut raw = Vec::new();
    (&mut file)
        .take(MAX_PRIVATE_KEY_BYTES.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|e| format!("RPC TLS key {}: {e}", path.display()))?;
    if raw.len() as u64 > MAX_PRIVATE_KEY_BYTES {
        return Err(format!(
            "RPC TLS key {} is larger than {MAX_PRIVATE_KEY_BYTES} bytes; it does not hold one key",
            path.display()
        ));
    }
    Ok(raw)
}

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
    let key_bytes = read_private_key_bytes(key_file)?;
    let key = PrivateKeyDer::from_pem_slice(&key_bytes)
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
        std::fs::write(&key, generated.signing_key.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(acceptor_from_files(&cert, &key).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_private_key_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, generated.cert.pem()).unwrap();
        std::fs::write(&key, generated.signing_key.serialize_pem()).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let answer = acceptor_from_files(&cert, &key);
        assert!(
            answer.is_err(),
            "a world-readable TLS private key must be refused"
        );
        let err = match answer {
            Ok(_) => String::from("the key was accepted"),
            Err(message) => message,
        };
        assert!(
            err.contains("group or world") || err.contains("0600"),
            "the refusal must name the mode: got {err}"
        );
    }
}
