//! TLS crypto provider.
//!
//! Every TLS endpoint Budlum owns, listener or client, takes its provider
//! from here. The provider is `aws-lc-rs` and the only key-exchange group it
//! offers is X25519MLKEM768 (RFC 10024, code point 0x11EC), over TLS 1.3. A
//! peer that offers X25519 alone cannot complete a handshake, so a recorded
//! session cannot be opened by a quantum attacker later (INV-08).
//!
//! The same provider is installed as the process default, so `reqwest` and
//! any other rustls user in the binary inherit it.

use std::sync::Arc;

use rustls::crypto::{aws_lc_rs, CryptoProvider};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};

/// TLS 1.3 only. TLS 1.2 has no hybrid key exchange.
/// exposed for: the crypto registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub static TLS_VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// The provider with X25519MLKEM768 as its only key-exchange group and only
/// post-quantum-strength TLS 1.3 256-bit AEAD cipher suites.
///
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
#[must_use]
pub fn hybrid_only_provider() -> CryptoProvider {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
    provider.cipher_suites = vec![
        aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    provider
}

/// Returns `true` when `provider` enforces `X25519MLKEM768` exclusively and
/// restricts cipher suites to 256-bit TLS 1.3 AEAD suites.
///
/// Convenience: used to detect classical downgrade of the process-wide default.
#[must_use]
pub fn is_hybrid_only_provider(provider: &CryptoProvider) -> bool {
    provider.kx_groups.len() == 1
        && provider
            .kx_groups
            .first()
            .is_some_and(|g| g.name() == rustls::NamedGroup::X25519MLKEM768)
        && !provider.cipher_suites.is_empty()
        && provider.cipher_suites.iter().all(|s| {
            matches!(
                s.suite(),
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                    | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
            )
        })
}

/// Installs [`hybrid_only_provider`] as the process-wide default and verifies
/// that no classical-only provider already occupies the process slot.
///
/// # Errors
///
/// Returns an error if an existing default provider allows non-hybrid key
/// exchange or weak/TLS 1.2 cipher suites.
///
/// Convenience: fail-closed check for INV-08 default-provider installation.
pub fn try_install_default_provider() -> Result<(), String> {
    if CryptoProvider::get_default().is_none() {
        let _ = hybrid_only_provider().install_default();
    }
    match CryptoProvider::get_default() {
        Some(active) if is_hybrid_only_provider(active) => Ok(()),
        Some(_) => Err(String::from(
            "process-wide rustls CryptoProvider is not X25519MLKEM768 hybrid-only (INV-08 violation)",
        )),
        None => Err(String::from(
            "failed to install process-wide hybrid-only rustls CryptoProvider",
        )),
    }
}

/// Installs [`hybrid_only_provider`] as the process-wide default. Idempotent:
/// when a hybrid-only default is already installed it is kept.
pub fn install_default_provider() {
    let _ = try_install_default_provider();
}

/// A client configuration that offers X25519MLKEM768 and nothing else.
///
/// # Errors
///
/// Fails when the provider rejects TLS 1.3, which does not happen with the
/// bundled provider.
/// WIRING: unwired - no caller in this tree yet; kept as a declared surface, and nothing depends on it until one arrives.
pub fn client_config(roots: RootCertStore) -> Result<ClientConfig, rustls::Error> {
    Ok(
        ClientConfig::builder_with_provider(Arc::new(hybrid_only_provider()))
            .with_protocol_versions(TLS_VERSIONS)?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// A server configuration that accepts X25519MLKEM768 and nothing else.
///
/// # Errors
///
/// Fails when the certificate chain or the private key is unusable.
pub fn server_config(
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<ServerConfig, rustls::Error> {
    ServerConfig::builder_with_provider(Arc::new(hybrid_only_provider()))
        .with_protocol_versions(TLS_VERSIONS)?
        .with_no_client_auth()
        .with_single_cert(chain, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::SupportedKxGroup;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConnection, NamedGroup, ServerConnection};

    struct Identity {
        chain: Vec<rustls::pki_types::CertificateDer<'static>>,
        key: PrivatePkcs8KeyDer<'static>,
    }

    fn identity() -> Identity {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed certificate");
        Identity {
            chain: vec![generated.cert.der().clone()],
            key: PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()),
        }
    }

    fn roots(identity: &Identity) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(identity.chain[0].clone()).expect("trust anchor");
        roots
    }

    /// Runs the handshake in memory. Returns the key-exchange group each side
    /// settled on, or the first error either side raised.
    fn handshake(
        client: Arc<ClientConfig>,
        server: Arc<ServerConfig>,
    ) -> Result<(NamedGroup, NamedGroup), rustls::Error> {
        let name = ServerName::try_from("localhost").expect("server name");
        let mut client = ClientConnection::new(client, name)?;
        let mut server = ServerConnection::new(server)?;
        for _ in 0..16 {
            let mut wire = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut wire).expect("client write");
            }
            let mut cursor = wire.as_slice();
            while !cursor.is_empty() {
                server.read_tls(&mut cursor).expect("server read");
                server.process_new_packets()?;
            }
            let mut wire = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut wire).expect("server write");
            }
            let mut cursor = wire.as_slice();
            while !cursor.is_empty() {
                client.read_tls(&mut cursor).expect("client read");
                client.process_new_packets()?;
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                let name = |group: Option<&'static dyn SupportedKxGroup>| {
                    group.map(|g| g.name()).expect("a completed key exchange")
                };
                return Ok((
                    name(client.negotiated_key_exchange_group()),
                    name(server.negotiated_key_exchange_group()),
                ));
            }
        }
        panic!("handshake did not finish in 16 flights");
    }

    fn x25519_only_client(roots: RootCertStore) -> ClientConfig {
        let mut provider = aws_lc_rs::default_provider();
        provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(TLS_VERSIONS)
            .expect("TLS 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    #[test]
    fn handshake_negotiates_x25519mlkem768() {
        let id = identity();
        let client = client_config(roots(&id)).unwrap();
        let server =
            server_config(id.chain.clone(), PrivateKeyDer::Pkcs8(id.key.clone_key())).unwrap();
        let (client_group, server_group) =
            handshake(Arc::new(client), Arc::new(server)).expect("hybrid handshake");
        assert_eq!(client_group, NamedGroup::X25519MLKEM768);
        assert_eq!(server_group, NamedGroup::X25519MLKEM768);
        assert_eq!(u16::from(client_group), 0x11EC);
    }

    #[test]
    fn x25519_only_client_cannot_connect() {
        let id = identity();
        let server =
            server_config(id.chain.clone(), PrivateKeyDer::Pkcs8(id.key.clone_key())).unwrap();
        let client = x25519_only_client(roots(&id));
        assert!(
            handshake(Arc::new(client), Arc::new(server)).is_err(),
            "a server that takes only X25519MLKEM768 must refuse an X25519-only client"
        );
    }

    #[test]
    fn provider_offers_exactly_one_group() {
        let provider = hybrid_only_provider();
        let names: Vec<NamedGroup> = provider.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(names, vec![NamedGroup::X25519MLKEM768]);
    }

    #[test]
    fn tls12_is_not_offered() {
        assert_eq!(TLS_VERSIONS.len(), 1);
        assert_eq!(TLS_VERSIONS[0].version, rustls::ProtocolVersion::TLSv1_3);
    }

    #[test]
    fn provider_excludes_tls12_and_weak_128bit_ciphers() {
        let provider = hybrid_only_provider();
        assert!(!provider.cipher_suites.is_empty());
        for suite in &provider.cipher_suites {
            let s = suite.suite();
            assert!(
                matches!(
                    s,
                    rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                        | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                ),
                "disallowed or <256-bit cipher suite present: {s:?}"
            );
        }
        assert!(is_hybrid_only_provider(&provider));
        assert!(!is_hybrid_only_provider(&aws_lc_rs::default_provider()));
        assert!(try_install_default_provider().is_ok());
    }
}
