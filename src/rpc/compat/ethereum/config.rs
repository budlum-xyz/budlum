//! Where the Ethereum gateway listens, and the two numbers a client can get
//! wrong (section 8.11.1's port table and section 8.10's chain id).
//!
//! # Why this is a constant and not a settings file field
//!
//! Section 8.11.1 gives every compatibility gateway its own **loopback** port:
//! `127.0.0.1:18547` for Ethereum. The public name in front of it is a TLS
//! terminator that routes by host, and the gateway itself never binds a
//! network address. A configuration file that could move this listener to
//! `0.0.0.0` would publish a vocabulary this chain only partly speaks -
//! `eth_getProof` is refused there, and a client that met that refusal through
//! a public endpoint would conclude the chain is broken rather than that the
//! proof format differs.
//!
//! So the address is [`DEFAULT_LISTEN`], and [`Config::validate`] refuses
//! anything that is not loopback. An operator who genuinely needs a different
//! port changes it in the same commit that changes the directive's table.
//!
//! # The chain id
//!
//! Section 8.7.2 and section 8.10 fix foreign-domain chain identity at 45261
//! for Ethereum-family envelopes (WP-27 item 4). `eth_chainId` must answer
//! with this chain's own id, not Ethereum's, or a wallet signs a transaction
//! for a network it is not on. The two numbers are different questions and
//! both are here so a reader can see them side by side.

/// The listener section 8.11.1 assigns to the Ethereum gateway.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:18547";

/// The port the table names, parsed once so a typo in [`DEFAULT_LISTEN`] is a
/// compile-time-adjacent failure rather than a surprise at bind time.
pub const DEFAULT_PORT: u16 = 18547;

/// The chain id a foreign Ethereum-family envelope names (section 8.7.2).
///
/// This is *not* what `eth_chainId` answers; it is the identity this chain
/// presents when it acts inside an Ethereum-shaped envelope, and the two are
/// deliberately separate constants so that neither can be changed by editing
/// the other.
pub const FOREIGN_ETHEREUM_CHAIN_ID: u64 = 45261;

/// Why a gateway configuration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// The listen address is not a loopback address.
    NotLoopback,
    /// The listen address has no port, or an unparseable one.
    BadPort,
    /// The listen address is the native listener's port.
    PortCollision,
}

impl ConfigError {
    /// The reason, as a sentence an operator can act on.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::NotLoopback => {
                "a compatibility gateway binds loopback only; the public name is the TLS \
                 terminator's, and a gateway on a network address publishes a vocabulary this \
                 chain only partly speaks"
            }
            Self::BadPort => "the listen address needs a port between 1 and 65535",
            Self::PortCollision => {
                "18545 and 18546 belong to the native listeners; the Ethereum gateway has its own"
            }
        }
    }
}

/// The gateway's configuration.
///
/// One field, because the rest is not configurable: the method table is fixed
/// by section 8.11.2 and the bounds by rule 3 of the same section. A struct
/// rather than a bare string so the listener can be carried beside the other
/// gateway settings when the transport lands without every caller re-reading a
/// constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The loopback address to bind.
    pub listen: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN.to_owned(),
        }
    }
}

impl Config {
    /// A configuration for `listen`.
    #[must_use]
    pub fn new(listen: impl Into<String>) -> Self {
        Self {
            listen: listen.into(),
        }
    }

    /// The port this configuration binds.
    ///
    /// # Errors
    ///
    /// [`ConfigError::BadPort`] when the address has no port, or a port that is
    /// not a number or is zero.
    pub fn port(&self) -> Result<u16, ConfigError> {
        let (_, port) = self.listen.rsplit_once(':').ok_or(ConfigError::BadPort)?;
        let port: u16 = port.parse().map_err(|_| ConfigError::BadPort)?;
        if port == 0 {
            return Err(ConfigError::BadPort);
        }
        Ok(port)
    }

    /// Check the configuration against section 8.11.1.
    ///
    /// # Errors
    ///
    /// [`ConfigError::NotLoopback`] when the host part is not `127.0.0.1`,
    /// `::1` or `localhost`; [`ConfigError::BadPort`] when the port is not a
    /// number; [`ConfigError::PortCollision`] when the port is one of the
    /// native listeners'.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let (host, _) = self.listen.rsplit_once(':').ok_or(ConfigError::BadPort)?;
        // An IPv6 literal is bracketed: `[::1]:18547`.
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port = self.port()?;
        if port == 18545 || port == 18546 {
            return Err(ConfigError::PortCollision);
        }
        match host {
            "127.0.0.1" | "::1" | "localhost" => Ok(()),
            _ => Err(ConfigError::NotLoopback),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_listener_is_the_directive_s_table() {
        let config = Config::default();
        assert_eq!(config.listen, DEFAULT_LISTEN);
        assert_eq!(config.port(), Ok(DEFAULT_PORT));
        assert_eq!(config.validate(), Ok(()));
        // The constant and the parse agree, or the port table has two answers.
        assert_eq!(DEFAULT_LISTEN, format!("127.0.0.1:{DEFAULT_PORT}"));
    }

    #[test]
    fn a_network_address_is_refused() {
        for listen in ["0.0.0.0:18547", "192.0.2.10:18547", ":18547"] {
            let config = Config::new(listen);
            assert_eq!(
                config.validate(),
                Err(ConfigError::NotLoopback),
                "{listen} must not be bindable"
            );
        }
        // Loopback spellings that are actually loopback.
        for listen in ["127.0.0.1:18547", "[::1]:18547", "localhost:18547"] {
            assert_eq!(
                Config::new(listen).validate(),
                Ok(()),
                "{listen} is loopback"
            );
        }
    }

    #[test]
    fn the_native_ports_are_not_available_to_a_gateway() {
        for listen in ["127.0.0.1:18545", "127.0.0.1:18546"] {
            assert_eq!(
                Config::new(listen).validate(),
                Err(ConfigError::PortCollision)
            );
        }
        assert_eq!(Config::new("127.0.0.1:0").validate(), Err(ConfigError::BadPort));
        assert_eq!(Config::new("127.0.0.1").validate(), Err(ConfigError::BadPort));
        assert_eq!(
            Config::new("127.0.0.1:http").validate(),
            Err(ConfigError::BadPort)
        );
    }

    #[test]
    fn the_foreign_chain_id_is_not_this_chain_s_answer() {
        // Two questions with two answers: a wallet that saw 45261 from
        // `eth_chainId` would be told it is on the foreign envelope's network.
        assert_eq!(FOREIGN_ETHEREUM_CHAIN_ID, 45261);
        assert_ne!(FOREIGN_ETHEREUM_CHAIN_ID, 0);
        // Every refusal names its own reason, or an operator cannot tell a
        // typo from a policy.
        let messages = [
            ConfigError::NotLoopback.message(),
            ConfigError::BadPort.message(),
            ConfigError::PortCollision.message(),
        ];
        for (i, a) in messages.iter().enumerate() {
            for b in &messages[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
