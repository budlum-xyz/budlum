//! Shared admission settings for the public testnet HTTP services.

use hyper::header::HeaderMap;
use std::net::IpAddr;
use std::time::Duration;

pub const MAX_CONNECTIONS: usize = 128;
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
pub const CONNECTION_LIFETIME: Duration = Duration::from_secs(60);
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

/// A listener either serves direct clients, ignoring forwarded headers, or
/// serves only configured proxies and requires their forwarded identity.
#[derive(Clone)]
pub struct ClientIdentity {
    trusted: Vec<IpAddr>,
    direct: bool,
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        other => other,
    }
}

impl ClientIdentity {
    pub fn new(direct: bool, trusted: Vec<IpAddr>) -> Result<Self, String> {
        if direct != trusted.is_empty() {
            return Err(
                "choose exactly one of --allow-direct or one or more --trusted-proxy addresses"
                    .into(),
            );
        }
        Ok(Self {
            trusted: trusted.into_iter().map(canonical).collect(),
            direct,
        })
    }

    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> Result<IpAddr, &'static str> {
        let peer = canonical(peer);
        if self.direct {
            // Direct clients can write XFF themselves. It is never a source
            // of identity unless the immediate peer is a configured proxy.
            return Ok(peer);
        }
        if !self.trusted.contains(&peer) {
            return Err("connection did not come from a trusted proxy");
        }
        let mut values = headers.get_all("x-forwarded-for").iter();
        let header = values
            .next()
            .ok_or("trusted proxy omitted X-Forwarded-For")?;
        if values.next().is_some() {
            return Err("multiple X-Forwarded-For headers");
        }
        let header = header.to_str().map_err(|_| "invalid X-Forwarded-For")?;
        let mut hops = Vec::new();
        for hop in header.split(',') {
            if hops.len() >= 16 {
                return Err("too many X-Forwarded-For hops");
            }
            hops.push(canonical(
                hop.trim()
                    .parse::<IpAddr>()
                    .map_err(|_| "invalid X-Forwarded-For address")?,
            ));
        }
        hops.into_iter()
            .rev()
            .find(|ip| !self.trusted.contains(ip))
            .ok_or("X-Forwarded-For contains no untrusted client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn direct_and_proxy_modes_are_explicit_and_fail_closed() {
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        let client: IpAddr = "203.0.113.50".parse().unwrap();
        assert!(ClientIdentity::new(false, vec![]).is_err());
        assert!(ClientIdentity::new(true, vec![proxy]).is_err());
        let direct = ClientIdentity::new(true, vec![]).unwrap();
        let proxied = ClientIdentity::new(false, vec![proxy]).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.1, 203.0.113.50"),
        );
        assert_eq!(direct.client_ip(client, &headers), Ok(client));
        assert_eq!(proxied.client_ip(proxy, &headers), Ok(client));
        assert!(proxied.client_ip(client, &headers).is_err());
        headers.clear();
        assert!(proxied.client_ip(proxy, &headers).is_err());
        headers.insert("x-forwarded-for", HeaderValue::from_static("bad"));
        assert!(proxied.client_ip(proxy, &headers).is_err());
        headers.insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
        assert!(proxied.client_ip(proxy, &headers).is_err());
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.50"));
        headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
        assert!(proxied.client_ip(proxy, &headers).is_err());
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        headers.remove("x-forwarded-for");
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("::ffff:203.0.113.50"),
        );
        assert_eq!(proxied.client_ip(mapped, &headers), Ok(client));
    }
}
