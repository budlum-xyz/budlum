# B-0044: Garden cannot start on an IP-only host without a DNS resolver

- **Location:** `src/garden/net.rs:728-743` on `garden` commit `c34cc016cf15e512be2861a92be2b8649f4e02ae`. The same resolver construction is present in the fetched `budlum-stack`, consensus and aggregation heads.
- **Severity:** medium, availability and deployment portability. The observation is not an Ubuntu-specific security exploit.
- **Faulty lines:**

  ```rust
  let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default());
  let dns_transport = libp2p::dns::tokio::Transport::system(tcp_transport)?;
  ```

  A failure to initialize the system resolver propagates through `with_other_transport` as `garden transport cannot start`, before any listener is created.
- **Cause:** DNS initialization is mandatory even when the configured listen and all dial addresses are numeric IP addresses and therefore need no name resolution.
- **Reproduction:** An official Ubuntu 26.04.1 Base amd64 root filesystem, with its original zero-byte `/etc/resolv.conf`, ran the Garden test binary from staged tree `d12cd194998aec69f0e091e4a7760e3f128e206a` as UID 1000. Ten of the 16 `garden::net::tests` passed; six tests that start a swarm failed with `garden transport cannot start: failed to build transport: io error: no nameservers found in config`. The same root filesystem shares the host's Debian Linux kernel; it is not a separately booted Ubuntu system. The image checksum matched Canonical's HTTPS SHA256SUMS file. The failure log is retained locally as `/home/user/audit-notes/os-testing/ubuntu-garden-no-dns.log`.
- **Impact:** A local or IP-address-only Garden cannot start if the OS resolver configuration is missing or empty. No production outage or remote exploit was demonstrated. Copying a valid resolver configuration is an operational workaround, not a root-cause fix.
- **Repair plan:** Make numeric TCP transport usable when the system DNS resolver cannot be initialized, while keeping Noise/Yamux, connection limits, admission checks and timeouts intact. Clearly warn that DNS multiaddresses cannot be resolved in that mode; do not silently substitute an unrelated public resolver. Add an isolated no-resolver regression proving two loopback peers can exchange a request and a DNS address still fails cleanly, plus a normal-resolver test.
- **Status:** open. No fixing commit or green CI run exists. The configured-resolver Ubuntu rerun and a real end-user CLI/node journey remain pending.
