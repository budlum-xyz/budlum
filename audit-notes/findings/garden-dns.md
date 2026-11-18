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
- **Fresh reproduction on the actual Garden head:** a checksum-verified official Ubuntu Base 24.04.5 amd64 userland runs the Debian-built library executable from Garden `3467a0bababb7648c75631173228d460da935485` as UID/GID 1000 in separate mount/PID namespaces. Executable SHA-256: `45164048f6e64c555f91fef854d1381f41ddc1d55ce98a5349c1233ed023f4dd`. With an empty resolver file, `garden::net::tests:: --test-threads=1` fails with 8 passed and the same 6 swarm-start failures, exit 101. With a valid resolver file, the identical executable passes all 14 network tests, exit 0. No production code or admission limit changes between these two runs. The older 16-test staged-tree counts above describe a different source tree and are not substituted for these results.
- **Current evidence paths:** `/home/user/validation/os/ubuntu-24.04/before-no-dns.log`, `before-configured-dns.log`, `library-before.sha256`, `image-checksum.log` and `provenance.txt`.
- **Status:** open. Both resolver conditions are now reproduced on Ubuntu 24.04 userland, but no fixing commit or green CI run exists. A real end-user CLI/node journey, an Ubuntu-native build and the other requested operating systems remain pending.
