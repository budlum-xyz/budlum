# Ubuntu userland execution record

## Environment and provenance

- Ubuntu 26.04.1 LTS Base amd64 userland, with GNU libc `2.43-2ubuntu2.3`, running in a chroot and separate mount/PID namespaces on the Debian host's Linux `6.1.189+` x86-64 kernel. This is not a separately booted Ubuntu kernel or a full Ubuntu desktop/server installation.
- Image: `ubuntu-base-26.04.1-base-amd64.tar.gz` from <https://cdimage.ubuntu.com/ubuntu-base/releases/26.04/release/>. SHA-256 `a496a960472ce474a59590b8987d3a1135d3cbef1991f3b1abe8cacfea8bf85a` matched Canonical's HTTPS `SHA256SUMS` file. A separate signature verification was not performed.
- Processes ran as UID/GID 1000 (`budtester`), not root in the chroot. `/proc` and basic `/dev` devices were supplied for the isolated environment.
- Tested binary SHA-256: `acb95cc55737999c9ed5c8c4b91caffb8da9631c4d8ab2d34c1b5775b9d576e8`; it was built from staged Garden tree `d12cd194998aec69f0e091e4a7760e3f128e206a` with the repository's Rust 1.97.1 toolchain on Debian, then executed with the Ubuntu userland. It was not rebuilt on Ubuntu.

## Results

1. With the original empty Ubuntu Base `/etc/resolv.conf`, `garden::net::tests` returned exit 101: 10 passed and 6 failed. Every failing case attempted to start a swarm and reported `no nameservers found in config`. See [B-0044](garden-dns.md). The unmodified failure log remains in the local workspace.
2. A valid resolver configuration was subsequently installed in this disposable root filesystem. The rerun and its result are pending.

## Limitations

This is targeted library-test evidence, not an end-user CLI or node startup journey, not a full operating-system test, and not CI. It does not establish behavior on Ubuntu 24.04, ARM64, Windows, macOS, Alpine, Android or iOS. The experimental B-0043 repair is not included in this binary.
