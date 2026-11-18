# Ubuntu userland execution record

## Environment and provenance

- Ubuntu 26.04.1 LTS Base amd64 userland, with GNU libc `2.43-2ubuntu2.3`, running in a chroot and separate mount/PID namespaces on the Debian host's Linux `6.1.189+` x86-64 kernel. This is not a separately booted Ubuntu kernel or a full Ubuntu desktop/server installation.
- Image: `ubuntu-base-26.04.1-base-amd64.tar.gz` from <https://cdimage.ubuntu.com/ubuntu-base/releases/26.04/release/>. SHA-256 `a496a960472ce474a59590b8987d3a1135d3cbef1991f3b1abe8cacfea8bf85a` matched Canonical's HTTPS `SHA256SUMS` file. A separate signature verification was not performed.
- Processes ran as UID/GID 1000 (`budtester`), not root in the chroot. `/proc` and basic `/dev` devices were supplied for the isolated environment.
- Tested binary SHA-256: `acb95cc55737999c9ed5c8c4b91caffb8da9631c4d8ab2d34c1b5775b9d576e8`; it was built from staged Garden tree `d12cd194998aec69f0e091e4a7760e3f128e206a` with the repository's Rust 1.97.1 toolchain on Debian, then executed with the Ubuntu userland. It was not rebuilt on Ubuntu.

## Results

1. With the original empty Ubuntu Base `/etc/resolv.conf`, `garden::net::tests` returned exit 101: 10 passed and 6 failed. Every failing case attempted to start a swarm and reported `no nameservers found in config`. See [B-0044](garden-dns.md). The unmodified failure log remains in the local workspace.
2. A valid resolver configuration was subsequently installed in this disposable root filesystem. The rerun and its result are pending.

## New Ubuntu 24.04 execution on the pushed Garden source

This is a separate environment and executable, not a continuation of the historical staged-tree result above.

- Official Ubuntu Base 24.04.5 LTS amd64 root filesystem. Archive and SHA256SUMS come from `https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/`. The archive digest is checked against the HTTPS checksum file. Signature verification is not performed. The local provenance and checksum files retain the exact archive name and digest.
- Host kernel is Debian's Linux kernel. Mount and PID namespaces are isolated with `unshare`; processes run as UID/GID 1000 in the chroot. No host resolver file is modified.
- Source: Garden `3467a0bababb7648c75631173228d460da935485`, before the separately proposed invite-test-only repair. The library executable is built on Debian with Rust 1.97.1 and then copied into Ubuntu; it is not an Ubuntu-native build.
- Library executable SHA-256: `45164048f6e64c555f91fef854d1381f41ddc1d55ce98a5349c1233ed023f4dd`.
- Command inside the Ubuntu userland: `/work/garden-lib-before garden::net::tests:: --test-threads=1`.
- Empty `/etc/resolv.conf`: 8 passed, 6 failed, 0 ignored, exit 101. Every failed test starts a swarm and returns `no nameservers found in config`.
- Valid `/etc/resolv.conf`, identical executable: 14 passed, 0 failed, 0 ignored, exit 0. This isolates the deployment failure to resolver availability rather than a general Ubuntu network incompatibility.
- Evidence: `/home/user/validation/os/ubuntu-24.04/`, including `provenance.txt`, `image-checksum.log`, `os-release.txt`, both test logs and `results.txt`.

## Limitations

These are targeted library-test results, not an end-user CLI or node startup journey, not a full operating-system test, and not CI. They do not establish an Ubuntu-native build or behavior on ARM64, Windows, macOS, Alpine, Android or iOS. The experimental B-0043 repair is not included. B-0044 remains open until a production repair is tested in the empty-resolver environment and CI passes.
