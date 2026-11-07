# Mobile Validator Guide

Budlum divides validators into two operational classes:

- **Full validators**: server-grade nodes (`>= 10,000 BUD` minimum bond) executing every
  block, holding finality committee seats (`S = min(128, 4 * |E|)`), and serving as
  primary `B.U.D. 3.0` storage custodians.
- **Mobile validators**: Android 10+ (and opportunistic iOS) phones (`>= 10 BUD` minimum
  bond) running `mobile/core` (`budlum-mobile-core`). Mobile validators store encrypted,
  erasure-coded `B.U.D. 3.0` symbols, answer periodic custody challenges, serve repair
  and view symbols, and earn storage custody rewards without holding finality seats.

## Resource and Hardware Guarantees

- **Key isolation**: the owner key (`ML-DSA-87`) stays cold behind biometric / PIN
  confirmation; the hot duty key (`ML-DSA-65`) is hardware-wrapped in Android Keystore
  or iOS Secure Enclave.
- **Network and thermal policy**: Wi-Fi-only by default with configurable daily cellular
  caps, charging/idle scheduling, and thermal pause thresholds (`mobile/core/src/`).
- **NAT traversal**: `libp2p` AutoNAT, circuit relay v2, and DCUtR hole punching.
- **Reproducible F-Droid build**: see [`docs/MOBILE_STORE_DISTRIBUTION.md`](MOBILE_STORE_DISTRIBUTION.md)
  and [`docs/MOBILE_DEVICE_MATRIX.md`](MOBILE_DEVICE_MATRIX.md).
