//! The foreign transaction doors (directive 8.2, the foreign envelope table).
//!
//! A foreign envelope is the raw, signed transaction of another chain's type
//! system, signed *for the Budlum foreign lane* (never for the home chain's
//! chain id). Each environment gets its own module here. The Ethereum row
//! lands first; WASM, SVM and Move follow with their environments.
//!
//! WIRING: the WP-27 foreign-lane door consumes the Ethereum envelope once
//! the EVM environment lands. Until then the module is exercised by its
//! tests, mirroring the scheduler's landing.

pub mod ethereum;
