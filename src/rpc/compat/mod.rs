//! Ecosystem compatibility gateways.
//!
//! JSON-RPC gateways and REST gateways keep their own wire tables. They share
//! the Budlum HTTP admission path, but they never translate one wire protocol
//! into another.

pub mod aptos;
