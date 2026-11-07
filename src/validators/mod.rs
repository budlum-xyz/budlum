//! Validator classes, duties, presence, and Instant Task Handover.
//!
//! This module is the home of the validator surface (directive 7). The
//! handover rule engine lives in [`handover`]; validator classes, registration
//! and the presence protocol land in their own work packages on top of it.

pub mod handover;
