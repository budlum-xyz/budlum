use crate::core::hash::hash_fields_bytes;
use crate::crypto::primitives::{verify_signature, KeyPair};
use crate::domain::types::DomainStatus;
use crate::garden::types::{
    GardenChainId, GardenLimits, GardenValidatorEntry, TAG_GARDEN_PRESENCE,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Signed host presence heartbeat aligned with Section 7.8 liveness semantics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenPresenceSignal {
    pub chain_id: GardenChainId,
    pub host_pubkey: [u8; 32],
    pub epoch: u64,
    pub signature: Vec<u8>,
}

impl GardenPresenceSignal {
    pub fn signing_message(
        chain_id: GardenChainId,
        host_pubkey: &[u8; 32],
        epoch: u64,
    ) -> [u8; 32] {
        hash_fields_bytes(&[
            TAG_GARDEN_PRESENCE,
            &chain_id.value().to_le_bytes(),
            host_pubkey,
            &epoch.to_le_bytes(),
        ])
    }

    pub fn sign(keypair: &KeyPair, chain_id: GardenChainId, epoch: u64) -> Self {
        let host_pubkey = keypair.public_key_bytes();
        let msg = Self::signing_message(chain_id, &host_pubkey, epoch);
        let signature = keypair.sign(&msg).to_vec();
        Self {
            chain_id,
            host_pubkey,
            epoch,
            signature,
        }
    }

    pub fn verify(
        &self,
        expected_chain: GardenChainId,
        expected_host: &[u8; 32],
    ) -> Result<(), String> {
        if self.chain_id != expected_chain {
            return Err("presence signal chain_id mismatch".into());
        }
        if &self.host_pubkey != expected_host {
            return Err("presence signal is not from Garden host".into());
        }
        let msg = Self::signing_message(self.chain_id, &self.host_pubkey, self.epoch);
        verify_signature(&msg, &self.signature, &self.host_pubkey)
            .map_err(|e| format!("invalid host presence signature: {e}"))
    }
}

/// Tracks Garden host presence, active PoA validator membership, and lifecycle
/// transitions (`Active` <-> `Frozen` -> `Retired`) (Directive 3.2, 3.4, 3.7, 3.8).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GardenLivenessState {
    pub chain_id: GardenChainId,
    pub host_pubkey: [u8; 32],
    pub status: DomainStatus,
    pub current_epoch: u64,
    pub last_host_epoch: u64,
    pub host_present: bool,
    pub limits: GardenLimits,
    /// Keyed by hex-encoded public key for deterministic ordering and string-keyed serialization.
    pub validators: BTreeMap<String, GardenValidatorEntry>,
}

impl GardenLivenessState {
    pub fn new(
        chain_id: GardenChainId,
        host_pubkey: [u8; 32],
        host_name: String,
        limits: GardenLimits,
    ) -> Self {
        let mut validators = BTreeMap::new();
        validators.insert(
            hex::encode(host_pubkey),
            GardenValidatorEntry {
                pubkey: host_pubkey,
                display_name: host_name,
                is_host: true,
                joined_height: 0,
                active: true,
                last_presence_epoch: 0,
            },
        );
        Self {
            chain_id,
            host_pubkey,
            status: DomainStatus::Active,
            current_epoch: 0,
            last_host_epoch: 0,
            host_present: true,
            limits,
            validators,
        }
    }

    pub fn active_validator_pubkeys(&self) -> Vec<[u8; 32]> {
        self.validators
            .values()
            .filter(|v| v.active)
            .map(|v| v.pubkey)
            .collect()
    }

    pub fn active_validator_count(&self) -> usize {
        self.validators.values().filter(|v| v.active).count()
    }

    pub fn is_active_validator(&self, pubkey: &[u8; 32]) -> bool {
        self.validators
            .get(&hex::encode(pubkey))
            .is_some_and(|v| v.active)
    }

    pub fn require_accepts_new_blocks(&self) -> Result<(), String> {
        match self.status {
            DomainStatus::Active => Ok(()),
            DomainStatus::Frozen => {
                Err("garden is Frozen while host is absent; reads work, new blocks and transactions are closed".into())
            }
            DomainStatus::Retired => {
                Err("garden is Retired after last validator departed".into())
            }
        }
    }

    pub fn join_validator(
        &mut self,
        pubkey: [u8; 32],
        display_name: String,
        height: u64,
    ) -> Result<(), String> {
        if self.status == DomainStatus::Retired {
            return Err("cannot join a Retired garden".into());
        }
        if display_name.trim().is_empty() || display_name.len() > 64 {
            return Err("validator display_name must be 1..=64 bytes".into());
        }
        let key = hex::encode(pubkey);
        if let Some(existing) = self.validators.get(&key) {
            if existing.active {
                return Err("validator is already active in this garden".into());
            }
        } else if self.active_validator_count() >= self.limits.max_validators {
            return Err(format!(
                "garden validator limit {} reached (TESTNET-DEFAULT)",
                self.limits.max_validators
            ));
        }
        let is_host = pubkey == self.host_pubkey;
        self.validators.insert(
            key,
            GardenValidatorEntry {
                pubkey,
                display_name,
                is_host,
                joined_height: height,
                active: true,
                last_presence_epoch: self.current_epoch,
            },
        );
        if is_host {
            self.host_present = true;
            self.last_host_epoch = self.current_epoch;
            if self.status == DomainStatus::Frozen {
                self.status = DomainStatus::Active;
            }
        }
        Ok(())
    }

    /// Leave the Garden.
    ///
    /// - Non-host departure: chain remains `Active` as long as host is active (V-1).
    /// - Host departure while others remain: chain transitions to `Frozen` (3.2).
    /// - Last active validator departure: chain transitions to `Retired` (3.7).
    pub fn leave_validator(&mut self, pubkey: &[u8; 32]) -> Result<DomainStatus, String> {
        let key = hex::encode(pubkey);
        let entry = self
            .validators
            .get_mut(&key)
            .ok_or_else(|| "validator is not a member of this garden".to_string())?;
        if !entry.active {
            return Err("validator has already left this garden".into());
        }
        entry.active = false;
        let is_host = entry.is_host;
        if is_host {
            self.host_present = false;
        }
        let remaining = self.active_validator_count();
        if remaining == 0 {
            self.status = DomainStatus::Retired;
        } else if is_host && self.status == DomainStatus::Active {
            self.status = DomainStatus::Frozen;
        }
        Ok(self.status)
    }

    /// Return a previously joined validator (or the host) to the Garden (3.8).
    pub fn return_validator(&mut self, pubkey: &[u8; 32]) -> Result<DomainStatus, String> {
        if self.status == DomainStatus::Retired {
            return Err("cannot return to a Retired garden".into());
        }
        let key = hex::encode(pubkey);
        let was_active = self
            .validators
            .get(&key)
            .ok_or_else(|| "unknown validator cannot return before joining".to_string())?
            .active;
        if was_active {
            return Ok(self.status);
        }
        if self.active_validator_count() >= self.limits.max_validators {
            return Err(format!(
                "garden validator limit {} reached (TESTNET-DEFAULT)",
                self.limits.max_validators
            ));
        }
        let entry = self
            .validators
            .get_mut(&key)
            .ok_or_else(|| "validator entry disappeared".to_string())?;
        entry.active = true;
        entry.last_presence_epoch = self.current_epoch;
        if entry.is_host {
            self.host_present = true;
            self.last_host_epoch = self.current_epoch;
            if self.status == DomainStatus::Frozen {
                self.status = DomainStatus::Active;
            }
        }
        Ok(self.status)
    }

    /// Record a verified host presence signal (7.8), waking a `Frozen` Garden
    /// back to `Active`.
    pub fn record_host_presence(
        &mut self,
        signal: &GardenPresenceSignal,
    ) -> Result<DomainStatus, String> {
        if self.status == DomainStatus::Retired {
            return Err("cannot unfreeze a Retired garden".into());
        }
        signal.verify(self.chain_id, &self.host_pubkey)?;
        if signal.epoch > self.current_epoch {
            self.current_epoch = signal.epoch;
        }
        self.last_host_epoch = self.last_host_epoch.max(signal.epoch);
        self.host_present = true;
        if let Some(host_entry) = self.validators.get_mut(&hex::encode(self.host_pubkey)) {
            host_entry.active = true;
            host_entry.last_presence_epoch = self.last_host_epoch;
        }
        if self.status == DomainStatus::Frozen {
            self.status = DomainStatus::Active;
        }
        Ok(self.status)
    }

    /// Advance the liveness epoch and freeze the Garden if the host has been
    /// silent for `host_liveness_timeout_epochs` (Directive 3.2, 7.8).
    pub fn advance_epoch(&mut self, new_epoch: u64) -> DomainStatus {
        if self.status == DomainStatus::Retired {
            return DomainStatus::Retired;
        }
        if new_epoch > self.current_epoch {
            self.current_epoch = new_epoch;
        }
        if self.active_validator_count() == 0 {
            self.status = DomainStatus::Retired;
            return self.status;
        }
        let elapsed = self.current_epoch.saturating_sub(self.last_host_epoch);
        if (!self.host_present || elapsed >= self.limits.host_liveness_timeout_epochs)
            && self.status == DomainStatus::Active
        {
            self.host_present = false;
            self.status = DomainStatus::Frozen;
        }
        self.status
    }
}
