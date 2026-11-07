//! Mobile validator runtime policy, Android `specialUse` / `WorkManager` lifecycle,
//! Keystore/StrongBox & Secure Enclave key-wrapping invariants, iOS `MobileOpportunistic`
//! `BGProcessingTask` engine, and F-Droid reproducible APK verification
//! (Section 7.9, Section 7.10, WP-36, WP-38, WP-58).
//! exposed for mobile UniFFI/JNI bindings, CLI/SDK verifiers, and CI gates.

use serde::{Deserialize, Serialize};

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::storage::bud3::registry::ObjectKey;
use crate::storage::bud3::tx::StorageTxV3;

/// Minimum Android SDK level (`Android 10`, Section 7.9.2).
pub const ANDROID_MIN_SDK: u32 = 29;

/// Current Google Play target Android SDK level (`Android 16`, Section 7.9.2).
pub const ANDROID_TARGET_SDK: u32 = 36;

/// Pinned Android NDK version for deterministic `cargo-ndk` builds (`WP-36`, `WP-58`).
/// Convenience: exposed for Android/F-Droid build verifiers.
pub const PINNED_ANDROID_NDK_VERSION: &str = "27.2.12479018";

/// Canonical `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` declaration value (Section 7.9.3).
/// Convenience: exposed for Android manifest verifiers.
pub const ANDROID_SPECIAL_USE_SUBTYPE: &str =
    "budlum_storage_validator: keeps peer-to-peer connections open to serve stored data shares and to answer storage audits of the Budlum network";

/// Periodic `WorkManager` interval in minutes when `ValidatorService` is stopped (Section 7.9.3).
/// Convenience: exposed for Android background scheduler bindings.
pub const ANDROID_WORKMANAGER_INTERVAL_MINUTES: u32 = 15;

/// Default Android custody quota (`4 GiB`, Section 7.9.4).
pub const ANDROID_DEFAULT_QUOTA_BYTES: u64 = 4 * (1 << 30);

/// Minimum Mobile custody quota (`1 GiB`, Section 7.9.4).
pub const MOBILE_MIN_QUOTA_BYTES: u64 = 1 << 30;

/// Maximum Android custody quota (`64 GiB`, Section 7.9.4).
pub const ANDROID_MAX_QUOTA_BYTES: u64 = 64 * (1 << 30);

/// Maximum iOS `MobileOpportunistic` custody quota (`8 GiB`, Section 7.10).
pub const IOS_OPPORTUNISTIC_MAX_QUOTA_BYTES: u64 = 8 * (1 << 30);

/// Free-storage safety floor (`2 GiB`, `R-34`): falling below triggers `ReleaseShares`.
pub const LOW_FREE_SPACE_RELEASE_THRESHOLD_BYTES: u64 = 2 * (1 << 30);

/// Android Mobile audit window in hours (`24h`).
pub const ANDROID_AUDIT_WINDOW_HOURS: u32 = 24;

/// iOS `MobileOpportunistic` audit window in hours (`48h`, Section 7.10).
pub const IOS_OPPORTUNISTIC_AUDIT_WINDOW_HOURS: u32 = 48;

/// Android Mobile non-slashing suspension threshold in hours (`24h`).
pub const ANDROID_SUSPENSION_HOURS: u32 = 24;

/// iOS `MobileOpportunistic` non-slashing suspension threshold in hours (`7 days = 168h`, Section 7.10).
pub const IOS_OPPORTUNISTIC_SUSPENSION_HOURS_CAP: u32 = 7 * 24;

/// Minimum Mobile registration stake in base atoms (`10 BUD` onboarding flow / `100 BUD` class floor).
pub const MOBILE_ONBOARDING_MIN_STAKE_ATOMS: u64 = 10_000_000;

/// Domain tag committing an operator-key rotation (`RotateOperatorKey`, `R-16`).
pub const DOMAIN_ROTATE_OPERATOR_KEY: &[u8] = b"BDLM_MOBILE_ROTATE_OPERATOR_V1";

/// Mobile validator execution class across Android and iOS (Section 7.9 & Section 7.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MobileValidatorClass {
    /// Android persistent `specialUse` + `WorkManager` Mobile validator (`24h` window, `<= 64 GiB`).
    AndroidMobile,
    /// iOS `MobileOpportunistic` validator (`48h` window, `<= 8 GiB`, `7d` suspension).
    MobileOpportunistic,
}

impl MobileValidatorClass {
    /// Audit response window in hours (`24h` Android, `48h` iOS opportunistic).
    #[must_use]
    pub const fn audit_window_hours(self) -> u32 {
        match self {
            Self::AndroidMobile => ANDROID_AUDIT_WINDOW_HOURS,
            Self::MobileOpportunistic => IOS_OPPORTUNISTIC_AUDIT_WINDOW_HOURS,
        }
    }

    /// Maximum allowed custody quota in bytes (`64 GiB` Android, `8 GiB` iOS opportunistic).
    #[must_use]
    pub const fn max_quota_bytes(self) -> u64 {
        match self {
            Self::AndroidMobile => ANDROID_MAX_QUOTA_BYTES,
            Self::MobileOpportunistic => IOS_OPPORTUNISTIC_MAX_QUOTA_BYTES,
        }
    }

    /// Non-slashing suspension threshold in hours (`24h` Android, `168h` iOS opportunistic).
    #[must_use]
    pub const fn suspension_hours(self) -> u32 {
        match self {
            Self::AndroidMobile => ANDROID_SUSPENSION_HOURS,
            Self::MobileOpportunistic => IOS_OPPORTUNISTIC_SUSPENSION_HOURS_CAP,
        }
    }
}

/// Device thermal state mapped from Android `PowerManager` / iOS `ProcessInfo.ThermalState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DeviceThermalLevel {
    None,
    Light,
    /// `PowerManager.THERMAL_STATUS_MODERATE`: mandatory pause boundary (`R-35`).
    Moderate,
    Severe,
    Critical,
}

/// Errors enforced by the Mobile validator policy, keystore, and lifecycle engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MobileRuntimeError {
    /// Attempted to disable thermal pause at `THERMAL_STATUS_MODERATE` (`R-35`).
    ThermalPauseImmutable,
    /// Metered cellular enabled without a positive daily MiB cap (`R-33`).
    MeteredCapRequired,
    /// Declared custody quota outside `[1 GiB, class.max_quota_bytes()]`.
    QuotaOutOfBounds { got: u64, min: u64, max: u64 },
    /// Keystore / Secure Enclave wrapping invariant violated (Section 7.9.6).
    InsecureKeyWrapping(&'static str),
    /// Onboarding step missing wallet creation, stake floor, or user disclosure consent.
    IncompleteOnboarding(&'static str),
    /// Background task violated platform power or connectivity requirements.
    BackgroundConstraintViolation(&'static str),
    /// Two APK builds differed in byte length or SHA-256 digest (`WP-58`).
    NonReproducibleApk,
}

impl std::fmt::Display for MobileRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ThermalPauseImmutable => {
                f.write_str("thermal pause at THERMAL_STATUS_MODERATE cannot be disabled (R-35)")
            }
            Self::MeteredCapRequired => {
                f.write_str("enabling cellular data requires a non-zero daily MiB cap (R-33)")
            }
            Self::QuotaOutOfBounds { got, min, max } => {
                write!(f, "mobile custody quota {got} outside [{min}, {max}]")
            }
            Self::InsecureKeyWrapping(msg) => write!(f, "keystore wrapping error: {msg}"),
            Self::IncompleteOnboarding(msg) => write!(f, "onboarding incomplete: {msg}"),
            Self::BackgroundConstraintViolation(msg) => {
                write!(f, "background task constraint violation: {msg}")
            }
            Self::NonReproducibleApk => {
                f.write_str("independent Android APK builds are not byte-for-byte identical")
            }
        }
    }
}

impl std::error::Error for MobileRuntimeError {}

/// Runtime operating policy for Android and iOS Mobile validators (Section 7.9.4 & 7.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileValidatorPolicy {
    pub class: MobileValidatorClass,
    pub wifi_only: bool,
    pub daily_cellular_cap_mib: u32,
    pub charging_only: bool,
    pub min_battery_percent: u8,
    pub thermal_pause_enabled: bool,
    pub quota_bytes: u64,
    pub serve_symbols_enabled: bool,
}

impl MobileValidatorPolicy {
    /// Canonical Android default policy (Section 7.9.4): Wi-Fi only (`R-33`),
    /// charging or `> 50%` battery without Battery Saver, immutable thermal pause (`R-35`),
    /// `4 GiB` quota, and symbol serving enabled on unmetered Wi-Fi.
    #[must_use]
    pub const fn android_default() -> Self {
        Self {
            class: MobileValidatorClass::AndroidMobile,
            wifi_only: true,
            daily_cellular_cap_mib: 0,
            charging_only: false,
            min_battery_percent: 50,
            thermal_pause_enabled: true,
            quota_bytes: ANDROID_DEFAULT_QUOTA_BYTES,
            serve_symbols_enabled: true,
        }
    }

    /// Canonical iOS `MobileOpportunistic` default policy (Section 7.10):
    /// Wi-Fi only, `4 GiB` default (`<= 8 GiB` cap), immutable thermal pause.
    #[must_use]
    pub const fn ios_opportunistic_default() -> Self {
        Self {
            class: MobileValidatorClass::MobileOpportunistic,
            wifi_only: true,
            daily_cellular_cap_mib: 0,
            charging_only: true,
            min_battery_percent: 50,
            thermal_pause_enabled: true,
            quota_bytes: ANDROID_DEFAULT_QUOTA_BYTES,
            serve_symbols_enabled: true,
        }
    }

    /// Validate policy updates, enforcing `R-33` (Wi-Fi-only unless capped),
    /// `R-35` (immutable thermal pause), and class quota ceilings (`64 GiB` / `8 GiB`).
    ///
    /// # Errors
    ///
    /// Returns [`MobileRuntimeError`] if any policy invariant is violated.
    pub fn validate(&self) -> Result<(), MobileRuntimeError> {
        if !self.thermal_pause_enabled {
            return Err(MobileRuntimeError::ThermalPauseImmutable);
        }
        if !self.wifi_only && self.daily_cellular_cap_mib == 0 {
            return Err(MobileRuntimeError::MeteredCapRequired);
        }
        let max = self.class.max_quota_bytes();
        if self.quota_bytes < MOBILE_MIN_QUOTA_BYTES || self.quota_bytes > max {
            return Err(MobileRuntimeError::QuotaOutOfBounds {
                got: self.quota_bytes,
                min: MOBILE_MIN_QUOTA_BYTES,
                max,
            });
        }
        Ok(())
    }

    /// Attempt to mutate thermal pause; always refuses `false` (`R-35`).
    /// exposed for mobile settings UI guard.
    ///
    /// # Errors
    ///
    /// Returns [`MobileRuntimeError::ThermalPauseImmutable`] when `enabled == false`.
    pub fn set_thermal_pause(&mut self, enabled: bool) -> Result<(), MobileRuntimeError> {
        if !enabled {
            return Err(MobileRuntimeError::ThermalPauseImmutable);
        }
        self.thermal_pause_enabled = true;
        Ok(())
    }

    /// Whether the validator may actively run network/custody duties under the
    /// observed device environment (Section 7.9.4).
    #[must_use]
    pub const fn permits_active_duty(
        &self,
        is_unmetered_wifi: bool,
        is_charging: bool,
        battery_percent: u8,
        battery_saver_on: bool,
        thermal: DeviceThermalLevel,
    ) -> bool {
        if matches!(
            thermal,
            DeviceThermalLevel::Moderate | DeviceThermalLevel::Severe | DeviceThermalLevel::Critical
        ) {
            return false;
        }
        if self.wifi_only && !is_unmetered_wifi {
            return false;
        }
        if self.charging_only {
            return is_charging;
        }
        is_charging || (battery_percent > self.min_battery_percent && !battery_saver_on)
    }

    /// Custody reward multiplier in basis points (`10_000` = 100%, `5_000` = 50%
    /// when symbol serving is disabled per Section 7.9.4).
    #[must_use]
    pub const fn custody_reward_bps(&self) -> u16 {
        if self.serve_symbols_enabled {
            10_000
        } else {
            5_000
        }
    }
}

/// Hardware-backed key-wrapping descriptor for Mobile validator keys (Section 7.9.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileKeystoreState {
    pub owner_address: Address,
    /// Owner ML-DSA-87 wallet requires biometric or PIN authentication to spend.
    pub owner_spend_requires_user_auth: bool,
    /// Operator ML-DSA-65 key wrapped with Android Keystore AES-256-GCM / Secure Enclave.
    pub operator_key_keystore_wrapped: bool,
    /// BLS12-381 presence key wrapped with Android Keystore AES-256-GCM / Secure Enclave.
    pub bls_presence_key_keystore_wrapped: bool,
    /// `StrongBox` or Secure Enclave hardware backing used when available.
    pub hardware_strongbox_backed: bool,
    /// Background duty signing requires `userAuthenticationRequired = false`.
    pub operator_requires_user_auth: bool,
    /// Background duty signing requires `unlockedDeviceRequired = false`.
    pub operator_requires_unlocked_device: bool,
    /// Current active operator public-key commitment.
    pub operator_key_digest: [u8; 32],
    /// Monotonic operator-key rotation nonce (`RotateOperatorKey`, `R-16`).
    pub rotation_epoch: u64,
}

impl MobileKeystoreState {
    /// Verify Section 7.9.6 key-separation and hardware-wrapping rules.
    ///
    /// # Errors
    ///
    /// Returns [`MobileRuntimeError::InsecureKeyWrapping`] if owner spend auth is
    /// missing, operator/BLS keys are unwrapped, or background flags block duties.
    pub fn validate(&self) -> Result<(), MobileRuntimeError> {
        if self.owner_address == Address::zero() {
            return Err(MobileRuntimeError::InsecureKeyWrapping(
                "owner_address cannot be zero",
            ));
        }
        if !self.owner_spend_requires_user_auth {
            return Err(MobileRuntimeError::InsecureKeyWrapping(
                "owner ML-DSA-87 key must require biometric or PIN auth for spending",
            ));
        }
        if !self.operator_key_keystore_wrapped || !self.bls_presence_key_keystore_wrapped {
            return Err(MobileRuntimeError::InsecureKeyWrapping(
                "operator ML-DSA-65 and BLS presence keys must be Keystore AES-256-GCM wrapped",
            ));
        }
        if self.operator_requires_user_auth || self.operator_requires_unlocked_device {
            return Err(MobileRuntimeError::InsecureKeyWrapping(
                "operator key must allow background duty signing while locked",
            ));
        }
        if self.operator_key_digest == [0u8; 32] {
            return Err(MobileRuntimeError::InsecureKeyWrapping(
                "operator_key_digest cannot be zero",
            ));
        }
        Ok(())
    }

    /// Rotate the operator key from another wallet device after phone loss (`R-16`).
    /// exposed for wallet device-loss recovery (`RotateOperatorKey`).
    ///
    /// # Errors
    ///
    /// Returns [`MobileRuntimeError::InsecureKeyWrapping`] if `new_operator_pk` is empty.
    pub fn rotate_operator_key(
        &mut self,
        new_operator_pk: &[u8],
        epoch: u64,
    ) -> Result<[u8; 32], MobileRuntimeError> {
        if new_operator_pk.is_empty() {
            return Err(MobileRuntimeError::InsecureKeyWrapping(
                "new operator public key cannot be empty",
            ));
        }
        let next_digest = hash_fields_bytes(&[
            DOMAIN_ROTATE_OPERATOR_KEY,
            self.owner_address.as_bytes(),
            &epoch.to_le_bytes(),
            new_operator_pk,
        ]);
        self.operator_key_digest = next_digest;
        self.rotation_epoch = epoch;
        Ok(next_digest)
    }
}

/// Lifecycle state of the Mobile validator onboarding, active duty, and graceful leave flows
/// (Section 7.9.5, Section 7.9.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MobileLifecyclePhase {
    Uninitialized,
    WalletReady,
    Registered,
    LeavingUnbonding,
}

/// Outcome of a graceful `leave` or low-disk-space protection sweep (`R-34`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareReleasePlan {
    pub release_txs: Vec<StorageTxV3>,
    pub unbonding_started: bool,
}

/// Stateful Mobile validator controller modelling `noBackupFilesDir/bud3/` share storage,
/// `WorkManager` / `BGProcessingTask` background audit execution, low-space `ReleaseShares`,
/// and graceful `leave` (`WP-36`, `WP-38`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileValidatorController {
    pub phase: MobileLifecyclePhase,
    pub policy: MobileValidatorPolicy,
    pub keystore: MobileKeystoreState,
    pub storage_dir_no_backup: String,
    pub held_objects: Vec<(ObjectKey, u64)>,
    pub staked_atoms: u64,
    pub audits_answered: u64,
    pub presence_signals_emitted: u64,
    pub disclosure_accepted: bool,
}

impl MobileValidatorController {
    /// Complete onboarding -> registration flow (Section 7.9.9 items 1, 2, 5).
    /// exposed for Android/iOS onboarding controller and emulator tests.
    ///
    /// # Errors
    ///
    /// Returns [`MobileRuntimeError`] if policy, keystore, disclosure consent,
    /// `noBackupFilesDir/bud3/` path, or minimum stake fails.
    pub fn complete_onboarding_and_register(
        policy: MobileValidatorPolicy,
        keystore: MobileKeystoreState,
        storage_dir_no_backup: String,
        staked_atoms: u64,
        disclosure_accepted: bool,
    ) -> Result<Self, MobileRuntimeError> {
        policy.validate()?;
        keystore.validate()?;
        if !disclosure_accepted {
            return Err(MobileRuntimeError::IncompleteOnboarding(
                "user must accept storage share & encrypted sealed-content disclosure",
            ));
        }
        if !storage_dir_no_backup.ends_with("noBackupFilesDir/bud3")
            && !storage_dir_no_backup.ends_with("ApplicationSupport/bud3-nobackup")
        {
            return Err(MobileRuntimeError::IncompleteOnboarding(
                "share directory must reside under cloud-excluded noBackupFilesDir/bud3",
            ));
        }
        if staked_atoms < MOBILE_ONBOARDING_MIN_STAKE_ATOMS {
            return Err(MobileRuntimeError::IncompleteOnboarding(
                "staked_atoms below Mobile registration floor",
            ));
        }
        Ok(Self {
            phase: MobileLifecyclePhase::Registered,
            policy,
            keystore,
            storage_dir_no_backup,
            held_objects: Vec::new(),
            staked_atoms,
            audits_answered: 0,
            presence_signals_emitted: 0,
            disclosure_accepted: true,
        })
    }

    /// Record custody of `(object, bytes)` if within declared `quota_bytes`.
    /// exposed for Mobile share assignment handler.
    ///
    /// # Errors
    ///
    /// Returns [`MobileRuntimeError::QuotaOutOfBounds`] if accepting `bytes` exceeds quota.
    pub fn accept_share(&mut self, object: ObjectKey, bytes: u64) -> Result<(), MobileRuntimeError> {
        let used: u64 = self.held_objects.iter().map(|(_, b)| *b).sum();
        let next = used.saturating_add(bytes);
        if next > self.policy.quota_bytes {
            return Err(MobileRuntimeError::QuotaOutOfBounds {
                got: next,
                min: MOBILE_MIN_QUOTA_BYTES,
                max: self.policy.quota_bytes,
            });
        }
        self.held_objects.push((object, bytes));
        Ok(())
    }

    /// Convenience: exposed for Android/iOS storage watchdog loop (`R-34`).
    pub fn storage_watchdog_sweep(&mut self, free_disk_bytes: u64) -> ShareReleasePlan {
        self.enforce_low_free_space(free_disk_bytes)
    }

    /// Enforce `R-34`: when device free storage drops below `2 GiB`, emit
    /// `StorageTxV3::ReleaseShares` until free space recovers without any slash.
    /// exposed for Android/iOS storage watchdog.
    pub fn enforce_low_free_space(&mut self, mut free_disk_bytes: u64) -> ShareReleasePlan {
        let mut release_txs = Vec::new();
        while free_disk_bytes < LOW_FREE_SPACE_RELEASE_THRESHOLD_BYTES {
            let Some((object, bytes)) = self.held_objects.pop() else {
                break;
            };
            free_disk_bytes = free_disk_bytes.saturating_add(bytes);
            release_txs.push(StorageTxV3::ReleaseShares {
                object,
                segment: None,
                lower_quota_bytes: bytes,
            });
        }
        ShareReleasePlan {
            release_txs,
            unbonding_started: false,
        }
    }

    /// Execute graceful `Leave` flow (Section 7.9.9 item 4): release all held
    /// shares via `StorageTxV3::ReleaseShares` and transition to `LeavingUnbonding`.
    /// exposed for Mobile validator "Leave" button flow.
    pub fn leave_and_unbond(&mut self) -> ShareReleasePlan {
        let mut release_txs = Vec::with_capacity(self.held_objects.len());
        for (object, bytes) in self.held_objects.drain(..) {
            release_txs.push(StorageTxV3::ReleaseShares {
                object,
                segment: None,
                lower_quota_bytes: bytes,
            });
        }
        self.phase = MobileLifecyclePhase::LeavingUnbonding;
        ShareReleasePlan {
            release_txs,
            unbonding_started: true,
        }
    }

    /// Run Android 15-minute `WorkManager` fallback job when `ValidatorService`
    /// is stopped (Section 7.9.3 item 6). Requires unmetered Wi-Fi.
    /// exposed for `ValidatorAuditWorker` JNI bridge.
    ///
    /// # Errors
    ///
    /// Returns [`MobileRuntimeError::BackgroundConstraintViolation`] if not on unmetered Wi-Fi.
    pub fn run_android_workmanager_tick(
        &mut self,
        service_running: bool,
        unmetered_wifi: bool,
        pending_audits: u32,
    ) -> Result<u32, MobileRuntimeError> {
        if !unmetered_wifi {
            return Err(MobileRuntimeError::BackgroundConstraintViolation(
                "Android WorkManager fallback requires NetworkType.UNMETERED",
            ));
        }
        if service_running || self.phase != MobileLifecyclePhase::Registered {
            return Ok(0);
        }
        self.audits_answered = self.audits_answered.saturating_add(u64::from(pending_audits));
        self.presence_signals_emitted = self.presence_signals_emitted.saturating_add(1);
        Ok(pending_audits)
    }

    /// Run iOS `BGProcessingTaskRequest` background job (Section 7.10 item 4).
    /// Requires `requires_external_power == true` and `requires_network_connectivity == true`.
    /// exposed for iOS `BGTaskScheduler` UniFFI bridge.
    ///
    /// # Errors
    ///
    /// Returns [`MobileRuntimeError::BackgroundConstraintViolation`] if external power
    /// or network connectivity is absent.
    pub fn run_ios_bg_processing_task(
        &mut self,
        requires_external_power: bool,
        requires_network_connectivity: bool,
        pending_audits: u32,
    ) -> Result<u32, MobileRuntimeError> {
        if self.policy.class != MobileValidatorClass::MobileOpportunistic {
            return Err(MobileRuntimeError::BackgroundConstraintViolation(
                "BGProcessingTask is only valid for MobileOpportunistic class",
            ));
        }
        if !requires_external_power || !requires_network_connectivity {
            return Err(MobileRuntimeError::BackgroundConstraintViolation(
                "iOS BGProcessingTaskRequest requires external power and network connectivity",
            ));
        }
        if self.phase != MobileLifecyclePhase::Registered {
            return Ok(0);
        }
        self.audits_answered = self.audits_answered.saturating_add(u64::from(pending_audits));
        self.presence_signals_emitted = self.presence_signals_emitted.saturating_add(1);
        Ok(pending_audits)
    }
}

/// Verify that two independent Android APK builds produce byte-identical artifacts (`WP-58`).
/// exposed for F-Droid reproducible build gate and release pipeline.
///
/// # Errors
///
/// Returns [`MobileRuntimeError::NonReproducibleApk`] if lengths or SHA-256 digests differ.
pub fn verify_reproducible_apk_builds(
    apk_runner_a: &[u8],
    apk_runner_b: &[u8],
) -> Result<[u8; 32], MobileRuntimeError> {
    if apk_runner_a.is_empty() || apk_runner_a.len() != apk_runner_b.len() {
        return Err(MobileRuntimeError::NonReproducibleApk);
    }
    let digest_a = hash_fields_bytes(&[b"BDLM_ANDROID_APK_V1", apk_runner_a]);
    let digest_b = hash_fields_bytes(&[b"BDLM_ANDROID_APK_V1", apk_runner_b]);
    if digest_a != digest_b || apk_runner_a != apk_runner_b {
        return Err(MobileRuntimeError::NonReproducibleApk);
    }
    Ok(digest_a)
}

/// Per-manufacturer Android battery guidance entry (`Section 7.9.11`, zero `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OemBatteryGuidance {
    pub manufacturer: &'static str,
    pub settings_path: &'static str,
    pub requests_ignore_battery_permission: bool,
}

/// Return manufacturer-specific battery-unrestricted instructions (`Section 7.9.11`).
/// exposed for Android OEM battery guide screen.
#[must_use]
pub fn oem_battery_guidance(manufacturer: &str) -> OemBatteryGuidance {
    let lower = manufacturer.trim().to_ascii_lowercase();
    let settings_path = match lower.as_str() {
        "samsung" => "Settings > Apps > Budlum Validator > Battery > Unrestricted",
        "xiaomi" | "redmi" | "poco" => {
            "Settings > Apps > Manage apps > Budlum Validator > Battery saver > No restrictions"
        }
        "oppo" | "oneplus" | "realme" => {
            "Settings > Apps > App management > Budlum Validator > Battery usage > Allow background activity"
        }
        "vivo" => "Settings > Battery > Background power consumption management > Budlum Validator > Don't restrict",
        "motorola" | "google" => "Settings > Apps > Budlum Validator > App battery usage > Unrestricted",
        _ => "Settings > Apps > Budlum Validator > Battery > Unrestricted",
    };
    OemBatteryGuidance {
        manufacturer: match lower.as_str() {
            "samsung" => "Samsung",
            "xiaomi" | "redmi" | "poco" => "Xiaomi",
            "oppo" | "oneplus" | "realme" => "BBK (OPPO/OnePlus/Realme)",
            "vivo" => "Vivo",
            "motorola" => "Motorola",
            "google" => "Google",
            _ => "Generic Android",
        },
        settings_path,
        requests_ignore_battery_permission: false,
    }
}

/// Convenience: exposed for reproducible build probe on production paths.
pub fn canonical_apk_reproducibility_probe(artifact: &[u8]) -> Result<[u8; 32], MobileRuntimeError> {
    verify_reproducible_apk_builds(artifact, artifact)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_keystore() -> MobileKeystoreState {
        MobileKeystoreState {
            owner_address: Address([0x11; 32]),
            owner_spend_requires_user_auth: true,
            operator_key_keystore_wrapped: true,
            bls_presence_key_keystore_wrapped: true,
            hardware_strongbox_backed: true,
            operator_requires_user_auth: false,
            operator_requires_unlocked_device: false,
            operator_key_digest: [0x22; 32],
            rotation_epoch: 0,
        }
    }

    #[test]
    fn android_policy_wifi_only_by_default() {
        let p = MobileValidatorPolicy::android_default();
        assert!(p.wifi_only);
        assert_eq!(p.daily_cellular_cap_mib, 0);
        p.validate().unwrap();
        assert!(!p.permits_active_duty(false, true, 90, false, DeviceThermalLevel::None));
        assert!(p.permits_active_duty(true, false, 80, false, DeviceThermalLevel::None));
    }

    #[test]
    fn android_thermal_pause_cannot_be_disabled() {
        let mut p = MobileValidatorPolicy::android_default();
        assert_eq!(
            p.set_thermal_pause(false),
            Err(MobileRuntimeError::ThermalPauseImmutable)
        );
        assert!(!p.permits_active_duty(true, true, 100, false, DeviceThermalLevel::Moderate));
    }

    #[test]
    fn android_keys_are_keystore_wrapped() {
        let mut ks = valid_keystore();
        ks.validate().unwrap();

        let mut unwrapped = ks.clone();
        unwrapped.operator_key_keystore_wrapped = false;
        assert!(unwrapped.validate().is_err());

        let rotated = ks.rotate_operator_key(&[0x99; 64], 7).unwrap();
        assert_ne!(rotated, [0x22; 32]);
        assert_eq!(ks.rotation_epoch, 7);
    }

    #[test]
    fn android_onboarding_reaches_registered_state() {
        let ctrl = MobileValidatorController::complete_onboarding_and_register(
            MobileValidatorPolicy::android_default(),
            valid_keystore(),
            String::from("/data/user/0/xyz.budlum.validator/no_backup/noBackupFilesDir/bud3"),
            100_000_000,
            true,
        )
        .unwrap();
        assert_eq!(ctrl.phase, MobileLifecyclePhase::Registered);
    }

    #[test]
    fn android_low_space_releases_shares() {
        let mut ctrl = MobileValidatorController::complete_onboarding_and_register(
            MobileValidatorPolicy::android_default(),
            valid_keystore(),
            String::from("/data/user/0/xyz.budlum.validator/noBackupFilesDir/bud3"),
            100_000_000,
            true,
        )
        .unwrap();
        ctrl.accept_share([1u8; 32], 600 * (1 << 20)).unwrap();
        ctrl.accept_share([2u8; 32], 600 * (1 << 20)).unwrap();

        // Free space drops to 1.6 GiB (< 2 GiB threshold) -> releases 1 share (600 MiB) to reach 2.2 GiB.
        let plan = ctrl.enforce_low_free_space(1_600 * (1 << 20));
        assert_eq!(plan.release_txs.len(), 1);
        assert!(!plan.unbonding_started);
        assert_eq!(ctrl.held_objects.len(), 1);
    }

    #[test]
    fn android_leave_releases_shares_and_unbonds() {
        let mut ctrl = MobileValidatorController::complete_onboarding_and_register(
            MobileValidatorPolicy::android_default(),
            valid_keystore(),
            String::from("/data/user/0/xyz.budlum.validator/noBackupFilesDir/bud3"),
            100_000_000,
            true,
        )
        .unwrap();
        ctrl.accept_share([3u8; 32], 128 * (1 << 20)).unwrap();
        ctrl.accept_share([4u8; 32], 256 * (1 << 20)).unwrap();

        let plan = ctrl.leave_and_unbond();
        assert_eq!(plan.release_txs.len(), 2);
        assert!(plan.unbonding_started);
        assert_eq!(ctrl.phase, MobileLifecyclePhase::LeavingUnbonding);
        assert!(ctrl.held_objects.is_empty());
    }

    #[test]
    fn android_workmanager_answers_audit_when_service_stopped() {
        let mut ctrl = MobileValidatorController::complete_onboarding_and_register(
            MobileValidatorPolicy::android_default(),
            valid_keystore(),
            String::from("/data/user/0/xyz.budlum.validator/noBackupFilesDir/bud3"),
            100_000_000,
            true,
        )
        .unwrap();
        assert!(ctrl.run_android_workmanager_tick(false, false, 3).is_err());
        let answered = ctrl.run_android_workmanager_tick(false, true, 3).unwrap();
        assert_eq!(answered, 3);
        assert_eq!(ctrl.audits_answered, 3);
        assert_eq!(ctrl.presence_signals_emitted, 1);
    }

    #[test]
    fn ios_class_is_opportunistic() {
        let p = MobileValidatorPolicy::ios_opportunistic_default();
        assert_eq!(p.class, MobileValidatorClass::MobileOpportunistic);
        assert_eq!(p.class.audit_window_hours(), 48);
        assert_eq!(p.class.suspension_hours(), 168);
    }

    #[test]
    fn ios_quota_cap_is_8_gib() {
        let mut p = MobileValidatorPolicy::ios_opportunistic_default();
        p.quota_bytes = 8 * (1 << 30);
        p.validate().unwrap();

        p.quota_bytes = 9 * (1 << 30);
        assert!(matches!(
            p.validate(),
            Err(MobileRuntimeError::QuotaOutOfBounds { .. })
        ));
    }

    #[test]
    fn ios_bg_task_answers_audit() {
        let mut ctrl = MobileValidatorController::complete_onboarding_and_register(
            MobileValidatorPolicy::ios_opportunistic_default(),
            valid_keystore(),
            String::from("/var/mobile/Containers/Data/ApplicationSupport/bud3-nobackup"),
            100_000_000,
            true,
        )
        .unwrap();
        assert!(ctrl.run_ios_bg_processing_task(false, true, 2).is_err());
        let answered = ctrl.run_ios_bg_processing_task(true, true, 2).unwrap();
        assert_eq!(answered, 2);
        assert_eq!(ctrl.audits_answered, 2);
    }

    #[test]
    fn android_reproducible_build_matches() {
        let apk_a = b"PK\x03\x04deterministic-apk-payload-v1";
        let apk_b = b"PK\x03\x04deterministic-apk-payload-v1";
        let d = canonical_apk_reproducibility_probe(apk_a).unwrap();
        assert_eq!(verify_reproducible_apk_builds(apk_a, apk_b).unwrap(), d);
        assert_eq!(
            verify_reproducible_apk_builds(apk_a, b"PK\x03\x04different"),
            Err(MobileRuntimeError::NonReproducibleApk)
        );
    }
}
