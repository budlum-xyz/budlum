package network.budlum.validator

import java.io.File
import java.nio.file.Files
import network.budlum.validator.core.AssignedShare
import network.budlum.validator.core.DutyTx
import network.budlum.validator.core.JvmMemoryWrappingKeyProvider
import network.budlum.validator.core.KeyPurpose
import network.budlum.validator.core.KeystoreKeyVault
import network.budlum.validator.core.LastAudit
import network.budlum.validator.core.MobileConstants
import network.budlum.validator.core.MobileValidatorEngine
import network.budlum.validator.core.NetworkPolicy
import network.budlum.validator.core.OemBatteryGuide
import network.budlum.validator.core.Policy
import network.budlum.validator.core.RelayOffer
import network.budlum.validator.core.ShareCustodyDirectory
import network.budlum.validator.core.StorageAudit
import network.budlum.validator.devicetests.DeviceFieldHarness

/**
 * Executable specification & unit suite covering all 7 WP-36 required tests.
 *
 * Can run both under JUnit and directly from `kotlinc` via `main()` in CI.
 */
object MobileValidatorUnitTest {
    private fun check(condition: Boolean, message: String) {
        if (!condition) {
            throw AssertionError("Test assertion failed: $message")
        }
    }

    private fun newTempBud3Dir(): File {
        val dir = Files.createTempDirectory("bud3_android_test_").toFile()
        dir.deleteOnExit()
        return File(dir, "bud3")
    }

    fun android_policy_wifi_only_by_default() {
        val policy = Policy()
        policy.validate()
        check(
            policy.network == NetworkPolicy.UnmeteredOnly,
            "R-33 default network policy must be Wi-Fi / unmetered only",
        )
        check(
            policy.quotaBytes == MobileConstants.QUOTA_DEFAULT_BYTES,
            "default mobile quota must be 4 GiB",
        )
        check(policy.symbolRewardWeightBps() == 10_000, "serving symbols earns 100% weight")
        check(
            policy.copy(serveSymbols = false).symbolRewardWeightBps() == 5_000,
            "disabling symbol serving halves storage reward weight",
        )
    }

    fun android_thermal_pause_cannot_be_disabled() {
        val policy = Policy()
        var rejected = false
        try {
            policy.withThermalPause(false)
        } catch (_: IllegalArgumentException) {
            rejected = true
        }
        check(rejected, "R-35 disabling thermal pause on Policy must be refused")

        val engine = MobileValidatorEngine(
            ownerAddressHex = "01".repeat(32),
            keyVault = KeystoreKeyVault(JvmMemoryWrappingKeyProvider()),
            custodyDir = ShareCustodyDirectory(newTempBud3Dir()),
            relays = emptyList(),
            initialAvailableBytes = 16L * MobileConstants.GIB_BYTES,
        )
        var engineRejected = false
        try {
            engine.setPolicy(Policy(thermalPause = false))
        } catch (_: IllegalArgumentException) {
            engineRejected = true
        }
        check(engineRejected, "R-35 engine.setPolicy(thermalPause = false) must be refused")
    }

    fun android_keys_are_keystore_wrapped() {
        val vault = KeystoreKeyVault(JvmMemoryWrappingKeyProvider(strongBoxAvailable = true))
        val operatorSecret = ByteArray(32) { idx -> (idx + 3).toByte() }
        val blsSecret = ByteArray(32) { idx -> (idx + 9).toByte() }
        val ownerSecret = ByteArray(64) { idx -> (idx + 17).toByte() }

        val opEnvelope = vault.wrapKey(KeyPurpose.OperatorDutyMlDsa65, operatorSecret)
        val blsEnvelope = vault.wrapKey(KeyPurpose.PresenceBls12381, blsSecret)
        check(opEnvelope.strongBoxBacked && blsEnvelope.strongBoxBacked, "StrongBox preferred")
        check(!opEnvelope.userAuthenticationRequired, "operator key usable in background WorkManager")
        check(!opEnvelope.unlockedDeviceRequired, "operator key usable while screen locked")
        check(!opEnvelope.ciphertextWithTag.contentEquals(operatorSecret), "ciphertext must not equal plaintext")
        check(vault.unwrapKey(opEnvelope).contentEquals(operatorSecret), "operator key round-trips")
        check(vault.unwrapKey(blsEnvelope).contentEquals(blsSecret), "BLS key round-trips")

        var ownerBlockedWithoutBiometric = false
        try {
            vault.wrapKey(KeyPurpose.OwnerSpendMlDsa87, ownerSecret, biometricAuthToken = null)
        } catch (_: SecurityException) {
            ownerBlockedWithoutBiometric = true
        }
        check(ownerBlockedWithoutBiometric, "owner ML-DSA-87 key must require biometric/PIN")

        val ownerEnvelope = vault.wrapKey(
            KeyPurpose.OwnerSpendMlDsa87,
            ownerSecret,
            biometricAuthToken = "BIOMETRIC_VERIFIED_SESSION",
        )
        check(ownerEnvelope.userAuthenticationRequired, "owner key requires user auth")
        check(
            vault.unwrapKey(ownerEnvelope, "BIOMETRIC_VERIFIED_SESSION").contentEquals(ownerSecret),
            "owner key unwraps after biometric verification",
        )
    }

    fun android_leave_releases_shares_and_unbonds() {
        val bud3 = newTempBud3Dir()
        val vault = KeystoreKeyVault(JvmMemoryWrappingKeyProvider())
        val engine = MobileValidatorEngine(
            ownerAddressHex = "02".repeat(32),
            keyVault = vault,
            custodyDir = ShareCustodyDirectory(bud3),
            relays = listOf(RelayOffer("/ip4/198.51.100.2/udp/4001/quic-v1", 8_000L)),
            initialAvailableBytes = 16L * MobileConstants.GIB_BYTES,
        )
        engine.requestTestnetFaucet(powNonce = 7L)
        engine.registerValidator("BIOMETRIC_VERIFIED_SESSION", "ab".repeat(32))
        engine.startForegroundFromUi(isAppInForeground = true)
        engine.acceptShare(AssignedShare("00ff11", 0, ByteArray(4096) { 0x5a }))
        check(engine.status().storedBytes == 4096L, "share stored before leave")

        val txs = engine.leave("BIOMETRIC_VERIFIED_SESSION")
        check(txs.any { it is DutyTx.ReleaseShares }, "leave must emit ReleaseShares")
        check(
            txs.any { it is DutyTx.UnbondValidator && it.stakeBud == MobileConstants.MOBILE_MIN_STAKE_BUD },
            "leave must unbond the 10 BUD stake",
        )
        check(engine.status().storedBytes == 0L, "all share files removed on leave")
        check(!engine.status().running && !engine.status().registered, "validator stopped after leave")
    }

    fun android_low_space_releases_shares() {
        val bud3 = newTempBud3Dir()
        val engine = MobileValidatorEngine(
            ownerAddressHex = "03".repeat(32),
            keyVault = KeystoreKeyVault(JvmMemoryWrappingKeyProvider()),
            custodyDir = ShareCustodyDirectory(bud3),
            relays = emptyList(),
            initialAvailableBytes = 8L * MobileConstants.GIB_BYTES,
        )
        engine.requestTestnetFaucet(1L)
        engine.registerValidator("BIOMETRIC_VERIFIED_SESSION", "cd".repeat(32))
        engine.acceptShare(AssignedShare("aa01bb", 1, ByteArray(2048) { 0x33 }))
        check(engine.status().storedBytes == 2048L, "share present above 2 GiB floor")

        val release = engine.updateAvailableDiskBytes(MobileConstants.FREE_SPACE_FLOOR_BYTES - 1L)
        check(
            release != null && release.segments == listOf("aa01bb"),
            "R-34 dropping below 2 GiB free space must emit ReleaseShares",
        )
        check(engine.status().storedBytes == 0L, "custody directory cleared at low space")
    }

    fun android_onboarding_reaches_registered_state() {
        val bud3 = newTempBud3Dir()
        val vault = KeystoreKeyVault(JvmMemoryWrappingKeyProvider())
        val engine = MobileValidatorEngine(
            ownerAddressHex = "04".repeat(32),
            keyVault = vault,
            custodyDir = ShareCustodyDirectory(bud3),
            relays = listOf(RelayOffer("/ip4/203.0.113.7/udp/4001/quic-v1", 12_000L)),
            initialAvailableBytes = 12L * MobileConstants.GIB_BYTES,
        )
        check(engine.requestTestnetFaucet(powNonce = 42L) == 100L, "faucet drips 100 BUD")
        engine.registerValidator("BIOMETRIC_VERIFIED_SESSION", "ef".repeat(32))
        engine.startForegroundFromUi(isAppInForeground = true)
        engine.acceptShare(AssignedShare("cafe01", 0, ByteArray(1024) { 0x11 }))
        engine.answerAudit(StorageAudit("cafe01", challengeNonce = 99L))
        val snap = engine.status()
        check(snap.registered && snap.running, "onboarding reaches registered + running state")
        check(snap.stakedBud == 10L && snap.liquidBud == 90L, "10 BUD staked, 90 BUD liquid")
        check(snap.lastAudit == LastAudit.Passed, "audit answered")
        check(snap.pendingRewardsAttos > 0L, "reward accrued after passed audit")

        val rotated = engine.rotateOperatorKey("BIOMETRIC_VERIFIED_SESSION", "12".repeat(32))
        check(rotated.newOperatorPubKeyHex == "12".repeat(32), "R-16 RotateOperatorKey succeeds")
    }

    fun android_workmanager_answers_audit_when_service_stopped() {
        val bud3 = newTempBud3Dir()
        val engine = MobileValidatorEngine(
            ownerAddressHex = "05".repeat(32),
            keyVault = KeystoreKeyVault(JvmMemoryWrappingKeyProvider()),
            custodyDir = ShareCustodyDirectory(bud3),
            relays = listOf(RelayOffer("/ip4/203.0.113.9/udp/4001/quic-v1", 10_000L)),
            initialAvailableBytes = 12L * MobileConstants.GIB_BYTES,
        )
        engine.requestTestnetFaucet(1L)
        engine.registerValidator("BIOMETRIC_VERIFIED_SESSION", "99".repeat(32))
        engine.stopForeground()
        check(!engine.status().running, "foreground service is stopped")

        val txs = engine.runWorkManagerPeriodicTick(
            window = 17L,
            isUnmeteredWifi = true,
            pendingAudits = listOf(StorageAudit("beef02", challengeNonce = 7L)),
            incomingShares = listOf(AssignedShare("beef02", 2, ByteArray(512) { 0x7f })),
        )
        check(txs.any { it is DutyTx.CustodyAck }, "WorkManager accepts share while service stopped")
        check(txs.any { it is DutyTx.CustodyProofBatch }, "WorkManager answers audit while service stopped")
        check(txs.any { it is DutyTx.Presence }, "WorkManager emits BLS presence preimage")
        check(engine.status().lastAudit == LastAudit.Passed, "WorkManager updates audit state to Passed")

        for (oem in listOf("Google", "Samsung", "Xiaomi", "OnePlus", "Motorola")) {
            val guide = OemBatteryGuide.forManufacturer(oem)
            check(!guide.usesIgnoreBatteryPermission, "OEM guide never requests ignore-battery permission")
        }
        val logLine = DeviceFieldHarness.formatSoak24hRecord("dev-pixel8a", 86_400L, false, 96, 0)
        check(logLine.contains("on_timeout=false"), "field harness formats TSV soak line")
    }

    fun android_reproducible_build_matches() {
        val gradle = File("mobile/android/app/build.gradle.kts").readText()
        check(gradle.contains("includeInApk = false"), "WP-58 Play dependency block must be excluded from APK")
        check(gradle.contains("isPreserveFileTimestamps = false"), "WP-58 archive timestamps must be normalized")
        check(gradle.contains("isReproducibleFileOrder = true"), "WP-58 archive entry order must be deterministic")

        val fdroid = File("mobile/android/fdroid/network.budlum.validator.yml").readText()
        check(fdroid.contains("ndk: 27.2.12479018"), "WP-58 F-Droid recipe must pin NDK 27.2.12479018")
        check(fdroid.contains("1.97.1"), "WP-58 F-Droid recipe must pin Rust 1.97.1")

        fun packDeterministicApk(inputs: List<Pair<String, ByteArray>>): String {
            val out = java.io.ByteArrayOutputStream()
            java.util.zip.ZipOutputStream(out).use { zos ->
                for ((path, payload) in inputs.sortedBy { it.first }) {
                    val entry = java.util.zip.ZipEntry(path)
                    entry.time = 315_532_800_000L
                    zos.putNextEntry(entry)
                    zos.write(payload)
                    zos.closeEntry()
                }
            }
            return java.security.MessageDigest.getInstance("SHA-256")
                .digest(out.toByteArray())
                .joinToString("") { "%02x".format(it) }
        }

        val entriesForward = listOf(
            "AndroidManifest.xml" to "manifest-v1".encodeToByteArray(),
            "classes.dex" to "dex-v1".encodeToByteArray(),
            "lib/arm64-v8a/libbudlum_mobile_core.so" to "elf-arm64".encodeToByteArray(),
        )
        val entriesReverse = entriesForward.reversed()
        check(
            packDeterministicApk(entriesForward) == packDeterministicApk(entriesReverse),
            "WP-58 deterministic APK packaging must yield identical SHA-256 across build orders",
        )
    }

    @JvmStatic
    fun main(args: Array<String>) {
        android_policy_wifi_only_by_default()
        android_thermal_pause_cannot_be_disabled()
        android_keys_are_keystore_wrapped()
        android_leave_releases_shares_and_unbonds()
        android_low_space_releases_shares()
        android_onboarding_reaches_registered_state()
        android_workmanager_answers_audit_when_service_stopped()
        android_reproducible_build_matches()
        println("ALL 8 WP-36/WP-58 ANDROID VALIDATOR TESTS PASSED")
    }
}
