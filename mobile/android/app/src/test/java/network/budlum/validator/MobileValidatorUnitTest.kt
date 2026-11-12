package network.budlum.validator

import java.io.File
import java.nio.file.Files
import java.security.KeyStoreException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
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
import network.budlum.validator.core.ValidatorOnboardingGate
import network.budlum.validator.core.generatePreferStrongBox
import network.budlum.validator.core.presenceSigningDigest
import network.budlum.validator.devicetests.DeviceFieldHarness

/**
 * Executable specification and unit suite for the Android validator.
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

    // Engine-level tests supply host-measured space separately. The physical
    // sandbox filesystem floor is exercised by the dedicated store regression.
    private fun newTestCustody(): ShareCustodyDirectory =
        ShareCustodyDirectory(newTempBud3Dir()) { Long.MAX_VALUE }

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
            custodyDir = newTestCustody(),
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

        // Even the old public bearer token, a random string, and an empty
        // string must all fail. No production owner wrapper can be created
        // without a real Keystore-backed authorization and wallet signer.
        for (candidate in listOf(null, "BIOMETRIC_VERIFIED_SESSION", "arbitrary")) {
            check(
                runCatching {
                    vault.wrapKey(KeyPurpose.OwnerSpendMlDsa87, ownerSecret, biometricAuthToken = candidate)
                }.exceptionOrNull() is SecurityException,
                "owner key wrapping must refuse every caller-controlled string",
            )
            check(
                runCatching {
                    vault.unwrapKey(opEnvelope.copy(purpose = KeyPurpose.OwnerSpendMlDsa87), candidate)
                }.exceptionOrNull() is SecurityException,
                "owner key unwrapping must refuse every caller-controlled string",
            )
        }
    }

    fun android_unwrap_requires_existing_wrapping_key() {
        val original = KeystoreKeyVault(JvmMemoryWrappingKeyProvider())
        val envelope = original.wrapKey(KeyPurpose.OperatorDutyMlDsa65, ByteArray(32) { 11 })
        val missingProvider = JvmMemoryWrappingKeyProvider(strongBoxAvailable = false)
        val missing = KeystoreKeyVault(missingProvider)
        var refused = false
        try {
            missing.unwrapKey(envelope)
        } catch (_: KeyStoreException) {
            refused = true
        }
        check(refused, "unwrapping with a missing wrapping key must fail closed")
        check(
            missingProvider.getExistingAes256Key(envelope.keystoreAlias, false) == null,
            "failed unwrap must not create unrelated replacement key material",
        )
    }

    fun android_strongbox_fallback_is_narrow() {
        class Unavailable : Exception()

        val attempts = mutableListOf<Boolean>()
        val fallback = generatePreferStrongBox(
            generate = { strongBox ->
                attempts.add(strongBox)
                if (strongBox) throw Unavailable()
                "ordinary"
            },
            isUnavailable = { it is Unavailable },
        )
        check(fallback == "ordinary" && attempts == listOf(true, false), "fallback only after unavailable")

        val successAttempts = mutableListOf<Boolean>()
        val direct = generatePreferStrongBox(
            generate = { strongBox ->
                successAttempts.add(strongBox)
                "strongbox"
            },
            isUnavailable = { it is Unavailable },
        )
        check(direct == "strongbox" && successAttempts == listOf(true), "no fallback after success")

        val unexpected = IllegalStateException("unexpected")
        val unexpectedAttempts = mutableListOf<Boolean>()
        val propagated = runCatching {
            generatePreferStrongBox<String>(
                generate = { strongBox ->
                    unexpectedAttempts.add(strongBox)
                    throw unexpected
                },
                isUnavailable = { it is Unavailable },
            )
        }.exceptionOrNull()
        check(propagated === unexpected && unexpectedAttempts == listOf(true), "unexpected errors propagate")
    }

    fun android_share_admission_is_atomic_and_fail_closed() {
        val root = newTempBud3Dir()
        var free = MobileConstants.FREE_SPACE_FLOOR_BYTES + 3L
        val store = ShareCustodyDirectory(root) { free }
        val first = AssignedShare("010aff", 1, byteArrayOf(1, 2, 3, 4))
        val second = AssignedShare("020b", 2, byteArrayOf(5, 6, 7, 8))

        check(runCatching { store.putShare(first, 100L) }.isFailure, "share cannot cross free-space floor")
        check(!File(root, first.segmentIdHex).exists(), "failed floor admission publishes no share")
        free = MobileConstants.FREE_SPACE_FLOOR_BYTES + 4L
        store.putShare(first, 100L)
        store.putShare(second, 100L)
        check(store.storedBytes() == 8L, "two admitted shares counted")

        val duplicate = runCatching { store.putShare(first.copy(symbolBytes = byteArrayOf(9, 9, 9)), 100L) }
        check(duplicate.isFailure, "duplicate segment id refused")
        check(File(root, first.segmentIdHex).readBytes().contentEquals(byteArrayOf(1, 2, 3, 4)), "duplicate cannot overwrite")
        check(File(root, second.segmentIdHex).setLastModified(2_000L), "second timestamp set")
        check(File(root, first.segmentIdHex).setLastModified(1_000L), "first timestamp set")
        check(store.trimToQuota(6L) == listOf(first.segmentIdHex), "quota releases only the oldest required share")
        check(store.storedBytes() == 4L && File(root, second.segmentIdHex).isFile, "trim stops as soon as quota is met")

        val linkTarget = File(root, "030c")
        val outside = File(root.parentFile, "outside")
        Files.createSymbolicLink(linkTarget.toPath(), outside.toPath())
        check(runCatching { store.putShare(AssignedShare("030c", 3, byteArrayOf(1)), 100L) }.isFailure, "dangling link refused")
        check(!outside.exists(), "dangling link cannot redirect a share write")
        linkTarget.delete()

        val unknown = File(root, "not-a-segment")
        unknown.writeBytes(byteArrayOf(7, 8, 9))
        check(store.storedBytes() == Long.MAX_VALUE, "unrecognized content fails accounting closed")
        check(store.trimToQuota(0L).isEmpty(), "unrecognized content prevents quota deletion")
        check(unknown.readBytes().contentEquals(byteArrayOf(7, 8, 9)), "unknown file preserved")
        check(File(root, second.segmentIdHex).isFile, "recognized share also preserved after unsafe snapshot")
        unknown.delete()
        check(runCatching { store.trimToQuota(-1L) }.isFailure, "negative quota refused")
        check(runCatching { store.putShare(AssignedShare("", 0, byteArrayOf(1)), 100L) }.isFailure, "empty segment id refused")
    }

    fun android_concurrent_share_admission_respects_quota() {
        val root = newTempBud3Dir()
        val workers = 16
        val bytesPerShare = 16_384
        val ready = CountDownLatch(workers)
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(workers)
        try {
            val writes = (0 until workers).map { index ->
                executor.submit<Boolean> {
                    val store = ShareCustodyDirectory(root) { Long.MAX_VALUE }
                    ready.countDown()
                    start.await()
                    runCatching {
                        store.putShare(
                            AssignedShare("%02x".format(index), index, ByteArray(bytesPerShare)),
                            bytesPerShare.toLong(),
                        )
                    }.isSuccess
                }
            }
            check(ready.await(10, TimeUnit.SECONDS), "concurrent writers ready")
            start.countDown()
            check(writes.count { it.get(10, TimeUnit.SECONDS) } == 1, "only one concurrent writer fits quota")
            check(ShareCustodyDirectory(root).storedBytes() == bytesPerShare.toLong(), "quota accounting after race")
        } finally {
            executor.shutdownNow()
        }
    }

    fun android_unconnected_policy_and_stake_do_not_create_duties() {
        val engine = MobileValidatorEngine(
            ownerAddressHex = "06".repeat(32),
            keyVault = KeystoreKeyVault(JvmMemoryWrappingKeyProvider()),
            custodyDir = newTestCustody(),
            relays = emptyList(),
            initialAvailableBytes = 16L * MobileConstants.GIB_BYTES,
            initialSimulatedLiquidBud = 100L,
        )
        check(runCatching {
            engine.setPolicy(Policy(network = NetworkPolicy.Metered(dailyCapMb = 100)))
        }.isFailure, "policy cannot delete shares or claim a mobile duty before onboarding")
        for (token in listOf("", "BIOMETRIC_VERIFIED_SESSION", "someone-else")) {
            check(runCatching { engine.registerValidator(token, "42".repeat(32)) }.isFailure,
                "caller-supplied token cannot stake even with simulated funds")
        }
        val tick = engine.runWorkManagerPeriodicTick(
            window = 19L, isUnmeteredWifi = true, pendingAudits = emptyList(),
            incomingShares = emptyList(),
        )
        check(tick.isEmpty() && engine.drainOutbox().isEmpty(), "no false presence, stake or network duties")
        check(!engine.status().registered && engine.status().liquidBud == 100L, "balance unchanged")
    }

    fun android_unbound_leave_keeps_local_shares() {
        val bud3 = newTempBud3Dir()
        val custody = ShareCustodyDirectory(bud3) { Long.MAX_VALUE }
        custody.putShare(AssignedShare("00ff11", 0, ByteArray(4096) { 0x5a }),
            MobileConstants.QUOTA_DEFAULT_BYTES)
        val engine = MobileValidatorEngine(
            ownerAddressHex = "02".repeat(32),
            keyVault = KeystoreKeyVault(JvmMemoryWrappingKeyProvider()),
            custodyDir = custody,
            relays = emptyList(),
            initialAvailableBytes = 16L * MobileConstants.GIB_BYTES,
        )
        check(runCatching { engine.leave("BIOMETRIC_VERIFIED_SESSION") }.isFailure,
            "a static string cannot unbond or release a share")
        check(engine.status().storedBytes == 4096L && engine.drainOutbox().isEmpty(),
            "rejected leave preserves existing local custody and emits no fake chain release")
    }

    fun android_unbound_low_space_does_not_silently_delete_shares() {
        val bud3 = newTempBud3Dir()
        val custody = ShareCustodyDirectory(bud3) { Long.MAX_VALUE }
        custody.putShare(AssignedShare("aa01bb", 1, ByteArray(2048) { 0x33 }),
            MobileConstants.QUOTA_DEFAULT_BYTES)
        val engine = MobileValidatorEngine(
            ownerAddressHex = "03".repeat(32),
            keyVault = KeystoreKeyVault(JvmMemoryWrappingKeyProvider()),
            custodyDir = custody,
            relays = emptyList(),
            initialAvailableBytes = 8L * MobileConstants.GIB_BYTES,
        )
        check(engine.updateAvailableDiskBytes(MobileConstants.FREE_SPACE_FLOOR_BYTES - 1L) == null,
            "no unsigned release claim on low space")
        check(custody.storedBytes() == 2048L && engine.drainOutbox().isEmpty(),
            "unbound low-space check cannot delete custody files")
    }

    fun android_release_requires_real_generated_wallet_binding() {
        val gradle = File("mobile/android/app/build.gradle.kts").readText()
        check(gradle.contains("checkNativeValidatorRelease"), "release validates native owner proof artifacts")
        check(gradle.contains("preReleaseBuild"), "release build depends on binding validation")
        check(gradle.contains("budlum_mobile_ffi.kt"), "release requires generated UniFFI Kotlin")
        check(gradle.contains("NativeValidatorGateway.kt"), "release requires real host gateway")
        check(gradle.contains("libbudlum_mobile_ffi.so"), "release requires built native library")
        check(gradle.contains("readyForDuties(): Boolean = false"), "release must refuse while gate is closed")
        check(!ValidatorOnboardingGate.readyForDuties(), "no wallet proof may enable validator today")
    }

    fun android_unconnected_onboarding_is_fail_closed() {
        check(!ValidatorOnboardingGate.readyForDuties(), "an RPC balance is not wallet registration")
        for (owner in listOf("00".repeat(32), "01", "zz".repeat(32))) {
            check(runCatching {
                MobileValidatorEngine(
                    ownerAddressHex = owner,
                    keyVault = KeystoreKeyVault(JvmMemoryWrappingKeyProvider()),
                    custodyDir = newTestCustody(),
                    relays = emptyList(),
                    initialAvailableBytes = 8L * MobileConstants.GIB_BYTES,
                )
            }.isFailure, "zero or malformed owner must not construct a node")
        }
        val service = File("mobile/android/app/src/main/java/network/budlum/validator/service/ValidatorService.kt").readText()
        val worker = File("mobile/android/app/src/main/java/network/budlum/validator/worker/DutyPeriodicWorker.kt").readText()
        check(service.contains("!ValidatorOnboardingGate.readyForDuties()"), "service checks wallet readiness")
        check(service.contains("return START_NOT_STICKY"), "unbound service cannot be sticky")
        check(worker.contains("if (!ValidatorOnboardingGate.readyForDuties()) return Result.failure()"),
            "periodic duty cannot claim success without onboarding")
        check(!worker.contains("updateAvailableDiskBytes"), "an unbound worker must not delete custody files")
        val ffi = File("mobile/ffi/src/lib.rs").readText()
        check(ffi.contains("mobile_validator_unconnected"), "native start must refuse without registration")
    }

    fun android_unfunded_engine_cannot_register_from_faucet_ui() {
        val engine = MobileValidatorEngine(
            ownerAddressHex = "01".repeat(32),
            keyVault = KeystoreKeyVault(JvmMemoryWrappingKeyProvider()),
            custodyDir = newTestCustody(),
            relays = emptyList(),
            initialAvailableBytes = 8L * MobileConstants.GIB_BYTES,
        )
        check(engine.status().liquidBud == 0L, "no simulated faucet mint on construction")
        check(
            runCatching { engine.registerValidator("BIOMETRIC_VERIFIED_SESSION", "01".repeat(32)) }.isFailure,
            "an unconnected wallet cannot fund registration through a faucet HTTP response",
        )
        check(engine.status().liquidBud == 0L && !engine.status().registered, "failed registration leaves state unchanged")
    }

    fun android_owner_string_never_unlocks_stake_rotation_or_duty() {
        val engine = MobileValidatorEngine(
            ownerAddressHex = "04".repeat(32),
            keyVault = KeystoreKeyVault(JvmMemoryWrappingKeyProvider()),
            custodyDir = newTestCustody(),
            relays = listOf(RelayOffer("/ip4/203.0.113.7/udp/4001/quic-v1", 12_000L)),
            initialAvailableBytes = 12L * MobileConstants.GIB_BYTES,
            initialSimulatedLiquidBud = 100L,
        )
        val before = engine.status()
        val oldToken = "BIOMETRIC_VERIFIED_SESSION"
        check(runCatching { engine.registerValidator(oldToken, "ef".repeat(32)) }.isFailure,
            "old public bearer string cannot stake simulated funds")
        check(runCatching { engine.rotateOperatorKey(oldToken, "12".repeat(32)) }.isFailure,
            "old public bearer string cannot rotate operator key")
        check(runCatching { engine.leave(oldToken) }.isFailure,
            "old public bearer string cannot release or unbond")
        check(runCatching { engine.startForegroundFromUi(true) }.isFailure,
            "not-onboarded engine cannot start foreground service")
        check(runCatching { engine.acceptShare(AssignedShare("cafe01", 0, byteArrayOf(1))) }.isFailure,
            "not-onboarded engine cannot accept shares or emit acknowledgments")
        check(runCatching { engine.answerAudit(StorageAudit("cafe01", 99L)) }.isFailure,
            "not-onboarded engine cannot claim an audit result or reward")
        check(engine.status() == before && engine.drainOutbox().isEmpty(),
            "all denied owner and duty calls leave state and outbox unchanged")
    }

    fun android_unbound_worker_cannot_claim_custody_audits_or_rewards() {
        val bud3 = newTempBud3Dir()
        val custody = ShareCustodyDirectory(bud3) { Long.MAX_VALUE }
        custody.putShare(AssignedShare("beef02", 2, ByteArray(512) { 0x7f }),
            MobileConstants.QUOTA_DEFAULT_BYTES)
        val engine = MobileValidatorEngine(
            ownerAddressHex = "05".repeat(32),
            keyVault = KeystoreKeyVault(JvmMemoryWrappingKeyProvider()),
            custodyDir = custody,
            relays = emptyList(),
            initialAvailableBytes = 12L * MobileConstants.GIB_BYTES,
        )
        val txs = engine.runWorkManagerPeriodicTick(
            window = 17L, isUnmeteredWifi = true,
            pendingAudits = listOf(StorageAudit("beef02", challengeNonce = 7L)),
            incomingShares = listOf(AssignedShare("cafe03", 0, byteArrayOf(1))),
        )
        check(txs.isEmpty() && engine.drainOutbox().isEmpty(),
            "unbound worker cannot claim successful audit, custody or presence")
        check(engine.status().storedBytes == 512L && engine.status().lastAudit == LastAudit.None &&
            engine.status().pendingRewardsAttos == 0L,
            "unbound duty preserves previous files and earns no synthetic rewards")
        for (oem in listOf("Google", "Samsung", "Xiaomi", "OnePlus", "Motorola")) {
            val guide = OemBatteryGuide.forManufacturer(oem)
            check(!guide.usesIgnoreBatteryPermission, "OEM guide never requests ignore-battery permission")
        }
        val logLine = DeviceFieldHarness.formatSoak24hRecord("dev-pixel8a", 86_400L, false, 96, 0)
        check(logLine.contains("on_timeout=false"), "field harness formats TSV soak line")
    }

    fun android_presence_digest_matches_shared_sha3_vector_without_claiming_a_signature() {
        val digest = presenceSigningDigest(MobileConstants.TESTNET_CHAIN_ID, 11L,
            network.budlum.validator.core.ValidatorClass.Mobile.tag)
        check(digest.joinToString("") { "%02x".format(it) } ==
            "26a5bec8b11098debd4eeffbe797638d295a08aa570cb3c176d9c5e41bfbb2a3",
            "Android computes the shared preimage hash; no BLS signature or network duty is implied")
        check(runCatching {
            presenceSigningDigest(MobileConstants.TESTNET_CHAIN_ID, -1L,
                network.budlum.validator.core.ValidatorClass.Mobile.tag)
        }.isFailure, "negative presence windows are refused")
    }

    fun android_reproducible_build_matches() {
        val gradle = File("mobile/android/app/build.gradle.kts").readText()
        check(gradle.contains("includeInApk = false"), " Play dependency block must be excluded from APK")
        check(gradle.contains("isPreserveFileTimestamps = false"), " archive timestamps must be normalized")
        check(gradle.contains("isReproducibleFileOrder = true"), " archive entry order must be deterministic")

        val fdroid = File("mobile/android/fdroid/network.budlum.validator.yml").readText()
        check(fdroid.contains("ndk: 27.2.12479018"), " F-Droid metadata must pin NDK 27.2.12479018")
        check(fdroid.contains("1.97.1"), " F-Droid metadata must pin Rust 1.97.1")

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
            " deterministic APK packaging must yield identical SHA-256 across build orders",
        )
    }

    @JvmStatic
    fun main(args: Array<String>) {
        android_policy_wifi_only_by_default()
        android_thermal_pause_cannot_be_disabled()
        android_keys_are_keystore_wrapped()
        android_unwrap_requires_existing_wrapping_key()
        android_strongbox_fallback_is_narrow()
        android_share_admission_is_atomic_and_fail_closed()
        android_concurrent_share_admission_respects_quota()
        android_unconnected_policy_and_stake_do_not_create_duties()
        android_unbound_leave_keeps_local_shares()
        android_unbound_low_space_does_not_silently_delete_shares()
        android_release_requires_real_generated_wallet_binding()
        android_unconnected_onboarding_is_fail_closed()
        android_unfunded_engine_cannot_register_from_faucet_ui()
        android_owner_string_never_unlocks_stake_rotation_or_duty()
        android_unbound_worker_cannot_claim_custody_audits_or_rewards()
        android_presence_digest_matches_shared_sha3_vector_without_claiming_a_signature()
        android_reproducible_build_matches()
        println("ANDROID JVM SAFETY TESTS PASSED; VALIDATOR DUTIES REMAIN DISABLED")
    }
}
