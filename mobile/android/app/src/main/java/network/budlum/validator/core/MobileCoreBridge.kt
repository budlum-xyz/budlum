package network.budlum.validator.core

import java.io.File
import java.io.FileOutputStream
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.security.MessageDigest

/**
 * UniFFI / Kotlin domain bridge aligned 1-to-1 with `mobile/core` (`budlum-mobile-core`).
 *
 * Enforces Section 7.9 invariants:
 * - `TESTNET_CHAIN_ID = 45261`
 * - Default network policy: `NetworkPolicy.UnmeteredOnly` (Wi-Fi only, R-33)
 * - Thermal pause: non-disablable (`thermalPause == true`, R-35)
 * - Custody quota: `[1 GiB, 64 GiB]`, default `4 GiB`
 * - Low free-space floor: `< 2 GiB` emits `DutyTx.ReleaseShares` (R-34)
 * - Graceful leave: releases all custody shares and initiates stake unbonding (V-1)
 */
object MobileConstants {
    const val TESTNET_CHAIN_ID: Long = 45_261L
    const val GIB_BYTES: Long = 1_073_741_824L
    const val QUOTA_MIN_BYTES: Long = 1L * GIB_BYTES
    const val QUOTA_DEFAULT_BYTES: Long = 4L * GIB_BYTES
    const val QUOTA_MAX_BYTES: Long = 64L * GIB_BYTES
    const val FREE_SPACE_FLOOR_BYTES: Long = 2L * GIB_BYTES
    const val MOBILE_MIN_STAKE_BUD: Long = 10L
    const val FAUCET_DRIP_BUD: Long = 100L
    const val WORKMANAGER_PERIOD_MINUTES: Long = 15L
    const val THERMAL_STATUS_MODERATE: Int = 2
}

enum class ValidatorClass(val tag: Byte) {
    Full(0),
    Mobile(1),
    MobileOpportunistic(2),
}

sealed interface NetworkPolicy {
    object UnmeteredOnly : NetworkPolicy {
        override fun toString(): String = "UnmeteredOnly"
    }

    data class Metered(val dailyCapMb: Int) : NetworkPolicy {
        init {
            require(dailyCapMb > 0) { "dailyCapMb must be positive" }
        }
    }
}

enum class PowerPolicy {
    ChargingOrBatteryAbove50,
    ChargingOnly,
}

data class Policy(
    val network: NetworkPolicy = NetworkPolicy.UnmeteredOnly,
    val power: PowerPolicy = PowerPolicy.ChargingOrBatteryAbove50,
    val thermalPause: Boolean = true,
    val quotaBytes: Long = MobileConstants.QUOTA_DEFAULT_BYTES,
    val serveSymbols: Boolean = true,
) {
    fun validate() {
        if (!thermalPause) {
            throw IllegalArgumentException("mobile_thermal_pause_locked: thermal pause cannot be disabled")
        }
        if (quotaBytes < MobileConstants.QUOTA_MIN_BYTES || quotaBytes > MobileConstants.QUOTA_MAX_BYTES) {
            throw IllegalArgumentException("mobile_quota_out_of_range: mobile quota must be 1 GiB to 64 GiB")
        }
    }

    fun withThermalPause(enabled: Boolean): Policy {
        if (!enabled) {
            throw IllegalArgumentException("mobile_thermal_pause_locked: thermal pause cannot be disabled")
        }
        return copy(thermalPause = true)
    }

    /** Storage reward multiplier in basis points (halved when symbol serving is off, Section 7.9.4). */
    fun symbolRewardWeightBps(): Int = if (serveSymbols) 10_000 else 5_000
}

enum class LastAudit {
    None,
    Passed,
    Missed,
}

data class RelayOffer(
    val multiaddr: String,
    val capacityKbps: Long,
)

sealed interface Connection {
    object Down : Connection {
        override fun toString(): String = "Down"
    }

    data class Relay(val offer: RelayOffer) : Connection
}

data class CoreStatus(
    val running: Boolean,
    val registered: Boolean,
    val pausedForThermal: Boolean,
    val storedBytes: Long,
    val quotaBytes: Long,
    val stakedBud: Long,
    val liquidBud: Long,
    val pendingRewardsAttos: Long,
    val lastAudit: LastAudit,
    val connection: Connection,
)

data class AssignedShare(
    val segmentIdHex: String,
    val esi: Int,
    val symbolBytes: ByteArray,
)

data class StorageAudit(
    val segmentIdHex: String,
    val challengeNonce: Long,
)

sealed interface DutyTx {
    data class CustodyAck(val segmentIdHex: String, val esi: Int) : DutyTx
    data class CustodyProofBatch(val segmentIdHex: String, val digestHex: String) : DutyTx
    data class Presence(val window: Long, val validatorClass: ValidatorClass, val preimageHex: String) : DutyTx
    data class Resume(val epoch: Long) : DutyTx
    data class ReleaseShares(val segments: List<String>) : DutyTx
    data class RegisterValidator(val stakeBud: Long, val operatorPubKeyHex: String) : DutyTx
    data class RotateOperatorKey(val newOperatorPubKeyHex: String) : DutyTx
    data class UnbondValidator(val stakeBud: Long) : DutyTx
}

/**
 * Manages `noBackupFilesDir/bud3/` segment share files (Section 7.9.5).
 */
class ShareCustodyDirectory(
    private val rootDir: File,
    private val freeSpaceProvider: () -> Long = { rootDir.usableSpace },
) {
    private data class StoredShareFile(val id: String, val file: File, val size: Long)

    // ESI metadata is process-local. After a process restart an audit fails
    // closed instead of guessing it; release can still use the filename.
    private val shareEsis = mutableMapOf<String, Int>()

    init {
        // Preserve first-run host-space measurement and the original app-private
        // directory behavior. Admission still verifies any creation failure.
        if (!rootDir.exists()) {
            rootDir.mkdirs()
        }
    }

    private fun validSegmentId(id: String): Boolean =
        id.isNotEmpty() && id.length % 2 == 0 && id.all { it.isDigit() || it in 'a'..'f' }

    private fun snapshot(): List<StoredShareFile>? {
        if (!rootDir.exists()) return emptyList()
        if (!rootDir.isDirectory) return null
        val files = rootDir.listFiles() ?: return null
        val result = mutableListOf<StoredShareFile>()
        for (file in files) {
            if (!Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS) ||
                !validSegmentId(file.name)
            ) {
                return null
            }
            result.add(StoredShareFile(file.name, file, file.length()))
        }
        return result.sortedBy { it.id }
    }

    private fun totalBytes(files: List<StoredShareFile>): Long? {
        var total = 0L
        for (file in files) {
            if (file.size > Long.MAX_VALUE - total) return null
            total += file.size
        }
        return total
    }

    /** A listing or arithmetic failure never understates occupied space. */
    fun storedBytes(): Long = synchronized(STORE_LOCK) {
        val files = snapshot() ?: return@synchronized Long.MAX_VALUE
        totalBytes(files) ?: Long.MAX_VALUE
    }

    fun segmentIds(): List<String> = synchronized(STORE_LOCK) {
        snapshot()?.map { it.id } ?: emptyList()
    }

    fun getShare(segmentIdHex: String): AssignedShare? = synchronized(STORE_LOCK) {
        if (!validSegmentId(segmentIdHex)) return@synchronized null
        val esi = shareEsis[segmentIdHex] ?: return@synchronized null
        val stored = snapshot()?.firstOrNull { it.id == segmentIdHex } ?: return@synchronized null
        val bytes = try {
            stored.file.readBytes()
        } catch (_: Exception) {
            return@synchronized null
        }
        if (bytes.size.toLong() != stored.size) return@synchronized null
        AssignedShare(segmentIdHex, esi, bytes)
    }

    /**
     * Publish a complete share without replacing an existing name. Duplicate
     * names, dangling links, quota/free-floor crossings and partial writes fail.
     * This is an interim local store, not a durable chain release protocol.
     */
    fun putShare(share: AssignedShare, quotaBytes: Long): Unit = synchronized(STORE_LOCK) {
        require(validSegmentId(share.segmentIdHex)) {
            "segmentIdHex must be non-empty lowercase hex with whole bytes"
        }
        val target = File(rootDir, share.segmentIdHex)
        if (Files.exists(target.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            throw IllegalStateException("mobile_share_already_stored: segment id is already occupied")
        }
        val files = snapshot()
            ?: throw IllegalStateException("mobile_store_unavailable: custody directory cannot be read safely")
        val used = totalBytes(files)
            ?: throw IllegalStateException("mobile_quota_exceeded: stored-byte accounting overflow")
        val size = share.symbolBytes.size.toLong()
        if (quotaBytes < 0L || used > quotaBytes || size > quotaBytes - used) {
            throw IllegalStateException("mobile_quota_exceeded: incoming share exceeds custody quota")
        }
        val free = freeSpaceProvider()
        if (free < MobileConstants.FREE_SPACE_FLOOR_BYTES ||
            size > free - MobileConstants.FREE_SPACE_FLOOR_BYTES
        ) {
            throw IllegalStateException("mobile_free_space_floor: incoming share crosses 2 GiB free-space floor")
        }
        if (!rootDir.isDirectory && !rootDir.mkdirs()) {
            throw IllegalStateException("mobile_store_unavailable: custody directory cannot be created")
        }

        val temporary = File.createTempFile(".share-", ".tmp", rootDir)
        try {
            FileOutputStream(temporary).use { output ->
                output.write(share.symbolBytes)
                output.fd.sync()
            }
            try {
                // Same-filesystem atomic no-replace publication. EEXIST cannot
                // overwrite a share or follow a dangling link planted concurrently.
                Files.createLink(target.toPath(), temporary.toPath())
            } catch (error: FileAlreadyExistsException) {
                throw IllegalStateException("mobile_share_already_stored: segment id is already occupied", error)
            }
            shareEsis[share.segmentIdHex] = share.esi
        } finally {
            temporary.delete()
        }
    }

    /** Delete oldest recognized shares until quota is met; never delete unknown files. */
    fun trimToQuota(newQuotaBytes: Long): List<String> = synchronized(STORE_LOCK) {
        require(newQuotaBytes >= 0L) { "quota must not be negative" }
        val files = snapshot() ?: return@synchronized emptyList()
        var total = totalBytes(files) ?: return@synchronized emptyList()
        val released = mutableListOf<String>()
        val candidates = files.sortedWith(compareBy<StoredShareFile> { it.file.lastModified() }.thenBy { it.id })
        for (stored in candidates) {
            if (total <= newQuotaBytes) break
            if (stored.file.delete()) {
                total -= stored.size
                shareEsis.remove(stored.id)
                released.add(stored.id)
            }
        }
        released
    }

    /** Local deletion only; no chain acknowledgement is implied. */
    fun releaseAll(): List<String> = synchronized(STORE_LOCK) {
        val files = snapshot() ?: return@synchronized emptyList()
        val released = mutableListOf<String>()
        for (stored in files) {
            if (stored.file.delete()) {
                shareEsis.remove(stored.id)
                released.add(stored.id)
            }
        }
        released
    }

    companion object {
        // All store instances in this process make admission/deletion decisions
        // against the same directory snapshot.
        private val STORE_LOCK = Any()
    }
}

/**
 * Deterministic Kotlin state machine mirroring `budlum-mobile-core` UniFFI entry points.
 */
class MobileValidatorEngine(
    private val ownerAddressHex: String,
    private val keyVault: KeystoreKeyVault,
    private val custodyDir: ShareCustodyDirectory,
    relays: List<RelayOffer>,
    initialAvailableBytes: Long,
) {
    private var policy: Policy = Policy()
    private val relayOffers: List<RelayOffer> = relays.toList()
    private var availableBytes: Long = initialAvailableBytes
    private var running: Boolean = false
    private var pausedForThermal: Boolean = false
    private var registered: Boolean = false
    private var unbonding: Boolean = false
    private var liquidBud: Long = 0L
    private var stakedBud: Long = 0L
    private var pendingRewardsAttos: Long = 0L
    private var lastAudit: LastAudit = LastAudit.None
    private val outbox = mutableListOf<DutyTx>()

    fun currentPolicy(): Policy = policy

    fun setPolicy(next: Policy): List<DutyTx> {
        next.validate()
        val emitted = mutableListOf<DutyTx>()
        val trimmed = if (next.quotaBytes < custodyDir.storedBytes()) {
            custodyDir.trimToQuota(next.quotaBytes)
        } else {
            emptyList()
        }
        check(custodyDir.storedBytes() <= next.quotaBytes) {
            "mobile_quota_release_incomplete: local shares still exceed the requested quota"
        }
        if (trimmed.isNotEmpty()) {
            val tx = DutyTx.ReleaseShares(trimmed)
            outbox.add(tx)
            emitted.add(tx)
        }
        policy = next
        return emitted
    }

    fun requestTestnetFaucet(powNonce: Long): Long {
        require(powNonce >= 0L) { "invalid PoW nonce" }
        liquidBud += MobileConstants.FAUCET_DRIP_BUD
        return liquidBud
    }

    fun registerValidator(biometricAuthToken: String, operatorPubKeyHex: String): DutyTx.RegisterValidator {
        keyVault.requireOwnerSpendAuthorization(biometricAuthToken)
        if (liquidBud < MobileConstants.MOBILE_MIN_STAKE_BUD) {
            throw IllegalStateException("insufficient BUD for 10 BUD mobile validator stake")
        }
        liquidBud -= MobileConstants.MOBILE_MIN_STAKE_BUD
        stakedBud += MobileConstants.MOBILE_MIN_STAKE_BUD
        registered = true
        unbonding = false
        val tx = DutyTx.RegisterValidator(MobileConstants.MOBILE_MIN_STAKE_BUD, operatorPubKeyHex)
        outbox.add(tx)
        return tx
    }

    fun rotateOperatorKey(biometricAuthToken: String, newOperatorPubKeyHex: String): DutyTx.RotateOperatorKey {
        keyVault.requireOwnerSpendAuthorization(biometricAuthToken)
        require(registered) { "validator must be registered to rotate operator key" }
        val tx = DutyTx.RotateOperatorKey(newOperatorPubKeyHex)
        outbox.add(tx)
        return tx
    }

    fun startForegroundFromUi(isAppInForeground: Boolean) {
        if (!isAppInForeground) {
            throw IllegalStateException("specialUse foreground service may only start while app is visible")
        }
        require(registered && !unbonding) { "validator must be registered before starting duty" }
        running = true
    }

    fun stopForeground() {
        running = false
    }

    fun onThermalStatusChanged(thermalStatus: Int) {
        pausedForThermal = thermalStatus >= MobileConstants.THERMAL_STATUS_MODERATE
    }

    fun updateAvailableDiskBytes(freeBytes: Long): DutyTx.ReleaseShares? {
        availableBytes = freeBytes
        if (availableBytes < MobileConstants.FREE_SPACE_FLOOR_BYTES) {
            val dropped = custodyDir.releaseAll()
            if (dropped.isNotEmpty()) {
                val tx = DutyTx.ReleaseShares(dropped)
                outbox.add(tx)
                return tx
            }
        }
        return null
    }

    fun acceptShare(share: AssignedShare): DutyTx.CustodyAck {
        updateAvailableDiskBytes(availableBytes)?.let {
            throw IllegalStateException("mobile_free_space_floor: released shares below 2 GiB free space")
        }
        if (availableBytes < MobileConstants.FREE_SPACE_FLOOR_BYTES) {
            throw IllegalStateException("mobile_free_space_floor: free space below 2 GiB")
        }
        if (pausedForThermal) {
            throw IllegalStateException("mobile_thermal_paused: custody intake paused under thermal load")
        }
        val incoming = share.symbolBytes.size.toLong()
        if (incoming > availableBytes - MobileConstants.FREE_SPACE_FLOOR_BYTES) {
            throw IllegalStateException("mobile_free_space_floor: incoming share crosses 2 GiB free-space floor")
        }
        custodyDir.putShare(share, policy.quotaBytes)
        availableBytes -= incoming
        val ack = DutyTx.CustodyAck(share.segmentIdHex, share.esi)
        outbox.add(ack)
        return ack
    }

    fun answerAudit(audit: StorageAudit): DutyTx.CustodyProofBatch {
        val share = custodyDir.getShare(audit.segmentIdHex)
        if (share == null) {
            lastAudit = LastAudit.Missed
            throw IllegalStateException("missing share for segment ${audit.segmentIdHex}")
        }
        val md = MessageDigest.getInstance("SHA-256")
        md.update("BDLM_MOBILE_AUDIT_V1".toByteArray(Charsets.UTF_8))
        md.update(share.symbolBytes)
        md.update(audit.challengeNonce.toString().toByteArray(Charsets.UTF_8))
        val digestHex = md.digest().joinToString("") { "%02x".format(it) }
        lastAudit = LastAudit.Passed
        pendingRewardsAttos += 1_000_000L * policy.symbolRewardWeightBps() / 10_000L
        val tx = DutyTx.CustodyProofBatch(audit.segmentIdHex, digestHex)
        outbox.add(tx)
        return tx
    }

    /**
     * Executed by the 15-minute unmetered `WorkManager` job when `ValidatorService` is stopped.
     */
    fun runWorkManagerPeriodicTick(
        window: Long,
        isUnmeteredWifi: Boolean,
        pendingAudits: List<StorageAudit>,
        mobileUsedMbToday: Long? = null,
        incomingShares: List<AssignedShare>,
    ): List<DutyTx> {
        if (!registered || unbonding || pausedForThermal) {
            return emptyList()
        }
        when (val network = policy.network) {
            NetworkPolicy.UnmeteredOnly -> if (!isUnmeteredWifi) return emptyList()
            is NetworkPolicy.Metered -> if (!isUnmeteredWifi) {
                val used = mobileUsedMbToday ?: return emptyList()
                if (used < 0L || used >= network.dailyCapMb) return emptyList()
            }
        }
        val produced = mutableListOf<DutyTx>()
        for (share in incomingShares) {
            val stored = custodyDir.storedBytes()
            val size = share.symbolBytes.size.toLong()
            if (availableBytes >= MobileConstants.FREE_SPACE_FLOOR_BYTES &&
                stored <= policy.quotaBytes && size <= policy.quotaBytes - stored
            ) {
                produced.add(acceptShare(share))
            }
        }
        for (audit in pendingAudits) {
            produced.add(answerAudit(audit))
        }
        val md = MessageDigest.getInstance("SHA-256")
        md.update("BDLM_PRESENCE_V1".toByteArray(Charsets.UTF_8))
        md.update(MobileConstants.TESTNET_CHAIN_ID.toString().toByteArray(Charsets.UTF_8))
        md.update(window.toString().toByteArray(Charsets.UTF_8))
        md.update(byteArrayOf(ValidatorClass.Mobile.tag))
        val preimageHex = md.digest().joinToString("") { "%02x".format(it) }
        val presence = DutyTx.Presence(window, ValidatorClass.Mobile, preimageHex)
        outbox.add(presence)
        produced.add(presence)
        return produced
    }

    fun leave(biometricAuthToken: String): List<DutyTx> {
        keyVault.requireOwnerSpendAuthorization(biometricAuthToken)
        running = false
        registered = false
        unbonding = true
        val emitted = mutableListOf<DutyTx>()
        val released = custodyDir.releaseAll()
        if (released.isNotEmpty()) {
            val releaseTx = DutyTx.ReleaseShares(released)
            outbox.add(releaseTx)
            emitted.add(releaseTx)
        }
        val stakeToUnbond = stakedBud
        stakedBud = 0L
        val unbondTx = DutyTx.UnbondValidator(stakeToUnbond)
        outbox.add(unbondTx)
        emitted.add(unbondTx)
        return emitted
    }

    fun status(): CoreStatus {
        val conn = if ((running || registered) && relayOffers.isNotEmpty()) {
            Connection.Relay(relayOffers.first())
        } else {
            Connection.Down
        }
        return CoreStatus(
            running = running,
            registered = registered,
            pausedForThermal = pausedForThermal,
            storedBytes = custodyDir.storedBytes(),
            quotaBytes = policy.quotaBytes,
            stakedBud = stakedBud,
            liquidBud = liquidBud,
            pendingRewardsAttos = pendingRewardsAttos,
            lastAudit = lastAudit,
            connection = conn,
        )
    }

    fun drainOutbox(): List<DutyTx> {
        val copy = outbox.toList()
        outbox.clear()
        return copy
    }
}
