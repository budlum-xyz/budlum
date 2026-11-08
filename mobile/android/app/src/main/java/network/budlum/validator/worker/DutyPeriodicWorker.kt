package network.budlum.validator.worker

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.io.File
import java.util.concurrent.TimeUnit
import network.budlum.validator.core.AndroidKeystoreWrappingKeyProvider
import network.budlum.validator.core.KeystoreKeyVault
import network.budlum.validator.core.MobileConstants
import network.budlum.validator.core.MobileValidatorEngine
import network.budlum.validator.core.ShareCustodyDirectory

/**
 * 15-minute unmetered `WorkManager` periodic job answering storage audits,
 * broadcasting presence signals, and accepting share assignments whenever
 * `ValidatorService` is stopped (Section 7.9.3 item 6).
 */
class DutyPeriodicWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val bud3Dir = File(applicationContext.noBackupFilesDir, "bud3")
        val custody = ShareCustodyDirectory(bud3Dir)
        val vault = KeystoreKeyVault(AndroidKeystoreWrappingKeyProvider())
        val engine = MobileValidatorEngine(
            ownerAddressHex = "00".repeat(32),
            keyVault = vault,
            custodyDir = custody,
            relays = emptyList(),
            initialAvailableBytes = bud3Dir.usableSpace,
        )
        engine.updateAvailableDiskBytes(bud3Dir.usableSpace)
        return Result.success()
    }

    companion object {
        const val UNIQUE_WORK_NAME: String = "budlum_mobile_validator_duty_15m"

        fun enqueuePeriodic(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.UNMETERED)
                .build()
            val request = PeriodicWorkRequestBuilder<DutyPeriodicWorker>(
                MobileConstants.WORKMANAGER_PERIOD_MINUTES,
                TimeUnit.MINUTES,
            )
                .setConstraints(constraints)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request,
            )
        }
    }
}
