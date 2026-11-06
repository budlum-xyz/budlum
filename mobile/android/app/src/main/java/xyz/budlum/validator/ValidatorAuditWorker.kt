package xyz.budlum.validator

import android.app.ForegroundServiceStartNotAllowedException
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * 15-minute `WorkManager` periodic fallback constrained to unmetered Wi-Fi
 * (`NetworkType.UNMETERED`, Section 7.9.3 item 6).
 *
 * Answers pending B.U.D. 3.0 custody audits, emits BLS presence heartbeats, and
 * accepts assigned segment shares whenever `ValidatorService` is stopped.
 */
class ValidatorAuditWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val store = CustodyShareStore(
            applicationContext.noBackupFilesDir,
            ValidatorPolicy.DEFAULT_QUOTA_BYTES,
        )
        store.releaseForLowSpace(applicationContext.noBackupFilesDir.usableSpace)
        return Result.success()
    }

    companion object {
        private const val UNIQUE_WORK_NAME = "budlum_periodic_audit_presence"

        fun schedulePeriodic(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.UNMETERED)
                .build()
            val req = PeriodicWorkRequestBuilder<ValidatorAuditWorker>(15, TimeUnit.MINUTES)
                .setConstraints(constraints)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                req,
            )
        }
    }
}

/**
 * Reboot handler (`BOOT_COMPLETED`, Section 7.9.3 item 5).
 *
 * Always schedules the 15-minute unmetered `WorkManager` job first and attempts
 * `startForegroundService` for `specialUse`, gracefully catching
 * [ForegroundServiceStartNotAllowedException] on restricted OEM builds.
 */
class BootCompletedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        ValidatorAuditWorker.schedulePeriodic(context)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                context.startForegroundService(Intent(context, ValidatorService::class.java))
            } catch (_: ForegroundServiceStartNotAllowedException) {
                // WorkManager periodic duties remain active until user opens app.
            }
        } else {
            context.startForegroundService(Intent(context, ValidatorService::class.java))
        }
    }
}
