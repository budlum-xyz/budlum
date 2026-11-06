package dev.budlum.validator

import android.app.Application
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import dev.budlum.validator.work.AuditWorker
import java.util.concurrent.TimeUnit

/**
 * Application entry point.
 *
 * Periodic work is scheduled every 15 minutes with an unmetered network
 * constraint and survives reboots. Until the mobile-core binding exists, it
 * evaluates policy only; it does not answer audits or perform network duties.
 */
class BudlumApp : Application() {

    override fun onCreate() {
        super.onCreate()
        enqueueAuditWork()
    }

    fun enqueueAuditWork() {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.UNMETERED)
            .build()
        val request = PeriodicWorkRequestBuilder<AuditWorker>(15, TimeUnit.MINUTES)
            .setConstraints(constraints)
            .build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            AuditWorker.WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            request
        )
    }
}
