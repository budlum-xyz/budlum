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
 * Directive 7.9.3.6: while the foreground service is stopped, a WorkManager
 * periodic work answers audits, broadcasts presence and accepts new shares.
 * The interval is 15 minutes with an unmetered network constraint. WorkManager
 * work survives reboots, so it is (re-)enqueued here defensively.
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
