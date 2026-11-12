package network.budlum.validator.worker

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit
import network.budlum.validator.core.MobileConstants
import network.budlum.validator.core.ValidatorOnboardingGate

/**
 * No wallet signer, on-chain registration or network duty transport is wired
 * yet. Even if an older install left periodic work scheduled, it must fail
 * without creating/deleting custody files or claiming to answer an audit.
 */
class DutyPeriodicWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        if (!ValidatorOnboardingGate.readyForDuties()) return Result.failure()
        // Once all dependencies exist, replace this refusal with actual
        // registered-validator work and a verifiable duty submission result.
        return Result.failure()
    }

    companion object {
        const val UNIQUE_WORK_NAME: String = "budlum_mobile_validator_duty_15m"

        fun enqueuePeriodic(context: Context) {
            if (!ValidatorOnboardingGate.readyForDuties()) return
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
