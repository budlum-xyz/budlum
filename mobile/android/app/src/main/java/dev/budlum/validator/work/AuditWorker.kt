package dev.budlum.validator.work

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dev.budlum.validator.policy.AppPolicy
import dev.budlum.validator.policy.DeviceState
import dev.budlum.validator.policy.PolicyEngine
import dev.budlum.validator.policy.RunDecision

/**
 * Periodic background duty. Directive 7.9.3.6.
 *
 * Runs every 15 minutes with an unmetered network constraint while the
 * foreground service is stopped: answers storage audits, broadcasts presence
 * and accepts new share assignments.
 *
 * 1/N note: the actual network duty is bound to the Rust mobile core
 * (`budlum-mobile-core`, WP-11) through UniFFI in a later PR of this package.
 * Until the binding lands, this worker evaluates the policy and records the
 * decision, so the policy path itself is exercised on every run.
 */
class AuditWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val policy = AppPolicy()
        val state = currentDeviceState(applicationContext)
        val decision = PolicyEngine.decision(policy, state)
        DutyLog.record(applicationContext, decision)
        return when (decision) {
            RunDecision.RUN -> Result.success()
            RunDecision.PAUSED_THERMAL,
            RunDecision.PAUSED_NETWORK,
            RunDecision.PAUSED_POWER,
            -> Result.success() // paused by policy: not a failure
        }
    }

    companion object {
        const val WORK_NAME = "budlum_audit_work"
    }
}
