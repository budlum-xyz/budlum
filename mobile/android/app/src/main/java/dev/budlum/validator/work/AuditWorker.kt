package dev.budlum.validator.work

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dev.budlum.validator.policy.AppPolicy
import dev.budlum.validator.policy.PolicyEngine
import dev.budlum.validator.policy.RunDecision

/**
 * Periodic policy evaluation with a 15-minute unmetered network constraint.
 * This scaffold does not answer audits, broadcast presence, or accept shares.
 * Those duties require the WP-11 mobile-core UniFFI binding (directive 7.9.3.6).
 * A successful worker run only means the policy decision was recorded; it is
 * not evidence of an audit or a connected validator.
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
