package dev.budlum.validator.work

import android.content.Context
import dev.budlum.validator.policy.RunDecision
import java.io.File

/**
 * Tiny append-only duty log in app-private storage. Crash-safe, plain file
 * (the embedded-DB selection is measured in WP-11; sled is never used).
 */
object DutyLog {
    private fun logFile(context: Context): File =
        File(context.noBackupFilesDir, "duty.log")

    @Synchronized
    fun record(context: Context, decision: RunDecision) {
        val line = "${System.currentTimeMillis()} $decision\n"
        logFile(context).appendText(line)
    }
}
