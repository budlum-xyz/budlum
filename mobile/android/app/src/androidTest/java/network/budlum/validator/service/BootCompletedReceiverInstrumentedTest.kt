package network.budlum.validator.service

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class BootCompletedReceiverInstrumentedTest {
    private class RecordingContext(base: Context) : ContextWrapper(base) {
        var serviceStarts = 0

        override fun startForegroundService(service: Intent): ComponentName? {
            serviceStarts++
            return null
        }

        override fun startService(service: Intent): ComponentName? {
            serviceStarts++
            return null
        }
    }

    @Test
    fun boot_receiver_does_not_start_a_service_from_background() {
        val context = RecordingContext(InstrumentationRegistry.getInstrumentation().targetContext)
        BootCompletedReceiver().onReceive(context, Intent(Intent.ACTION_BOOT_COMPLETED))
        assertEquals(0, context.serviceStarts)
    }

    @Test
    fun unrelated_broadcast_does_not_start_a_service() {
        val context = RecordingContext(InstrumentationRegistry.getInstrumentation().targetContext)
        BootCompletedReceiver().onReceive(context, Intent("network.budlum.validator.UNRELATED"))
        assertEquals(0, context.serviceStarts)
    }
}
