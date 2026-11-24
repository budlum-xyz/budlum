package network.budlum.validator.garden

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.lifecycle.lifecycleScope

/**
 * The Garden app: three screens and nothing else (section 2.4).
 *
 * It also answers the invite link itself. Section 5.12 says an invite that
 * arrives by a deliberate act, which tapping a link is, joins directly, so
 * a `budlum://garden/join#...` link and the `http://<address>/g#...` a QR
 * carries both land here.
 */
class GardenActivity : ComponentActivity() {

    private lateinit var model: GardenModel

    private val scan = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val record = it.data?.getStringExtra(QrScanActivity.RESULT_TEXT)
        if (!record.isNullOrBlank()) {
            model.scanned(record)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        model = GardenModel(this, lifecycleScope)
        model.scanner = { scan.launch(Intent(this, QrScanActivity::class.java)) }
        // Section 4: the self test runs at first open, before the person is
        // offered anything to join.
        model.runSelfTest()
        handle(intent)
        setContent {
            MaterialTheme {
                Surface { GardenApp(model) }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    private fun handle(intent: Intent?) {
        val link = intent?.data?.toString() ?: return
        if (link.isNotBlank()) {
            model.preview(link)
        }
    }
}
