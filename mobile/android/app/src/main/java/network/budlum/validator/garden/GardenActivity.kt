package network.budlum.validator.garden

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
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

    // Android shows a permission prompt for an activity, never for a
    // model, so the activity owns the asking and the model owns the why.
    private val ask = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        model.readPermissions()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        model = GardenModel(this, lifecycleScope)
        model.scanner = { scan.launch(Intent(this, QrScanActivity::class.java)) }
        model.permissionAsker = { permission -> ask.launch(permission) }
        model.readPermissions()
        // Section 4: the self test runs at first open, before the person is
        // offered anything to join.
        model.runSelfTest()
        // A seat survives the process. If this phone is already in a
        // Garden, the validator goes back on the network as the app opens
        // rather than waiting to be asked.
        model.resumeIfSeated()
        handle(intent)
        setContent {
            GardenTheme {
                Surface {
                    GardenApp(model) {
                        // The testnet is the other duty a validator can
                        // take on, reached by choosing it rather than by
                        // being dropped into it.
                        startActivity(
                            Intent(this, network.budlum.validator.ui.MainActivity::class.java),
                        )
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // The person may have changed any of this in settings and walked
        // back, so what Android allows is read again rather than
        // remembered from the last time the app looked.
        model.readPermissions()
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
