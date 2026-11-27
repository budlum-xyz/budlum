package network.budlum.validator.garden

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.remember
import network.budlum.validator.ui.MainActivity

/**
 * The entry point of the app: Garden only.
 *
 * The activity hosts the screens while the validator itself lives in
 * [GardenValidatorService], so closing the screen leaves the Garden
 * standing. A button on the welcome screen reaches the testnet custody
 * screens for operators who need them.
 */
class GardenActivity : ComponentActivity() {

    private var model: GardenModel? = null

    private val ask = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        model?.readPermissions()
    }

    private val scanLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            val scanned = result.data?.getStringExtra(QrScanActivity.RESULT_TEXT)
            if (!scanned.isNullOrBlank()) {
                model?.scanned(scanned)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val initialInvite = extractAllowedInvite(intent)
        setContent {
            val created = remember {
                val permission = GardenReadiness.notificationPermission()
                GardenModel(
                    app = application,
                    askNotifications = {
                        if (permission != null) {
                            ask.launch(permission)
                        } else {
                            model?.readPermissions()
                        }
                    },
                    openScanner = {
                        scanLauncher.launch(Intent(this@GardenActivity, QrScanActivity::class.java))
                    },
                ).also {
                    model = it
                    it.runSelfTest()
                    it.resumeIfSeated()
                    if (initialInvite != null) {
                        it.stageIncomingInvite(initialInvite)
                    }
                }
            }
            GardenTheme {
                GardenApp(
                    model = created,
                    onTestnet = {
                        startActivity(Intent(this, MainActivity::class.java))
                    },
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        model?.readPermissions()
        model?.onForeground()
    }

    override fun onStop() {
        super.onStop()
        model?.onBackground()
    }

    override fun onDestroy() {
        model?.shutdown()
        model = null
        super.onDestroy()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        extractAllowedInvite(intent)?.let { link ->
            model?.stageIncomingInvite(link)
        }
    }

    private fun extractAllowedInvite(intent: Intent?): String? {
        if (intent?.action != Intent.ACTION_VIEW) return null
        return GardenModel.extractAllowedInviteFromUri(intent.data)
    }
}
