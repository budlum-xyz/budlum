package network.budlum.validator.garden

import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.core.view.WindowCompat
import androidx.lifecycle.lifecycleScope

/**
 * The Budlum Garden host activity.
 *
 * Enables API 36 edge-to-edge layout with live light/dark system bar polarity,
 * protects recovery-word screens with FLAG_SECURE, routes `budlum://garden/...`
 * and `/g#...` deep links directly into Join, and inspects the clipboard
 * strictly for Garden invite prefixes on resume (section 5.9).
 */
class GardenActivity : ComponentActivity() {

    private lateinit var model: GardenModel

    private val scan = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val record = it.data?.getStringExtra(QrScanActivity.RESULT_TEXT)
        if (!record.isNullOrBlank()) {
            model.scanned(record)
        }
    }

    private val ask = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        model.readPermissions()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        model = GardenModel(this, lifecycleScope)
        model.scanner = { scan.launch(Intent(this, QrScanActivity::class.java)) }
        model.permissionAsker = { permission -> ask.launch(permission) }
        model.readPermissions()
        model.readWallet()
        model.runSelfTest()
        model.resumeIfSeated()
        handle(intent)
        setContent {
            val skin = model.skin
            LaunchedEffect(skin) {
                val controller = WindowCompat.getInsetsController(window, window.decorView)
                controller.isAppearanceLightStatusBars = !skin.isDark
                controller.isAppearanceLightNavigationBars = !skin.isDark
            }
            GardenTheme(skin = skin) {
                Surface(color = skin.behind) {
                    GardenApp(
                        model = model,
                        onSecureScreen = { secure -> setSecureWindow(secure) },
                        onTestnet = {
                            startActivity(
                                Intent(this, network.budlum.validator.ui.MainActivity::class.java),
                            )
                        },
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        model.readPermissions()
        inspectClipboardForInvite()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    private fun handle(intent: Intent?) {
        val link = intent?.data?.toString() ?: return
        if (link.isNotBlank()) {
            model.receiveInviteLink(link)
        }
    }

    /**
     * Section 5.9: inspect clipboard only for a Budlum Garden invite prefix.
     * Ordinary clipboard content is ignored immediately and never stored.
     */
    private fun inspectClipboardForInvite() {
        val manager = getSystemService(ClipboardManager::class.java) ?: return
        val clip = runCatching { manager.primaryClip }.getOrNull() ?: return
        if (clip.itemCount <= 0) return
        val text = runCatching { clip.getItemAt(0)?.coerceToText(this)?.toString() }.getOrNull()
        model.checkClipboardInvite(text)
    }

    private fun setSecureWindow(secure: Boolean) {
        if (secure) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}
