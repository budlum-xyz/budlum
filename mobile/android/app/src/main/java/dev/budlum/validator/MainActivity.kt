package dev.budlum.validator

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable

/**
 * Entry activity. The full onboarding/dashboard UI (directive 7.9.9) lands with
 * the mobile-core binding; 1/N ships the scaffold, policy engine, key wrapping,
 * storage, service and background work.
 */
class MainActivity : ComponentActivity() {

    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* the
            service keeps running either way; without the permission only the
            drawer notification is hidden (directive 7.9.3.7) */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // API 33+ hides notifications until POST_NOTIFICATIONS is granted. The
        // foreground service still runs, but the persistent status the card
        // requires (stored bytes, last audit, connection) would be invisible.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        setContent { App() }
    }
}

@Composable
fun App() {
    MaterialTheme {
        Text(text = "Budlum validator")
    }
}
