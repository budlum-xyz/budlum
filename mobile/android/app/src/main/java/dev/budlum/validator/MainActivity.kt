package dev.budlum.validator

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable

/**
 * Entry activity. The full onboarding/dashboard UI (directive 7.9.9) lands with
 * the mobile-core binding; 1/N ships the scaffold, policy engine, key wrapping,
 * storage, service and background work.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { App() }
    }
}

@Composable
fun App() {
    MaterialTheme {
        Text(text = "Budlum validator")
    }
}
