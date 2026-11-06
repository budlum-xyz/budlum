package xyz.budlum.validator

import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp

/**
 * Jetpack Compose UI for onboarding, faucet PoW request, registration disclosure,
 * active validator dashboard, OEM battery guide, security tradeoff note, and
 * graceful `Leave` (`ReleaseShares` + unbond; Section 7.9.9 & 7.9.11).
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    ValidatorDashboardScreen(
                        manufacturer = Build.MANUFACTURER ?: "Generic",
                        onStartForegroundValidator = {
                            startForegroundService(Intent(this, ValidatorService::class.java))
                        },
                        onLeaveValidator = {
                            CustodyShareStore(
                                noBackupFilesDir,
                                ValidatorPolicy.DEFAULT_QUOTA_BYTES,
                            ).releaseAllForLeave()
                            stopService(Intent(this, ValidatorService::class.java))
                        },
                    )
                }
            }
        }
    }
}

@Composable
fun ValidatorDashboardScreen(
    manufacturer: String,
    onStartForegroundValidator: () -> Unit,
    onLeaveValidator: () -> Unit,
) {
    var registered by remember { mutableStateOf(false) }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.app_name),
            style = MaterialTheme.typography.headlineSmall,
        )
        Text(text = stringResource(R.string.disclosure_custody_notice))
        Text(text = stringResource(R.string.validator_unavailable))
        Text(text = stringResource(R.string.security_keystore_tradeoff))
        Text(text = "OEM Battery Guide ($manufacturer): Settings > Apps > Budlum Validator > Battery > Unrestricted")

        if (!registered) {
            Button(enabled = false, onClick = {
                registered = true
                onStartForegroundValidator()
            }) {
                Text(text = stringResource(R.string.action_register_validator))
            }
        } else {
            Text(text = stringResource(R.string.status_registered_active))
            Button(enabled = false, onClick = {
                registered = false
                onLeaveValidator()
            }) {
                Text(text = stringResource(R.string.action_leave_validator))
            }
        }
    }
}
