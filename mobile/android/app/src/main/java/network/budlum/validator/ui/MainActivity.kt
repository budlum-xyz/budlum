package network.budlum.validator.ui

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
import java.io.File
import network.budlum.validator.R
import network.budlum.validator.core.AndroidKeystoreWrappingKeyProvider
import network.budlum.validator.core.KeyPurpose
import network.budlum.validator.core.KeystoreKeyVault
import network.budlum.validator.core.MobileValidatorEngine
import network.budlum.validator.core.OemBatteryGuide
import network.budlum.validator.core.RelayOffer
import network.budlum.validator.core.ShareCustodyDirectory
import network.budlum.validator.worker.DutyPeriodicWorker

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DutyPeriodicWorker.enqueuePeriodic(this)
        val bud3Dir = File(noBackupFilesDir, "bud3")
        val vault = KeystoreKeyVault(AndroidKeystoreWrappingKeyProvider())
        val engine = MobileValidatorEngine(
            ownerAddressHex = "01".repeat(32),
            keyVault = vault,
            custodyDir = ShareCustodyDirectory(bud3Dir),
            relays = listOf(RelayOffer("/ip4/203.0.113.10/udp/4001/quic-v1", 16_000L)),
            initialAvailableBytes = bud3Dir.usableSpace,
        )
        val oemGuide = OemBatteryGuide.forManufacturer(Build.MANUFACTURER)

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    ValidatorDashboardScreen(engine = engine, vault = vault, oemSettingsPath = oemGuide.settingsPath)
                }
            }
        }
    }
}

@Composable
fun ValidatorDashboardScreen(
    engine: MobileValidatorEngine,
    vault: KeystoreKeyVault,
    oemSettingsPath: String,
) {
    var status by remember { mutableStateOf(engine.status()) }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(text = stringResource(R.string.app_name), style = MaterialTheme.typography.headlineSmall)
        Text(text = stringResource(R.string.onboarding_disclosure))
        Text(text = "Liquid: ${status.liquidBud} BUD | Staked: ${status.stakedBud} BUD")
        Text(text = "Stored: ${status.storedBytes} / ${status.quotaBytes} B | Audit: ${status.lastAudit}")
        Text(text = "Rewards: ${status.pendingRewardsAttos} uBUD")

        Button(onClick = {
            engine.requestTestnetFaucet(powNonce = 1L)
            status = engine.status()
        }) {
            Text(text = stringResource(R.string.action_faucet_request))
        }

        Button(onClick = {
            val opWrapped = vault.wrapKey(KeyPurpose.OperatorDutyMlDsa65, ByteArray(32) { 7 })
            val opHex = opWrapped.ciphertextWithTag.take(16).joinToString("") { "%02x".format(it) }
            engine.registerValidator("BIOMETRIC_VERIFIED_SESSION", opHex)
            engine.startForegroundFromUi(isAppInForeground = true)
            status = engine.status()
        }) {
            Text(text = stringResource(R.string.action_register_validator))
        }

        Button(onClick = {
            engine.rotateOperatorKey("BIOMETRIC_VERIFIED_SESSION", "aa".repeat(32))
            status = engine.status()
        }) {
            Text(text = stringResource(R.string.action_rotate_operator_key))
        }

        Button(onClick = {
            engine.leave("BIOMETRIC_VERIFIED_SESSION")
            status = engine.status()
        }) {
            Text(text = stringResource(R.string.action_leave_validator))
        }

        Text(text = stringResource(R.string.security_tradeoff_note))
        Text(text = "${stringResource(R.string.battery_guide_title)}: $oemSettingsPath")
    }
}
