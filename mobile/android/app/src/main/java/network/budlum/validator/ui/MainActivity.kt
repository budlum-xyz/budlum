package network.budlum.validator.ui

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Alignment
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.runtime.LaunchedEffect
import androidx.core.view.WindowCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import network.budlum.validator.garden.GardenHolder
import network.budlum.validator.garden.Skin
import network.budlum.validator.R
import network.budlum.validator.core.AccountBalanceResult
import network.budlum.validator.core.FaucetResult
import network.budlum.validator.core.TestnetAccountReader
import network.budlum.validator.core.TestnetFaucetClient

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        val savedSkin = Skin.fromName(
            getSharedPreferences("budlum_garden_ui", Context.MODE_PRIVATE)
                .getString("skin", null),
        )
        setContent {
            LaunchedEffect(savedSkin) {
                val controller = WindowCompat.getInsetsController(window, window.decorView)
                controller.isAppearanceLightStatusBars = !savedSkin.isDark
                controller.isAppearanceLightNavigationBars = !savedSkin.isDark
            }
            // The same surface and skin as the Garden, so one app does not look
            // like two, and a plain way back to the choice that led here.
            network.budlum.validator.garden.GardenTheme(skin = savedSkin) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = savedSkin.behind,
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .statusBarsPadding()
                            .navigationBarsPadding()
                            .imePadding(),
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 8.dp, vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            TextButton(onClick = { finish() }) {
                                Text(stringResource(R.string.g_back))
                            }
                            Text(
                                stringResource(R.string.g_testnet),
                                style = MaterialTheme.typography.labelSmall,
                                color = savedSkin.ink,
                            )
                        }
                        ValidatorDashboardScreen(skin = savedSkin)
                    }
                }
            }
        }
    }
}

@Composable
fun ValidatorDashboardScreen(
    client: TestnetFaucetClient = remember { TestnetFaucetClient() },
    accountReader: TestnetAccountReader = remember { TestnetAccountReader() },
    skin: Skin = Skin.Page,
) {
    val scope = rememberCoroutineScope()
    var endpoint by rememberSaveable { mutableStateOf("") }
    var rpcEndpoint by rememberSaveable { mutableStateOf("") }
    // The faucet has one destination and the phone already knows it: this
    // phone's own wallet. A validator drawing its own faucet is the whole
    // flow, so there is nothing to type and nothing to get wrong here.
    var address by rememberSaveable { mutableStateOf("") }
    val context = LocalContext.current
    LaunchedEffect(Unit) {
        if (address.isEmpty()) {
            val mine = withContext(Dispatchers.IO) {
                runCatching {
                    val phone = GardenHolder.phone(context)
                    if (phone.walletExists()) phone.walletAddress() else ""
                }.getOrDefault("")
            }
            if (mine.isNotEmpty()) {
                address = mine
            }
        }
    }
    var pending by remember { mutableStateOf(false) }
    var balancePending by remember { mutableStateOf(false) }
    var outcome by remember { mutableStateOf<FaucetResult?>(null) }
    var balanceResult by remember { mutableStateOf<AccountBalanceResult?>(null) }
    val busy = pending || balancePending
    val validEndpoint = TestnetFaucetClient.requestUrl(endpoint) != null
    val validRpcEndpoint = TestnetAccountReader.rpcUrl(rpcEndpoint) != null
    val validAddress = TestnetFaucetClient.walletAddress(address) != null
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // The same wordmark that heads every sheet in the design file.
        network.budlum.validator.garden.Wordmark(
            skin = skin,
            modifier = Modifier.align(Alignment.CenterHorizontally),
        )
        OutlinedTextField(
            value = endpoint,
            onValueChange = { endpoint = it; outcome = null },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.faucet_endpoint)) },
            enabled = !busy,
            singleLine = true,
        )
        if (endpoint.isNotBlank() && !validEndpoint) Text(stringResource(R.string.faucet_invalid_endpoint))
        if (address.isNotEmpty()) {
            Text(stringResource(R.string.faucet_own_wallet, address))
        } else {
            Text(stringResource(R.string.faucet_no_wallet))
        }
        Button(
            enabled = !busy && validEndpoint && validAddress,
            onClick = {
                if (busy) return@Button
                pending = true
                outcome = null
                balanceResult = null
                val requestedEndpoint = endpoint
                val requestedAddress = address
                scope.launch {
                    try {
                        outcome = withContext(Dispatchers.IO) {
                            client.request(requestedEndpoint, requestedAddress)
                        }
                    } finally {
                        pending = false
                    }
                }
            },
        ) {
            Text(text = stringResource(R.string.action_faucet_request))
        }
        if (pending) Text(stringResource(R.string.faucet_pending))
        when (val result = outcome) {
            is FaucetResult.Submitted -> {
                Text(stringResource(R.string.faucet_submitted))
                Text(result.txHash)
            }
            FaucetResult.Failure.InvalidEndpoint -> Text(stringResource(R.string.faucet_invalid_endpoint))
            FaucetResult.Failure.InvalidAddress -> Text(stringResource(R.string.faucet_invalid_address))
            FaucetResult.Failure.InvalidChallenge -> Text(stringResource(R.string.faucet_invalid_challenge))
            FaucetResult.Failure.ProofTooHard -> Text(stringResource(R.string.faucet_proof_too_hard))
            FaucetResult.Failure.RateLimited -> Text(stringResource(R.string.faucet_rate_limited))
            FaucetResult.Failure.Unavailable -> Text(stringResource(R.string.faucet_unavailable))
            FaucetResult.Failure.Rejected -> Text(stringResource(R.string.faucet_rejected))
            FaucetResult.Failure.NetworkError -> Text(stringResource(R.string.faucet_network_error))
            FaucetResult.Failure.InvalidReceipt -> Text(stringResource(R.string.faucet_invalid_receipt))
            null -> Unit
        }

        OutlinedTextField(
            value = rpcEndpoint,
            onValueChange = { rpcEndpoint = it; balanceResult = null },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.balance_rpc_endpoint)) },
            enabled = !busy,
            singleLine = true,
        )
        if (rpcEndpoint.isNotBlank() && !validRpcEndpoint) Text(stringResource(R.string.faucet_invalid_endpoint))
        Button(
            enabled = !busy && validRpcEndpoint && validAddress,
            onClick = {
                if (busy) return@Button
                balancePending = true
                balanceResult = null
                val requestedEndpoint = rpcEndpoint
                val requestedAddress = address
                scope.launch {
                    try {
                        balanceResult = withContext(Dispatchers.IO) {
                            accountReader.read(requestedEndpoint, requestedAddress)
                        }
                    } finally {
                        balancePending = false
                    }
                }
            },
        ) { Text(stringResource(R.string.balance_refresh)) }
        if (balancePending) Text(stringResource(R.string.balance_pending))
        when (val result = balanceResult) {
            is AccountBalanceResult.RpcReported -> Text(
                stringResource(R.string.balance_reported, result.bud, result.atoms.toString(), result.address)
            )
            AccountBalanceResult.Failure.InvalidEndpoint -> Text(stringResource(R.string.faucet_invalid_endpoint))
            AccountBalanceResult.Failure.InvalidAddress -> Text(stringResource(R.string.faucet_invalid_address))
            AccountBalanceResult.Failure.WrongChain -> Text(stringResource(R.string.balance_wrong_chain))
            AccountBalanceResult.Failure.Unavailable -> Text(stringResource(R.string.balance_unavailable))
            AccountBalanceResult.Failure.InvalidResponse -> Text(stringResource(R.string.balance_invalid_response))
            AccountBalanceResult.Failure.NetworkError -> Text(stringResource(R.string.balance_network_error))
            null -> Unit
        }
    }
}
