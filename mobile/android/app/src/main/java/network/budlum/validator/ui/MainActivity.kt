package network.budlum.validator.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import network.budlum.validator.R
import network.budlum.validator.core.AccountBalanceResult
import network.budlum.validator.core.FaucetResult
import network.budlum.validator.core.TestnetAccountReader
import network.budlum.validator.core.TestnetFaucetClient

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    ValidatorDashboardScreen()
                }
            }
        }
    }
}

@Composable
fun ValidatorDashboardScreen(
    client: TestnetFaucetClient = remember { TestnetFaucetClient() },
    accountReader: TestnetAccountReader = remember { TestnetAccountReader() },
) {
    val scope = rememberCoroutineScope()
    var endpoint by rememberSaveable { mutableStateOf("") }
    var rpcEndpoint by rememberSaveable { mutableStateOf("") }
    var address by rememberSaveable { mutableStateOf("") }
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
        Text(text = stringResource(R.string.app_name), style = MaterialTheme.typography.headlineSmall)
        Text(text = stringResource(R.string.onboarding_disclosure))
        Text(text = stringResource(R.string.validator_unavailable))
        Text(text = stringResource(R.string.faucet_explanation))
        OutlinedTextField(
            value = endpoint,
            onValueChange = { endpoint = it; outcome = null },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.faucet_endpoint)) },
            enabled = !busy,
            singleLine = true,
        )
        if (endpoint.isNotBlank() && !validEndpoint) Text(stringResource(R.string.faucet_invalid_endpoint))
        OutlinedTextField(
            value = address,
            onValueChange = { address = it; outcome = null; balanceResult = null },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.faucet_wallet_address)) },
            enabled = !busy,
            singleLine = true,
        )
        if (address.isNotBlank() && !validAddress) Text(stringResource(R.string.faucet_invalid_address))
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

        Text(stringResource(R.string.balance_explanation))
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
