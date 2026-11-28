package network.budlum.validator.garden

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/** Where in the app the person is. Nothing is a dead end. */
enum class Step {
    /** What this phone must be allowed to do before it validates anything. */
    Setup,

    /** Which network this validator serves. */
    Choose,

    /** The three Garden screens. */
    Garden,
}

/**
 * The choice the app is actually offering.
 *
 * Being a validator comes first and is one thing; which network that
 * validator serves is a second, separate thing. Before this the two were
 * tangled - the app opened on a Garden invite box, and the testnet lived
 * behind a second launcher icon that greeted people with a faucet. Now
 * the requirements are settled once, and then the person picks, and can
 * come back and pick the other as well.
 */
@Composable
fun ChooseScreen(
    model: GardenModel,
    onGarden: () -> Unit,
    onTestnet: () -> Unit,
    onBack: () -> Unit,
) {
    val state = model.state
    val seated = state.status.contains("\"chain_id\"")
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("THIS PHONE IS READY", style = MaterialTheme.typography.labelSmall)
        Text("Where do you want to validate?", style = MaterialTheme.typography.headlineSmall)
        Text(
            "The checks passed and Android is allowing the background work. " +
                "A validator serves a network; pick the one you want to serve. " +
                "You can do both, and you can change your mind later.",
            style = MaterialTheme.typography.bodyMedium,
        )

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("GARDEN", style = MaterialTheme.typography.labelSmall)
                Text(
                    "A small chain run by a group you know - a household, a " +
                        "room, a street. This phone checks every block and keeps " +
                        "a share of what the group stores. No account, no money, " +
                        "no internet needed beyond the network you are on.",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (seated) {
                    Text(
                        "This phone already holds a seat.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                Button(onClick = onGarden, modifier = Modifier.fillMaxWidth()) {
                    Text(if (seated) "Open my Garden" else "Validate a Garden")
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("TESTNET", style = MaterialTheme.typography.labelSmall)
                Text(
                    "The public Budlum test network. This is the one that has " +
                        "an account, a faucet and storage duties attached to it, " +
                        "which is why it is a choice and not the front door.",
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedButton(onClick = onTestnet, modifier = Modifier.fillMaxWidth()) {
                    Text("Validate the testnet")
                }
            }
        }

        TextButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text("Back to the requirements")
        }
        if (state.message.isNotEmpty()) {
            Text(state.message, style = MaterialTheme.typography.bodySmall)
        }
    }
}
