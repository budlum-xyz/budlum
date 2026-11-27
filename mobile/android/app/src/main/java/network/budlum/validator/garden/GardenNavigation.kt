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

    /** Starting a network, or taking an invite to one. */
    Garden,

    /** Taking an invite, reached straight from the choice. */
    Join,
}

/**
 * The choice the app is offering.
 *
 * Being a validator comes first and is one thing; which network that
 * validator serves is a second, separate thing.
 *
 * What a Garden is *not* needs saying on this screen, because every
 * other chain people have met works the other way: there is no token
 * here, no balance, no payment and nothing to buy. A Garden carries
 * data. Validators check blocks and hold a share of what the group
 * sends, and that is the whole of the arrangement.
 */
@Composable
fun ChooseScreen(
    model: GardenModel,
    onStartOwn: () -> Unit,
    onHaveInvite: () -> Unit,
    onTestnet: () -> Unit,
    onBack: () -> Unit,
) {
    val state = model.state
    val seated = state.hasSeat
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("THIS PHONE IS READY", style = MaterialTheme.typography.labelSmall)
        Text("What is this phone validating?", style = MaterialTheme.typography.headlineSmall)

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("YOUR OWN NETWORK", style = MaterialTheme.typography.labelSmall)
                Text(
                    "A network of your own, run by the phones you invite - a " +
                        "household, a room, a street. It carries data: you send " +
                        "something, it goes over the chain through B.U.D. 3.0, " +
                        "and anyone in the group can pull it back out verified.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    "There is no token, no balance and nothing to pay. Running " +
                        "your own network does not mean issuing money; it means " +
                        "the group carries its own data.",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (seated) {
                    Text(
                        "This phone is already in a network.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Button(onClick = onStartOwn, modifier = Modifier.fillMaxWidth()) {
                        Text("Open my network")
                    }
                } else {
                    Button(onClick = onStartOwn, modifier = Modifier.fillMaxWidth()) {
                        Text("Start my own network")
                    }
                    OutlinedButton(onClick = onHaveInvite, modifier = Modifier.fillMaxWidth()) {
                        Text("I was invited to one")
                    }
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
                    "The public Budlum test network, which is a different thing " +
                        "and not needed for your own. It is the one with an " +
                        "address and a faucet attached, and it is here only " +
                        "because a validator may also serve it.",
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedButton(onClick = onTestnet, modifier = Modifier.fillMaxWidth()) {
                    Text("Validate the testnet instead")
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
