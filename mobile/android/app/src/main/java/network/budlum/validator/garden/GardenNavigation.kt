package network.budlum.validator.garden

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import network.budlum.validator.R

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

    /**
     * Making this phone's wallet, or putting back one it already had.
     *
     * It sits after the validator checks because that is the order the
     * app asks for things: be a validator first, then hold a key. A
     * phone that cannot do the duties has no use for the key.
     */
    Wallet,

    /** The twenty-four words, shown once, before anything else happens. */
    Seed,
}

/**
 * The choice, as the sheets would put it: a few lowercase lines.
 *
 * This screen used to carry five paragraphs explaining what a network
 * is, what a token is not, and what the testnet is for. The design
 * file has a menu in its bottom left corner reading "a.o / market /
 * ecosystem / participation" - four words, no sentences - and that is
 * the voice this app is supposed to have. Someone who needs to know
 * what the thing is reads the one line that says it; everyone else
 * taps the line they came for.
 */
@Composable
fun ChooseScreen(
    model: GardenModel,
    onStartOwn: () -> Unit,
    onHaveInvite: () -> Unit,
    onTestnet: () -> Unit,
    onWallet: () -> Unit,
    onBack: () -> Unit,
) {
    val state = model.state
    val seated = state.status.contains("\"chain_id\"")
    CubeFloor(model.skin) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Label(stringResource(R.string.g_what_this_is))
            Text(
                stringResource(R.string.g_data_not_money),
                style = MaterialTheme.typography.bodySmall,
                color = Ink,
                modifier = Modifier.padding(bottom = 22.dp),
            )

            if (seated) {
                MenuLine(stringResource(R.string.g_my_network), onStartOwn)
            } else {
                MenuLine(stringResource(R.string.g_start_own), onStartOwn)
                MenuLine(stringResource(R.string.g_was_invited), onHaveInvite)
            }
            MenuLine(stringResource(R.string.w_wallet), onWallet)
            MenuLine(stringResource(R.string.g_testnet), onTestnet)
            MenuLine(stringResource(R.string.g_back), onBack)

            if (state.message.isNotEmpty()) {
                Label(state.message, color = Flow, modifier = Modifier.padding(top = 18.dp))
            }
        }
    }
}

/** One line of the menu: lowercase, no box, no shadow, just a word. */
@Composable
private fun MenuLine(text: String, onTap: () -> Unit) {
    Text(
        text = text.lowercase(),
        style = MaterialTheme.typography.bodyLarge,
        color = Ink,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onTap)
            .padding(vertical = 9.dp),
    )
}
