package network.budlum.validator.garden

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

/**
 * What this phone is about to become, and what it needs to do it.
 *
 * This is not a fourth screen of section 2.4: it is the way in to the
 * three. Before it existed the app opened on a box asking for the name of
 * a Garden, with nothing to say what a Garden was, whether the person was
 * meant to have one already, or why the phone would keep working after
 * the screen went dark. Then the permissions it never asked for turned
 * into warnings from the system.
 *
 * The shape is the design file's: one panel per requirement, an uppercase
 * label over each, a number on the left so the order is visible, and one
 * line of state under it instead of a paragraph of prose.
 */
@Composable
fun SetupScreen(model: GardenModel, onReady: () -> Unit) {
    val context = LocalContext.current
    val state = model.state
    val ready = state.readiness
    val checksDone = state.selfTest.isNotEmpty()
    val checksPassed = checksDone && state.selfTest.all { it.passed }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = GardenDesignTokens.gutter)
            .padding(bottom = GardenDesignTokens.gutter),
        verticalArrangement = Arrangement.spacedBy(GardenDesignTokens.gap),
    ) {
        GardenPanel(outlined = true) {
            GardenLabel("BUDLUM GARDEN")
            GardenHeading("This phone becomes a validator")
            GardenBody(
                "A Garden is a small chain that a group of phones runs together. " +
                    "Yours will check every block, keep a share of what the group " +
                    "stores, and answer for it while the app is open and while it is not.",
            )
            val passed = state.selfTest.count { it.passed }
            GardenMeta(
                listOf(
                    "checks " + passed + "/" + state.selfTest.size,
                    state.selfTestMs.toString() + " ms",
                    if (ready.canValidate) "android ready" else "android not ready",
                ),
            )
        }

        GardenPanel {
            Row(verticalAlignment = Alignment.CenterVertically) {
                GardenLabel("01")
                Spacer(modifier = Modifier.width(10.dp))
                GardenLabel("THIS PHONE CAN DO THE WORK", tone = GardenDesignTokens.ink)
            }
            if (state.selfTest.isEmpty()) {
                GardenCaption("Running...")
            } else {
                state.selfTest.forEach { step ->
                    GardenStat(step.name, if (step.passed) "ok" else "failed")
                }
                GardenCaption("Nothing here touches the network.")
            }
        }

        GardenPanel {
            Row(verticalAlignment = Alignment.CenterVertically) {
                GardenLabel("02")
                Spacer(modifier = Modifier.width(10.dp))
                GardenLabel("NOTIFICATIONS", tone = GardenDesignTokens.ink)
            }
            GardenBody(
                "The validator keeps running when you leave the app. Android only " +
                    "allows that with a notification that says so, and that " +
                    "notification is also how you see which block you are on.",
            )
            if (ready.notifications) {
                GardenStat("Allowed", "yes")
            } else {
                Button(
                    onClick = { model.askForNotifications() },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Allow notifications") }
                OutlinedButton(
                    onClick = {
                        context.startActivity(GardenReadiness.notificationSettings(context))
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Open notification settings") }
            }
        }

        GardenPanel {
            Row(verticalAlignment = Alignment.CenterVertically) {
                GardenLabel("03")
                Spacer(modifier = Modifier.width(10.dp))
                GardenLabel("BATTERY", tone = GardenDesignTokens.ink)
            }
            GardenBody(
                "Android puts background apps to sleep to save power. A sleeping " +
                    "validator is an absent one, and the Garden will eventually " +
                    "suspend its seat. This app may not ask for the exemption itself.",
            )
            GardenStat(
                "Background",
                if (ready.batteryUnrestricted) "not restricted" else "restricted",
            )
            if (ready.batteryPath.isNotBlank()) {
                GardenMeta(listOf(ready.batteryPath))
            }
            OutlinedButton(
                onClick = { context.startActivity(GardenReadiness.batterySettings(context)) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Open battery settings") }
        }

        GardenPanel {
            Row(verticalAlignment = Alignment.CenterVertically) {
                GardenLabel("04")
                Spacer(modifier = Modifier.width(10.dp))
                GardenLabel("CAMERA", tone = GardenDesignTokens.ink)
            }
            GardenBody(
                "Only for reading an invite QR code, and only at the moment you " +
                    "tap scan. An invite can be pasted instead, and the camera " +
                    "never has to be granted.",
            )
            GardenStat(
                "Camera",
                when {
                    ready.camera -> "allowed"
                    else -> "not asked yet"
                },
            )
        }

        // The gate says which of the things is missing rather than sitting
        // there greyed out. A disabled button with no reason on it is the
        // thing that made this screen feel broken.
        Button(
            onClick = onReady,
            enabled = checksPassed && ready.canValidate,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                when {
                    !checksDone -> "Running the checks..."
                    !checksPassed -> "This phone cannot validate"
                    !ready.notifications -> "Allow notifications to continue"
                    else -> "Continue"
                },
            )
        }
        if (checksPassed && !ready.notifications) {
            GardenMeta(
                listOf("the switch is also in notification settings above"),
            )
        }
        if (checksDone && !checksPassed) {
            GardenMeta(
                listOf("one of the checks failed; the failing line above says which"),
            )
        }
        if (state.message.isNotEmpty()) {
            GardenMeta(listOf(state.message))
        }
    }
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
    val seated = GardenSeat.seated(state.status)
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = GardenDesignTokens.gutter)
            .padding(bottom = GardenDesignTokens.gutter),
        verticalArrangement = Arrangement.spacedBy(GardenDesignTokens.gap),
    ) {
        Column(modifier = Modifier.padding(top = 4.dp)) {
            GardenLabel("THIS PHONE IS READY")
            Text(
                "Where do you want to validate?",
                style = MaterialTheme.typography.headlineSmall,
                color = GardenDesignTokens.ink,
            )
            GardenCaption(
                "A validator serves a network. You can do both, and change your mind later.",
            )
        }

        GardenPanel(outlined = true) {
            GardenLabel("GARDEN")
            GardenHeading(
                if (seated) "This phone already holds a seat" else "A small chain you run with others",
            )
            GardenBody(
                "A household, a room, a street. This phone checks every block and " +
                    "keeps a share of what the group stores. No account, no money, " +
                    "and no internet beyond the network you are on.",
            )
            Button(onClick = onGarden, modifier = Modifier.fillMaxWidth()) {
                Text(if (seated) "Open my Garden" else "Validate a Garden")
            }
        }

        GardenPanel {
            GardenLabel("TESTNET")
            GardenHeading("The public Budlum test network")
            GardenBody(
                "This is the one with an account, a faucet and storage duties " +
                    "attached to it, which is why it is a choice and not the front door.",
            )
            OutlinedButton(onClick = onTestnet, modifier = Modifier.fillMaxWidth()) {
                Text("Validate the testnet")
            }
        }

        Button(
            onClick = onBack,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Back to the requirements") }
        if (state.message.isNotEmpty()) {
            GardenMeta(listOf(state.message))
        }
    }
}
