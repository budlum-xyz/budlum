package network.budlum.validator.garden

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
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
import androidx.compose.runtime.Composable
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
 * Everything is asked for here, with the reason attached, and the person
 * can see at a glance what is still missing.
 */
@Composable
fun SetupScreen(model: GardenModel, onReady: () -> Unit) {
    val context = LocalContext.current
    val state = model.state
    val ready = state.readiness
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("BUDLUM GARDEN", style = MaterialTheme.typography.labelSmall)
        Text(
            "This phone becomes a validator.",
            style = MaterialTheme.typography.headlineSmall,
        )
        Text(
            "A Garden is a small chain that a group of phones runs together. " +
                "Yours will check every block, keep a share of what the group " +
                "stores, and answer for it - while the app is open and while it " +
                "is not. It needs two things from you before it can start.",
            style = MaterialTheme.typography.bodyMedium,
        )

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("1 - THIS PHONE CAN DO THE WORK", style = MaterialTheme.typography.labelSmall)
                if (state.selfTest.isEmpty()) {
                    Text("Checking...", style = MaterialTheme.typography.bodySmall)
                } else {
                    state.selfTest.forEach { step ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(step.name, style = MaterialTheme.typography.bodySmall)
                            Text(
                                if (step.passed) "ok" else "failed",
                                style = MaterialTheme.typography.bodySmall,
                                color = if (step.passed) {
                                    MaterialTheme.colorScheme.onSurface
                                } else {
                                    MaterialTheme.colorScheme.error
                                },
                            )
                        }
                    }
                    Text(
                        "Took ${state.selfTestMs} ms. Nothing here touches the network.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("2 - NOTIFICATIONS", style = MaterialTheme.typography.labelSmall)
                Text(
                    "The validator keeps running when you leave the app. Android " +
                        "only allows that if it can show you a notification saying " +
                        "so, and that notification is also how you see which block " +
                        "you are on. Without it the work has to stop.",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (ready.notifications) {
                    Text("Allowed.", style = MaterialTheme.typography.bodyMedium)
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
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("3 - BATTERY", style = MaterialTheme.typography.labelSmall)
                Text(
                    "Android puts background apps to sleep to save power. A " +
                        "sleeping validator is an absent one, and the Garden will " +
                        "eventually suspend its seat. This app is not allowed to " +
                        "ask for the exemption itself, so the choice is yours to " +
                        "make in settings.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(
                    if (ready.batteryUnrestricted) {
                        "Not restricted right now. Worth confirming on " +
                            ready.batteryFamily + "."
                    } else {
                        "This app is currently restricted in the background."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(ready.batteryPath, style = MaterialTheme.typography.bodySmall)
                OutlinedButton(
                    onClick = { context.startActivity(GardenReadiness.batterySettings(context)) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Open battery settings") }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("4 - CAMERA", style = MaterialTheme.typography.labelSmall)
                Text(
                    "Only for reading an invite QR code, and only asked for at " +
                        "the moment you tap scan. You can paste an invite instead " +
                        "and never grant it.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        Button(
            onClick = onReady,
            enabled = ready.canValidate && state.selfTest.all { it.passed } &&
                state.selfTest.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                if (ready.canValidate) "Continue" else "Allow notifications to continue",
            )
        }
        if (state.message.isNotEmpty()) {
            Text(state.message, style = MaterialTheme.typography.bodySmall)
        }
    }
}
