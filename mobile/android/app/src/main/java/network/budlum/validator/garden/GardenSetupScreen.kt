package network.budlum.validator.garden

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import network.budlum.validator.R

/**
 * What this phone has to be allowed to do before it validates anything.
 *
 * The old version of this screen explained all of it in four paragraphs
 * of prose - what a Garden is, why Android sleeps background apps, what
 * the camera is for. A person opening an app for the first time does
 * not read that. Each requirement is now one row: what it is, where it
 * stands, and the way to fix it if it does not stand.
 */
@Composable
fun SetupScreen(model: GardenModel, onReady: () -> Unit) {
    val context = LocalContext.current
    val state = model.state
    val ready = state.readiness
    val checksDone = state.selfTest.isNotEmpty()
    val checksPassed = checksDone && state.selfTest.all { it.passed }

    CubeFloor(model.skin) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Label(stringResource(R.string.g_what_this_is))
            Text(
                stringResource(R.string.g_becomes_validator),
                style = MaterialTheme.typography.bodySmall,
                color = Ink,
                modifier = Modifier.padding(bottom = 20.dp),
            )

            Slab(modifier = Modifier.fillMaxWidth()) {
                Column {
                    Fact(
                        stringResource(R.string.g_self_test),
                        when {
                            !checksDone -> stringResource(R.string.g_checking)
                            checksPassed -> stringResource(R.string.g_passed) +
                                " · " + state.selfTestMs + " ms"
                            else -> stringResource(R.string.g_failed)
                        },
                    )
                    // Only a failing line is worth the room. Four green
                    // rows telling a person their phone works are four
                    // rows of nothing.
                    state.selfTest.filterNot { it.passed }.forEach { step ->
                        Rule()
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 7.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Label(step.name, color = Flow)
                            Label(step.detail, color = Flow)
                        }
                    }
                }
            }

            Rule()

            Slab(modifier = Modifier.fillMaxWidth()) {
                Column {
                    Need(
                        name = stringResource(R.string.g_notifications),
                        met = ready.notifications,
                        why = stringResource(R.string.g_why_notifications),
                        onFix = { model.askForNotifications() },
                        onSettings = {
                            context.startActivity(GardenReadiness.notificationSettings(context))
                        },
                    )
                    Rule()
                    Need(
                        name = stringResource(R.string.g_battery),
                        met = ready.batteryUnrestricted,
                        why = stringResource(R.string.g_why_battery) +
                            " · " + ready.batteryPath,
                        onFix = null,
                        onSettings = {
                            context.startActivity(GardenReadiness.batterySettings(context))
                        },
                    )
                }
            }

            Rule()
            Fact(stringResource(R.string.g_camera), stringResource(R.string.g_only_for_qr))

            RuleButton(
                text = when {
                    !checksDone -> stringResource(R.string.g_checking)
                    !checksPassed -> stringResource(R.string.g_cannot_validate)
                    !ready.notifications -> stringResource(R.string.g_notifications_needed)
                    else -> stringResource(R.string.g_done)
                },
                onTap = onReady,
                enabled = checksPassed && ready.canValidate,
                modifier = Modifier.padding(top = 20.dp),
            )

            if (state.message.isNotEmpty()) {
                Label(state.message, color = Flow, modifier = Modifier.padding(top = 12.dp))
            }
        }
    }
}

/**
 * One thing Android has to allow: its name, whether it is allowed, and
 * the shortest way to change that. The reason shows only while the
 * answer is no, because a reason for something already done is noise.
 */
@Composable
private fun Need(
    name: String,
    met: Boolean,
    why: String,
    onFix: (() -> Unit)?,
    onSettings: () -> Unit,
) {
    Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 9.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Label(name, color = Ink)
            if (met) {
                Label(stringResource(R.string.g_allowed))
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (onFix != null) {
                        RuleButton(stringResource(R.string.g_allow), onTap = onFix)
                    }
                    Label(
                        stringResource(R.string.g_settings),
                        color = Flow,
                        modifier = Modifier.clickable(onClick = onSettings),
                    )
                }
            }
        }
        if (!met) {
            Label(why, modifier = Modifier.padding(top = 4.dp))
        }
    }
}
