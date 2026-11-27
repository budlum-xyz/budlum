package network.budlum.validator.garden

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
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
 * Validator readiness checklist shown on first run (and reachable any time).
 *
 * Each requirement is a single contrast-safe row inside a Figma Sheet:
 * self-test status, notification permission, battery guidance, and camera note.
 */
@Composable
fun SetupScreen(
    model: GardenModel,
    onReady: () -> Unit,
    onBack: (() -> Unit)? = null,
    spotlight: List<SpotlightEntry> = emptyList(),
) {
    val context = LocalContext.current
    val state = model.state
    val skin = model.skin
    val ready = state.readiness
    val checksDone = state.selfTest.isNotEmpty()
    val checksPassed = checksDone && state.selfTest.all { it.passed }

    BudlumPage(
        skin = skin,
        onSkinChange = { model.selectSkin(it) },
        onBack = onBack,
        searchHint = stringResource(R.string.w_search_hint),
        spotlight = spotlight,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Label(
                    text = stringResource(R.string.g_step_label, 1, 3),
                    skin = skin,
                    color = skin.muted,
                )
                Text(
                    text = stringResource(R.string.g_become_validator),
                    style = MaterialTheme.typography.headlineSmall,
                    color = skin.ink,
                )
                Text(
                    text = stringResource(R.string.g_becomes_validator),
                    style = MaterialTheme.typography.bodySmall,
                    color = skin.ink,
                )
            }

            Sheet(skin = skin) {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Fact(
                        name = stringResource(R.string.g_self_test),
                        value = when {
                            !checksDone -> stringResource(R.string.g_checking)
                            checksPassed -> stringResource(R.string.g_passed) +
                                " · " + state.selfTestMs + " ms"
                            else -> stringResource(R.string.g_failed)
                        },
                        skin = skin,
                        valueColor = when {
                            !checksDone -> skin.surfaceMuted
                            checksPassed -> skin.accentOnSurface
                            else -> skin.danger
                        },
                    )
                    state.selfTest.filterNot { it.passed }.forEach { step ->
                        Rule(skin = skin)
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 7.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Label(step.name, skin = skin, color = skin.danger)
                            Label(step.detail, skin = skin, color = skin.danger)
                        }
                    }
                    if (checksDone && !checksPassed) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 6.dp),
                            horizontalArrangement = Arrangement.End,
                        ) {
                            RuleButton(
                                text = stringResource(R.string.g_recheck),
                                onTap = { model.runSelfTest() },
                                enabled = !state.busy,
                                skin = skin,
                            )
                        }
                    }

                    Rule(skin = skin)

                    Need(
                        name = stringResource(R.string.g_notifications),
                        met = ready.notifications,
                        why = stringResource(R.string.g_why_notifications),
                        skin = skin,
                        onFix = { model.askForNotifications() },
                        onSettings = {
                            context.startActivity(GardenReadiness.notificationSettings(context))
                        },
                    )

                    Rule(skin = skin)

                    Need(
                        name = stringResource(R.string.g_battery),
                        met = ready.batteryUnrestricted,
                        why = stringResource(R.string.g_why_battery) +
                            if (ready.batteryPath.isNotEmpty()) " · " + ready.batteryPath else "",
                        skin = skin,
                        onFix = null,
                        onSettings = {
                            context.startActivity(GardenReadiness.batterySettings(context))
                        },
                    )

                    Rule(skin = skin)

                    Fact(
                        name = stringResource(R.string.g_camera),
                        value = stringResource(R.string.g_only_for_qr),
                        skin = skin,
                        valueColor = skin.surfaceMuted,
                    )
                }
            }

            PillButton(
                text = when {
                    !checksDone -> stringResource(R.string.g_checking)
                    !checksPassed || !ready.notifications -> stringResource(R.string.g_become_anyway)
                    else -> stringResource(R.string.g_become_validator)
                },
                onTap = onReady,
                enabled = checksDone,
                skin = skin,
                primary = checksDone && checksPassed && ready.notifications,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 4.dp),
            )

            if (checksDone && (!checksPassed || !ready.notifications)) {
                Label(
                    text = if (!checksPassed) {
                        stringResource(R.string.g_self_test_failed_why)
                    } else {
                        stringResource(R.string.g_without_notifications)
                    },
                    skin = skin,
                    color = skin.danger,
                )
            }

            if (state.message.isNotEmpty()) {
                Label(state.message, skin = skin, color = skin.danger)
            }
        }
    }
}

@Composable
private fun Need(
    name: String,
    met: Boolean,
    why: String,
    skin: Skin,
    onFix: (() -> Unit)?,
    onSettings: () -> Unit,
) {
    Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Label(name, skin = skin, color = skin.surfaceInk)
            if (met) {
                Label(stringResource(R.string.g_allowed), skin = skin, color = skin.accentOnSurface)
            } else {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    if (onFix != null) {
                        RuleButton(
                            text = stringResource(R.string.g_allow),
                            onTap = onFix,
                            skin = skin,
                        )
                    }
                    Label(
                        text = stringResource(R.string.g_settings),
                        skin = skin,
                        color = skin.danger,
                        modifier = Modifier
                            .clickable(onClick = onSettings)
                            .padding(vertical = 4.dp),
                    )
                }
            }
        }
        if (!met) {
            Label(why, skin = skin, modifier = Modifier.padding(top = 4.dp))
        }
    }
}
