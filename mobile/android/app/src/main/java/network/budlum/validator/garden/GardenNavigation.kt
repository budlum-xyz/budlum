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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import network.budlum.validator.R

/** Where in Budlum Garden the person is. Nothing is a dead end. */
enum class Step {
    /** The interactive field of blocks the Figma home sheet opens on. */
    Blocks,

    /** Validator permissions and local self-test. */
    Setup,

    /** Choosing between hosting a Garden, joining one, Wallet or Testnet. */
    Choose,

    /** Active Garden workspace: Room, People and Status tabs. */
    Garden,

    /** Joining via six-digit code, QR scan or pasted invite record. */
    Join,

    /** Making, restoring or unlocking this phone's wallet. */
    Wallet,

    /** Twenty-four recovery words, shown once under FLAG_SECURE. */
    Seed,

    /** Confirming three words before releasing them from memory. */
    SeedVerify,
}

/**
 * The network hub screen, faithful to Figma's clean typographic hierarchy with
 * guaranteed contrast on Page, Sage and Ground skins plus section 5.9 clipboard
 * invite awareness.
 */
@Composable
fun ChooseScreen(
    model: GardenModel,
    onBack: (() -> Unit)? = null,
    onStartOwn: () -> Unit,
    onHaveInvite: () -> Unit,
    onReviewClipboardInvite: (String) -> Unit,
    onTestnet: () -> Unit,
    onWallet: () -> Unit,
    onSetup: () -> Unit,
    spotlight: List<SpotlightEntry> = emptyList(),
) {
    val state = model.state
    val skin = model.skin
    val seated = state.seated

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
            if (state.clipboardInvite.isNotEmpty()) {
                Sheet(skin = skin) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Label(
                                text = stringResource(R.string.g_clipboard_invite),
                                skin = skin,
                                color = skin.accentOnSurface,
                            )
                            Text(
                                text = GardenLogic.shortAddress(state.clipboardInvite),
                                style = MaterialTheme.typography.bodySmall,
                                color = skin.surfaceInk,
                            )
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            RuleButton(
                                text = stringResource(R.string.g_clipboard_join),
                                onTap = { onReviewClipboardInvite(state.clipboardInvite) },
                                skin = skin,
                                filled = true,
                            )
                            RuleButton(
                                text = stringResource(R.string.g_dismiss),
                                onTap = { model.dismissClipboardInvite() },
                                skin = skin,
                            )
                        }
                    }
                }
            }

            Text(
                text = stringResource(R.string.g_data_not_money),
                style = MaterialTheme.typography.bodySmall,
                color = skin.ink,
                modifier = Modifier.padding(bottom = 4.dp),
            )

            Sheet(skin = skin) {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    if (seated) {
                        MenuLine(
                            text = stringResource(R.string.g_my_network),
                            badge = if (state.waitingCount > 0) {
                                state.waitingCount.toString() + " " +
                                    stringResource(R.string.g_waiting)
                            } else {
                                stringResource(R.string.g_active_badge)
                            },
                            skin = skin,
                            onTap = onStartOwn,
                        )
                    } else {
                        MenuLine(
                            text = stringResource(R.string.g_start_own),
                            badge = "",
                            skin = skin,
                            onTap = onStartOwn,
                        )
                        Rule(skin = skin)
                        MenuLine(
                            text = stringResource(R.string.g_was_invited),
                            badge = "",
                            skin = skin,
                            onTap = onHaveInvite,
                        )
                    }
                    Rule(skin = skin)
                    MenuLine(
                        text = stringResource(R.string.w_wallet),
                        badge = if (state.walletAddress.isNotEmpty()) {
                            GardenLogic.shortAddress(state.walletAddress)
                        } else {
                            ""
                        },
                        skin = skin,
                        onTap = onWallet,
                    )
                    Rule(skin = skin)
                    MenuLine(
                        text = stringResource(R.string.g_testnet),
                        badge = "",
                        skin = skin,
                        onTap = onTestnet,
                    )
                    Rule(skin = skin)
                    MenuLine(
                        text = stringResource(R.string.g_search_jump_setup),
                        badge = if (state.readiness.notifications) {
                            stringResource(R.string.g_allowed)
                        } else {
                            stringResource(R.string.g_notifications_off)
                        },
                        skin = skin,
                        onTap = onSetup,
                    )
                }
            }

            if (state.canReturn && !seated) {
                Sheet(skin = skin) {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text(
                            text = stringResource(R.string.g_away_notice),
                            style = MaterialTheme.typography.bodySmall,
                            color = skin.surfaceInk,
                        )
                        PillButton(
                            text = stringResource(R.string.g_return_to_garden),
                            onTap = { model.returnToGarden(onSuccess = onStartOwn) },
                            enabled = !state.busy,
                            skin = skin,
                            primary = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }
            }

            if (state.message.isNotEmpty()) {
                Label(state.message, skin = skin, color = skin.danger)
            }
        }
    }
}

@Composable
private fun MenuLine(
    text: String,
    badge: String,
    skin: Skin,
    onTap: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onTap)
            .padding(vertical = 12.dp, horizontal = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = text.lowercase(),
            style = MaterialTheme.typography.titleMedium,
            color = skin.accentOnSurface,
        )
        if (badge.isNotEmpty()) {
            Label(badge, skin = skin, color = skin.surfaceMuted)
        }
    }
}
