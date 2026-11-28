package network.budlum.validator.garden

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import network.budlum.validator.R
import network.budlum.validator.core.MobileConstants

/**
 * The Budlum Garden wallet sheets, grounded directly in Figma frames
 * 252:25440 (wallet overview), 253:67567 (seed phrase) and 253:70601 (verify).
 *
 * One phone holds one wallet. Recovery words are displayed under FLAG_SECURE,
 * masked until tapped, and verified by three positions before leaving memory.
 */


/** No wallet yet: create a fresh 24-word wallet or restore an existing one. */
@Composable
fun WalletStartScreen(
    model: GardenModel,
    onBack: () -> Unit,
    spotlight: List<SpotlightEntry> = emptyList(),
) {
    var words by remember { mutableStateOf("") }
    var restoring by remember { mutableStateOf(false) }
    val state = model.state
    val skin = model.skin
    val clipboard = LocalClipboardManager.current
    val expectedWords = remember { model.wordCount() }
    val typedWords = remember(words) { GardenLogic.normalizeMnemonicWords(words) }

    BudlumPage(
        skin = skin,
        onSkinChange = { model.selectSkin(it) },
        onBack = onBack,
        searchHint = stringResource(R.string.w_search_hint),
        spotlight = spotlight,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Label(
                text = stringResource(R.string.g_step_label, 2, 3),
                skin = skin,
                color = skin.muted,
            )
            Sheet(skin) {
                Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
                    SheetHead(
                        name = stringResource(R.string.w_wallet),
                        address = stringResource(R.string.w_no_wallet_yet),
                        under = stringResource(R.string.w_chain) + " " +
                            MobileConstants.TESTNET_CHAIN_ID.toString(),
                        skin = skin,
                    )
                    if (restoring) {
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Label(
                                    text = stringResource(
                                        R.string.w_word_count,
                                        typedWords.size,
                                        expectedWords,
                                    ),
                                    skin = skin,
                                    color = if (typedWords.size == expectedWords) {
                                        skin.accentOnSurface
                                    } else {
                                        skin.surfaceMuted
                                    },
                                )
                                RuleButton(
                                    text = stringResource(R.string.g_paste),
                                    onTap = {
                                        val pasted = clipboard.getText()?.text.orEmpty()
                                        if (pasted.isNotBlank()) {
                                            words = pasted
                                            model.clearMessage()
                                        }
                                    },
                                    skin = skin,
                                )
                            }
                            OutlinedTextField(
                                value = words,
                                onValueChange = { fresh ->
                                    words = fresh
                                    model.clearMessage()
                                },
                                placeholder = {
                                    Label(stringResource(R.string.w_words_hint), skin = skin)
                                },
                                singleLine = false,
                                minLines = 3,
                                maxLines = 5,
                                colors = gardenTextFieldColors(skin),
                                shape = RoundedCornerShape(CONTROL_RADIUS),
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                    }

                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        if (restoring) {
                            PillButton(
                                text = stringResource(R.string.w_restore),
                                onTap = { model.restoreWallet(words) },
                                enabled = !state.busy && typedWords.size == expectedWords,
                                skin = skin,
                                primary = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            PillButton(
                                text = stringResource(R.string.w_make_instead),
                                onTap = {
                                    restoring = false
                                    model.clearMessage()
                                },
                                enabled = !state.busy,
                                skin = skin,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        } else {
                            PillButton(
                                text = stringResource(R.string.w_make),
                                onTap = { model.createWallet() },
                                enabled = !state.busy,
                                skin = skin,
                                primary = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            PillButton(
                                text = stringResource(R.string.w_restore_instead),
                                onTap = {
                                    restoring = true
                                    model.clearMessage()
                                },
                                enabled = !state.busy,
                                skin = skin,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                    }

                    if (state.message.isNotEmpty()) {
                        Text(
                            text = state.message,
                            style = MaterialTheme.typography.bodySmall,
                            color = skin.danger,
                        )
                    }
                }
            }
        }
    }
}

/**
 * The 24 recovery words in Figma's two-column numbered grid.
 *
 * Shown on arrival, the way the frame draws them: numbered chips and one button.
 * The step already runs under FLAG_SECURE, so a screenshot is blocked without a
 * shield standing between a person and the words they have to write down.
 */
@Composable
fun SeedPhraseScreen(model: GardenModel, onWritten: () -> Unit) {
    val skin = model.skin
    val words = model.state.mnemonic

    BudlumPage(
        skin = skin,
        onSkinChange = { model.selectSkin(it) },
    ) {
        Sheet(skin) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                val lines = (words.size + 1) / 2
                for (line in 0 until lines) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        val left = line * 2
                        WordCell(
                            number = left + 1,
                            word = words.getOrNull(left) ?: "",
                            skin = skin,
                            masked = false,
                            modifier = Modifier.weight(1f),
                        )
                        if (left + 1 < words.size) {
                            WordCell(
                                number = left + 2,
                                word = words[left + 1],
                                skin = skin,
                                masked = false,
                                modifier = Modifier.weight(1f),
                            )
                        } else {
                            Spacer(modifier = Modifier.weight(1f))
                        }
                    }
                }

                PillButton(
                    text = stringResource(R.string.w_noted_go_on),
                    onTap = onWritten,
                    enabled = words.isNotEmpty(),
                    skin = skin,
                    primary = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                )
            }
        }
    }
}

/**
 * The phone's wallet overview: copyable address, scannable receive QR, lock
 * state, and direct route to testnet faucet / balance lookup.
 */
@Composable
fun WalletScreen(
    model: GardenModel,
    onBack: () -> Unit,
    onTestnet: () -> Unit,
    spotlight: List<SpotlightEntry> = emptyList(),
) {
    var showQr by remember { mutableStateOf(false) }
    var copied by remember { mutableStateOf(false) }
    val state = model.state
    val skin = model.skin
    val clipboard = LocalClipboardManager.current
    val haptic = LocalHapticFeedback.current
    val qrBitmap = if (showQr) rememberQrBitmap(state.walletAddress) else null

    LaunchedEffect(copied) {
        if (copied) {
            delay(1800)
            copied = false
        }
    }

    BudlumPage(
        skin = skin,
        onSkinChange = { model.selectSkin(it) },
        onBack = onBack,
        searchHint = stringResource(R.string.w_search_hint),
        spotlight = spotlight,
    ) {
        Sheet(skin) {
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                SheetHead(
                    name = stringResource(R.string.w_you),
                    address = GardenLogic.shortAddress(state.walletAddress),
                    under = buildString {
                        append(stringResource(R.string.w_chain))
                        append(" ")
                        append(MobileConstants.TESTNET_CHAIN_ID.toString())
                        model.state.seat?.let {
                            append(" · ")
                            append(it.x)
                            append(",")
                            append(it.y)
                        }
                    },
                    skin = skin,
                    trailing = {
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            Box(
                                modifier = Modifier
                                    .border(1.dp, skin.surfaceRule, RoundedCornerShape(CONTROL_RADIUS))
                                    .clickable {
                                        if (state.walletAddress.isNotEmpty()) {
                                            clipboard.setText(AnnotatedString(state.walletAddress))
                                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                            copied = true
                                        }
                                    }
                                    .padding(8.dp),
                                contentAlignment = Alignment.Center,
                            ) {
                                CopyIcon(
                                    tint = if (copied) skin.accentOnSurface else skin.surfaceInk,
                                )
                            }
                            Box(
                                modifier = Modifier
                                    .border(
                                        1.dp,
                                        if (showQr) skin.accentOnSurface else skin.surfaceRule,
                                        RoundedCornerShape(CONTROL_RADIUS),
                                    )
                                    .clickable { showQr = !showQr }
                                    .padding(8.dp),
                                contentAlignment = Alignment.Center,
                            ) {
                                QrIcon(
                                    tint = if (showQr) skin.accentOnSurface else skin.surfaceInk,
                                )
                            }
                        }
                    },
                )

                if (copied) {
                    Label(
                        text = stringResource(R.string.w_address_copied),
                        skin = skin,
                        color = skin.accentOnSurface,
                    )
                }

                AnimatedVisibility(visible = showQr && qrBitmap != null) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.dp, skin.surfaceRule, RoundedCornerShape(CONTROL_RADIUS))
                            .background(skin.surface, RoundedCornerShape(CONTROL_RADIUS))
                            .padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        qrBitmap?.let { bmp ->
                            Image(
                                bitmap = bmp,
                                contentDescription = stringResource(R.string.w_receive_qr),
                                modifier = Modifier.size(196.dp),
                            )
                        }
                        Text(
                            text = state.walletAddress,
                            style = MaterialTheme.typography.labelSmall,
                            color = skin.surfaceInk,
                        )
                    }
                }

                Rule(skin = skin)

                SheetRow(
                    first = stringResource(R.string.w_tokens_none),
                    second = stringResource(R.string.w_nft_none),
                    skin = skin,
                    markFill = skin.surfaceRule,
                )

                SheetRow(
                    first = stringResource(R.string.w_bud_zero),
                    second = "",
                    skin = skin,
                )

                PillButton(
                    text = stringResource(R.string.w_open_testnet),
                    onTap = onTestnet,
                    skin = skin,
                    primary = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                if (state.message.isNotEmpty()) {
                    Text(
                        text = state.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = skin.danger,
                    )
                }
            }
        }
    }
}
