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
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
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

private const val MIN_PASSWORD = 8
private const val CHECKED_WORDS = 3

/** No wallet yet: create a fresh 24-word wallet or restore an existing one. */
@Composable
fun WalletStartScreen(
    model: GardenModel,
    onBack: () -> Unit,
    spotlight: List<SpotlightEntry> = emptyList(),
) {
    var password by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var words by remember { mutableStateOf("") }
    var restoring by remember { mutableStateOf(false) }
    val state = model.state
    val skin = model.skin
    val clipboard = LocalClipboardManager.current
    val expectedWords = remember { model.wordCount() }
    val typedWords = remember(words) { GardenLogic.normalizeMnemonicWords(words) }
    val missingChars = (MIN_PASSWORD - password.length).coerceAtLeast(0)

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
                    Text(
                        text = stringResource(R.string.w_what_a_wallet_is),
                        style = MaterialTheme.typography.bodySmall,
                        color = skin.surfaceInk,
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

                    OutlinedTextField(
                        value = password,
                        onValueChange = { fresh ->
                            password = fresh
                            model.clearMessage()
                        },
                        placeholder = {
                            Label(stringResource(R.string.w_password_hint), skin = skin)
                        },
                        singleLine = true,
                        visualTransformation = if (showPassword) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        trailingIcon = {
                            Box(
                                modifier = Modifier
                                    .clickable { showPassword = !showPassword }
                                    .padding(8.dp),
                                contentAlignment = Alignment.Center,
                            ) {
                                EyeIcon(visible = showPassword, tint = skin.surfaceMuted)
                            }
                        },
                        colors = gardenTextFieldColors(skin),
                        shape = RoundedCornerShape(CONTROL_RADIUS),
                        modifier = Modifier.fillMaxWidth(),
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = if (missingChars == 0) {
                                stringResource(R.string.w_password_ok)
                            } else if (password.isNotEmpty()) {
                                stringResource(R.string.w_password_short, missingChars)
                            } else {
                                stringResource(R.string.w_password_floor)
                            },
                            style = MaterialTheme.typography.labelSmall,
                            color = if (missingChars == 0) {
                                skin.accentOnSurface
                            } else {
                                skin.surfaceMuted
                            },
                        )
                    }

                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        if (restoring) {
                            PillButton(
                                text = stringResource(R.string.w_restore),
                                onTap = { model.restoreWallet(words, password) },
                                enabled = !state.busy &&
                                    password.length >= MIN_PASSWORD &&
                                    typedWords.size == expectedWords,
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
                                onTap = { model.createWallet(password) },
                                enabled = !state.busy && password.length >= MIN_PASSWORD,
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
 * Masked behind a tap-to-reveal privacy shield until the owner confirms nobody
 * is looking over their shoulder; FLAG_SECURE blocks screenshots on this step.
 */
@Composable
fun SeedPhraseScreen(model: GardenModel, onWritten: () -> Unit) {
    val skin = model.skin
    val words = model.state.mnemonic
    var revealed by remember { mutableStateOf(false) }

    BudlumPage(
        skin = skin,
        onSkinChange = { model.selectSkin(it) },
    ) {
        Sheet(skin) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = stringResource(R.string.w_seed_warning),
                    style = MaterialTheme.typography.bodySmall,
                    color = skin.surfaceInk,
                )

                if (!revealed) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.dp, skin.accentOnSurface, RoundedCornerShape(CONTROL_RADIUS))
                            .background(
                                skin.accentOnSurface.copy(alpha = 0.08f),
                                RoundedCornerShape(CONTROL_RADIUS),
                            )
                            .clickable { revealed = true }
                            .padding(horizontal = 16.dp, vertical = 28.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        EyeIcon(visible = false, tint = skin.accentOnSurface, size = 24.dp)
                        Text(
                            text = stringResource(R.string.w_tap_to_reveal),
                            style = MaterialTheme.typography.bodyMedium,
                            color = skin.surfaceInk,
                        )
                        Label(
                            text = stringResource(R.string.w_reveal_hint),
                            skin = skin,
                        )
                    }
                }

                val lines = (words.size + 1) / 2
                for (line in 0 until lines) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        val left = line * 2
                        WordCell(
                            number = left + 1,
                            word = words.getOrNull(left) ?: "",
                            skin = skin,
                            masked = !revealed,
                            modifier = Modifier.weight(1f),
                        )
                        if (left + 1 < words.size) {
                            WordCell(
                                number = left + 2,
                                word = words[left + 1],
                                skin = skin,
                                masked = !revealed,
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
                    enabled = revealed && words.isNotEmpty(),
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
 * Confirm three positions from the recovery phrase before dropping it from RAM.
 */
@Composable
fun SeedVerifyScreen(
    model: GardenModel,
    onBackToWords: () -> Unit,
    onVerified: () -> Unit,
) {
    val skin = model.skin
    val words = model.state.mnemonic
    val positions = remember(words) {
        if (words.size <= CHECKED_WORDS) {
            words.indices.toList()
        } else {
            words.indices.shuffled().take(CHECKED_WORDS).sorted()
        }
    }
    var answers by remember(positions) { mutableStateOf(List(positions.size) { "" }) }
    var wrong by remember { mutableStateOf(false) }

    BudlumPage(
        skin = skin,
        onSkinChange = { model.selectSkin(it) },
        onBack = onBackToWords,
    ) {
        Sheet(skin) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = stringResource(R.string.w_verify_why),
                    style = MaterialTheme.typography.bodySmall,
                    color = skin.surfaceInk,
                )

                positions.forEachIndexed { slot, position ->
                    val expected = words.getOrNull(position)?.lowercase().orEmpty()
                    val typed = answers.getOrNull(slot).orEmpty()
                    val matched = typed.trim().lowercase() == expected && expected.isNotEmpty()
                    WordField(
                        number = position + 1,
                        value = typed,
                        onValue = { fresh ->
                            answers = answers.toMutableList().also { it[slot] = fresh }
                            wrong = false
                        },
                        skin = skin,
                        matched = matched,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                if (wrong) {
                    Text(
                        text = stringResource(R.string.w_not_those_words),
                        style = MaterialTheme.typography.bodySmall,
                        color = skin.danger,
                    )
                }

                PillButton(
                    text = stringResource(R.string.w_thats_it),
                    onTap = {
                        val allMatch = positions.indices.all { slot ->
                            val expected = words.getOrNull(positions[slot])?.lowercase() ?: ""
                            answers.getOrNull(slot)?.trim()?.lowercase() == expected
                        }
                        if (allMatch) {
                            model.forgetMnemonic()
                            onVerified()
                        } else {
                            wrong = true
                        }
                    },
                    enabled = answers.all { it.isNotBlank() },
                    skin = skin,
                    primary = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                PillButton(
                    text = stringResource(R.string.w_back_to_words),
                    onTap = onBackToWords,
                    skin = skin,
                    modifier = Modifier.fillMaxWidth(),
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
    var password by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
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
                    under = stringResource(R.string.w_chain) + " " +
                        MobileConstants.TESTNET_CHAIN_ID.toString() + " · " +
                        if (state.walletUnlocked) {
                            stringResource(R.string.w_unlocked_badge)
                        } else {
                            stringResource(R.string.w_locked_badge)
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
                            .background(Page, RoundedCornerShape(CONTROL_RADIUS))
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
                            color = Ink,
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

                if (!state.walletUnlocked) {
                    OutlinedTextField(
                        value = password,
                        onValueChange = { fresh ->
                            password = fresh
                            model.clearMessage()
                        },
                        placeholder = {
                            Label(stringResource(R.string.w_password_hint), skin = skin)
                        },
                        singleLine = true,
                        visualTransformation = if (showPassword) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        trailingIcon = {
                            Box(
                                modifier = Modifier
                                    .clickable { showPassword = !showPassword }
                                    .padding(8.dp),
                                contentAlignment = Alignment.Center,
                            ) {
                                EyeIcon(visible = showPassword, tint = skin.surfaceMuted)
                            }
                        },
                        colors = gardenTextFieldColors(skin),
                        shape = RoundedCornerShape(CONTROL_RADIUS),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    PillButton(
                        text = stringResource(R.string.w_sign_in),
                        onTap = {
                            model.unlockWallet(password)
                            password = ""
                        },
                        enabled = !state.busy && password.isNotEmpty(),
                        skin = skin,
                        primary = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                } else {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        PillButton(
                            text = stringResource(R.string.w_open_testnet),
                            onTap = onTestnet,
                            skin = skin,
                            primary = true,
                            modifier = Modifier.weight(1f),
                        )
                        PillButton(
                            text = stringResource(R.string.w_lock_wallet),
                            onTap = { model.lockWallet() },
                            skin = skin,
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
