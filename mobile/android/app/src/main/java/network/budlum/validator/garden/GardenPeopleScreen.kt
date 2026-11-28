package network.budlum.validator.garden

import android.content.Context
import android.content.Intent
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
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import network.budlum.validator.R

/**
 * Who is in this Garden, who is waiting for host admission, and every way to
 * invite somebody: six-digit same-Wi-Fi code, scannable cross-network QR code
 * (section 2.5), and shareable long invite link.
 */
@Composable
fun PeopleScreen(model: GardenModel) {
    val state = model.state
    val skin = model.skin

    LaunchedEffect(Unit) {
        model.readChat()
        model.syncCode()
    }
    LaunchedEffect(state.code) {
        if (state.code.isNotEmpty()) {
            while (model.state.codeSecondsLeft > 0L) {
                delay(1000L)
                model.tickCode()
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .navigationBarsPadding(),
    ) {
        if (state.iAmHost) {
            CodeRow(model)
            Rule(skin = skin, color = skin.rule)
        }
        if (state.waitingForHost) {
            Sheet(skin = skin, modifier = Modifier.padding(14.dp)) {
                Label(
                    text = stringResource(R.string.g_waiting_for_host),
                    skin = skin,
                    color = skin.surfaceInk,
                )
            }
        }
        if (state.people.isEmpty()) {
            Label(
                text = stringResource(R.string.g_nobody_yet),
                skin = skin,
                color = skin.muted,
                modifier = Modifier.padding(16.dp),
            )
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(state.people, key = { it.key }) { person ->
                    PersonRow(
                        person = person,
                        canAnswer = state.iAmHost,
                        isHostRow = person.isMe && state.iAmHost,
                        model = model,
                    )
                    Rule(skin = skin, color = skin.rule)
                }
            }
        }
    }
}

/** Host invite desk: copyable 6-digit code, live timer, QR sheet and link share. */
@Composable
private fun CodeRow(model: GardenModel) {
    val state = model.state
    val skin = model.skin
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val haptic = LocalHapticFeedback.current
    var showQr by remember { mutableStateOf(false) }
    var copied by remember { mutableStateOf(false) }
    val qrBitmap = if (showQr && state.record.isNotEmpty()) rememberQrBitmap(state.record) else null

    LaunchedEffect(copied) {
        if (copied) {
            delay(1800)
            copied = false
        }
    }

    Sheet(skin = skin, modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(
                    modifier = Modifier.clickable(enabled = state.code.isNotBlank()) {
                        clipboard.setText(AnnotatedString(state.code))
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        copied = true
                    },
                    verticalArrangement = Arrangement.spacedBy(2.dp),
                ) {
                    Label(stringResource(R.string.g_code_label), skin = skin)
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            text = if (state.code.isBlank()) {
                                "--- ---"
                            } else {
                                GardenLogic.formatCode(state.code)
                            },
                            style = MaterialTheme.typography.headlineSmall,
                            color = skin.surfaceInk,
                        )
                        if (state.code.isNotBlank()) {
                            CopyIcon(
                                tint = if (copied) skin.accentOnSurface else skin.surfaceMuted,
                            )
                        }
                    }
                    Label(
                        text = when {
                            copied -> stringResource(R.string.g_code_copied)
                            state.code.isBlank() -> stringResource(R.string.g_code_reach)
                            else -> GardenLogic.formatCountdown(state.codeSecondsLeft) +
                                " · " + stringResource(R.string.g_code_reach)
                        },
                        skin = skin,
                        color = if (copied) skin.accentOnSurface else skin.surfaceMuted,
                    )
                }

                RuleButton(
                    text = stringResource(R.string.g_code_new),
                    onTap = { model.newCode() },
                    enabled = !state.busy,
                    skin = skin,
                    filled = state.code.isBlank(),
                )
            }

            // A code opens one of two doors; the switch says which before the
            // code is asked for, and the link it is shared as carries it.
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                RuleButton(
                    text = stringResource(R.string.g_purpose_garden),
                    onTap = { model.selectInvitePurpose(GardenLogic.InvitePurpose.Garden) },
                    skin = skin,
                    filled = model.invitePurpose == GardenLogic.InvitePurpose.Garden,
                    modifier = Modifier.weight(1f),
                )
                RuleButton(
                    text = stringResource(R.string.g_purpose_person),
                    onTap = { model.selectInvitePurpose(GardenLogic.InvitePurpose.Person) },
                    skin = skin,
                    filled = model.invitePurpose == GardenLogic.InvitePurpose.Person,
                    modifier = Modifier.weight(1f),
                )
            }

            if (state.record.isNotEmpty()) {
                Rule(skin = skin)
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    RuleButton(
                        text = if (showQr) {
                            stringResource(R.string.g_hide_qr)
                        } else {
                            stringResource(R.string.g_show_qr)
                        },
                        onTap = { showQr = !showQr },
                        skin = skin,
                        modifier = Modifier.weight(1f),
                    )
                    RuleButton(
                        text = stringResource(R.string.g_long_invite),
                        onTap = {
                            shareInvite(
                                context,
                                GardenLogic.inviteLink(state.record, model.invitePurpose),
                            )
                        },
                        skin = skin,
                        modifier = Modifier.weight(1f),
                    )
                }
            }

            AnimatedVisibility(visible = showQr && qrBitmap != null) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, skin.surfaceRule, RoundedCornerShape(CONTROL_RADIUS))
                        .background(skin.surface, RoundedCornerShape(CONTROL_RADIUS))
                        .padding(14.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    qrBitmap?.let { bmp ->
                        Image(
                            bitmap = bmp,
                            contentDescription = stringResource(R.string.g_show_qr),
                            modifier = Modifier.size(204.dp),
                        )
                    }
                    Text(
                        text = stringResource(R.string.g_qr_hint),
                        style = MaterialTheme.typography.labelSmall,
                        color = skin.surfaceInk,
                    )
                }
            }

            if (state.message.isNotEmpty()) {
                Label(state.message, skin = skin, color = skin.danger)
            }
        }
    }
}

private fun shareInvite(context: Context, record: String) {
    val sending = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, record)
    }
    context.startActivity(Intent.createChooser(sending, null))
}

/** One validator row: 80 px round portrait, name, short key, status and admission controls. */
@Composable
private fun PersonRow(
    person: Person,
    canAnswer: Boolean,
    isHostRow: Boolean,
    model: GardenModel,
) {
    val skin = model.skin
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(skin.surface.copy(alpha = 0.86f))
            .padding(horizontal = 14.dp, vertical = 11.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Portrait(round = true)
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = if (person.isMe) stringResource(R.string.g_you) else person.name,
                    style = MaterialTheme.typography.bodyMedium,
                    color = skin.surfaceInk,
                )
                if (isHostRow) {
                    Label(
                        text = stringResource(R.string.g_host_badge),
                        skin = skin,
                        color = skin.accentOnSurface,
                    )
                } else if (person.active) {
                    Label(
                        text = stringResource(R.string.g_active_badge),
                        skin = skin,
                        color = skin.accentOnSurface,
                    )
                }
            }
            Label(person.shortKey, skin = skin)
            if (person.waiting) {
                Label(
                    text = if (canAnswer) {
                        stringResource(R.string.g_waiting_for_you)
                    } else {
                        stringResource(R.string.g_waiting)
                    },
                    skin = skin,
                    color = skin.danger,
                )
            }
        }
        if (person.waiting && canAnswer) {
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                RuleButton(
                    text = stringResource(R.string.g_let_in),
                    onTap = { model.answerRequest(person.key, true) },
                    skin = skin,
                    filled = true,
                )
                RuleButton(
                    text = stringResource(R.string.g_turn_away),
                    onTap = { model.answerRequest(person.key, false) },
                    skin = skin,
                    rule = skin.danger,
                    ink = skin.danger,
                )
            }
        }
    }
}

/**
 * Join a Garden via six-digit same-Wi-Fi code, QR scan, or pasted invite record.
 *
 * Only advances to the Garden screen once the join call succeeds, keeping clear
 * errors visible right here if the code times out or the link is expired.
 */
@Composable
fun CodeJoinScreen(
    model: GardenModel,
    onJoined: () -> Unit,
) {
    var typedCode by remember { mutableStateOf("") }
    var typedRecord by remember { mutableStateOf("") }
    var showLinkBox by remember { mutableStateOf(false) }
    val state = model.state
    val skin = model.skin
    val clipboard = LocalClipboardManager.current

    // If a deep-link or clipboard invite preloaded previewRecord, reveal the link box.
    LaunchedEffect(state.previewRecord) {
        if (state.previewRecord.isNotEmpty()) {
            typedRecord = state.previewRecord
            showLinkBox = true
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .navigationBarsPadding()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 18.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Sheet(skin = skin) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Label(stringResource(R.string.g_code_label), skin = skin)

                // Six visual digit slots reflecting the typed code cleanly.
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    repeat(6) { idx ->
                        val ch = typedCode.getOrNull(idx)?.toString() ?: ""
                        val focused = typedCode.length == idx
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .border(
                                    width = if (focused) 1.5.dp else 1.dp,
                                    color = if (ch.isNotEmpty() || focused) {
                                        skin.accentOnSurface
                                    } else {
                                        skin.surfaceRule
                                    },
                                    shape = RoundedCornerShape(CONTROL_RADIUS),
                                )
                                .padding(vertical = 10.dp),
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(
                                text = ch.ifEmpty { "-" },
                                style = MaterialTheme.typography.titleMedium,
                                color = if (ch.isNotEmpty()) skin.surfaceInk else skin.surfaceMuted,
                            )
                        }
                    }
                }

                OutlinedTextField(
                    value = typedCode,
                    onValueChange = { fresh ->
                        typedCode = fresh.filter { it.isDigit() }.take(6)
                        model.clearMessage()
                    },
                    placeholder = { Label(stringResource(R.string.g_code_enter), skin = skin) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    colors = gardenTextFieldColors(skin),
                    shape = RoundedCornerShape(CONTROL_RADIUS),
                    modifier = Modifier.fillMaxWidth(),
                )

                if (state.busy) {
                    Label(
                        text = stringResource(R.string.g_searching_wifi),
                        skin = skin,
                        color = skin.accentOnSurface,
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    PillButton(
                        text = stringResource(R.string.g_join_network),
                        onTap = { model.joinWithCode(typedCode, onSuccess = onJoined) },
                        enabled = !state.busy && typedCode.length == 6,
                        skin = skin,
                        primary = true,
                        modifier = Modifier.weight(1f),
                    )
                    PillButton(
                        text = stringResource(R.string.g_scan_qr),
                        onTap = { model.scan() },
                        enabled = !state.busy,
                        skin = skin,
                    )
                }
            }
        }

        Sheet(skin = skin) {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { showLinkBox = !showLinkBox },
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Label(
                        text = stringResource(R.string.g_paste_invite),
                        skin = skin,
                        color = skin.surfaceInk,
                    )
                    RuleButton(
                        text = stringResource(R.string.g_paste),
                        onTap = {
                            val pasted = clipboard.getText()?.text.orEmpty().trim()
                            if (pasted.isNotEmpty()) {
                                typedRecord = pasted
                                showLinkBox = true
                                model.preview(pasted)
                            }
                        },
                        enabled = !state.busy,
                        skin = skin,
                    )
                }

                AnimatedVisibility(visible = showLinkBox) {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        OutlinedTextField(
                            value = typedRecord,
                            onValueChange = { fresh ->
                                typedRecord = fresh
                                if (fresh.trim().length > 16) {
                                    model.preview(fresh)
                                } else {
                                    model.preview("")
                                }
                            },
                            placeholder = {
                                Label(stringResource(R.string.g_paste_invite_hint), skin = skin)
                            },
                            singleLine = false,
                            minLines = 2,
                            maxLines = 4,
                            colors = gardenTextFieldColors(skin),
                            shape = RoundedCornerShape(CONTROL_RADIUS),
                            modifier = Modifier.fillMaxWidth(),
                        )

                        if (state.preview.isNotEmpty()) {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .border(1.dp, skin.accentOnSurface, RoundedCornerShape(CONTROL_RADIUS))
                                    .padding(10.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Label(
                                    text = stringResource(R.string.g_invited_by),
                                    skin = skin,
                                    color = skin.accentOnSurface,
                                )
                                Text(
                                    text = state.preview,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = skin.surfaceInk,
                                )
                            }
                        }

                        PillButton(
                            text = stringResource(R.string.g_join_with_link),
                            onTap = {
                                val target = state.previewRecord.ifBlank { typedRecord.trim() }
                                model.join(target, onSuccess = onJoined)
                            },
                            enabled = !state.busy &&
                                (state.previewRecord.isNotEmpty() || typedRecord.trim().length > 16),
                            skin = skin,
                            primary = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }
            }
        }

        if (state.message.isNotEmpty()) {
            Label(state.message, skin = skin, color = skin.danger)
        }
    }
}
