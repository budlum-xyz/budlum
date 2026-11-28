package network.budlum.validator.garden

import android.graphics.BitmapFactory
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
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
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.delay
import network.budlum.validator.R

/**
 * The Garden conversation room, ordered strictly by chain block and transaction
 * position. Tapping any message opens its verified chain provenance and B.U.D.
 * 3.0 custody details (section 3.9).
 */
@Composable
fun ChatScreen(model: GardenModel) {
    val state = model.state
    val skin = model.skin
    var draft by remember { mutableStateOf("") }
    var inspected by remember { mutableStateOf<ChatLine?>(null) }
    var fullImage by remember { mutableStateOf<ImageBitmap?>(null) }
    val listState = rememberLazyListState()
    val picker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent(),
    ) { uri -> if (uri != null) model.sendTextFrom(uri) }

    LaunchedEffect(Unit) {
        while (true) {
            model.readChat()
            delay(REFRESH_MS)
        }
    }
    LaunchedEffect(state.messages.size) {
        if (state.messages.isNotEmpty()) {
            listState.animateScrollToItem(state.messages.size - 1)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .navigationBarsPadding()
            .imePadding(),
    ) {
        Box(modifier = Modifier.weight(1f)) {
            if (state.messages.isEmpty()) {
                Column(
                    modifier = Modifier
                        .align(Alignment.Center)
                        .padding(28.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    GardenBrandMark(skin = skin, height = 20.dp, onSurface = false)
                    Label(
                        text = stringResource(R.string.g_nothing_said),
                        skin = skin,
                        color = skin.muted,
                    )
                }
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(state.messages, key = { it.id }) { line ->
                        Bubble(
                            line = line,
                            mine = line.author == state.myKey && state.myKey.isNotEmpty(),
                            skin = skin,
                            onInspect = { inspected = line },
                            onOpenImage = { bmp -> fullImage = bmp },
                        )
                    }
                }
            }
        }
        if (state.message.isNotEmpty()) {
            Label(
                text = state.message,
                skin = skin,
                color = skin.danger,
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp),
            )
        }
        Rule(skin = skin, color = skin.rule)
        Composer(
            draft = draft,
            busy = state.busy,
            skin = skin,
            onDraft = { draft = it },
            onSend = {
                val trimmed = draft.trim()
                if (trimmed.isNotEmpty()) {
                    model.say(trimmed)
                    draft = ""
                }
            },
            onAttach = { picker.launch("*/*") },
        )
    }

    inspected?.let { line ->
        MessageProofDialog(
            line = line,
            skin = skin,
            onDismiss = { inspected = null },
        )
    }

    fullImage?.let { bmp ->
        FullScreenImageDialog(
            image = bmp,
            skin = skin,
            onDismiss = { fullImage = null },
        )
    }
}

/**
 * One message bubble using the chat section's measured radii (32 px = 10.7 dp)
 * and surface fill on both sides, with sage/accent metadata and proof cues.
 */
@Composable
private fun Bubble(
    line: ChatLine,
    mine: Boolean,
    skin: Skin,
    onInspect: () -> Unit,
    onOpenImage: (ImageBitmap) -> Unit,
) {
    val bg = if (skin.isDark) skin.surface else Chalk
    val border = if (mine) skin.accentOnSurface else skin.surfaceRule
    val textColor = skin.surfaceInk
    val metaColor = skin.accentOnSurface

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .alpha(if (line.sending) 0.72f else 1f),
        horizontalArrangement = if (mine) Arrangement.End else Arrangement.Start,
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 296.dp)
                .background(bg, RoundedCornerShape(BUBBLE_RADIUS))
                .border(1.dp, border, RoundedCornerShape(BUBBLE_RADIUS))
                .clickable(onClick = onInspect)
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            if (!mine) {
                Text(
                    text = line.who,
                    style = MaterialTheme.typography.titleSmall,
                    color = textColor,
                )
            }
            if (line.picture != null) {
                Image(
                    bitmap = line.picture,
                    contentDescription = line.caption,
                    contentScale = ContentScale.FillWidth,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 240.dp)
                        .clickable { onOpenImage(line.picture) },
                )
                if (line.caption.isNotBlank()) {
                    Text(
                        text = line.caption,
                        style = MaterialTheme.typography.bodySmall,
                        color = textColor,
                    )
                }
            } else if (line.isFile) {
                Text(
                    text = line.caption.ifBlank { stringResource(R.string.g_a_file) },
                    style = MaterialTheme.typography.bodyMedium,
                    color = textColor,
                )
            } else {
                Text(
                    text = line.text.orEmpty(),
                    style = MaterialTheme.typography.bodyMedium,
                    color = textColor,
                )
            }
            Label(footer(line), skin = skin, color = metaColor)
        }
    }
}

@Composable
private fun footer(line: ChatLine): String {
    if (line.sending) return stringResource(R.string.g_sending)
    val parts = mutableListOf(stringResource(R.string.g_block, line.height.toInt()))
    if (line.heldHere) parts.add(stringResource(R.string.g_kept_here))
    if (line.verified) parts.add(stringResource(R.string.g_checked))
    return parts.joinToString(" · ")
}

/** Section 3.9: verify block height, content id, author key and B.U.D. 3.0 custody. */
@Composable
private fun MessageProofDialog(
    line: ChatLine,
    skin: Skin,
    onDismiss: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    val haptic = LocalHapticFeedback.current
    var copiedLabel by remember { mutableStateOf(false) }
    // The other half of B.U.D. 3: what crossed as text comes back as a QR code.
    val asQr = rememberQrBitmap(line.text.orEmpty())

    Dialog(onDismissRequest = onDismiss) {
        Sheet(skin = skin) {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = stringResource(R.string.g_chain_proof),
                        style = MaterialTheme.typography.titleSmall,
                        color = skin.surfaceInk,
                    )
                    Label(
                        text = stringResource(R.string.g_close),
                        skin = skin,
                        color = skin.accentOnSurface,
                        modifier = Modifier.clickable(onClick = onDismiss),
                    )
                }
                Rule(skin = skin)
                if (asQr != null) {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Image(
                            bitmap = asQr,
                            contentDescription = stringResource(R.string.g_message_qr),
                            modifier = Modifier.size(160.dp),
                        )
                        Label(stringResource(R.string.g_message_qr), skin = skin)
                    }
                    Rule(skin = skin)
                }
                Fact(
                    name = stringResource(R.string.g_block, line.height.toInt()),
                    value = line.who,
                    skin = skin,
                )
                Rule(skin = skin)
                Fact(
                    name = stringResource(R.string.g_content_id),
                    value = GardenLogic.shortAddress(line.id),
                    skin = skin,
                )
                Rule(skin = skin)
                Fact(
                    name = stringResource(R.string.g_author_key),
                    value = GardenLogic.shortAddress(line.author),
                    skin = skin,
                )
                Rule(skin = skin)
                Fact(
                    name = stringResource(R.string.g_size_label),
                    value = GardenLogic.formatBytes(line.size.toLong()),
                    skin = skin,
                )
                Rule(skin = skin)
                Fact(
                    name = stringResource(R.string.g_held_label),
                    value = if (line.heldHere) {
                        stringResource(R.string.g_yes)
                    } else {
                        stringResource(R.string.g_no)
                    },
                    skin = skin,
                    valueColor = if (line.heldHere) skin.accentOnSurface else skin.surfaceMuted,
                )
                Rule(skin = skin)
                Fact(
                    name = stringResource(R.string.g_verified_label),
                    value = if (line.verified) {
                        stringResource(R.string.g_yes)
                    } else {
                        stringResource(R.string.g_no)
                    },
                    skin = skin,
                    valueColor = if (line.verified) skin.accentOnSurface else skin.surfaceMuted,
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 10.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    if (!line.text.isNullOrBlank()) {
                        RuleButton(
                            text = if (copiedLabel) {
                                stringResource(R.string.g_copied)
                            } else {
                                stringResource(R.string.g_copy_text)
                            },
                            onTap = {
                                clipboard.setText(AnnotatedString(line.text))
                                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                copiedLabel = true
                            },
                            skin = skin,
                            modifier = Modifier.weight(1f),
                        )
                    }
                    RuleButton(
                        text = stringResource(R.string.g_content_id),
                        onTap = {
                            clipboard.setText(AnnotatedString(line.id))
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            copiedLabel = true
                        },
                        skin = skin,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
    }
}

@Composable
private fun FullScreenImageDialog(
    image: ImageBitmap,
    skin: Skin,
    onDismiss: () -> Unit,
) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Ground.copy(alpha = 0.94f))
                .clickable(onClick = onDismiss)
                .padding(16.dp),
        ) {
            Image(
                bitmap = image,
                contentDescription = null,
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .fillMaxSize()
                    .align(Alignment.Center),
            )
            RuleButton(
                text = stringResource(R.string.g_close),
                onTap = onDismiss,
                skin = Skin.Ground,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(top = 24.dp),
            )
        }
    }
}

@Composable
private fun Composer(
    draft: String,
    busy: Boolean,
    skin: Skin,
    onDraft: (String) -> Unit,
    onSend: () -> Unit,
    onAttach: () -> Unit,
) {
    val iconTint = if (skin.isDark) skin.surfaceInk else skin.surfaceInk
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(skin.surface.copy(alpha = 0.96f))
            .padding(horizontal = 10.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Glyph(
            which = R.drawable.icon_attach,
            description = stringResource(R.string.g_attach),
            onTap = onAttach,
            size = 24.dp,
            tint = iconTint,
        )
        OutlinedTextField(
            value = draft,
            onValueChange = onDraft,
            placeholder = { Label(stringResource(R.string.g_say), skin = skin) },
            modifier = Modifier.weight(1f),
            maxLines = 4,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
            keyboardActions = KeyboardActions(
                onSend = {
                    if (draft.isNotBlank() && !busy) onSend()
                },
            ),
            colors = gardenTextFieldColors(skin),
            shape = RoundedCornerShape(CHAT_CONTROL_RADIUS),
        )
        Glyph(
            which = R.drawable.icon_send,
            description = stringResource(R.string.g_send),
            onTap = onSend,
            size = 24.dp,
            enabled = draft.isNotBlank() && !busy,
            tint = if (draft.isNotBlank() && !busy) skin.accentOnSurface else iconTint,
        )
    }
}

/** Chat bubble corner measured from the 1080 px Figma chat sheet (32 px = 10.7 dp). */
internal val BUBBLE_RADIUS = 10.7.dp

/** Chat control corner measured from the same sheet (16 px = 5.3 dp). */
internal val CHAT_CONTROL_RADIUS = 5.3.dp

private const val REFRESH_MS = 3000L

/** Decode verified image bytes handed back from the chain. */
internal fun pictureFrom(hex: String): ImageBitmap? {
    if (hex.length < 2 || hex.length % 2 != 0) return null
    val bytes = ByteArray(hex.length / 2)
    for (i in bytes.indices) {
        val hi = hex[i * 2].digitToIntOrNull(16) ?: return null
        val lo = hex[i * 2 + 1].digitToIntOrNull(16) ?: return null
        bytes[i] = ((hi shl 4) or lo).toByte()
    }
    return BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.asImageBitmap()
}
