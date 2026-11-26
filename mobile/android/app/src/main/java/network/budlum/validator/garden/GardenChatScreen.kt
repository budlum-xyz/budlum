package network.budlum.validator.garden

import android.graphics.BitmapFactory
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import network.budlum.validator.R

/**
 * What the group has said, oldest at the top.
 *
 * Square corners, one hairline, no filled cards: the measured tokens
 * give every panel and row a radius of zero, and the sheets separate
 * things with a rule rather than a shadow. Mine sit right in sage,
 * everyone else's left on the page colour.
 *
 * Order is the chain's. The feed arrives newest first, already sorted
 * by block and by position inside the block, so it is reversed rather
 * than re-sorted - two lines sharing a block have a real order and
 * re-sorting threw it away.
 */
@Composable
fun ChatScreen(model: GardenModel) {
    val state = model.state
    var draft by remember { mutableStateOf("") }
    val listState = rememberLazyListState()
    val picker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent(),
    ) { uri -> if (uri != null) model.sendFile(uri) }

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

    Column(modifier = Modifier.fillMaxSize()) {
        Box(modifier = Modifier.weight(1f)) {
            if (state.messages.isEmpty()) {
                Label(
                    stringResource(R.string.g_nothing_said),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                )
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(10.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    items(state.messages, key = { it.id }) { line ->
                        Bubble(line, mine = line.author == state.myKey && state.myKey.isNotEmpty())
                    }
                }
            }
        }
        if (state.message.isNotEmpty()) {
            Label(
                state.message,
                color = Color(0xFF8C0000),
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
            )
        }
        Rule()
        Composer(
            draft = draft,
            busy = state.busy,
            onDraft = { draft = it },
            onSend = {
                model.say(draft.trim())
                draft = ""
            },
            onAttach = { picker.launch("*/*") },
        )
    }
}

/** One line. A file shows itself; the rest show their words. */
@Composable
private fun Bubble(line: ChatLine, mine: Boolean) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = if (mine) Arrangement.End else Arrangement.Start,
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 290.dp)
                .background(if (mine) Sage else Page, RectangleShape)
                .border(1.dp, if (mine) Sage else Faint, RectangleShape)
                .padding(horizontal = 10.dp, vertical = 7.dp),
            verticalArrangement = Arrangement.spacedBy(3.dp),
        ) {
            if (!mine) {
                Label(line.who, color = Ink)
            }
            if (line.picture != null) {
                Image(
                    bitmap = line.picture,
                    contentDescription = line.caption,
                    contentScale = ContentScale.FillWidth,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 240.dp),
                )
            } else if (line.isFile) {
                Text(
                    line.caption.ifBlank { "dosya" },
                    style = MaterialTheme.typography.bodyMedium,
                    color = Ink,
                )
            } else {
                Text(
                    line.text.orEmpty(),
                    style = MaterialTheme.typography.bodyMedium,
                    color = Ink,
                )
            }
            Label(footer(line), color = if (mine) Ink else Mute)
        }
    }
}

/**
 * What the chain says about this line, in three words at most.
 *
 * A validator holding a part of what it shows is the whole difference
 * between this and a group chat on somebody's server, so it is worth
 * the three words - but only three.
 */
@Composable
private fun footer(line: ChatLine): String {
    val parts = mutableListOf(stringResource(R.string.g_block, line.height.toInt()))
    if (line.heldHere) parts.add(stringResource(R.string.g_kept_here))
    if (line.verified) parts.add(stringResource(R.string.g_checked))
    if (line.sending) parts.add(stringResource(R.string.g_sending))
    return parts.joinToString(" · ")
}

/**
 * The bar from the sheets: the sparkle on the left loads content, the
 * arrow on the right sends it. Both are the exported assets, and both
 * carry the same name in the design file - one act, two ends.
 */
@Composable
private fun Composer(
    draft: String,
    busy: Boolean,
    onDraft: (String) -> Unit,
    onSend: () -> Unit,
    onAttach: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 10.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Glyph(
            which = R.drawable.icon_attach,
            description = stringResource(R.string.g_attach),
            onTap = onAttach,
            size = 26.dp,
        )
        OutlinedTextField(
            value = draft,
            onValueChange = onDraft,
            placeholder = { Label(stringResource(R.string.g_say)) },
            modifier = Modifier.weight(1f),
            maxLines = 4,
            shape = RectangleShape,
        )
        Glyph(
            which = R.drawable.icon_send,
            description = stringResource(R.string.g_send),
            onTap = onSend,
            size = 26.dp,
            enabled = draft.isNotBlank() && !busy,
        )
    }
}

/** How often the room is read back off the chain. */
private const val REFRESH_MS = 3000L

/** Turn the bytes the chain handed back into something to look at. */
internal fun pictureFrom(hex: String): androidx.compose.ui.graphics.ImageBitmap? {
    if (hex.isEmpty() || hex.length % 2 != 0) return null
    val bytes = ByteArray(hex.length / 2)
    for (index in bytes.indices) {
        val at = index * 2
        bytes[index] = hex.substring(at, at + 2).toIntOrNull(16)?.toByte() ?: return null
    }
    return runCatching {
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.asImageBitmap()
    }.getOrNull()
}
