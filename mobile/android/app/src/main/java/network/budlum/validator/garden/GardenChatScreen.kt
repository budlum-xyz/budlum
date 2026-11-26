package network.budlum.validator.garden

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import network.budlum.validator.R

/**
 * The Garden as a conversation.
 *
 * Everything in here is already a chain operation; what changed is that
 * it now reads like a room rather than like a form. A line typed here
 * is signed by the phone, coded into parts by B.U.D. 3.0, spread over
 * the validators and ordered by the block it landed in - which is why
 * the order is the same on every phone, with no server deciding it.
 *
 * Order is by block height, not by any phone's clock. Two phones
 * disagree about the time; they do not disagree about the chain.
 */
@Composable
fun ChatScreen(model: GardenModel) {
    val state = model.state
    var draft by remember { mutableStateOf("") }
    val listState = rememberLazyListState()
    // The system picker, so the app never asks for storage permission
    // to read one file the person chose themselves.
    val picker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent(),
    ) { uri -> if (uri != null) model.sendFile(uri) }

    // The group is a live thing, and a phone waiting alone for the
    // others needs to see them arrive without being told to refresh.
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
                EmptyRoom(state.aloneHere)
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(state.messages, key = { it.id }) { line ->
                        Bubble(line, mine = line.author == state.myKey && state.myKey.isNotEmpty())
                    }
                }
            }
        }
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
        if (state.message.isNotEmpty()) {
            Text(
                state.message,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            )
        }
    }
}

/** What a room looks like before anybody has said anything. */
@Composable
private fun EmptyRoom(alone: Boolean) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(28.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            if (alone) "you are the only one here" else "nothing said yet",
            style = MaterialTheme.typography.labelSmall,
        )
        Text(
            if (alone) {
                "Share the invite from the Invite tab. When somebody takes " +
                    "it their phone becomes a validator of this network, and " +
                    "whatever either of you sends lands on the same chain."
            } else {
                "Say something, or send a file. It goes to everyone here."
            },
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 10.dp),
        )
    }
}

/**
 * One line, from this phone or from somebody else.
 *
 * Mine sit against the right in sage; everyone else's against the left
 * on the page colour with a hairline, which is how the rest of Budlum
 * separates things - a rule, not a shadow.
 */
@Composable
private fun Bubble(line: ChatLine, mine: Boolean) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = if (mine) Arrangement.End else Arrangement.Start,
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 300.dp)
                .background(
                    color = if (mine) Sage else Page,
                    shape = RoundedCornerShape(12.dp),
                )
                .border(
                    width = 1.dp,
                    color = if (mine) Sage else Faint,
                    shape = RoundedCornerShape(12.dp),
                )
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(3.dp),
        ) {
            if (!mine) {
                Text(
                    line.who.lowercase(),
                    style = MaterialTheme.typography.labelSmall,
                    color = Ink,
                )
            }
            if (line.isFile) {
                FileLine(line)
            } else {
                Text(
                    line.text.orEmpty(),
                    style = MaterialTheme.typography.bodyMedium,
                    color = Ink,
                )
            }
            Text(
                footer(line),
                style = MaterialTheme.typography.labelSmall,
                color = if (mine) Ink else Mute,
            )
        }
    }
}

/** A file reads as what it is, with the size it took on the chain. */
@Composable
private fun FileLine(line: ChatLine) {
    Text(
        line.caption.ifBlank { "a file" },
        style = MaterialTheme.typography.bodyMedium,
        color = Ink,
    )
    Text(
        line.mime.ifBlank { "unknown type" } + " - " + readableSize(line.size),
        style = MaterialTheme.typography.bodySmall,
        color = Ink,
    )
}

/** Where the line sits in the chain, and whether a part of it is here. */
private fun footer(line: ChatLine): String {
    val held = if (line.heldHere) " - a part kept here" else ""
    val checked = if (line.verified) " - checked" else ""
    return "block " + line.height + held + checked
}

private fun readableSize(bytes: Int): String = when {
    bytes >= 1024 * 1024 -> (bytes / (1024 * 1024)).toString() + " MB"
    bytes >= 1024 -> (bytes / 1024).toString() + " KB"
    else -> bytes.toString() + " bytes"
}

/** The line being written, with the way to attach a file next to it. */
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
            .padding(10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        IconButton(onClick = onAttach, enabled = !busy) {
            Icon(
                painter = painterResource(R.drawable.ic_attach),
                contentDescription = "Send a file",
                tint = Sage,
            )
        }
        OutlinedTextField(
            value = draft,
            onValueChange = onDraft,
            placeholder = { Text("say something") },
            modifier = Modifier.weight(1f),
            maxLines = 4,
        )
        TextButton(onClick = onSend, enabled = draft.isNotBlank() && !busy) {
            Text(if (busy) "..." else "send")
        }
    }
}

/** How often the room is read back off the chain. */
private const val REFRESH_MS = 3000L
