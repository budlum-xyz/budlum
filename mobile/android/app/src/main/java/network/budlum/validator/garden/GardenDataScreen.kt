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
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.json.JSONArray
import org.json.JSONObject

/**
 * What the network is actually for.
 *
 * A Garden is not a currency and there is nothing to pay into it. The
 * work a validator does is checking blocks and holding a share of what
 * the group stores, and this screen is the thing being stored: data,
 * sent over the chain through B.U.D. 3.0, coming back out verified
 * rather than trusted.
 *
 * Until now the phone could join a group and then do nothing with it,
 * which made the whole thing look like an empty ceremony. The core
 * could already publish, resolve and list; the phone simply had no way
 * to ask.
 */
@Composable
fun DataScreen(model: GardenModel) {
    val state = model.state
    var text by remember { mutableStateOf("") }
    var caption by remember { mutableStateOf("") }
    var wanted by remember { mutableStateOf("") }

    LaunchedEffect(Unit) { model.refreshFeed() }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("SEND DATA", style = MaterialTheme.typography.labelSmall)
        Text(
            "Whatever you put here is signed by this phone, broken into " +
                "parts and spread across the group. No token moves and " +
                "nothing is charged - the network carries data, and that is " +
                "all it does.",
            style = MaterialTheme.typography.bodySmall,
        )
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            label = { Text("What to send") },
            placeholder = { Text("A note, a reading, anything") },
            modifier = Modifier.fillMaxWidth(),
            minLines = 3,
        )
        OutlinedTextField(
            value = caption,
            onValueChange = { caption = it },
            label = { Text("A short label (optional)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = {
                model.send(text.trim(), caption.trim())
                text = ""
                caption = ""
            },
            enabled = text.isNotBlank() && !state.busy,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(if (state.busy) "Sending..." else "Send into the Garden") }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { model.refreshFeed() }) { Text("Refresh") }
        }

        Text("WHAT THE GROUP HAS SENT", style = MaterialTheme.typography.labelSmall)
        FeedList(state.feed)

        Text("FETCH IT BACK", style = MaterialTheme.typography.labelSmall)
        Text(
            "Paste a content id to rebuild it from the parts the validators " +
                "hold. What comes back is checked against the chain.",
            style = MaterialTheme.typography.bodySmall,
        )
        OutlinedTextField(
            value = wanted,
            onValueChange = { wanted = it },
            label = { Text("Content id") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedButton(
            onClick = { model.fetch(wanted) },
            enabled = wanted.isNotBlank() && !state.busy,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Fetch") }
        if (state.fetched.isNotEmpty()) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text("FETCHED", style = MaterialTheme.typography.labelSmall)
                    Text(readable(state.fetched), style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
        if (state.message.isNotEmpty()) {
            Text(state.message, style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** The feed, as a list rather than as the raw answer. */
@Composable
private fun FeedList(feed: String) {
    if (feed.isBlank()) {
        Text("Nothing yet.", style = MaterialTheme.typography.bodyMedium)
        return
    }
    val items = runCatching {
        val root = JSONObject(feed)
        root.optJSONArray("items") ?: root.optJSONArray("feed") ?: JSONArray()
    }.getOrElse { JSONArray() }
    if (items.length() == 0) {
        Text("Nothing yet.", style = MaterialTheme.typography.bodyMedium)
        return
    }
    for (index in 0 until items.length()) {
        val item = items.optJSONObject(index) ?: continue
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                val label = item.optString("caption").ifBlank {
                    item.optString("kind").ifBlank { "item" }
                }
                Text(label, style = MaterialTheme.typography.bodyLarge)
                val id = item.optString("content_id")
                if (id.isNotBlank()) {
                    Text(id, style = MaterialTheme.typography.bodySmall)
                }
                val who = item.optString("author_name")
                val size = item.optInt("size", -1)
                val held = if (item.optBoolean("held_here")) " - a part is held here" else ""
                val line = buildString {
                    if (who.isNotBlank() && who != "null") append(who)
                    if (size >= 0) {
                        if (isNotEmpty()) append(" - ")
                        append(size).append(" bytes")
                    }
                    append(held)
                }
                if (line.isNotBlank()) {
                    Text(line, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

/** Show the text of an answer where there is one, the answer otherwise. */
private fun readable(answer: String): String = runCatching {
    val root = JSONObject(answer)
    val text = root.optString("text")
    if (text.isNotBlank() && text != "null") text else answer
}.getOrElse { answer }
