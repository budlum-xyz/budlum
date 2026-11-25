package network.budlum.validator.garden

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.json.JSONObject

/**
 * The three screens of section 2.4: Invite, Join and Status. Nothing else
 * is here on purpose. Section 2.8 keeps message, post and trace queries out
 * of the app, so there is no screen for them.
 */
@Composable
fun GardenApp(model: GardenModel, onTestnet: () -> Unit) {
    var step by remember { mutableStateOf(Step.Setup) }
    var tab by remember { mutableStateOf(0) }

    // Every step can be left the way it was entered.
    BackHandler(enabled = step != Step.Setup) {
        step = if (step == Step.Setup) Step.Setup else
            if (step == Step.Choose) Step.Setup else Step.Choose
    }

    when (step) {
        Step.Setup -> SetupScreen(model) { step = Step.Choose }
        Step.Choose -> ChooseScreen(
            model = model,
            onStartOwn = { step = Step.Garden; tab = 0 },
            onHaveInvite = { step = Step.Join },
            onTestnet = onTestnet,
            onBack = { step = Step.Setup },
        )
        Step.Join -> Column(modifier = Modifier.fillMaxSize()) {
            TopBar("Join a network") { step = Step.Choose }
            JoinScreen(model)
        }
        Step.Garden -> Column(modifier = Modifier.fillMaxSize()) {
            TopBar("My network") { step = Step.Choose }
            // Sending data is the first tab because it is the reason the
            // network exists; the invite and the state of the group come
            // after it.
            val titles = listOf("Data", "Invite", "Status")
            TabRow(selectedTabIndex = tab) {
                titles.forEachIndexed { index, title ->
                    Tab(
                        selected = tab == index,
                        onClick = { tab = index },
                        text = { Text(title) },
                    )
                }
            }
            when (tab) {
                0 -> if (model.state.status.contains("\"chain_id\"")) {
                    DataScreen(model)
                } else {
                    InviteScreen(model) { step = Step.Join }
                }
                1 -> InviteScreen(model) { step = Step.Join }
                else -> StatusScreen(model)
            }
        }
    }
}

/** A title with the way back next to it, on every screen that has one. */
@Composable
private fun TopBar(title: String, onBack: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        TextButton(onClick = onBack) { Text("Back") }
        Text(title.uppercase(), style = MaterialTheme.typography.labelSmall)
    }
}

/**
 * Section 2.5: the link, the QR and a way to share them.
 */
@Composable
private fun InviteScreen(model: GardenModel, onJoinInstead: () -> Unit) {
    val context = LocalContext.current
    val state = model.state
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (state.record.isEmpty()) {
            // The old version of this screen opened on an empty box
            // labelled "Name of the Garden" and nothing else. There was no
            // way to know that the name is simply what you decide to call
            // a group you are starting, or that somebody who was invited
            // should not be here at all.
            Text("This phone is in no network yet.", style = MaterialTheme.typography.bodyLarge)
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text("WERE YOU INVITED?", style = MaterialTheme.typography.labelSmall)
                    Text(
                        "Then you do not need to name anything. Go to Join, scan " +
                            "the code you were sent or paste the invite, and this " +
                            "phone joins the Garden that already exists.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedButton(
                        onClick = onJoinInstead,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("I have an invite") }
                }
            }
            Text("OR START ONE", style = MaterialTheme.typography.labelSmall)
            Text(
                "Your network is a group of phones carrying data for each " +
                    "other. Starting one makes this phone the first validator " +
                    "and the host; the others join by invite. Nothing is " +
                    "issued and nothing is owed - the group checks blocks and " +
                    "holds a share of what it sends.",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "The name is only how the group recognises it. Pick anything, " +
                    "like the place you are in.",
                style = MaterialTheme.typography.bodySmall,
            )
            var title by remember { mutableStateOf("") }
            OutlinedTextField(
                value = title,
                onValueChange = { title = it },
                label = { Text("Call it something") },
                placeholder = { Text("Kitchen table") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = { model.create(title.trim()) },
                enabled = title.isNotBlank() && !state.busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (state.busy) "Starting..." else "Start my network") }
        } else {
            Text("Anyone who has this can join.", style = MaterialTheme.typography.bodyLarge)
            qrBitmap(state.recordQr)?.let { bitmap ->
                Image(
                    bitmap = bitmap.asImageBitmap(),
                    contentDescription = "Invite QR code",
                    modifier = Modifier.size(260.dp),
                )
            }
            Card(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = state.record,
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Text(
                "Good until ${state.expiry}. Seats left on this invite: ${state.uses}.",
                style = MaterialTheme.typography.bodySmall,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        val share = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_TEXT, model.shareText())
                        }
                        context.startActivity(Intent.createChooser(share, "Share the invite"))
                    },
                    modifier = Modifier.weight(1f),
                ) { Text("Share") }
                OutlinedButton(
                    onClick = { model.refreshInvite() },
                    enabled = !state.busy,
                    modifier = Modifier.weight(1f),
                ) { Text("New invite") }
            }
        }
        if (state.message.isNotEmpty()) {
            Text(state.message, style = MaterialTheme.typography.bodySmall)
        }
    }
}

/**
 * Section 2.6: scan a QR, paste an invite, confirm.
 */
@Composable
private fun JoinScreen(model: GardenModel) {
    val state = model.state
    var pasted by remember { mutableStateOf("") }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Button(
            onClick = { model.scan() },
            enabled = !state.busy,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Scan a QR code") }
        OutlinedTextField(
            value = pasted,
            onValueChange = {
                pasted = it
                model.preview(it)
            },
            label = { Text("Or paste an invite") },
            modifier = Modifier.fillMaxWidth(),
        )
        if (state.preview.isNotEmpty()) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("You were invited by", style = MaterialTheme.typography.bodySmall)
                    Text(state.preview, style = MaterialTheme.typography.bodyMedium)
                }
            }
            // Section 5.12: an invite that arrived by a deliberate act is
            // confirmed with one tap, and nothing happens without it.
            Button(
                onClick = { model.join(pasted) },
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Join this Garden") }
        }
        if (state.message.isNotEmpty()) {
            Text(state.message, style = MaterialTheme.typography.bodySmall)
        }
    }
}

/**
 * Section 2.7: the self test result, the Garden status, the validator
 * counters, and the button that leaves.
 */
@Composable
private fun StatusScreen(model: GardenModel) {
    val state = model.state
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text("Self test", style = MaterialTheme.typography.titleMedium)
                state.selfTest.forEach { step ->
                    Text(
                        text = (if (step.passed) "ok   " else "FAIL ") + step.name +
                            (if (step.detail.isEmpty()) "" else " - " + step.detail),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Text(
                    "Took ${state.selfTestMs} ms.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
        GardenCard(state.status)
        PermissionCard(model)
        Spacer(modifier = Modifier.height(4.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { model.refreshStatus() },
                enabled = !state.busy,
                modifier = Modifier.weight(1f),
            ) { Text("Refresh") }
            Button(
                onClick = { model.leave() },
                enabled = !state.busy && state.record.isNotEmpty(),
                modifier = Modifier.weight(1f),
            ) { Text("Leave") }
        }
        // A phone that left keeps its seat until it leaves a second time,
        // and the answer says so. The way back belongs on the screen that
        // said goodbye, not in another scan of an invite the person who
        // left may no longer have.
        if (state.status.contains("\"can_return\":true")) {
            Button(
                onClick = { model.returnToGarden() },
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Return to the Garden") }
        }
        if (state.message.isNotEmpty()) {
            Text(state.message, style = MaterialTheme.typography.bodySmall)
        }
    }
}

/**
 * Draw the QR a scanner reads. The content is whatever the core handed
 * back, so the phone never invents an invite of its own.
 */
/**
 * What Android is allowing, after the way in.
 *
 * Permissions are not a thing you grant once at the start: a person
 * revokes notifications a week later, or a manufacturer's cleaner app
 * restricts the battery on its own. The validator would then go quiet
 * with nothing on screen to say why, so the state stays visible and
 * fixable from the screen that reports the work.
 */
@Composable
private fun PermissionCard(model: GardenModel) {
    val context = LocalContext.current
    val ready = model.state.readiness
    if (ready.notifications && ready.batteryUnrestricted) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text("ANDROID", style = MaterialTheme.typography.labelSmall)
                Text(
                    "Notifications allowed, background work not restricted.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
        return
    }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("ANDROID IS IN THE WAY", style = MaterialTheme.typography.labelSmall)
            if (!ready.notifications) {
                Text(
                    "Notifications are off, so the validator cannot keep running " +
                        "once you leave the app.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Button(
                    onClick = { model.askForNotifications() },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Allow notifications") }
            }
            if (!ready.batteryUnrestricted) {
                Text(
                    "Background work is restricted for this app. The Garden will " +
                        "suspend this seat if the phone keeps going absent.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(ready.batteryPath, style = MaterialTheme.typography.bodySmall)
                OutlinedButton(
                    onClick = { context.startActivity(GardenReadiness.batterySettings(context)) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Open battery settings") }
            }
        }
    }
}

/**
 * The Garden as a person reads it, not as the core writes it.
 *
 * The answer is JSON because the core speaks one language to the app, the
 * node and the tests alike. A screen is not a log: the fields that say
 * whether this phone is doing its job are pulled out and named, and the
 * raw answer stays available underneath for when something is wrong.
 */
@Composable
private fun GardenCard(status: String) {
    val garden = remember(status) {
        runCatching { JSONObject(status).optJSONObject("garden") }.getOrNull()
    }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            if (garden == null) {
                Text("GARDEN", style = MaterialTheme.typography.labelSmall)
                Text("This phone is in no Garden.", style = MaterialTheme.typography.bodyMedium)
                return@Column
            }
            Text(
                garden.optString("title").ifBlank { "GARDEN" }.uppercase(),
                style = MaterialTheme.typography.labelSmall,
            )
            val state = garden.optString("status")
            Text(
                when (state) {
                    "Away" -> "Stepped out. The seat is kept."
                    "" -> "This phone is in no Garden."
                    else -> "Validating in the background."
                },
                style = MaterialTheme.typography.bodyLarge,
            )
            if (state != "Away" && state.isNotEmpty()) {
                Line("Block", garden.optLong("height", 0).toString())
                Line("Validators", garden.optInt("active_validators", 0).toString())
                Line("Connected", garden.optInt("connected_peers", 0).toString())
                val work = garden.optJSONObject("work")
                Line("Parts held", (work?.optLong("parts_held", 0) ?: 0).toString())
                Line("Blocks checked", (work?.optLong("blocks_executed", 0) ?: 0).toString())
                val me = garden.optJSONObject("me")
                if (me != null) {
                    Line("This phone", me.optString("name") + " - " + me.optString("member"))
                }
            }
            Line("Chain", garden.optString("chain_id"))
        }
    }
}

/** One named value, the way the design file sets a label against a row. */
@Composable
private fun Line(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label.uppercase(), style = MaterialTheme.typography.labelSmall)
        Text(value, style = MaterialTheme.typography.bodySmall)
    }
}

private fun qrBitmap(content: String): Bitmap? {
    if (content.isEmpty()) {
        return null
    }
    return runCatching {
        val size = 512
        val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size)
        val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
        for (x in 0 until size) {
            for (y in 0 until size) {
                bitmap.setPixel(x, y, if (matrix.get(x, y)) Color.BLACK else Color.WHITE)
            }
        }
        bitmap
    }.getOrNull()
}
