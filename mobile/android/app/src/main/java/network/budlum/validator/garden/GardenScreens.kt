package network.budlum.validator.garden

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.json.JSONObject

/**
 * The Garden app: the shell, the rail and the screens that hang off it.
 *
 * The shape is the one measured from the design file (Figma
 * `7tASYNmfotWyIrXpJ4ktrW`, page `43:26870`): a narrow rail of line marks
 * down the left, one content column to the right of it, and every piece of
 * content in a 16 px panel with an uppercase label over it. The rail is
 * the way between screens, so nothing is ever more than one tap away and
 * no screen is a dead end.
 *
 * What the screens may say is fixed by the directive: the invite, the join
 * and the status, plus the requirements before a seat. The home panel is
 * not a fourth duty - it is the status of the whole phone at a glance,
 * which is what a person opens the app to see.
 */
@Composable
fun GardenApp(model: GardenModel, onTestnet: () -> Unit) {
    var step by remember { mutableStateOf(Step.Setup) }
    var mark by remember { mutableStateOf(GardenMark.Sparkle) }

    // A phone that already holds a seat opens on its Garden. The seat
    // survives the process, so a person who set the phone up once was
    // walking Setup and Choose again on every open just to reach the
    // home panel they already had. The jump happens once per launch:
    // after it, Back still walks to Choose and Setup, and staying
    // there is respected rather than snapped away from.
    var landed by remember { mutableStateOf(false) }

    // A code read by the camera is answered on the Join screen, because that
    // is the screen that says whose Garden it is and asks for the tap.
    LaunchedEffect(model.state.scanTaken) {
        if (model.state.scanTaken) {
            step = Step.Garden
            mark = GardenMark.Join
        }
    }
    LaunchedEffect(model.state.status) {
        if (!landed && GardenSeat.seated(model.state.status)) {
            landed = true
            if (step == Step.Setup) {
                step = Step.Garden
                mark = GardenMark.Sparkle
            }
        }
    }

    // Every step can be left the way it was entered. Before this the app
    // went forward only: a person who reached the Garden screens had no
    // way back to the requirements, and the system gesture closed the app
    // instead of stepping back.
    BackHandler(enabled = step != Step.Setup) {
        step = if (step == Step.Garden) Step.Choose else Step.Setup
    }

    when (step) {
        Step.Setup -> SetupScreen(model) { step = Step.Choose }
        Step.Choose -> ChooseScreen(
            model = model,
            onGarden = { step = Step.Garden },
            onTestnet = onTestnet,
            onBack = { step = Step.Setup },
        )
        Step.Garden -> Row(modifier = Modifier.fillMaxSize()) {
            GardenRail(
                current = mark,
                marks = GardenMark.entries,
                onChoose = { mark = it },
            )
            Column(modifier = Modifier.fillMaxSize()) {
                GardenHeader(
                    title = headerTitle(mark),
                    subtitle = headerSubtitle(mark, model.state),
                )
                Box(modifier = Modifier.fillMaxSize()) {
                    when (mark) {
                        GardenMark.Sparkle -> HomeScreen(model, onInvite = { mark = GardenMark.Invite })
                        GardenMark.Invite -> InviteScreen(model, onJoinInstead = { mark = GardenMark.Join })
                        GardenMark.Join -> JoinScreen(model)
                        GardenMark.Chain -> StatusScreen(model)
                        GardenMark.Storage -> DataScreen(model)
                        GardenMark.Phone -> SetupScreen(model) {}
                    }
                }
            }
        }
    }
}

private fun headerTitle(mark: GardenMark): String = when (mark) {
    GardenMark.Sparkle -> "Garden"
    GardenMark.Invite -> "Invite"
    GardenMark.Join -> "Join"
    GardenMark.Chain -> "Status"
    GardenMark.Storage -> "Data"
    GardenMark.Phone -> "Setup"
}

private fun headerSubtitle(mark: GardenMark, state: GardenState): String = when (mark) {
    GardenMark.Sparkle -> if (state.record.isEmpty()) "no Garden yet" else "this phone is a validator"
    GardenMark.Invite -> "one link, one code"
    GardenMark.Join -> "scan or paste"
    GardenMark.Chain -> "this phone and its block"
    GardenMark.Storage -> "what this phone holds"
    GardenMark.Phone -> "what Android must allow"
}

/**
 * The head of every screen: the name of the screen, and one line that says
 * what it is about. A screen without a head is a wall of text, which is
 * what these were.
 */
@Composable
private fun GardenHeader(title: String, subtitle: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(
                start = GardenDesignTokens.gutter,
                end = GardenDesignTokens.gutter,
                top = GardenDesignTokens.gutter,
                bottom = 4.dp,
            ),
    ) {
        Text(title, style = MaterialTheme.typography.headlineSmall, color = GardenDesignTokens.ink)
        GardenCaption(subtitle)
    }
}

/**
 * The whole phone in one panel: seated or not, and if seated, the line
 * that says whether the work is running.
 *
 * This is the screen a person actually opens the app for. Before it the
 * app opened on an invitation box even after a Garden existed, so the
 * first thing a returning person saw was an instruction to start another
 * one.
 */
@Composable
private fun HomeScreen(model: GardenModel, onInvite: () -> Unit) {
    val state = model.state
    val garden = remember(state.status) {
        runCatching { JSONObject(state.status).optJSONObject("garden") }.getOrNull()
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = GardenDesignTokens.gutter)
            .padding(bottom = GardenDesignTokens.gutter),
        verticalArrangement = Arrangement.spacedBy(GardenDesignTokens.gap),
    ) {
        GardenPanel(outlined = garden == null) {
            GardenLabel(if (garden == null) "NOT IN A GARDEN" else "THIS PHONE")
            if (garden == null) {
                GardenHeading("Start one, or join someone else's")
                GardenBody(
                    "A Garden is a small chain run by phones that know each other. " +
                        "This phone checks every block and keeps a share of what the group stores.",
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = onInvite, modifier = Modifier.weight(1f)) {
                        Text("Start one")
                    }
                    OutlinedButton(onClick = onInvite, modifier = Modifier.weight(1f)) {
                        Text("I was invited")
                    }
                }
            } else {
                GardenHeading(garden.optString("title").ifBlank { "Untitled Garden" })
                GardenBody(gardenSentence(garden.optString("status")))
                GardenMeta(
                    listOf(
                        "block " + garden.optLong("height", 0),
                        garden.optInt("active_validators", 0).toString() + " validators",
                        garden.optInt("connected_peers", 0).toString() + " peers",
                        "chain " + garden.optString("chain_id").take(8),
                    ),
                )
            }
        }
        if (garden != null) {
            GardenPanel {
                GardenLabel("WORK")
                GardenStat("Parts held", workLong(garden, "parts_held").toString())
                GardenStat("Blocks checked", workLong(garden, "blocks_executed").toString())
                GardenStat("Objects stored", garden.optInt("objects", 0).toString())
                GardenStat("Pending", garden.optInt("pending_transactions", 0).toString())
            }
            GardenPanel {
                GardenLabel("WHAT HAPPENS NEXT")
                GardenBody(
                    "Invite the phones that should hold a share, and leave this screen " +
                        "when you are done: the validator keeps running with the app closed, " +
                        "and the notification says which block it is on.",
                )
            }
        }
        if (state.message.isNotEmpty()) {
            GardenNote(state.message)
        }
    }
}

/**
 * Data: the feed this phone would read, stated as a limit rather than
 * shown.
 *
 * Section 2.8 keeps message, post and trace out of the app, so there is no
 * feed screen and no message box. What a person can still be told is what
 * this phone is holding, which is a counter and not content.
 */
@Composable
private fun DataScreen(model: GardenModel) {
    val garden = remember(model.state.status) {
        runCatching { JSONObject(model.state.status).optJSONObject("garden") }.getOrNull()
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = GardenDesignTokens.gutter)
            .padding(bottom = GardenDesignTokens.gutter),
        verticalArrangement = Arrangement.spacedBy(GardenDesignTokens.gap),
    ) {
        GardenPanel {
            GardenLabel("STORED HERE")
            if (garden == null) {
                GardenBody("This phone holds nothing: it is in no Garden.")
            } else {
                GardenStat("Objects", garden.optInt("objects", 0).toString())
                GardenStat("Wanted here", garden.optInt("objects_wanted_here", 0).toString())
                GardenStat("Bytes stored", garden.optLong("stored_object_bytes", 0).toString())
                GardenStat("Parts held", workLong(garden, "parts_held").toString())
            }
        }
        GardenPanel(outlined = true) {
            GardenLabel("READING CONTENT")
            GardenBody(
                "The app does not read messages or posts. This phone stores and serves " +
                    "shares for the Garden, and an object is read back where it is written, " +
                    "by the core, not from this screen.",
            )
        }
        if (model.state.message.isNotEmpty()) {
            GardenNote(model.state.message)
        }
    }
}

/**
 * Section 2.5: the link, the QR and a way to share them.
 *
 * The empty state is the front door for a person who was invited, and the
 * one thing it does is send them to Join. Starting a Garden is the other
 * door, and its name field says what the name is for.
 */
@Composable
private fun InviteScreen(model: GardenModel, onJoinInstead: () -> Unit) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val state = model.state
    var copied by remember { mutableStateOf(false) }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = GardenDesignTokens.gutter)
            .padding(bottom = GardenDesignTokens.gutter),
        verticalArrangement = Arrangement.spacedBy(GardenDesignTokens.gap),
    ) {
        if (state.record.isEmpty()) {
            GardenPanel {
                GardenLabel("WERE YOU INVITED?")
                GardenHeading("Then nothing here has to be named")
                GardenBody(
                    "Scan the code you were sent or paste the invite. This phone joins " +
                        "the Garden that already exists, and the person who invited you " +
                        "is named before you agree.",
                )
                OutlinedButton(onClick = onJoinInstead, modifier = Modifier.fillMaxWidth()) {
                    Text("I have an invite")
                }
            }
            var title by remember { mutableStateOf("") }
            GardenPanel(outlined = true) {
                GardenLabel("OR START ONE")
                GardenHeading("Name the group")
                GardenBody(
                    "Starting one makes this phone its first validator and its host. " +
                        "The name is only how the group recognises it; pick anything, " +
                        "like the place you are in.",
                )
                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text("Garden name") },
                    placeholder = { Text("Kitchen table") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = { model.create(title.trim()) },
                    enabled = title.isNotBlank() && !state.busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(if (state.busy) "Starting..." else "Start a Garden") }
            }
        } else {
            GardenPanel(outlined = true) {
                GardenLabel("INVITE")
                GardenHeading("Anyone with this can join")
                qrBitmap(state.recordQr)?.let { bitmap ->
                    Image(
                        bitmap = bitmap.asImageBitmap(),
                        contentDescription = "Invite QR code",
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(GardenDesignTokens.panelRadius)),
                    )
                }
                GardenMeta(
                    listOf(
                        "good until " + state.expiry,
                        "seats left " + state.uses,
                    ),
                )
            }
            GardenPanel {
                GardenLabel("LINK")
                Text(
                    text = state.record,
                    style = MaterialTheme.typography.bodySmall,
                    color = GardenDesignTokens.ink,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = {
                            clipboard.setText(AnnotatedString(model.shareText()))
                            copied = true
                        },
                        modifier = Modifier.weight(1f),
                    ) { Text(if (copied) "Copied" else "Copy") }
                    OutlinedButton(
                        onClick = {
                            val share = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_TEXT, model.shareText())
                            }
                            context.startActivity(Intent.createChooser(share, "Share the invite"))
                        },
                        modifier = Modifier.weight(1f),
                    ) { Text("Share") }
                }
                TextButton(
                    onClick = { model.refreshInvite() },
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Make a new invite") }
            }
        }
        if (state.message.isNotEmpty()) {
            GardenNote(state.message)
        }
    }
}

/**
 * Section 2.6: scan a QR, paste an invite, confirm.
 *
 * The preview states who is inviting and until when before the confirm
 * button exists. A person who pasted the wrong record finds out there,
 * not after a seat was taken.
 */
@Composable
private fun JoinScreen(model: GardenModel) {
    val state = model.state
    var pasted by remember { mutableStateOf("") }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = GardenDesignTokens.gutter)
            .padding(bottom = GardenDesignTokens.gutter),
        verticalArrangement = Arrangement.spacedBy(GardenDesignTokens.gap),
    ) {
        GardenPanel {
            GardenLabel("SCAN")
            GardenBody("Point the camera at the code of the person who invited you.")
            Button(
                onClick = { model.scan() },
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Scan a QR code") }
        }
        GardenPanel {
            GardenLabel("OR PASTE")
            OutlinedTextField(
                value = pasted,
                onValueChange = {
                    pasted = it
                    model.preview(it)
                },
                label = { Text("Invite link or code") },
                modifier = Modifier.fillMaxWidth(),
            )
            if (state.preview.isNotEmpty()) {
                GardenMeta(listOf(state.preview))
            }
            if (state.previewRecord.isNotEmpty()) {
                // Section 5.12: an invite that arrived by a deliberate act
                // is confirmed with one tap, and nothing happens without it.
                Button(
                    onClick = { model.join(state.previewRecord) },
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Join this Garden") }
            }
        }
        if (state.message.isNotEmpty()) {
            GardenNote(state.message)
        }
    }
}

/**
 * Section 2.7: the self test result, the Garden status, the validator
 * counters, and the button that leaves.
 *
 * Leave asks first. It used to act on one tap, and a tap on the wrong row
 * is how a seat gets given up by accident.
 */
@Composable
private fun StatusScreen(model: GardenModel) {
    val state = model.state
    var askingToLeave by remember { mutableStateOf(false) }
    val garden = remember(state.status) {
        runCatching { JSONObject(state.status).optJSONObject("garden") }.getOrNull()
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = GardenDesignTokens.gutter)
            .padding(bottom = GardenDesignTokens.gutter),
        verticalArrangement = Arrangement.spacedBy(GardenDesignTokens.gap),
    ) {
        GardenPanel(outlined = garden == null) {
            GardenLabel("GARDEN")
            if (garden == null) {
                GardenHeading("This phone is in no Garden")
                GardenBody("Start one from Invite, or join one from Join.")
            } else {
                GardenHeading(garden.optString("title").ifBlank { "Untitled Garden" })
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    GardenPill(
                        text = garden.optString("status").ifBlank { "unknown" },
                        active = garden.optString("status") == "Active",
                    )
                    GardenCaption(gardenSentence(garden.optString("status")))
                }
                Spacer(modifier = Modifier.size(2.dp))
                GardenStat("Block", garden.optLong("height", 0).toString())
                GardenStat("Validators", garden.optInt("active_validators", 0).toString())
                GardenStat("Connected", garden.optInt("connected_peers", 0).toString())
                GardenStat("Parts held", workLong(garden, "parts_held").toString())
                GardenStat("Blocks checked", workLong(garden, "blocks_executed").toString())
                val me = garden.optJSONObject("me")
                if (me != null) {
                    GardenStat(
                        "This phone",
                        me.optString("name") + " - " +
                            if (me.optBoolean("host")) "host" else "validator",
                    )
                    GardenStat("Seat", me.optString("member").ifBlank { "unknown" })
                }
                GardenStat("Chain", garden.optString("chain_id"))
            }
        }
        GardenPanel {
            GardenLabel("SELF TEST")
            if (state.selfTest.isEmpty()) {
                GardenCaption("Running...")
            } else {
                state.selfTest.forEach { step ->
                    GardenStat(
                        step.name,
                        if (step.passed) "ok" else "failed",
                    )
                }
                GardenMeta(listOf("took " + state.selfTestMs + " ms", "no network used"))
            }
        }
        PermissionCard(model)
        GardenPanel {
            GardenLabel("THIS SEAT")
            GardenBody(
                if (garden != null && garden.optString("status") == "Away") {
                    "The seat is kept while this phone is away. Returning puts the " +
                        "validator back on the network; leaving again gives the Garden up."
                } else {
                    "Leaving keeps the seat once, so this phone can come back without a " +
                        "new invite. Leaving a second time gives the Garden up for good."
                },
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { model.refreshStatus() },
                    enabled = !state.busy,
                    modifier = Modifier.weight(1f),
                ) { Text("Refresh") }
                Button(
                    onClick = { askingToLeave = true },
                    enabled = !state.busy && garden != null,
                    modifier = Modifier.weight(1f),
                ) { Text("Leave") }
            }
            // A phone that left keeps its seat until it leaves a second
            // time, and the answer says so. The way back belongs on the
            // screen that said goodbye.
            if (GardenSeat.canReturn(state.status) || GardenSeat.away(state.status)) {
                Button(
                    onClick = { model.returnToGarden() },
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Return to the Garden") }
            }
        }
        if (state.message.isNotEmpty()) {
            GardenNote(state.message)
        }
    }
    if (askingToLeave) {
        AlertDialog(
            onDismissRequest = { askingToLeave = false },
            title = { Text("Leave this Garden?") },
            text = {
                Text(
                    "The first leave keeps the seat, so this phone can come back. " +
                        "A second leave gives the Garden up and wipes it from this phone.",
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        askingToLeave = false
                        model.leave()
                    },
                ) { Text("Leave") }
            },
            dismissButton = {
                TextButton(onClick = { askingToLeave = false }) { Text("Stay") }
            },
        )
    }
}

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
        GardenPanel {
            GardenLabel("ANDROID")
            GardenStat("Notifications", "allowed")
            GardenStat("Background work", "not restricted")
        }
        return
    }
    GardenPanel(outlined = true) {
        GardenLabel("ANDROID IS IN THE WAY")
        if (!ready.notifications) {
            GardenBody(
                "Notifications are off, so the validator cannot keep running once " +
                    "you leave the app.",
            )
            Button(
                onClick = { model.askForNotifications() },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Allow notifications") }
        }
        if (!ready.batteryUnrestricted) {
            GardenBody(
                "Background work is restricted for this app. The Garden will suspend " +
                    "this seat if the phone keeps going absent.",
            )
            GardenMeta(listOf(ready.batteryPath))
            OutlinedButton(
                onClick = { context.startActivity(GardenReadiness.batterySettings(context)) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Open battery settings") }
        }
    }
}

/**
 * One sentence for the status word the core answers with.
 *
 * It is internal and not private so the JVM test in `app/src/test` can pin
 * each word: a wrong sentence here is a wrong claim about what the phone is
 * doing, and the test is cheaper than noticing it on a screen.
 */
internal fun gardenSentence(status: String): String = when (status) {
    "Active" -> "Validating in the background."
    "Away" -> "Stepped out. The seat is kept."
    "Suspended" -> "Suspended: this phone has been absent too long."
    "Waiting" -> "Waiting for the host to admit this phone."
    "" -> "This phone is in no Garden."
    else -> status
}

/** One work counter out of the nested `work` object. */
private fun workLong(garden: JSONObject, key: String): Long =
    garden.optJSONObject("work")?.optLong(key, 0) ?: 0

/**
 * A note under the panels: what just happened, or why something did not.
 *
 * It is a panel of its own and not a line of small text, because the
 * messages here are the only place a refusal explains itself.
 */
@Composable
private fun GardenNote(text: String) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 2.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp),
        ) {
            GardenCaption(text, tone = GardenDesignTokens.ink)
        }
    }
}

/**
 * Draw the QR a scanner reads. The content is whatever the core handed
 * back, so the phone never invents an invite of its own.
 */
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
