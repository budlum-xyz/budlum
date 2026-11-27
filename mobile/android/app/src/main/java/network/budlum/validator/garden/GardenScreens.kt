package network.budlum.validator.garden

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import network.budlum.validator.R
import org.json.JSONObject

/**
 * The app, which is three places: the room, the people, and the work.
 *
 * It used to be Room, Invite and Status, and the Invite tab opened on
 * four paragraphs explaining what a network is. The sheets do not
 * explain anything - they put a thing on screen and name it in one
 * lowercase word. Everything that was a paragraph here is now a label
 * and a value, and the invite is six digits on the people screen,
 * beside the people it is for.
 */
@Composable
fun GardenApp(model: GardenModel, onTestnet: () -> Unit) {
    var step by remember { mutableStateOf(Step.Setup) }
    // Whether this phone holds a wallet, and which address it is, asked
    // once when the app opens rather than on every draw.
    LaunchedEffect(Unit) { model.readWallet() }
    var tab by remember { mutableStateOf(0) }

    BackHandler(enabled = step != Step.Setup) {
        step = when (step) {
            Step.Choose, Step.Wallet -> Step.Setup
            // The words are shown once. Going back out of them without
            // saying they are written down would be a way to lose a
            // wallet by pressing a system button, so that door stays
            // shut and the screen's own button is the only way on.
            Step.Seed -> Step.Seed
            // Same reason: backing out of the check would leave a
            // wallet whose words were never confirmed, and the words
            // are gone from this screen onward.
            Step.SeedVerify -> Step.SeedVerify
            else -> Step.Choose
        }
    }

    when (step) {
        // The validator checks pass first, then the key. A phone that
        // cannot do the duties has no use for a wallet, and a phone that
        // already holds one is not asked twice.
        Step.Setup -> SetupScreen(model) {
            step = if (model.state.walletExists) Step.Choose else Step.Wallet
        }
        Step.Wallet -> {
            // The same door serves both states, told apart by what was
            // true when it opened rather than by what is true now: a
            // phone that already had a wallet is shown it, and a phone
            // that did not is asked to make one and then moved on. If
            // the two were told apart by the live value instead, making
            // a wallet would turn this into the other screen mid-visit.
            // There is no list in either case, because there is never
            // more than one wallet.
            val hadOneAlready = remember { model.state.walletExists }
            if (hadOneAlready) {
                WalletScreen(model)
            } else {
                WalletStartScreen(model)
                // Words arriving is what means a wallet was just made,
                // so moving to the screen that shows them is an effect
                // of that rather than a decision taken while drawing.
                val madeNow = model.state.mnemonic.isNotEmpty()
                val restoredNow = model.state.walletExists && !madeNow
                LaunchedEffect(madeNow, restoredNow) {
                    if (madeNow) {
                        step = Step.Seed
                    } else if (restoredNow) {
                        step = Step.Choose
                    }
                }
            }
        }
        Step.Seed -> SeedPhraseScreen(model) { step = Step.SeedVerify }
        Step.SeedVerify -> SeedVerifyScreen(model) { step = Step.Choose }
        Step.Choose -> ChooseScreen(
            model = model,
            onStartOwn = { step = Step.Garden; tab = 0 },
            onHaveInvite = { step = Step.Join },
            onTestnet = onTestnet,
            onWallet = { step = Step.Wallet },
            onBack = { step = Step.Setup },
        )
        Step.Join -> CubeFloor(model.skin) {
            Column(modifier = Modifier.fillMaxSize()) {
                TopBar(stringResource(R.string.g_join_network)) { step = Step.Choose }
                CodeJoinScreen(model)
                // Asking got this phone into the waiting row, so the
                // join screen has done its job and the people screen
                // is where the host's answer will show up. Moving on
                // is an effect of the key arriving, not something
                // decided while drawing - a screen that reassigns its
                // own state mid-draw redraws forever.
                val seated = model.state.myKey.isNotEmpty()
                LaunchedEffect(seated) {
                    if (seated) {
                        step = Step.Garden
                        tab = 1
                    }
                }
            }
        }
        Step.Garden -> CubeFloor(model.skin) {
            Column(modifier = Modifier.fillMaxSize()) {
                TopBar(stringResource(R.string.g_my_network), model) { step = Step.Choose }
                val titles = listOf(
                    stringResource(R.string.g_room),
                    stringResource(R.string.g_people),
                    stringResource(R.string.g_status),
                )
                TabRow(
                    selectedTabIndex = tab,
                    containerColor = Color.Transparent,
                    contentColor = Ink,
                ) {
                    titles.forEachIndexed { index, title ->
                        Tab(
                            selected = tab == index,
                            onClick = { tab = index },
                            text = { Label(title, color = if (tab == index) Ink else Mute) },
                        )
                    }
                }
                when (tab) {
                    0 -> ChatScreen(model)
                    1 -> PeopleScreen(model)
                    else -> WorkScreen(model)
                }
            }
        }
    }
}

/**
 * The wordmark, the way back, and the three skins.
 *
 * The switch is the one in the sheets at 186:44: three squares, white,
 * black and sage, and the floor changes under everything. It is the one
 * ornament the design actually asks for.
 */
@Composable
private fun TopBar(title: String, model: GardenModel? = null, onBack: () -> Unit) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp, bottom = 4.dp),
            contentAlignment = Alignment.Center,
        ) {
            Image(
                painter = painterResource(R.drawable.budlum_wordmark),
                contentDescription = "Budlum",
                modifier = Modifier.height(20.dp),
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Label(stringResource(R.string.g_back), modifier = Modifier.clickable(onClick = onBack))
                if (model != null) SkinSwitch(model)
            }
        }
        Label(title, modifier = Modifier.padding(start = 14.dp, bottom = 6.dp))
        Rule()
    }
}

/** Three squares. Tapping one changes the floor. */
@Composable
private fun SkinSwitch(model: GardenModel) {
    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        Skin.entries.forEach { skin ->
            Box(
                modifier = Modifier
                    .size(16.dp)
                    .background(skin.behind, RectangleShape)
                    .border(
                        1.dp,
                        if (model.skin == skin) Ink else Faint,
                        RectangleShape,
                    )
                    .clickable { model.skin = skin },
            )
        }
    }
}

/**
 * What this phone is doing for the group.
 *
 * Four numbers, because four are the ones that answer the question
 * people actually ask - how can a phone hold what the network sends?
 * It does not hold all of it. An object is coded into segments, each
 * segment into repair symbols, and the placement table puts each
 * segment on three validators out of however many there are. This
 * phone holds its share, serves it when asked, and the counters say
 * how much.
 */
@Composable
private fun WorkScreen(model: GardenModel) {
    val state = model.state
    // stored_object_bytes sits beside work, not inside it - the disk is
    // the node's, the counters are the work's.
    val garden = runCatching {
        JSONObject(state.status).optJSONObject("garden")
    }.getOrNull()
    val work = garden?.optJSONObject("work")
    val bud3 = work?.optJSONObject("bud3")

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        Slab(modifier = Modifier.fillMaxWidth()) {
            Column {
                Fact(
                    stringResource(R.string.g_parts_held),
                    (work?.optLong("parts_held") ?: 0L).toString(),
                )
                Rule()
                Fact(
                    stringResource(R.string.g_stored),
                    megabytes(garden?.optLong("stored_object_bytes") ?: 0L),
                )
                Rule()
                Fact(
                    stringResource(R.string.g_coded),
                    (bud3?.optLong("objects_coded") ?: 0L).toString(),
                )
                Rule()
                Fact(
                    stringResource(R.string.g_symbols),
                    (bud3?.optLong("symbols_made") ?: 0L).toString(),
                )
                Rule()
                Fact(
                    stringResource(R.string.g_validators),
                    (garden?.optInt("active_validators") ?: 0).toString(),
                )
            }
        }
        Rule()
        PermissionRows(model)
        Rule()
        Row(
            modifier = Modifier.padding(14.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RuleButton(
                text = stringResource(R.string.g_leave),
                onTap = { model.leave() },
                enabled = !state.busy && state.record.isNotEmpty(),
                rule = Flow,
                ink = Flow,
            )
        }
        if (state.message.isNotEmpty()) {
            Label(state.message, color = Flow, modifier = Modifier.padding(14.dp))
        }
    }
}

/** Bytes as a person reads them. */
private fun megabytes(bytes: Long): String = when {
    bytes <= 0 -> "0"
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "${bytes / 1024} KB"
    else -> "${bytes / 1024 / 1024} MB"
}

/**
 * What Android is allowing, as rows rather than a card of prose.
 *
 * A person revokes notifications a week later, or a cleaner app
 * restricts the battery on its own, and the validator goes quiet with
 * nothing on screen to say why. Two rows, each with a way to fix it.
 */
@Composable
private fun PermissionRows(model: GardenModel) {
    val context = LocalContext.current
    val ready = model.state.readiness
    if (ready.notifications && ready.batteryUnrestricted) return
    Column {
        if (!ready.notifications) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Label(stringResource(R.string.g_notifications_off), color = Flow)
                RuleButton(stringResource(R.string.g_fix), onTap = { model.askForNotifications() })
            }
        }
        if (!ready.batteryUnrestricted) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Label(stringResource(R.string.g_battery_limited), color = Flow)
                RuleButton(
                    stringResource(R.string.g_fix),
                    onTap = {
                        context.startActivity(
                            Intent(
                                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                Uri.fromParts("package", context.packageName, null),
                            ),
                        )
                    },
                )
            }
        }
    }
}

// The palette lives in GardenTheme, which already measured it from the
// design file. Naming it twice is how two screens drift apart.
