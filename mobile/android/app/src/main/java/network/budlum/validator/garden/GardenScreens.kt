package network.budlum.validator.garden

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import network.budlum.validator.R
import org.json.JSONObject

/**
 * Root Budlum Garden navigator.
 *
 * Routes returning validators straight to their active Garden, honours incoming
 * deep-links, guards seed screens with FLAG_SECURE, animates transitions with
 * Figma's 320ms cubic-bezier easing, and eliminates stacked duplicate chrome.
 */
@Composable
fun GardenApp(
    model: GardenModel,
    onSecureScreen: (Boolean) -> Unit = {},
    onTestnet: () -> Unit,
) {
    val state = model.state
    val skin = model.skin
    var step by remember { mutableStateOf(Step.Blocks) }
    var initialRouteApplied by remember { mutableStateOf(false) }
    var walletReturnStep by remember { mutableStateOf(Step.Blocks) }
    var wantedTestnet by remember { mutableStateOf(false) }
    var tab by remember { mutableIntStateOf(0) }
    val gardenTitle = stringResource(R.string.g_default_title)

    // Enable FLAG_SECURE while 24-word recovery phrases are on screen.
    val isSecretStep = step == Step.Seed || step == Step.SeedVerify
    LaunchedEffect(isSecretStep) {
        onSecureScreen(isSecretStep)
    }
    DisposableEffect(Unit) {
        onDispose { onSecureScreen(false) }
    }

    // Apply smart landing step once initial wallet & seat checks finish.
    LaunchedEffect(state.walletLoaded, state.resumeChecked) {
        if (!initialRouteApplied && state.walletLoaded && state.resumeChecked) {
            initialRouteApplied = true
            val next = GardenLogic.resolveInitialStep(
                hasPendingLink = state.pendingJoinLink.isNotEmpty(),
                seated = state.seated,
                walletExists = state.walletExists,
                canValidate = state.readiness.canValidate,
            )
            step = next
            if (next == Step.Join) {
                model.consumePendingJoinLink()
            }
        }
    }

    // Deep-link arriving while the app is already open routes directly to Join.
    LaunchedEffect(state.pendingJoinLink) {
        if (state.pendingJoinLink.isNotEmpty() && initialRouteApplied) {
            step = Step.Join
            model.consumePendingJoinLink()
        }
    }

    // Local spotlight quick-jump destinations (zero network calls).
    val spotlight = listOf(
        SpotlightEntry(
            title = stringResource(R.string.g_search_jump_room),
            detail = stringResource(R.string.g_room),
            keywords = stringResource(R.string.g_keys_room),
            onSelect = {
                if (state.seated) {
                    tab = 0
                    step = Step.Garden
                } else {
                    model.create(gardenTitle) {
                        tab = 0
                        step = Step.Garden
                    }
                }
            },
        ),
        SpotlightEntry(
            title = stringResource(R.string.g_search_jump_people),
            detail = stringResource(R.string.g_people),
            keywords = stringResource(R.string.g_keys_people),
            onSelect = {
                if (state.seated) {
                    tab = 1
                    step = Step.Garden
                } else {
                    step = Step.Join
                }
            },
        ),
        SpotlightEntry(
            title = stringResource(R.string.g_search_jump_status),
            detail = stringResource(R.string.g_status),
            keywords = stringResource(R.string.g_keys_status),
            onSelect = {
                if (state.seated) {
                    tab = 2
                    step = Step.Garden
                } else {
                    step = Step.Setup
                }
            },
        ),
        SpotlightEntry(
            title = stringResource(R.string.g_search_jump_wallet),
            detail = stringResource(R.string.w_wallet),
            keywords = stringResource(R.string.g_keys_wallet),
            onSelect = {
                walletReturnStep = if (step == Step.Setup) Step.Setup else Step.Choose
                step = Step.Wallet
            },
        ),
        SpotlightEntry(
            title = stringResource(R.string.g_search_jump_join),
            detail = stringResource(R.string.g_code_label),
            keywords = stringResource(R.string.g_keys_join),
            onSelect = { step = Step.Join },
        ),
        SpotlightEntry(
            title = stringResource(R.string.g_search_jump_scan),
            detail = "QR",
            keywords = stringResource(R.string.g_keys_scan),
            onSelect = {
                step = Step.Join
                model.scan()
            },
        ),
        SpotlightEntry(
            title = stringResource(R.string.g_search_jump_setup),
            detail = stringResource(R.string.g_self_test),
            keywords = stringResource(R.string.g_keys_setup),
            onSelect = { step = Step.Setup },
        ),
        SpotlightEntry(
            title = stringResource(R.string.g_search_jump_testnet),
            detail = stringResource(R.string.g_testnet),
            keywords = stringResource(R.string.g_keys_testnet),
            onSelect = onTestnet,
        ),
    )

    BackHandler(enabled = step != Step.Blocks) {
        step = when (step) {
            // The words are shown once; block system back so the user never loses
            // their recovery phrase by accident before confirming they noted it.
            Step.Seed -> Step.Seed
            Step.SeedVerify -> Step.Seed
            Step.Wallet -> {
                wantedTestnet = false
                walletReturnStep
            }
            Step.Setup, Step.Choose, Step.Garden, Step.Join -> Step.Blocks
            Step.Blocks -> Step.Blocks
        }
    }

    AnimatedContent(
        targetState = step,
        transitionSpec = {
            fadeIn(tween(GardenMotion.BASE_MS, easing = GardenMotion.Ease)) togetherWith
                fadeOut(tween(GardenMotion.FAST_MS, easing = GardenMotion.Ease))
        },
        label = "gardenStep",
    ) { current ->
        when (current) {
            Step.Blocks -> BlockFieldScreen(
                model = model,
                onGo = { goes ->
                    when (goes) {
                        BlockGoes.Testnet -> {
                            if (model.state.walletExists) {
                                onTestnet()
                            } else {
                                wantedTestnet = true
                                walletReturnStep = Step.Blocks
                                step = Step.Wallet
                            }
                        }
                        BlockGoes.Validator -> step = Step.Setup
                        BlockGoes.Wallet -> {
                            wantedTestnet = false
                            walletReturnStep = Step.Blocks
                            step = Step.Wallet
                        }
                        BlockGoes.Garden -> {
                            if (model.state.seated) {
                                tab = 0
                                step = Step.Garden
                            } else {
                                model.create(gardenTitle) {
                                    tab = 0
                                    step = Step.Garden
                                }
                            }
                        }
                    }
                },
                onJoin = { step = Step.Join },
                onChoose = { step = Step.Choose },
                onReviewClipboardInvite = { link ->
                    model.preview(link)
                    model.dismissClipboardInvite()
                    step = Step.Join
                },
                spotlight = spotlight,
            )

            Step.Setup -> SetupScreen(
                model = model,
                onBack = { step = Step.Blocks },
                onReady = {
                    if (model.state.walletExists) {
                        step = Step.Choose
                    } else {
                        wantedTestnet = false
                        walletReturnStep = Step.Setup
                        step = Step.Wallet
                    }
                },
                spotlight = spotlight,
            )

            Step.Wallet -> {
                val hadOneAlready = remember { model.state.walletExists }
                if (hadOneAlready) {
                    WalletScreen(
                        model = model,
                        onBack = { step = walletReturnStep },
                        onTestnet = onTestnet,
                        spotlight = spotlight,
                    )
                } else {
                    WalletStartScreen(
                        model = model,
                        onBack = {
                            wantedTestnet = false
                            step = walletReturnStep
                        },
                        spotlight = spotlight,
                    )
                    val madeNow = model.state.mnemonic.isNotEmpty()
                    val restoredNow = model.state.walletExists && !madeNow
                    LaunchedEffect(madeNow, restoredNow) {
                        if (madeNow) {
                            step = Step.Seed
                        } else if (restoredNow) {
                            if (wantedTestnet) {
                                wantedTestnet = false
                                onTestnet()
                                step = Step.Blocks
                            } else {
                                step = Step.Choose
                            }
                        }
                    }
                }
            }

            Step.Seed -> SeedPhraseScreen(model) {
                step = Step.SeedVerify
            }

            Step.SeedVerify -> SeedVerifyScreen(
                model = model,
                onBackToWords = { step = Step.Seed },
                onVerified = {
                    if (wantedTestnet) {
                        wantedTestnet = false
                        onTestnet()
                        step = Step.Blocks
                    } else {
                        step = Step.Choose
                    }
                },
            )

            Step.Choose -> ChooseScreen(
                model = model,
                onBack = { step = Step.Blocks },
                onStartOwn = {
                    if (model.state.seated) {
                        step = Step.Garden
                        tab = 0
                    } else {
                        model.create(gardenTitle) {
                            step = Step.Garden
                            tab = 0
                        }
                    }
                },
                onHaveInvite = { step = Step.Join },
                onReviewClipboardInvite = { link ->
                    model.preview(link)
                    model.dismissClipboardInvite()
                    step = Step.Join
                },
                onTestnet = onTestnet,
                onWallet = {
                    wantedTestnet = false
                    walletReturnStep = Step.Choose
                    step = Step.Wallet
                },
                onSetup = { step = Step.Setup },
                spotlight = spotlight,
            )

            Step.Join -> CubeFloor(skin) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .statusBarsPadding(),
                ) {
                    TopBar(
                        title = stringResource(R.string.g_join_network),
                        skin = skin,
                        onSkinChange = { model.selectSkin(it) },
                        onBack = { step = Step.Choose },
                    )
                    CodeJoinScreen(
                        model = model,
                        onJoined = {
                            tab = 1
                            step = Step.Garden
                        },
                    )
                    val seated = model.state.myKey.isNotEmpty() && model.state.seated
                    LaunchedEffect(seated) {
                        if (seated) {
                            tab = 1
                            step = Step.Garden
                        }
                    }
                }
            }

            Step.Garden -> CubeFloor(skin) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .statusBarsPadding(),
                ) {
                    val activeTitle = remember(state.status) {
                        runCatching {
                            JSONObject(state.status)
                                .optJSONObject("garden")
                                ?.optString("title")
                                .orEmpty()
                        }.getOrDefault("")
                    }.ifBlank { stringResource(R.string.g_my_network) }

                    TopBar(
                        title = activeTitle,
                        skin = skin,
                        onSkinChange = { model.selectSkin(it) },
                        onBack = { step = Step.Choose },
                    )
                    val peopleLabel = if (state.waitingCount > 0) {
                        stringResource(R.string.g_people) + " · " + state.waitingCount
                    } else {
                        stringResource(R.string.g_people)
                    }
                    val titles = listOf(
                        stringResource(R.string.g_room),
                        peopleLabel,
                        stringResource(R.string.g_status),
                    )
                    TabRow(
                        selectedTabIndex = tab,
                        containerColor = skin.surface.copy(alpha = 0.88f),
                        contentColor = skin.surfaceInk,
                        indicator = { positions ->
                            if (tab < positions.size) {
                                TabRowDefaults.SecondaryIndicator(
                                    modifier = Modifier.tabIndicatorOffset(positions[tab]),
                                    color = skin.accentOnSurface,
                                )
                            }
                        },
                        divider = { Rule(skin = skin, color = skin.rule) },
                    ) {
                        titles.forEachIndexed { index, title ->
                            Tab(
                                selected = tab == index,
                                onClick = { tab = index },
                                text = {
                                    Label(
                                        text = title,
                                        skin = skin,
                                        color = if (tab == index) {
                                            skin.surfaceInk
                                        } else {
                                            skin.surfaceMuted
                                        },
                                    )
                                },
                            )
                        }
                    }
                    when (tab) {
                        0 -> ChatScreen(model)
                        1 -> PeopleScreen(model)
                        else -> WorkScreen(model) {
                            tab = 0
                        }
                    }
                }
            }
        }
    }
}

/**
 * Unified top bar for Join and Garden workspaces: single centered Budlum
 * wordmark, back chevron, subtitle and top-right 3-square skin switch.
 */
@Composable
private fun TopBar(
    title: String,
    skin: Skin,
    onSkinChange: (Skin) -> Unit,
    onBack: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(skin.behind.copy(alpha = 0.90f)),
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 10.dp),
        ) {
            Row(
                modifier = Modifier
                    .align(Alignment.CenterStart)
                    .clickable(role = Role.Button, onClick = onBack)
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                BackChevronIcon(tint = skin.ink)
                Label(stringResource(R.string.g_back), skin = skin, color = skin.ink)
            }
            Wordmark(
                skin = skin,
                modifier = Modifier.align(Alignment.Center),
            )
            SkinSwitch(
                current = skin,
                onSelect = onSkinChange,
                modifier = Modifier.align(Alignment.CenterEnd),
            )
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Label(title, skin = skin, color = skin.ink)
            GardenBrandMark(skin = skin, height = 11.dp, onSurface = false)
        }
        Rule(skin = skin, color = skin.rule)
    }
}

/**
 * Validator status and B.U.D. 3.0 storage counters, with Return-to-Garden
 * recovery when stepped out and two-step confirmation before leaving.
 */
@Composable
private fun WorkScreen(
    model: GardenModel,
    onReturned: () -> Unit,
) {
    val state = model.state
    val skin = model.skin
    var confirmingLeave by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        model.refreshStatus()
    }

    val garden = remember(state.status) {
        runCatching { JSONObject(state.status).optJSONObject("garden") }.getOrNull()
    }
    val work = garden?.optJSONObject("work")
    val bud3 = work?.optJSONObject("bud3")
    val chainId = garden?.optString("chain_id").orEmpty()
    val hasSeat = GardenLogic.hasGardenSeat(state.status)
    val canReturn = state.canReturn || GardenLogic.canReturnToGarden(state.status)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .navigationBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (canReturn) {
            Sheet(skin = skin) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = stringResource(R.string.g_away_notice),
                        style = MaterialTheme.typography.bodySmall,
                        color = skin.surfaceInk,
                    )
                    PillButton(
                        text = stringResource(R.string.g_return_to_garden),
                        onTap = { model.returnToGarden(onSuccess = onReturned) },
                        enabled = !state.busy,
                        skin = skin,
                        primary = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        }

        Sheet(skin = skin) {
            Column {
                if (chainId.isNotEmpty()) {
                    Fact(
                        name = stringResource(R.string.g_chain_id_label),
                        value = GardenLogic.shortAddress(chainId),
                        skin = skin,
                    )
                    Rule(skin = skin)
                }
                Fact(
                    name = stringResource(R.string.g_parts_held),
                    value = (work?.optLong("parts_held") ?: 0L).toString(),
                    skin = skin,
                )
                Rule(skin = skin)
                Fact(
                    name = stringResource(R.string.g_stored),
                    value = GardenLogic.formatBytes(garden?.optLong("stored_object_bytes") ?: 0L),
                    skin = skin,
                )
                Rule(skin = skin)
                Fact(
                    name = stringResource(R.string.g_coded),
                    value = (bud3?.optLong("objects_coded") ?: 0L).toString(),
                    skin = skin,
                )
                Rule(skin = skin)
                Fact(
                    name = stringResource(R.string.g_symbols),
                    value = (bud3?.optLong("symbols_made") ?: 0L).toString(),
                    skin = skin,
                )
                Rule(skin = skin)
                // The number that says whether the coding bought anything.
                // Source symbols are the object cut up; only these let it
                // come back with pieces missing.
                Fact(
                    name = stringResource(R.string.g_repair),
                    value = (bud3?.optLong("symbols_repair") ?: 0L).toString(),
                    skin = skin,
                )
                Rule(skin = skin)
                Fact(
                    name = stringResource(R.string.g_validators),
                    value = (garden?.optInt("active_validators") ?: 0).toString(),
                    skin = skin,
                )
            }
        }

        PermissionRows(model)

        if (hasSeat) {
            Sheet(skin = skin) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    if (confirmingLeave) {
                        Text(
                            text = stringResource(R.string.g_leave_confirm_body),
                            style = MaterialTheme.typography.bodySmall,
                            color = skin.surfaceInk,
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            RuleButton(
                                text = stringResource(R.string.g_leave_confirm),
                                onTap = {
                                    confirmingLeave = false
                                    model.leave()
                                },
                                enabled = !state.busy,
                                skin = skin,
                                rule = skin.danger,
                                ink = skin.danger,
                                modifier = Modifier.weight(1f),
                            )
                            RuleButton(
                                text = stringResource(R.string.g_stay),
                                onTap = { confirmingLeave = false },
                                skin = skin,
                                modifier = Modifier.weight(1f),
                            )
                        }
                    } else {
                        RuleButton(
                            text = stringResource(R.string.g_leave),
                            onTap = { confirmingLeave = true },
                            enabled = !state.busy,
                            skin = skin,
                            rule = skin.danger,
                            ink = skin.danger,
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

@Composable
private fun PermissionRows(model: GardenModel) {
    val context = LocalContext.current
    val ready = model.state.readiness
    val skin = model.skin
    if (ready.notifications && ready.batteryUnrestricted) return

    Sheet(skin = skin) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (!ready.notifications) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Label(stringResource(R.string.g_notifications_off), skin = skin, color = skin.danger)
                    RuleButton(
                        text = stringResource(R.string.g_fix),
                        onTap = { model.askForNotifications() },
                        skin = skin,
                    )
                }
            }
            if (!ready.notifications && !ready.batteryUnrestricted) {
                Rule(skin = skin)
            }
            if (!ready.batteryUnrestricted) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Label(stringResource(R.string.g_battery_limited), skin = skin, color = skin.danger)
                    RuleButton(
                        text = stringResource(R.string.g_fix),
                        onTap = {
                            context.startActivity(
                                Intent(
                                    Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                    Uri.fromParts("package", context.packageName, null),
                                ),
                            )
                        },
                        skin = skin,
                    )
                }
            }
        }
    }
}
