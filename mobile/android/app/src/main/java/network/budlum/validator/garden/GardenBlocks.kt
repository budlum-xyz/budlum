package network.budlum.validator.garden

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGesturesAfterLongPress
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import kotlin.math.roundToInt
import network.budlum.validator.R

/**
 * The interactive field of blocks the Figma home sheet opens on.
 *
 * Eight columns across whatever width the phone has keeps the sheet's
 * proportion at a thumb-reachable scale. A long press lifts a block with
 * haptic feedback and snaps it onto any free cell; a short tap goes where
 * the block leads.
 */

private const val COLUMNS = 8
private const val ROWS = 14

/** What a block leads to when tapped. */
enum class BlockGoes {
    /** The testnet screen: faucet and RPC balance. */
    Testnet,

    /** Validator readiness and permissions. */
    Validator,

    /** This phone's wallet: words, address, receive QR. */
    Wallet,

    /** The Garden room, people and validator work. */
    Garden,

    /** A quiet field block that can still be rearranged. */
    Nowhere,
}

/** One block on the grid: cell position and destination. */
data class Block(
    val id: Int,
    val column: Int,
    val row: Int,
    val goes: BlockGoes,
    val labelRes: Int?,
)

private fun openingBlocks(): List<Block> = listOf(
    Block(0, 3, 3, BlockGoes.Testnet, R.string.b_testnet),
    Block(1, 5, 5, BlockGoes.Validator, R.string.b_validator),
    Block(2, 2, 7, BlockGoes.Wallet, R.string.b_wallet),
    Block(3, 6, 8, BlockGoes.Garden, R.string.b_garden),
    Block(4, 1, 1, BlockGoes.Nowhere, null),
    Block(5, 6, 1, BlockGoes.Nowhere, null),
    Block(6, 0, 5, BlockGoes.Nowhere, null),
    Block(7, 7, 10, BlockGoes.Nowhere, null),
    Block(8, 4, 10, BlockGoes.Nowhere, null),
)

/**
 * The opening screen: unified wordmark + skin switch, working local spotlight
 * bar, optional section 5.9 clipboard invite banner, the draggable field of
 * blocks, and direct access to Join or all options.
 */
@Composable
fun BlockFieldScreen(
    model: GardenModel,
    onGo: (BlockGoes) -> Unit,
    onJoin: () -> Unit,
    onChoose: () -> Unit,
    onReviewClipboardInvite: (String) -> Unit,
    spotlight: List<SpotlightEntry> = emptyList(),
) {
    val skin = model.skin
    val state = model.state

    CubeFloor(skin) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
                .padding(horizontal = 16.dp, vertical = 14.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp),
            ) {
                Wordmark(
                    skin = skin,
                    modifier = Modifier.align(Alignment.Center),
                )
                SkinSwitch(
                    current = skin,
                    onSelect = { model.selectSkin(it) },
                    modifier = Modifier.align(Alignment.CenterEnd),
                )
            }

            if (spotlight.isNotEmpty()) {
                SpotlightBar(
                    hint = stringResource(R.string.w_search_hint),
                    skin = skin,
                    entries = spotlight,
                    modifier = Modifier.padding(bottom = 10.dp),
                )
            }

            if (state.clipboardInvite.isNotEmpty()) {
                Sheet(skin = skin, modifier = Modifier.padding(bottom = 10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Label(
                                text = stringResource(R.string.g_clipboard_invite),
                                skin = skin,
                                color = skin.accentOnSurface,
                            )
                            Text(
                                text = GardenLogic.shortAddress(state.clipboardInvite),
                                style = MaterialTheme.typography.bodySmall,
                                color = skin.surfaceInk,
                            )
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            RuleButton(
                                text = stringResource(R.string.g_clipboard_join),
                                onTap = { onReviewClipboardInvite(state.clipboardInvite) },
                                skin = skin,
                                filled = true,
                            )
                            RuleButton(
                                text = stringResource(R.string.g_dismiss),
                                onTap = { model.dismissClipboardInvite() },
                                skin = skin,
                            )
                        }
                    }
                }
            }

            BlockField(
                skin = skin,
                onGo = onGo,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
            )

            Spacer(modifier = Modifier.height(10.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Label(
                    text = stringResource(R.string.b_drag_hint),
                    skin = skin,
                    color = skin.muted,
                )
                Row(
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Label(
                        text = stringResource(R.string.g_was_invited),
                        skin = skin,
                        color = skin.accent,
                        modifier = Modifier
                            .clickable(onClick = onJoin)
                            .padding(vertical = 4.dp),
                    )
                    GardenBrandMark(
                        skin = skin,
                        height = 14.dp,
                        onSurface = false,
                        modifier = Modifier
                            .clickable(onClick = onChoose)
                            .padding(vertical = 4.dp),
                    )
                }
            }
        }
    }
}

/**
 * The interactive block grid.
 *
 * Reads the live cell position on drag completion so a block can be moved any
 * number of times cleanly, lifts the active block above siblings with zIndex,
 * and uses haptics on pickup and snap.
 */
@Composable
fun BlockField(
    skin: Skin,
    onGo: (BlockGoes) -> Unit,
    modifier: Modifier = Modifier,
) {
    val blocks = remember { mutableStateListOf<Block>().apply { addAll(openingBlocks()) } }
    var held by remember { mutableStateOf<Int?>(null) }
    var carry by remember { mutableStateOf(Offset.Zero) }
    val haptic = LocalHapticFeedback.current

    BoxWithConstraints(modifier = modifier) {
        val density = LocalDensity.current
        val cell = maxWidth / COLUMNS
        val cellPx = with(density) { cell.toPx() }
        val rowsDrawn = minOf(ROWS, (with(density) { maxHeight.toPx() } / cellPx).toInt().coerceAtLeast(1))

        Box(
            modifier = Modifier
                .fillMaxSize()
                .drawBehind {
                    val line = skin.ink.copy(alpha = 0.16f)
                    val mark = skin.ink.copy(alpha = 0.10f)
                    var row = 0
                    while (row < rowsDrawn) {
                        var column = 0
                        while (column < COLUMNS) {
                            val left = column * cellPx
                            val top = row * cellPx
                            drawRect(
                                color = line,
                                topLeft = Offset(left, top),
                                size = Size(cellPx, cellPx),
                                style = androidx.compose.ui.graphics.drawscope.Stroke(1f),
                            )
                            val inset = cellPx * 0.38f
                            drawRect(
                                color = mark,
                                topLeft = Offset(left + inset, top + inset),
                                size = Size(cellPx - inset * 2, cellPx - inset * 2),
                            )
                            column++
                        }
                        row++
                    }
                },
        )

        blocks.forEachIndexed { index, block ->
            val lifted = held == block.id
            val dx = if (lifted) carry.x else 0f
            val dy = if (lifted) carry.y else 0f
            val clampedRow = block.row.coerceIn(0, (rowsDrawn - 1).coerceAtLeast(0))

            Box(
                modifier = Modifier
                    .zIndex(if (lifted) 2f else 0f)
                    .offset {
                        IntOffset(
                            (block.column * cellPx + dx).roundToInt(),
                            (clampedRow * cellPx + dy).roundToInt(),
                        )
                    }
                    .size(cell)
                    .padding(2.dp)
                    .background(fillFor(block.goes, skin, lifted))
                    .border(if (lifted) 1.5.dp else 1.dp, edgeFor(block.goes, skin, lifted))
                    .pointerInput(block.id) {
                        detectTapGestures(
                            onLongPress = {},
                            onTap = {
                                if (block.goes != BlockGoes.Nowhere) {
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    onGo(block.goes)
                                }
                            },
                        )
                    }
                    .pointerInput(block.id, rowsDrawn) {
                        detectDragGesturesAfterLongPress(
                            onDragStart = {
                                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                held = block.id
                                carry = Offset.Zero
                            },
                            onDrag = { change, amount ->
                                change.consume()
                                carry += amount
                            },
                            onDragEnd = {
                                val live = blocks.getOrNull(index)
                                if (live != null) {
                                    val baseRow = live.row.coerceIn(0, (rowsDrawn - 1).coerceAtLeast(0))
                                    val wantColumn = (live.column + (carry.x / cellPx).roundToInt())
                                        .coerceIn(0, COLUMNS - 1)
                                    val wantRow = (baseRow + (carry.y / cellPx).roundToInt())
                                        .coerceIn(0, (rowsDrawn - 1).coerceAtLeast(0))
                                    val taken = blocks.any {
                                        it.id != live.id && it.column == wantColumn && it.row == wantRow
                                    }
                                    if (!taken) {
                                        blocks[index] = live.copy(column = wantColumn, row = wantRow)
                                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    }
                                }
                                held = null
                                carry = Offset.Zero
                            },
                            onDragCancel = {
                                held = null
                                carry = Offset.Zero
                            },
                        )
                    },
                contentAlignment = Alignment.Center,
            ) {
                if (block.labelRes != null) {
                    Text(
                        text = stringResource(block.labelRes),
                        style = MaterialTheme.typography.labelSmall,
                        color = blockLabelInk(skin, lifted),
                        textAlign = TextAlign.Center,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}

private fun fillFor(goes: BlockGoes, skin: Skin, lifted: Boolean): Color = when {
    lifted -> Chalk
    goes == BlockGoes.Nowhere -> skin.ink.copy(alpha = 0.07f)
    skin == Skin.Sage -> Page
    else -> Sage
}

private fun edgeFor(goes: BlockGoes, skin: Skin, lifted: Boolean): Color = when {
    lifted -> skin.accentOnSurface
    goes == BlockGoes.Nowhere -> skin.ink.copy(alpha = 0.20f)
    skin == Skin.Sage -> Ink
    else -> SageRule
}

private fun blockLabelInk(skin: Skin, lifted: Boolean): Color = when {
    lifted -> Ink
    else -> Ink
}
