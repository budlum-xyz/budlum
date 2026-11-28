package network.budlum.validator.garden

import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGesturesAfterLongPress
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.imageResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import kotlin.math.roundToInt
import network.budlum.validator.R

/**
 * The interactive field of blocks the Figma home sheet opens on.
 *
 * The field used to draw its own grid of rectangles over the floor that
 * CubeFloor was already tiling, at eight columns of a 60 dp tile. Two
 * grids at three times the drawn size turned the sheet's fine mesh into
 * a chessboard. One grid now, and it is the floor: a block occupies
 * whole tiles of it. A long press lifts a block with haptic feedback and
 * snaps it onto free tiles; a short tap goes where the block leads.
 */

/** A block covers two floor tiles each way: the stroke width the sheet uses. */
private const val SPAN = 2

/** How far a lit block's glow reaches past its edge, in tiles. */
private const val HALO = 2.2f

/** What a block leads to when tapped. */
/** Where the opening screen can take a person. */
enum class BlockGoes {
    /** The testnet screen: faucet and RPC balance. */
    Testnet,

    /** Validator readiness and permissions. */
    Validator,

    /** This phone's wallet: words, address, receive QR. */
    Wallet,

    /** The Garden room, people and validator work. */
    Garden,
}

/**
 * One block: which floor tile it sits on.
 *
 * A block carries no label and no destination. The sheet writes nothing
 * inside a lit cell, and hanging the app's navigation off cells scattered
 * through a field put the four places a person can go in four different
 * corners of the screen with nothing to say which was which. The field is
 * the sheet's field; where a person can go is a list, at the bottom,
 * where lists belong.
 */
data class Block(
    val id: Int,
    val column: Int,
    val row: Int,
)

/** Where the blocks start out. Scattered, the way the sheet scatters them. */
private fun openingBlocks(): List<Block> = listOf(
    Block(0, 2, 2),
    Block(1, 9, 4),
    Block(2, 5, 9),
    Block(3, 13, 11),
    Block(4, 1, 15),
    Block(5, 10, 18),
    Block(6, 6, 22),
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
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
            )

            DestinationMenu(
                skin = skin,
                onGo = onGo,
                onJoin = onJoin,
                onChoose = onChoose,
                modifier = Modifier.fillMaxWidth(),
            )
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
    modifier: Modifier = Modifier,
) {
    val blocks = remember { mutableStateListOf<Block>().apply { addAll(openingBlocks()) } }
    var held by remember { mutableStateOf<Int?>(null) }
    var carry by remember { mutableStateOf(Offset.Zero) }
    val haptic = LocalHapticFeedback.current
    val mark = ImageBitmap.imageResource(
        when (skin) {
            Skin.Page -> R.drawable.tile_page
            Skin.Sage -> R.drawable.tile_sage
            Skin.Ground -> R.drawable.tile_ground
        },
    )

    BoxWithConstraints(modifier = modifier) {
        val density = LocalDensity.current
        // One cell is one floor tile, so a block lands on the mesh
        // CubeFloor already lays down instead of on a second grid.
        val cell = TILE * SPAN
        val cellPx = with(density) { TILE.toPx() }
        val columns = (with(density) { maxWidth.toPx() } / cellPx).toInt().coerceAtLeast(1)
        val rowsDrawn = (with(density) { maxHeight.toPx() } / cellPx).toInt().coerceAtLeast(1)

        blocks.forEachIndexed { index, block ->
            val lifted = held == block.id
            val dx = if (lifted) carry.x else 0f
            val dy = if (lifted) carry.y else 0f
            val clampedRow = block.row.coerceIn(0, (rowsDrawn - SPAN).coerceAtLeast(0))

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
                    // A lit cell in the sheet is not a bordered card. It
                    // glows into the dark around it, and the floor's
                    // four-petal mark still reads through the light.
                    .drawBehind {
                        val reach = cellPx * HALO
                        drawRect(
                            brush = Brush.radialGradient(
                                colors = listOf(
                                    glowFor(skin).copy(alpha = if (lifted) 1f else 0.85f),
                                    glowFor(skin).copy(alpha = if (lifted) 0.55f else 0.40f),
                                    glowFor(skin).copy(alpha = 0f),
                                ),
                                center = center,
                                radius = size.minDimension / 2f + reach,
                            ),
                            topLeft = Offset(-reach, -reach),
                            size = Size(size.width + reach * 2, size.height + reach * 2),
                        )
                        drawRect(color = fillFor(skin, lifted))
                        val step = cellPx.toInt()
                        for (down in 0 until SPAN) {
                            for (across in 0 until SPAN) {
                                drawImage(
                                    image = mark,
                                    dstOffset = IntOffset(across * step, down * step),
                                    dstSize = IntSize(step, step),
                                    colorFilter = ColorFilter.tint(Ink.copy(alpha = 0.40f)),
                                    alpha = 0.45f,
                                )
                            }
                        }
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
                                    val baseRow = live.row.coerceIn(0, (rowsDrawn - SPAN).coerceAtLeast(0))
                                    val wantColumn = (live.column + (carry.x / cellPx).roundToInt())
                                        .coerceIn(0, (columns - SPAN).coerceAtLeast(0))
                                    val wantRow = (baseRow + (carry.y / cellPx).roundToInt())
                                        .coerceIn(0, (rowsDrawn - SPAN).coerceAtLeast(0))
                                    val taken = blocks.any {
                                        it.id != live.id &&
                                            kotlin.math.abs(it.column - wantColumn) < SPAN &&
                                            kotlin.math.abs(it.row - wantRow) < SPAN
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
            )
        }
    }
}

/**
 * Where a person can go, bottom left, one word a line.
 *
 * The sheet puts its own menu here - a.o, market, ecosystem,
 * participation - in lowercase against the floor. Those are sections of
 * a website and there is nothing behind them in a phone, so printing
 * them would have been four words that do nothing. The place and the
 * treatment are the sheet's; the words are the four places this app
 * actually goes.
 *
 * They were scattered across the field as lit cells before, each one
 * indistinguishable from the next, which meant the only way to find the
 * wallet was to tap blocks until one opened it.
 */
@Composable
private fun DestinationMenu(
    skin: Skin,
    onGo: (BlockGoes) -> Unit,
    onJoin: () -> Unit,
    onChoose: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val places = listOf(
        BlockGoes.Testnet to R.string.b_testnet,
        BlockGoes.Validator to R.string.b_validator,
        BlockGoes.Wallet to R.string.b_wallet,
        BlockGoes.Garden to R.string.b_garden,
    )
    Column(modifier = modifier) {
        places.forEach { (goes, label) ->
            Text(
                text = stringResource(label).lowercase(),
                style = MaterialTheme.typography.labelSmall,
                color = skin.ink,
                modifier = Modifier
                    .clickable { onGo(goes) }
                    .padding(vertical = 5.dp),
            )
        }
        // Two quieter lines under the four: arriving on somebody else's
        // invitation, and the long way round through every option.
        Row(
            modifier = Modifier.padding(top = 7.dp),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = stringResource(R.string.g_was_invited).lowercase(),
                style = MaterialTheme.typography.labelSmall,
                color = skin.muted,
                modifier = Modifier
                    .clickable(onClick = onJoin)
                    .padding(vertical = 4.dp),
            )
            Text(
                text = stringResource(R.string.g_all_options).lowercase(),
                style = MaterialTheme.typography.labelSmall,
                color = skin.muted,
                modifier = Modifier
                    .clickable(onClick = onChoose)
                    .padding(vertical = 4.dp),
            )
        }
    }
}

/** What a block is filled with. Lit, or brighter still while carried. */
private fun fillFor(skin: Skin, lifted: Boolean): Color = when {
    lifted -> Chalk
    skin == Skin.Sage -> Page
    else -> Sage
}

/** What colour the light around a lit block is, per skin. */
private fun glowFor(skin: Skin): Color = when (skin) {
    Skin.Sage -> Page
    else -> Sage
}
