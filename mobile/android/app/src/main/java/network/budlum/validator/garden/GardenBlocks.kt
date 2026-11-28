package network.budlum.validator.garden

import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
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
import androidx.compose.runtime.mutableStateMapOf
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
    val cell: Cell,
)

/**
 * Where the blocks start out, in the lattice the floor uses.
 *
 * No block starts at the origin corner: the sheet's clusters always read as
 * (0,1), (1,0), (1,1) around a place, never as (0,0).
 */
private fun openingBlocks(): List<Block> = listOf(
    Block(0, Cell(0, 1)),
    Block(1, Cell(1, 0)),
    Block(2, Cell(1, 1)),
    Block(3, Cell(3, 2)),
    Block(4, Cell(2, 4)),
    Block(5, Cell(5, 5)),
    Block(6, Cell(4, 7)),
)

/**
 * The opening screen: unified wordmark + skin switch, working local spotlight
 * bar, optional section 5.9 clipboard invite banner, the draggable field of
 * blocks, and direct access to Join or all options.
 */
@Composable
fun BlockFieldScreen(
    model: GardenModel,
    onCube: (Cell) -> Unit,
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
                mySeat = state.seat,
                onPick = onCube,
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
    mySeat: Cell? = null,
    onPick: (Cell) -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val blocks = remember { mutableStateListOf<Block>().apply { addAll(openingBlocks()) } }
    var held by remember { mutableStateOf<Int?>(null) }
    var carry by remember { mutableStateOf(Offset.Zero) }
    // Where a block has been taken to, in pixels, on top of the lattice place
    // it was drawn at: free, with nothing refusing a spot because another
    // block is near it.
    val taken = remember { mutableStateMapOf<Int, Offset>() }
    // The floor itself moves. Dragging the ground shifts the mesh and every
    // block with it, and the coordinate under a finger is read from where the
    // mesh is, not from where the glass is.
    var pan by remember { mutableStateOf(Offset.Zero) }
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
        // The cube is 32dp on a phone: the file draws it at 64 against a 60
        // pixel mesh, and half of that against the 20dp mesh this floor lays
        // down is the same drawing at phone scale.
        val cubePx = with(density) { CUBE.toPx() }
        val floorWidth = with(density) { maxWidth.toPx() }
        val floorHeight = with(density) { maxHeight.toPx() }

        fun cellAt(point: Offset): Cell {
            val x = ((point.x - pan.x) / cubePx).roundToInt().coerceAtLeast(0)
            val y = ((point.y - pan.y) / cubePx).roundToInt().coerceAtLeast(0)
            // The lattice has no origin corner: a press at the very corner is
            // read as the first place beside it.
            return if (x == 0 && y == 0) Cell(0, 1) else Cell(x, y)
        }

        // The ground: a press names a place, a drag moves the mesh.
        Box(
            modifier = Modifier
                .matchParentSize()
                .pointerInput(Unit) {
                    detectTapGestures { point -> onPick(cellAt(point)) }
                }
                .pointerInput(Unit) {
                    detectDragGestures { change, amount ->
                        change.consume()
                        pan += amount
                    }
                },
        )

        blocks.forEach { block ->
            val lifted = held == block.id
            val mine = mySeat == block.cell
            val settled = taken[block.id] ?: Offset.Zero
            val homeX = block.cell.x * cubePx + pan.x
            val homeY = block.cell.y * cubePx + pan.y
            val dx = homeX + settled.x + if (lifted) carry.x else 0f
            val dy = homeY + settled.y + if (lifted) carry.y else 0f

            Box(
                modifier = Modifier
                    .zIndex(if (lifted) 2f else 0f)
                    .offset { IntOffset(dx.roundToInt(), dy.roundToInt()) }
                    .size(CUBE)
                    // A lit cell in the sheet is not a bordered card. It
                    // glows into the dark around it, and the floor's
                    // four-petal mark still reads through the light.
                    .drawBehind {
                        val reach = cubePx * HALO
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
                        drawRect(color = if (mine) skin.accentOnSurface else fillFor(skin, lifted))
                        val step = (cubePx / SPAN).toInt()
                        for (down in 0 until SPAN) {
                            for (across in 0 until SPAN) {
                                drawImage(
                                    image = mark,
                                    dstOffset = IntOffset(across * step, down * step),
                                    dstSize = IntSize(step, step),
                                    colorFilter = ColorFilter.tint(skin.ink.copy(alpha = 0.40f)),
                                    alpha = 0.45f,
                                )
                            }
                        }
                    }
                    .pointerInput(block.id) {
                        detectTapGestures { onPick(block.cell) }
                    }
                    .pointerInput(block.id, floorWidth, floorHeight) {
                        detectDragGestures(
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
                                val want = (taken[block.id] ?: Offset.Zero) + carry
                                val minX = -homeX
                                val minY = -homeY
                                val topX = floorWidth - cubePx - homeX
                                val topY = floorHeight - cubePx - homeY
                                taken[block.id] = Offset(
                                    want.x.coerceIn(minX, maxOf(minX, topX)),
                                    want.y.coerceIn(minY, maxOf(minY, topY)),
                                )
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
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
    // A held block turns to the sheet's brightest surface; on the dark skin
    // that is chalk, on the light one it is the surface itself.
    lifted -> if (skin.isDark) Chalk else skin.behind
    skin.isDark -> skin.surface
    else -> Sage
}

/** What colour the light around a lit block is, per skin. */
private fun glowFor(skin: Skin): Color = when {
    skin.isDark -> skin.surface
    skin == Skin.Sage -> skin.surface
    else -> Sage
}
