package network.budlum.validator.garden

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectDragGesturesAfterLongPress
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
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
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import network.budlum.validator.R
import kotlin.math.roundToInt

/**
 * The field of blocks the design opens on.
 *
 * The file's home screen is not a menu. It is a dark grid of cells with
 * a handful of them lit, and the lit ones are the application: in
 * `final` they spell a figure out of the grid itself, in `token gerek`
 * a single pale block sits alone in the field. The cells are 60 px on a
 * 3840 px sheet, which is a sixty-fourth of the width.
 *
 * A sixty-fourth of a phone is five dp, which no thumb can hit, so the
 * grid is counted in columns instead of copied in pixels: eight columns
 * across whatever width the phone has. That keeps the proportion of the
 * sheet - a field of small cells, a few of them alive - at a size a
 * finger can actually land on.
 *
 * Two things the blocks do, both of which were asked for and neither of
 * which existed: a block can be picked up and put somewhere else, and a
 * block can be tapped to go where it leads.
 */

/** Columns across the field. Eight is the most that leaves a tappable cell. */
private const val COLUMNS = 8

/** Rows drawn. More than fits is fine - the field is meant to run past the edge. */
private const val ROWS = 14

/** What a block leads to when it is tapped. */
enum class BlockGoes {
    /** The testnet screen: the faucet, and the wallet it pays into. */
    Testnet,

    /** Start a Garden, which is what makes this phone a validator. */
    Validator,

    /** The wallet: its words, its address, what it holds. */
    Wallet,

    /** The room, the people, the work. */
    Garden,

    /** A block that is only a block. The field is mostly these. */
    Nowhere,
}

/**
 * One block: where it sits on the grid and what it leads to.
 *
 * `column` and `row` are grid cells, not pixels, because a block that
 * is dropped has to land on the grid rather than wherever the finger
 * happened to stop.
 */
data class Block(
    val id: Int,
    val column: Int,
    val row: Int,
    val goes: BlockGoes,
    val labelRes: Int?,
)

/**
 * Where the blocks start out.
 *
 * Scattered rather than stacked in a column, because the sheet scatters
 * them: the point of the field is that it is a field.
 */
private fun openingBlocks(): List<Block> = listOf(
    Block(0, 3, 4, BlockGoes.Testnet, R.string.b_testnet),
    Block(1, 5, 6, BlockGoes.Validator, R.string.b_validator),
    Block(2, 2, 8, BlockGoes.Wallet, R.string.b_wallet),
    Block(3, 6, 9, BlockGoes.Garden, R.string.b_garden),
    Block(4, 1, 2, BlockGoes.Nowhere, null),
    Block(5, 6, 2, BlockGoes.Nowhere, null),
    Block(6, 0, 6, BlockGoes.Nowhere, null),
    Block(7, 7, 11, BlockGoes.Nowhere, null),
    Block(8, 4, 11, BlockGoes.Nowhere, null),
)

/**
 * The opening screen: the wordmark, the search bar, the field, the menu.
 *
 * The app used to open on a permissions audit. The sheet opens on this.
 */
@Composable
fun BlockFieldScreen(skin: Skin, onGo: (BlockGoes) -> Unit) {
    CubeFloor(skin) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 14.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Wordmark()
            Spacer(modifier = Modifier.height(10.dp))
            SearchBar(stringResource(R.string.w_search_hint), skin)
            Spacer(modifier = Modifier.height(16.dp))
            BlockField(
                skin = skin,
                onGo = onGo,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
            )
            Box(modifier = Modifier.fillMaxWidth()) {
                CornerMenu(
                    listOf(
                        stringResource(R.string.w_menu_ao),
                        stringResource(R.string.w_menu_market),
                        stringResource(R.string.w_menu_ecosystem),
                        stringResource(R.string.w_menu_participation),
                    ),
                    skin,
                    modifier = Modifier.align(Alignment.CenterStart),
                )
            }
        }
    }
}

/**
 * The field itself.
 *
 * Long press picks a block up, dragging moves it, letting go drops it on
 * the nearest free cell. A short tap goes where the block leads. Long
 * press rather than plain drag, so that tapping a block is not mistaken
 * for the start of a drag by a thumb that moves a little.
 */
@Composable
fun BlockField(skin: Skin, onGo: (BlockGoes) -> Unit, modifier: Modifier = Modifier) {
    val blocks = remember { mutableStateListOf<Block>().apply { addAll(openingBlocks()) } }
    var held by remember { mutableStateOf<Int?>(null) }
    var carry by remember { mutableStateOf(Offset.Zero) }

    BoxWithConstraints(modifier = modifier) {
        val density = LocalDensity.current
        val cell = maxWidth / COLUMNS
        val cellPx = with(density) { cell.toPx() }
        val rowsDrawn = minOf(ROWS, (with(density) { maxHeight.toPx() } / cellPx).toInt() + 1)

        // The grid behind the blocks: a hairline cell with a faint mark
        // in the middle of it, which is what the sheet's tile is.
        Box(
            modifier = Modifier
                .fillMaxSize()
                .drawBehind {
                    val line = skin.ink.copy(alpha = 0.16f)
                    val mark = skin.ink.copy(alpha = 0.10f)
                    var row = 0
                    while (row * cellPx < size.height) {
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
                            // The small centre mark the tile carries.
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
            Box(
                modifier = Modifier
                    .offset {
                        IntOffset(
                            (block.column * cellPx + dx).roundToInt(),
                            (block.row * cellPx + dy).roundToInt(),
                        )
                    }
                    .size(cell)
                    .padding(2.dp)
                    .background(fillFor(block.goes, skin, lifted))
                    .border(1.dp, edgeFor(block.goes, skin))
                    .pointerInput(block.id) {
                        detectTapGestures(
                            // A long press is the drag, not a tap. Without
                            // this the finger that just carried a block
                            // across the field would also be taken as
                            // tapping it, and letting go of a dragged
                            // block would navigate away.
                            onLongPress = {},
                            onTap = { if (block.goes != BlockGoes.Nowhere) onGo(block.goes) },
                        )
                    }
                    .pointerInput(block.id) {
                        detectDragGesturesAfterLongPress(
                            onDragStart = {
                                held = block.id
                                carry = Offset.Zero
                            },
                            onDrag = { change, amount ->
                                change.consume()
                                carry += amount
                            },
                            onDragEnd = {
                                val wantColumn = (block.column + (carry.x / cellPx).roundToInt())
                                    .coerceIn(0, COLUMNS - 1)
                                val wantRow = (block.row + (carry.y / cellPx).roundToInt())
                                    .coerceIn(0, rowsDrawn - 1)
                                val taken = blocks.any {
                                    it.id != block.id && it.column == wantColumn && it.row == wantRow
                                }
                                if (!taken) {
                                    blocks[index] = block.copy(column = wantColumn, row = wantRow)
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
                        stringResource(block.labelRes),
                        style = MaterialTheme.typography.labelSmall,
                        color = Ink,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    }
}

/**
 * A block that leads somewhere is lit; the rest are the field.
 *
 * Lifting one pales it, so the finger can see which block it has.
 */
private fun fillFor(goes: BlockGoes, skin: Skin, lifted: Boolean): Color = when {
    lifted -> Chalk
    goes == BlockGoes.Nowhere -> skin.ink.copy(alpha = 0.07f)
    else -> Sage
}

private fun edgeFor(goes: BlockGoes, skin: Skin): Color =
    if (goes == BlockGoes.Nowhere) skin.ink.copy(alpha = 0.20f) else Sage
