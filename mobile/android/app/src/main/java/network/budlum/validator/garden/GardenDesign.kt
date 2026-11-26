package network.budlum.validator.garden

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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RectangleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.imageResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import network.budlum.validator.R

/**
 * The pieces every Garden screen is built from.
 *
 * None of this was invented here. The tile is the 60 pixel cube the
 * design file specifies (figma-frames/cube-spec.json, sheet 42:750);
 * the icons are the exported send and sparkle assets, not redrawings;
 * the rules are 1 pixel hairlines and the corners are square, because
 * every panel and row in the measured tokens has a radius of zero.
 *
 * The reason to keep them in one file is that the old screens drifted:
 * each grew its own rounded box and its own paragraph of explanation.
 * A group of people sending each other data does not need to be talked
 * at - it needs to see who is there and what arrived.
 */

/** The cube tile, repeated. The design's floor, not a decoration. */
@Composable
fun CubeFloor(theme: Skin, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    val tile = ImageBitmap.imageResource(
        when (theme) {
            Skin.Page -> R.drawable.tile_page
            Skin.Sage -> R.drawable.tile_sage
            Skin.Ground -> R.drawable.tile_ground
        },
    )
    Box(
        modifier = modifier
            .fillMaxSize()
            .background(theme.behind)
            .drawBehind { tileAcross(tile) },
    ) {
        content()
    }
}

/** Lay the tile edge to edge at its own size, the way the sheet does. */
private fun DrawScope.tileAcross(tile: ImageBitmap) {
    val step = TILE.toPx()
    var y = 0f
    while (y < size.height) {
        var x = 0f
        while (x < size.width) {
            drawImage(
                image = tile,
                dstOffset = androidx.compose.ui.unit.IntOffset(x.toInt(), y.toInt()),
                dstSize = androidx.compose.ui.unit.IntSize(step.toInt(), step.toInt()),
                alpha = 0.5f,
            )
            x += step
        }
        y += step
    }
}

/** The three skins the design's top-right switch offers. */
enum class Skin(val behind: Color, val ink: Color, val rule: Color) {
    Page(Color(0xFFFBFCFA), Color(0xFF060705), Color(0xFFE6E6E6)),
    Sage(Color(0xFF98AE89), Color(0xFF060705), Color(0xFF899D7C)),
    Ground(Color(0xFF060705), Color(0xFFFBFCFA), Color(0xFF191919)),
}

/** The design's tile, and so its unit of space. */
val TILE = 60.dp

/**
 * A panel: flat fill, one hairline, square corners.
 *
 * The measured tokens give panel and row a radius of zero. A rounded
 * card here would be a different product's card.
 */
@Composable
fun Slab(
    modifier: Modifier = Modifier,
    fill: Color = Color(0xFFFBFCFA),
    rule: Color = Color(0xFFE6E6E6),
    content: @Composable () -> Unit,
) {
    Box(
        modifier = modifier
            .background(fill, RectangleShape)
            .border(1.dp, rule, RectangleShape),
    ) {
        content()
    }
}

/** A small lowercase label: the design never shouts, and never explains. */
@Composable
fun Label(text: String, modifier: Modifier = Modifier, color: Color = Color(0xFFBDBDBD)) {
    Text(
        text = text.lowercase(),
        style = MaterialTheme.typography.labelSmall,
        color = color,
        modifier = modifier,
    )
}

/** One of the exported icons, tappable, at the size the sheet gives it. */
@Composable
fun Glyph(
    which: Int,
    description: String,
    onTap: () -> Unit,
    modifier: Modifier = Modifier,
    size: Dp = 28.dp,
    enabled: Boolean = true,
) {
    Image(
        painter = painterResource(which),
        contentDescription = description,
        modifier = modifier
            .size(size)
            .clickable(enabled = enabled, onClick = onTap),
        alpha = if (enabled) 1f else 0.35f,
    )
}

/**
 * A button the way the design draws one: a hairline box with small
 * lowercase text inside and nothing filled in.
 */
@Composable
fun RuleButton(
    text: String,
    onTap: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    rule: Color = Color(0xFF98AE89),
    ink: Color = Color(0xFF98AE89),
) {
    Box(
        modifier = modifier
            .border(1.dp, if (enabled) rule else Color(0xFFBDBDBD), RectangleShape)
            .clickable(enabled = enabled, onClick = onTap)
            .padding(horizontal = 14.dp, vertical = 7.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = text.lowercase(),
            style = MaterialTheme.typography.labelSmall,
            color = if (enabled) ink else Color(0xFFBDBDBD),
        )
    }
}

/**
 * A label and its value on one line, which is how the design states a
 * fact. There is no sentence anywhere in the sheets - there is a word
 * and a number.
 */
@Composable
fun Fact(name: String, value: String, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 14.dp, vertical = 7.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Label(name)
        Text(value, style = MaterialTheme.typography.bodySmall, color = Color(0xFF060705))
    }
}

/** A hairline across the width, the design's only separator. */
@Composable
fun Rule(color: Color = Color(0xFFE6E6E6)) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(color)
            .size(width = Dp.Unspecified, height = 1.dp),
    )
}

/**
 * The square avatar every person in the sheets has.
 *
 * The design gives each account a picture. There is none to show for a
 * validator key, so the key colours its own square - the same key always
 * gets the same colour, which is what makes it recognisable at a glance.
 */
@Composable
fun KeySquare(key: String, size: Dp = 40.dp) {
    val hue = key.take(6).toLongOrNull(16) ?: key.hashCode().toLong()
    val shade = SQUARES[(hue.toInt() and 0x7fffffff) % SQUARES.size]
    Box(
        modifier = Modifier
            .size(size)
            .background(shade, RectangleShape)
            .border(1.dp, Color(0xFF899D7C), RectangleShape),
    )
}

/** Colours a key square can take, all drawn from the measured palette. */
private val SQUARES = listOf(
    Color(0xFF98AE89),
    Color(0xFF899D7C),
    Color(0xFFBDBDBD),
    Color(0xFF060705),
    Color(0xFFE6E6E6),
    Color(0xFF8C0000),
)

/** Where the app came from, for the one place that has to say it. */
@Composable
fun appContext() = LocalContext.current

/** Vertical stack with the design's spacing, so screens stop inventing it. */
@Composable
fun Stack(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(1.dp),
    ) {
        content()
    }
}
