package network.budlum.validator.garden

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * The pieces the Garden screens are made of, measured from the design file.
 *
 * Figma `7tASYNmfotWyIrXpJ4ktrW`, page `43:26870` (`bud`): the chat shell
 * (`43:30406`, `43:30102`) and the friend list (`43:28885`). What was
 * measured there and is repeated here:
 *
 * - a rail of line icons down the left, one column, quiet until selected
 * - panels are white or page coloured with a 16 px corner radius
 * - one hairline in the accent colour (`#98AE89`) separates the head of a
 *   panel from its body, and nothing else is outlined
 * - a row is an avatar, a name, a second line, and a meta line underneath
 *   the panel in 11 px
 * - labels are uppercase and tracked out, values are sentence case
 *
 * Nothing here is a new invention: the names, sizes and colours come from
 * that file, and [GardenDesignTokens] is the single place they are written
 * down, so a screen cannot quietly pick a colour of its own.
 */

/** Every colour the Garden screens are allowed to use, by role. */
object GardenDesignTokens {

    /** The page the whole app sits on. Figma `arka plan`, `#FBFCFA`. */
    val page = Color(0xFFFBFCFA)

    /** Text and the ground of filled controls. Figma `#060705`. */
    val ink = Color(0xFF060705)

    /** The single accent: rules, selected icons, small labels. `#98AE89`. */
    val sage = Color(0xFF98AE89)

    /** Panels sit one step above the page. Figma `#FFFFFF`. */
    val panel = Color(0xFFFFFFFF)

    /** A surface that is present but not asking for attention. `#D9D9D9`. */
    val passive = Color(0xFFD9D9D9)

    /** Secondary text and the unselected rail. Figma `#BDBDBD`. */
    val mute = Color(0xFFBDBDBD)

    /** The quietest fill, for chips and tracks. `#E6E6E6`. */
    val faint = Color(0xFFE6E6E6)

    /** Refusals only. The design file keeps this for a failed state. */
    val flow = Color(0xFF8C0000)

    /** Panels and rows: the measured radius of every card in the file. */
    val panelRadius = 16.dp

    /** Controls and chips: the theme's control radius. */
    val controlRadius = 8.dp

    /** The side rail: one column of 28 dp marks, 56 dp wide. */
    val railWidth = 56.dp

    /** A list row is 56 dp tall: avatar 40, two lines of text. */
    val rowHeight = 56.dp

    /** Avatar in a row, measured as the icon's square in the file. */
    val avatarSize = 40.dp

    /** The gutter on every screen. */
    val gutter = 16.dp

    /** Space between two panels. */
    val gap = 12.dp
}

/**
 * A panel: the one container a screen is built from.
 *
 * In the file a panel is a rounded white rectangle with an optional 1 px
 * hairline in the accent colour, never a shadow and never a second border
 * colour. The same rule is kept here: `outlined` draws that one rule, and
 * nothing else about the panel changes.
 */
@Composable
fun GardenPanel(
    modifier: Modifier = Modifier,
    outlined: Boolean = false,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(GardenDesignTokens.panel, RoundedCornerShape(GardenDesignTokens.panelRadius))
            .border(
                width = if (outlined) 1.dp else 0.dp,
                color = if (outlined) GardenDesignTokens.sage else Color.Transparent,
                shape = RoundedCornerShape(GardenDesignTokens.panelRadius),
            )
            .padding(GardenDesignTokens.gutter),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        content = content,
    )
}

/** The uppercase, tracked label the file puts over every panel. */
@Composable
fun GardenLabel(text: String, modifier: Modifier = Modifier, tone: Color = GardenDesignTokens.sage) {
    Text(
        text = text.uppercase(),
        modifier = modifier,
        style = MaterialTheme.typography.labelSmall.copy(
            fontSize = 11.sp,
            letterSpacing = 1.1.sp,
        ),
        color = tone,
    )
}

/** A heading inside a panel: sentence case, one step above body. */
@Composable
fun GardenHeading(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        modifier = modifier,
        style = MaterialTheme.typography.titleMedium,
        color = GardenDesignTokens.ink,
    )
}

/** Body text with the file's measure: never wider than a comfortable line. */
@Composable
fun GardenBody(text: String, modifier: Modifier = Modifier, tone: Color = GardenDesignTokens.ink) {
    Text(
        text = text,
        modifier = modifier,
        style = MaterialTheme.typography.bodyMedium,
        color = tone,
    )
}

/** The small second line under a row's name. */
@Composable
fun GardenCaption(text: String, modifier: Modifier = Modifier, tone: Color = GardenDesignTokens.mute) {
    Text(
        text = text,
        modifier = modifier,
        style = MaterialTheme.typography.bodySmall,
        color = tone,
        maxLines = 2,
        overflow = TextOverflow.Ellipsis,
    )
}

/**
 * The meta line under a panel: values separated by a middle dot.
 *
 * The file writes one under every card - `20-12 - 100k - 3.7` - and it is
 * what tells a reader when the row spoke and how big it is without opening
 * it. Empty parts are dropped rather than printed as a broken separator.
 */
@Composable
fun GardenMeta(parts: List<String>, modifier: Modifier = Modifier) {
    val kept = parts.filter { it.isNotBlank() }
    if (kept.isEmpty()) {
        return
    }
    Text(
        text = kept.joinToString("  -  "),
        modifier = modifier,
        style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
        color = GardenDesignTokens.mute,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
    )
}

/**
 * A label on the left and its value on the right, one line.
 *
 * The space between the two closes the line, in that order: the opening
 * word, then the closing one. No rule between them, because in the file
 * the only hairline on a panel is the one under its head.
 */
@Composable
fun GardenStat(label: String, value: String, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label.uppercase(),
            style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp, letterSpacing = 0.9.sp),
            color = GardenDesignTokens.mute,
        )
        Spacer(modifier = Modifier.weight(1f))
        Text(value, style = MaterialTheme.typography.bodyMedium, color = GardenDesignTokens.ink)
    }
}

/**
 * A row of the file: avatar, name, second line.
 *
 * The avatar is a rounded square with the accent hairline, not a circle,
 * because that is what the file draws. A row with no second line still
 * keeps the height, so a list never jumps as rows arrive.
 */
@Composable
fun GardenRow(
    name: String,
    detail: String,
    modifier: Modifier = Modifier,
    initial: String = name.take(1).uppercase(),
    selected: Boolean = false,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .height(GardenDesignTokens.rowHeight)
            .background(
                if (selected) GardenDesignTokens.faint else Color.Transparent,
                RoundedCornerShape(GardenDesignTokens.controlRadius),
            )
            .padding(horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(GardenDesignTokens.avatarSize)
                .background(GardenDesignTokens.page, RoundedCornerShape(GardenDesignTokens.controlRadius))
                .border(
                    width = 1.dp,
                    color = GardenDesignTokens.sage,
                    shape = RoundedCornerShape(GardenDesignTokens.controlRadius),
                ),
            contentAlignment = Alignment.Center,
        ) {
            Text(initial, style = MaterialTheme.typography.titleSmall, color = GardenDesignTokens.ink)
        }
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = name,
                style = MaterialTheme.typography.bodyLarge,
                color = GardenDesignTokens.ink,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (detail.isNotBlank()) {
                GardenCaption(detail)
            }
        }
    }
}

/** The marks in the side rail. */
enum class GardenMark {
    /** The sparkle at the top of the file: the Garden itself. */
    Sparkle,

    /** A speech bubble: the invite. */
    Invite,

    /** A bookmark: joining. */
    Join,

    /** Stacked blocks: the chain this phone validates. */
    Chain,

    /** A grid: what the phone holds. */
    Storage,

    /** A rounded square: the Android permissions. */
    Phone,
}

/**
 * One mark from the rail, drawn rather than shipped as an image.
 *
 * The file uses single-weight line icons, one colour, no fills. Drawing
 * them keeps the APK free of an icon font and means the selected state is
 * the same geometry in the accent colour instead of a second asset.
 */
@Composable
fun GardenMarkIcon(
    mark: GardenMark,
    selected: Boolean,
    modifier: Modifier = Modifier,
) {
    val colour = if (selected) GardenDesignTokens.sage else GardenDesignTokens.ink
    Canvas(modifier = modifier.size(28.dp)) {
        val w = size.width
        val h = size.height
        val stroke = Stroke(width = 1.6.dp.toPx(), cap = StrokeCap.Round)
        when (mark) {
            GardenMark.Sparkle -> {
                val path = Path().apply {
                    moveTo(w * 0.5f, h * 0.08f)
                    cubicTo(w * 0.56f, h * 0.34f, w * 0.66f, h * 0.44f, w * 0.92f, h * 0.5f)
                    cubicTo(w * 0.66f, h * 0.56f, w * 0.56f, h * 0.66f, w * 0.5f, h * 0.92f)
                    cubicTo(w * 0.44f, h * 0.66f, w * 0.34f, h * 0.56f, w * 0.08f, h * 0.5f)
                    cubicTo(w * 0.34f, h * 0.44f, w * 0.44f, h * 0.34f, w * 0.5f, h * 0.08f)
                    close()
                }
                drawPath(path, colour, style = stroke)
            }
            GardenMark.Invite -> {
                val bubble = Path().apply {
                    moveTo(w * 0.14f, h * 0.16f)
                    lineTo(w * 0.86f, h * 0.16f)
                    lineTo(w * 0.86f, h * 0.66f)
                    lineTo(w * 0.44f, h * 0.66f)
                    lineTo(w * 0.26f, h * 0.86f)
                    lineTo(w * 0.26f, h * 0.66f)
                    lineTo(w * 0.14f, h * 0.66f)
                    close()
                }
                drawPath(bubble, colour, style = stroke)
            }
            GardenMark.Join -> {
                val mark = Path().apply {
                    moveTo(w * 0.26f, h * 0.12f)
                    lineTo(w * 0.74f, h * 0.12f)
                    lineTo(w * 0.74f, h * 0.9f)
                    lineTo(w * 0.5f, h * 0.68f)
                    lineTo(w * 0.26f, h * 0.9f)
                    close()
                }
                drawPath(mark, colour, style = stroke)
            }
            GardenMark.Chain -> {
                drawRoundRect(
                    color = colour,
                    topLeft = Offset(w * 0.32f, h * 0.10f),
                    size = androidx.compose.ui.geometry.Size(w * 0.36f, h * 0.28f),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(2.dp.toPx()),
                )
                drawRoundRect(
                    color = colour,
                    topLeft = Offset(w * 0.10f, h * 0.48f),
                    size = androidx.compose.ui.geometry.Size(w * 0.36f, h * 0.28f),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(2.dp.toPx()),
                )
                drawRoundRect(
                    color = colour,
                    topLeft = Offset(w * 0.54f, h * 0.48f),
                    size = androidx.compose.ui.geometry.Size(w * 0.36f, h * 0.28f),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(2.dp.toPx()),
                )
            }
            GardenMark.Storage -> {
                drawLine(colour, Offset(w * 0.5f, h * 0.1f), Offset(w * 0.5f, h * 0.9f), 1.6.dp.toPx(), StrokeCap.Round)
                drawRoundRect(
                    color = colour,
                    topLeft = Offset(w * 0.18f, h * 0.62f),
                    size = androidx.compose.ui.geometry.Size(w * 0.24f, h * 0.28f),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(2.dp.toPx()),
                )
                drawRoundRect(
                    color = colour,
                    topLeft = Offset(w * 0.58f, h * 0.62f),
                    size = androidx.compose.ui.geometry.Size(w * 0.24f, h * 0.28f),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(2.dp.toPx()),
                )
            }
            GardenMark.Phone -> {
                drawRoundRect(
                    color = colour,
                    topLeft = Offset(w * 0.2f, h * 0.08f),
                    size = androidx.compose.ui.geometry.Size(w * 0.6f, h * 0.84f),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(6.dp.toPx()),
                    style = stroke,
                )
            }
        }
    }
}

/** The rail: one column of marks, the current one in the accent colour. */
@Composable
fun GardenRail(
    current: GardenMark,
    marks: List<GardenMark>,
    onChoose: (GardenMark) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .width(GardenDesignTokens.railWidth)
            .fillMaxHeight()
            .background(GardenDesignTokens.page)
            .padding(vertical = GardenDesignTokens.gutter),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        marks.forEach { mark ->
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .background(
                        if (mark == current) GardenDesignTokens.faint else Color.Transparent,
                        RoundedCornerShape(GardenDesignTokens.controlRadius),
                    )
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = null,
                    ) { onChoose(mark) },
                contentAlignment = Alignment.Center,
            ) {
                GardenMarkIcon(mark = mark, selected = mark == current)
            }
        }
    }
}

/**
 * A chip that says in one word what state something is in.
 *
 * Two tones only, both taken from the file: the accent when the thing is
 * doing its job, the passive grey when it is not, refused, or waiting. A
 * chip never carries the failure colour, because a chip states, and the
 * sentence next to it explains.
 */
@Composable
fun GardenPill(text: String, active: Boolean = true, modifier: Modifier = Modifier) {
    Text(
        text = text.uppercase(),
        modifier = modifier
            .background(
                if (active) GardenDesignTokens.sage else GardenDesignTokens.passive,
                RoundedCornerShape(GardenDesignTokens.controlRadius),
            )
            .padding(horizontal = 8.dp, vertical = 3.dp),
        style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp, letterSpacing = 0.9.sp),
        color = GardenDesignTokens.ink,
    )
}
