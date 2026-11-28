package network.budlum.validator.garden

import android.graphics.Bitmap
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextFieldColors
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.imageResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.util.EnumMap
import network.budlum.validator.R

/**
 * The pieces every Garden screen is built from.
 *
 * The tile is the 60 pixel cube the design file specifies (sheet 42:750);
 * the icons are the exported Figma assets and geometric hairlines; the three
 * skins advance surface, ink and accent layers together so text and controls
 * never collide on any background.
 */

/**
 * A ground: what the floor is painted, and every colour that has to move with it.
 *
 * The design file does not ship three skins, it ships a ring of grounds - the
 * two-column palette on the depo page is one swatch per ground - and picking one
 * repaints the mesh, the sheets, the ink and the rules together. Three named
 * grounds stay as they were (they are what the preference file already holds and
 * what the frames draw), and any colour in the ring is a ground too.
 *
 * Everything that is not the ground itself answers from here, which is the whole
 * point: a screen that reaches for a literal white is a screen that stays white
 * on a green ground.
 */
data class Skin(
    val name: String,
    val behind: Color,
    val surface: Color,
    val ink: Color,
    val surfaceInk: Color,
    val muted: Color,
    val surfaceMuted: Color,
    val rule: Color,
    val surfaceRule: Color,
    val accent: Color,
    val accentOnSurface: Color,
    val danger: Color,
    val isDark: Boolean,
) {
    companion object {
        val Page = Skin(
            name = "page",
            behind = Color(0xFFFBFCFA),
            surface = Color(0xFFFBFCFA),
            ink = Color(0xFF060705),
            surfaceInk = Color(0xFF060705),
            muted = Color(0xFF5D635A),
            surfaceMuted = Color(0xFF5D635A),
            rule = Color(0xFFE0E4DC),
            surfaceRule = Color(0xFFD9D9D9),
            accent = Color(0xFF566B49),
            accentOnSurface = Color(0xFF566B49),
            danger = Color(0xFF8C0000),
            isDark = false,
        )

        val Sage = Skin(
            name = "sage",
            behind = Color(0xFF98AE89),
            surface = Color(0xFFFBFCFA),
            ink = Color(0xFF060705),
            surfaceInk = Color(0xFF060705),
            muted = Color(0xFF263022),
            surfaceMuted = Color(0xFF5D635A),
            rule = Color(0xFF7B916D),
            surfaceRule = Color(0xFFD9E0D4),
            accent = Color(0xFF060705),
            accentOnSurface = Color(0xFF566B49),
            danger = Color(0xFF6E0000),
            isDark = false,
        )

        val Ground = Skin(
            name = "ground",
            behind = Color(0xFF060705),
            surface = Color(0xFF0E100C),
            ink = Color(0xFFFBFCFA),
            surfaceInk = Color(0xFFFBFCFA),
            muted = Color(0xFF9EA69A),
            surfaceMuted = Color(0xFF9EA69A),
            rule = Color(0xFF252A22),
            surfaceRule = Color(0xFF252A22),
            accent = Color(0xFF98AE89),
            accentOnSurface = Color(0xFF98AE89),
            danger = Color(0xFFF27272),
            isDark = true,
        )

        /**
         * The ring of grounds, measured off the depo page's palette swatches.
         *
         * Sampled from the exported frame rather than guessed: each entry is the
         * centre pixel of one swatch (`42:113`).
         */
        val hues: List<Color> = listOf(
            Color(0xFFA0A789), Color(0xFFAE9A89), Color(0xFFAE8989),
            Color(0xFF898FAE), Color(0xFF9FAE89), Color(0xFF94AE8C),
            Color(0xFF89AE8E), Color(0xFF89AE99), Color(0xFF89ABA7),
            Color(0xFF89AAAE), Color(0xFFAE89AA), Color(0xFFAE8999),
            Color(0xFFAE898F), Color(0xFFAEA592), Color(0xFFAEAE89),
            Color(0xFF9A89AE), Color(0xFF9AAE89), Color(0xFF89AEA4),
        )

        /** The three painted grounds, then every swatch on the ring. */
        val ring: List<Skin> = listOf(Page, Sage, Ground) + hues.map(::of)

        /** A ground painted `ground`, with every layer that follows it. */
        fun of(ground: Color): Skin {
            val dark = ground.luminance() < 0.35f
            val hex = ground.toArgb().toUInt().toString(16).takeLast(6)
            return Skin(
                name = "ground-$hex",
                behind = ground,
                surface = if (dark) Color(0xFF0E100C) else Color(0xFFFBFCFA),
                ink = if (dark) Color(0xFFFBFCFA) else Color(0xFF060705),
                surfaceInk = if (dark) Color(0xFFFBFCFA) else Color(0xFF060705),
                muted = if (dark) Color(0xFF9EA69A) else Color(0xFF263022),
                surfaceMuted = if (dark) Color(0xFF9EA69A) else Color(0xFF5D635A),
                rule = if (dark) Color(0xFF252A22) else Color(0xFFE0E4DC),
                surfaceRule = if (dark) Color(0xFF252A22) else Color(0xFFD9D9D9),
                accent = if (dark) Color(0xFF98AE89) else Color(0xFF566B49),
                accentOnSurface = if (dark) Color(0xFF98AE89) else Color(0xFF566B49),
                danger = if (dark) Color(0xFFF27272) else Color(0xFF8C0000),
                isDark = dark,
            )
        }

        /** A stored ground by name; an older name still finds its paint. */
        fun fromName(name: String?): Skin =
            ring.firstOrNull { it.name.equals(name, ignoreCase = true) } ?: Page
    }
}

/**
 * The design's tile, and so its unit of space.
 *
 * The tile is 60 px in the file and was laid down here at 60 dp. A phone
 * runs at three times density, so the 60 px cell is 20 dp and the sheet
 * is 1080 px across to the phone's 360. At 60 dp the floor came out as a
 * handful of enormous squares where the file draws a fine mesh.
 */
val TILE = 20.dp

/**
 * A place on the floor.
 *
 * The lattice has no origin corner: a block never sits at (0,0), and the
 * places around any block are (x+1,y), (x,y+1) and (x+1,y+1) - the three the
 * sheet fills first when it draws a cluster. Two people whose blocks are
 * neighbours in this lattice are standing beside each other; two whose blocks
 * are not are not, however close the drawing makes them look.
 */
data class Cell(val x: Int, val y: Int) {
    /** Where a person can stand next to here, nearest first. */
    val neighbours: List<Cell>
        get() = listOf(
            Cell(x - 1, y),
            Cell(x, y - 1),
            Cell(x - 1, y - 1),
            Cell(x + 1, y),
            Cell(x, y + 1),
            Cell(x + 1, y + 1),
        ).filter { it.x >= 0 && it.y >= 0 && (it.x != 0 || it.y != 0) }

    /** Beside each other means one step in the lattice, either way. */
    fun beside(other: Cell): Boolean = neighbours.contains(other)
}

/**
 * The lit block: 32dp, which is the file's 64 against this floor's 20dp mesh.
 *
 * The same number is the step a person steps by when they move to the block
 * beside them, so it is also the unit the coordinate system counts in.
 */
val CUBE = 32.dp

/** The passive surface the file carries beside the mesh (`#D9D9D9`). */
internal val Passive = Color(0xFFD9D9D9)

/** The cube tile, repeated across the viewport with smooth skin transitions. */
@Composable
fun CubeFloor(theme: Skin, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    val animatedBg by animateColorAsState(
        targetValue = theme.behind,
        animationSpec = tween(GardenMotion.BASE_MS, easing = GardenMotion.Ease),
        label = "floorBg",
    )
    Box(
        modifier = modifier
            .fillMaxSize()
            .background(animatedBg)
            .drawBehind { floorMesh(theme) },
    ) {
        content()
    }
}

/**
 * The mesh, drawn from the ground's own inks.
 *
 * The file carries three exported tiles, one per painted ground, so any ground
 * picked off the ring fell back to the page tile and the mesh stopped belonging
 * to the colour under it. Drawing the mesh instead of stamping a PNG means every
 * ground - the three named ones and all eighteen on the ring - lays down lines
 * and a mark that are made of its own rule and ink.
 */
private fun DrawScope.floorMesh(ground: Skin) {
    val step = TILE.toPx()
    if (step <= 0f) return
    val hairline = ground.rule.copy(alpha = 0.55f)
    val mark = ground.ink.copy(alpha = 0.16f)
    var y = step
    while (y < size.height) {
        drawLine(hairline, androidx.compose.ui.geometry.Offset(0f, y), androidx.compose.ui.geometry.Offset(size.width, y), strokeWidth = 1f)
        y += step
    }
    var x = step
    while (x < size.width) {
        drawLine(hairline, androidx.compose.ui.geometry.Offset(x, 0f), androidx.compose.ui.geometry.Offset(x, size.height), strokeWidth = 1f)
        x += step
    }
    // The four-point mark the tile carries, at the centre of every second cell.
    val arm = step * 0.10f
    var cy = step * 1.5f
    while (cy < size.height) {
        var cx = step * 1.5f
        while (cx < size.width) {
            drawLine(mark, androidx.compose.ui.geometry.Offset(cx - arm, cy), androidx.compose.ui.geometry.Offset(cx + arm, cy), strokeWidth = 1f)
            drawLine(mark, androidx.compose.ui.geometry.Offset(cx, cy - arm), androidx.compose.ui.geometry.Offset(cx, cy + arm), strokeWidth = 1f)
            cx += step * 2f
        }
        cy += step * 2f
    }
}

/** A flat architectural panel with crisp 1dp hairline and full skin awareness. */
@Composable
fun Slab(
    modifier: Modifier = Modifier,
    skin: Skin = Skin.Page,
    fill: Color = skin.surface,
    rule: Color = skin.surfaceRule,
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

/**
 * The small tracked label the sheets use everywhere: field names, tab titles,
 * metadata and helper cues.
 */
@Composable
fun Label(
    text: String,
    modifier: Modifier = Modifier,
    skin: Skin = Skin.Page,
    color: Color = skin.surfaceMuted,
) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelSmall,
        color = color,
        modifier = modifier,
    )
}

/** One of the exported Figma PNG glyphs, tinted gently for contrast when needed. */
@Composable
fun Glyph(
    which: Int,
    description: String,
    onTap: () -> Unit,
    modifier: Modifier = Modifier,
    size: Dp = 24.dp,
    enabled: Boolean = true,
    tint: Color? = null,
) {
    val haptic = LocalHapticFeedback.current
    Box(
        modifier = modifier
            .size(size + 14.dp)
            .clickable(enabled = enabled, role = Role.Button) {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onTap()
            }
            .alpha(if (enabled) 1f else 0.35f),
        contentAlignment = Alignment.Center,
    ) {
        Image(
            painter = painterResource(which),
            contentDescription = description,
            colorFilter = tint?.let { ColorFilter.tint(it) },
            modifier = Modifier.size(size),
        )
    }
}

/**
 * A hairline-framed architectural action button.
 *
 * Respects the active skin so buttons stay legible on Page, Sage and Ground alike.
 */
@Composable
fun RuleButton(
    text: String,
    onTap: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    skin: Skin = Skin.Page,
    onSurface: Boolean = true,
    rule: Color? = null,
    ink: Color? = null,
    filled: Boolean = false,
) {
    val haptic = LocalHapticFeedback.current
    val resolvedAccent = if (onSurface) skin.accentOnSurface else skin.accent
    val activeRule = rule ?: resolvedAccent
    val activeInk = if (filled) {
        if (activeRule == Ink || activeRule == SageDeep || activeRule == Flow) Chalk else Ink
    } else {
        ink ?: resolvedAccent
    }
    val disabledColor = if (skin.isDark) Color(0xFF4A5047) else Color(0xFFA7ACA4)
    val bg = when {
        !filled -> Color.Transparent
        enabled -> activeRule
        else -> disabledColor.copy(alpha = 0.25f)
    }
    Box(
        modifier = modifier
            .background(bg, RoundedCornerShape(CONTROL_RADIUS))
            .border(
                width = 1.dp,
                color = if (enabled) activeRule else disabledColor,
                shape = RoundedCornerShape(CONTROL_RADIUS),
            )
            .clickable(enabled = enabled, role = Role.Button) {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onTap()
            }
            .padding(horizontal = 14.dp, vertical = 8.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = text.lowercase(),
            style = MaterialTheme.typography.labelSmall,
            color = if (enabled) activeInk else disabledColor,
        )
    }
}

/** A label and its value on one line, contrast-safe across all three skins. */
@Composable
fun Fact(
    name: String,
    value: String,
    modifier: Modifier = Modifier,
    skin: Skin = Skin.Page,
    valueColor: Color = skin.surfaceInk,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 14.dp, vertical = 9.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Label(name, skin = skin)
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            color = valueColor,
        )
    }
}

/** A 1dp hairline across the width, the design's separator. */
@Composable
fun Rule(skin: Skin = Skin.Page, color: Color = skin.surfaceRule) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(color),
    )
}

/** Contrast-safe Material3 text field colours matched to the active Budlum skin. */
@Composable
fun gardenTextFieldColors(skin: Skin): TextFieldColors =
    OutlinedTextFieldDefaults.colors(
        focusedTextColor = skin.surfaceInk,
        unfocusedTextColor = skin.surfaceInk,
        disabledTextColor = skin.surfaceMuted,
        cursorColor = skin.accentOnSurface,
        focusedBorderColor = skin.accentOnSurface,
        unfocusedBorderColor = skin.surfaceRule,
        focusedPlaceholderColor = skin.surfaceMuted,
        unfocusedPlaceholderColor = skin.surfaceMuted,
        focusedContainerColor = if (skin.isDark) Color(0xFF141712) else Color(0xFFF6F8F4),
        unfocusedContainerColor = if (skin.isDark) Color(0xFF11130F) else Color(0xFFF8FAF6),
    )

/**
 * The three-square Figma skin switch (`Page`, `Sage`, `Ground`), interactive
 * from every screen so the person can flip the floor at any moment.
 */
@Composable
fun SkinSwitch(
    current: Skin,
    onSelect: (Skin) -> Unit,
    modifier: Modifier = Modifier,
) {
    val haptic = LocalHapticFeedback.current
    val labels = mapOf(
        Skin.Page to stringResource(R.string.g_skin_page),
        Skin.Sage to stringResource(R.string.g_skin_sage),
        Skin.Ground to stringResource(R.string.g_skin_ground),
    )
    Row(
        modifier = modifier
            .horizontalScroll(rememberScrollState())
            .border(1.dp, current.rule, RoundedCornerShape(3.dp))
            .background(current.surface.copy(alpha = 0.85f), RoundedCornerShape(3.dp))
            .padding(3.dp),
        horizontalArrangement = Arrangement.spacedBy(3.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Skin.ring.forEach { option ->
            val selected = current == option
            val desc = labels[option] ?: option.name
            val borderColor = when {
                selected && current.isDark -> Chalk
                selected -> Ink
                option.isDark -> Color(0xFF3A3F38)
                else -> Color(0xFFC9CFC5)
            }
            Box(
                modifier = Modifier
                    .size(18.dp)
                    .background(option.behind, RoundedCornerShape(2.dp))
                    .border(if (selected) 1.5.dp else 1.dp, borderColor, RoundedCornerShape(2.dp))
                    .semantics { contentDescription = desc }
                    .clickable(role = Role.RadioButton) {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onSelect(option)
                    },
            )
        }
    }
}

/** The Budlum Garden sparkle-key brand emblem derived from the official logo. */
@Composable
fun GardenBrandMark(
    skin: Skin,
    modifier: Modifier = Modifier,
    height: Dp = 18.dp,
    onSurface: Boolean = false,
) {
    val tint = when {
        skin == Skin.Sage && !onSurface -> Ink
        skin.isDark -> Sage
        else -> null
    }
    Image(
        painter = painterResource(R.drawable.ic_budlum_garden_mark),
        contentDescription = stringResource(R.string.app_name),
        colorFilter = tint?.let { ColorFilter.tint(it) },
        modifier = modifier.height(height),
    )
}

/** Crisp geometric back chevron drawn at Figma hairline weight. */
@Composable
fun BackChevronIcon(tint: Color, modifier: Modifier = Modifier, size: Dp = 14.dp) {
    Canvas(modifier = modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val stroke = Stroke(width = 1.6.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round)
        val path = Path().apply {
            moveTo(w * 0.66f, h * 0.16f)
            lineTo(w * 0.30f, h * 0.50f)
            lineTo(w * 0.66f, h * 0.84f)
        }
        drawPath(path, color = tint, style = stroke)
    }
}

/** Crisp geometric eye icon for password reveal/hide (matches Figma eye control). */
@Composable
fun EyeIcon(visible: Boolean, tint: Color, modifier: Modifier = Modifier, size: Dp = 18.dp) {
    Canvas(modifier = modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val stroke = Stroke(width = 1.4.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round)
        val arch = Path().apply {
            moveTo(w * 0.08f, h * 0.50f)
            quadraticTo(w * 0.50f, h * 0.12f, w * 0.92f, h * 0.50f)
            quadraticTo(w * 0.50f, h * 0.88f, w * 0.08f, h * 0.50f)
            close()
        }
        drawPath(arch, color = tint, style = stroke)
        drawCircle(color = tint, radius = h * 0.14f, center = Offset(w * 0.50f, h * 0.50f), style = stroke)
        if (!visible) {
            drawLine(
                color = tint,
                start = Offset(w * 0.18f, h * 0.84f),
                end = Offset(w * 0.82f, h * 0.16f),
                strokeWidth = 1.5.dp.toPx(),
                cap = StrokeCap.Round,
            )
        }
    }
}

/** Crisp geometric copy icon. */
@Composable
fun CopyIcon(tint: Color, modifier: Modifier = Modifier, size: Dp = 15.dp) {
    Canvas(modifier = modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val stroke = Stroke(width = 1.35.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round)
        drawRoundRect(
            color = tint,
            topLeft = Offset(w * 0.34f, h * 0.30f),
            size = Size(w * 0.56f, h * 0.60f),
            cornerRadius = CornerRadius(2.dp.toPx()),
            style = stroke,
        )
        val back = Path().apply {
            moveTo(w * 0.28f, h * 0.66f)
            lineTo(w * 0.14f, h * 0.66f)
            lineTo(w * 0.14f, h * 0.12f)
            lineTo(w * 0.64f, h * 0.12f)
            lineTo(w * 0.64f, h * 0.24f)
        }
        drawPath(back, color = tint, style = stroke)
    }
}

/** Crisp geometric QR grid icon. */
@Composable
fun QrIcon(tint: Color, modifier: Modifier = Modifier, size: Dp = 15.dp) {
    Canvas(modifier = modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val stroke = Stroke(width = 1.35.dp.toPx())
        val box = w * 0.34f
        drawRect(tint, topLeft = Offset(w * 0.10f, h * 0.10f), size = Size(box, box), style = stroke)
        drawRect(tint, topLeft = Offset(w * 0.56f, h * 0.10f), size = Size(box, box), style = stroke)
        drawRect(tint, topLeft = Offset(w * 0.10f, h * 0.56f), size = Size(box, box), style = stroke)
        drawRect(tint, topLeft = Offset(w * 0.58f, h * 0.58f), size = Size(w * 0.14f, h * 0.14f))
        drawRect(tint, topLeft = Offset(w * 0.76f, h * 0.76f), size = Size(w * 0.14f, h * 0.14f))
    }
}

/** Render a crisp, high-contrast QR bitmap using bundled ZXing core. */
@Composable
fun rememberQrBitmap(content: String, sizePx: Int = 512): ImageBitmap? = remember(content, sizePx) {
    if (content.isBlank()) return@remember null
    runCatching {
        val hints = EnumMap<EncodeHintType, Any>(EncodeHintType::class.java).apply {
            put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M)
            put(EncodeHintType.MARGIN, 1)
            put(EncodeHintType.CHARACTER_SET, "UTF-8")
        }
        val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
        val pixels = IntArray(sizePx * sizePx)
        val dark = 0xFF060705.toInt()
        val light = 0xFFFBFCFA.toInt()
        for (y in 0 until sizePx) {
            val rowOffset = y * sizePx
            for (x in 0 until sizePx) {
                pixels[rowOffset + x] = if (matrix.get(x, y)) dark else light
            }
        }
        Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888).apply {
            setPixels(pixels, 0, sizePx, 0, 0, sizePx, sizePx)
        }.asImageBitmap()
    }.getOrNull()
}

/** Deterministic key-colored avatar square drawn from the measured palette. */
@Composable
fun KeySquare(key: String, size: Dp = 40.dp) {
    val hue = key.take(6).toLongOrNull(16) ?: key.hashCode().toLong()
    val shade = SQUARES[(hue.toInt() and 0x7fffffff) % SQUARES.size]
    Box(
        modifier = Modifier
            .size(size)
            .background(shade, RoundedCornerShape(CONTROL_RADIUS))
            .border(1.dp, SageRule, RoundedCornerShape(CONTROL_RADIUS)),
    )
}

private val SQUARES = listOf(
    Color(0xFF98AE89),
    Color(0xFF899D7C),
    Color(0xFF566B49),
    Color(0xFF2B3327),
    Color(0xFF666B63),
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
