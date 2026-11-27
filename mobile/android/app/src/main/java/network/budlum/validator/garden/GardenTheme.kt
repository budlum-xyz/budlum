package network.budlum.validator.garden

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import network.budlum.validator.R

/**
 * Budlum's own surface, not Material's default one.
 *
 * Every colour here is a measured token from the design file
 * (Figma 7tASYNmfotWyIrXpJ4ktrW): 19 frames, 13 interface colours, counted
 * by the canonical design token specification. Nothing
 * was picked by eye and nothing was invented: a colour that is not in the
 * tokens is not in this file, and the gate
 * `workspace/scripts/garden_apk_kapi.py` fails the tree if one appears.
 *
 * There is no error hue in the design - the measured palette has no red at
 * all. Error is therefore said with ink on paper plus a word, never with a
 * colour alone (WCAG 1.4.1 also asks for that). A hue can only be added
 * here after it is drawn in Figma and measured, never before.
 *
 * The radii come from the same place, and they matter more than they
 * look: panels and rows are square because the grid is the interface,
 * not decoration, and only controls and chips are allowed to soften.
 */
private val Page = Color(0xFFFBFCFA)
private val Ground = Color(0xFF060705)
private val Sage = Color(0xFF98AE89)
private val Ink = Color(0xFF060705)
private val Chalk = Color(0xFFFFFFFF)
private val Mute = Color(0xFFBDBDBD)
private val Faint = Color(0xFFE6E6E6)

/**
 * Panel and field boundaries.
 *
 * This used to be [Mute], which is 1.83:1 on [Page]: a boundary that a
 * person with low vision cannot see at all. The design's own panel stroke
 * is this value, so the token was already there - the wrong one was being
 * used for the job.
 */
private val Line = Color(0xFF333333)

private val budlumColors = lightColorScheme(
    primary = Ground,
    onPrimary = Chalk,
    primaryContainer = Sage,
    onPrimaryContainer = Ink,
    secondary = Sage,
    onSecondary = Ink,
    secondaryContainer = Faint,
    onSecondaryContainer = Ink,
    background = Page,
    onBackground = Ink,
    surface = Page,
    onSurface = Ink,
    surfaceVariant = Faint,
    onSurfaceVariant = Ink,
    outline = Line,
    outlineVariant = Faint,
    error = Ground,
    onError = Chalk,
)

/** Panel and row square, control and chip 8, shell 12 - the token radii. */
// Radii come from the measurement, like the colours do: 32 dp and 16 dp are
// the two the file uses most (88 and 87 samples). 8 dp and 12 dp appeared
// nowhere in it, so a shape that used them was drawing something the design
// never showed. The flat corner stays for the status chips.
private val budlumShapes = Shapes(
    extraSmall = RoundedCornerShape(0.dp),
    small = RoundedCornerShape(16.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(32.dp),
    extraLarge = RoundedCornerShape(32.dp),
)

private val budlum = FontFamily(Font(R.font.budlum_regular))

/**
 * One family throughout, as the design file has it. The label style is
 * the small uppercase one at .08em of tracking that the site uses over
 * every panel.
 */
private val budlumType = Typography().run {
    val body = TextStyle(fontFamily = budlum)
    copy(
        displayLarge = displayLarge.merge(body),
        displayMedium = displayMedium.merge(body),
        displaySmall = displaySmall.merge(body),
        headlineLarge = headlineLarge.merge(body),
        headlineMedium = headlineMedium.merge(body),
        headlineSmall = headlineSmall.merge(body),
        titleLarge = titleLarge.merge(body),
        titleMedium = titleMedium.merge(body),
        titleSmall = titleSmall.merge(body),
        bodyLarge = bodyLarge.merge(body),
        bodyMedium = bodyMedium.merge(body),
        bodySmall = bodySmall.merge(body),
        labelLarge = labelLarge.merge(body),
        labelMedium = labelMedium.merge(body),
        labelSmall = labelSmall.merge(body).copy(
            letterSpacing = 1.1.sp,
            fontSize = 11.sp,
        ),
    )
}

@Composable
fun GardenTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = budlumColors,
        shapes = budlumShapes,
        typography = budlumType,
        content = content,
    )
}
