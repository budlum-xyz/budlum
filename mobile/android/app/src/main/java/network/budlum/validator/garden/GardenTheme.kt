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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import network.budlum.validator.R

/**
 * Budlum's own surface, not Material's default one.
 *
 * Every colour here is a measured token from the design file
 * (Figma 7tASYNmfotWyIrXpJ4ktrW, by way of budlum.xyz `src/tokens.json`),
 * carried over by value. Nothing was picked by eye and nothing was
 * invented: a colour that is not in the tokens is not in this file.
 *
 * The radii come from the same place, and they matter more than they
 * look: panels and rows are square because the grid is the interface,
 * not decoration, and only controls and chips are allowed to soften.
 */
internal val Page = Color(0xFFFBFCFA)
internal val Ground = Color(0xFF060705)
internal val Sage = Color(0xFF98AE89)
internal val Ink = Color(0xFF060705)
internal val Chalk = Color(0xFFFFFFFF)
internal val Flow = Color(0xFF8C0000)
internal val Mute = Color(0xFFBDBDBD)
internal val Faint = Color(0xFFE6E6E6)

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
    outline = Mute,
    outlineVariant = Faint,
    error = Flow,
    onError = Chalk,
)

/** Panel and row square, control and chip 8, shell 12 - the token radii. */
private val budlumShapes = Shapes(
    extraSmall = RoundedCornerShape(0.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(8.dp),
    large = RoundedCornerShape(12.dp),
    extraLarge = RoundedCornerShape(12.dp),
)

/**
 * Two families, each kept to its own job.
 *
 * `budlum_regular` is the house display face. It carries 79 glyphs: enough
 * for a heading, nowhere near enough for running text, which is why it is
 * fenced off to the display, headline and title ramps and never reaches a
 * paragraph.
 *
 * Bricolage Grotesque is the text face. The four weights are static
 * instances cut from the upstream variable font at wght 400/500/600/700
 * with opsz 14 and wdth 100, so no caller has to ask for a variation axis
 * at run time. Both faces cover the Turkish set.
 */
private val budlum = FontFamily(Font(R.font.budlum_regular))

private val bricolage = FontFamily(
    Font(R.font.bricolage_grotesque_regular, FontWeight.Normal),
    Font(R.font.bricolage_grotesque_medium, FontWeight.Medium),
    Font(R.font.bricolage_grotesque_semibold, FontWeight.SemiBold),
    Font(R.font.bricolage_grotesque_bold, FontWeight.Bold),
)

/**
 * Headings in the house face, everything else in Bricolage Grotesque. The
 * label style stays the small tracked one the site sets over every panel.
 */
private val budlumType = Typography().run {
    val heading = TextStyle(fontFamily = budlum)
    val text = TextStyle(fontFamily = bricolage)
    copy(
        displayLarge = displayLarge.merge(heading),
        displayMedium = displayMedium.merge(heading),
        displaySmall = displaySmall.merge(heading),
        headlineLarge = headlineLarge.merge(heading),
        headlineMedium = headlineMedium.merge(heading),
        headlineSmall = headlineSmall.merge(heading),
        titleLarge = titleLarge.merge(heading),
        titleMedium = titleMedium.merge(heading),
        titleSmall = titleSmall.merge(heading),
        bodyLarge = bodyLarge.merge(text),
        bodyMedium = bodyMedium.merge(text),
        bodySmall = bodySmall.merge(text),
        labelLarge = labelLarge.merge(text),
        labelMedium = labelMedium.merge(text),
        labelSmall = labelSmall.merge(text).copy(
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
