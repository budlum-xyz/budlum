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
 * (Figma 7tASYNmfotWyIrXpJ4ktrW, by way of budlum.xyz `src/tokens.json`),
 * carried over by value. Nothing was picked by eye and nothing was
 * invented: a colour that is not in the tokens is not in this file.
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
private val Flow = Color(0xFF8C0000)
private val Mute = Color(0xFFBDBDBD)
private val Faint = Color(0xFFE6E6E6)

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
