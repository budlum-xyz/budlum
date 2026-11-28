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
 * (Figma 7tASYNmfotWyIrXpJ4ktrW): 19 frames, 13 interface colours,
 * carried over by value. Nothing was picked by eye and nothing was
 * invented: a colour that is not in the tokens is not in this file.
 *
 * There is no error hue in the design - the measured palette has no red at
 * all. Error is therefore said with ink on paper plus a word, never with a
 * colour alone (WCAG 1.4.1).
 *
 * The radii come from the same place, and they matter more than they
 * look: a panel is 16, measured on the chat shell in the file (`43:30406`,
 * `43:28885`, both 1080 wide with `r=16`), and larger shells sit at 32.
 * The role-named copy the Garden screens read lives in
 * [GardenDesignTokens]; this file keeps the Material scheme built from the
 * same values so a stock component cannot arrive in another palette.
 */
private val Page = Color(0xFFFBFCFA)
private val Ground = Color(0xFF060705)
private val Sage = Color(0xFF98AE89)
private val Ink = Color(0xFF060705)
private val Chalk = Color(0xFFFFFFFF)
private val Line = Color(0xFF333333)
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
    outline = Line,
    outlineVariant = Faint,
    error = Ground,
    onError = Chalk,
)

/** Panel and control 16, outer shell 32, and the flat corner for chips. */
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
