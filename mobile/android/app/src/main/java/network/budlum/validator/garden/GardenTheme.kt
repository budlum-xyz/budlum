package network.budlum.validator.garden

import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
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
 * Every primary colour is a measured token from the Figma design file
 * (7tASYNmfotWyIrXpJ4ktrW, mirrored in budlum.xyz `src/tokens.json`), paired
 * with contrast-verified light and dark Material schemes so switching between
 * Page, Sage and Ground keeps every control readable.
 */
internal val Page = Color(0xFFFBFCFA)
internal val Ground = Color(0xFF060705)
internal val Sage = Color(0xFF98AE89)
internal val SageDeep = Color(0xFF566B49)
internal val SageRule = Color(0xFF899D7C)
internal val Ink = Color(0xFF060705)
internal val Chalk = Color(0xFFFFFFFF)
internal val Flow = Color(0xFF8C0000)
internal val FlowLight = Color(0xFFF27272)
internal val Mute = Color(0xFF666B63)
internal val Faint = Color(0xFFE6E6E6)
internal val DarkSurface = Color(0xFF0E0F0C)
internal val DarkRule = Color(0xFF252922)
internal val DarkMute = Color(0xFF9EA69A)

/** Motion tokens measured from Figma (`320ms`, `120ms`, `cubic-bezier(.22,.61,.36,1)`). */
internal object GardenMotion {
    const val BASE_MS = 320
    const val FAST_MS = 120
    val Ease = CubicBezierEasing(0.22f, 0.61f, 0.36f, 1.0f)
}

private val budlumLightColors = lightColorScheme(
    primary = Ground,
    onPrimary = Chalk,
    primaryContainer = Sage,
    onPrimaryContainer = Ink,
    secondary = SageDeep,
    onSecondary = Chalk,
    secondaryContainer = Faint,
    onSecondaryContainer = Ink,
    background = Page,
    onBackground = Ink,
    surface = Page,
    onSurface = Ink,
    surfaceVariant = Faint,
    onSurfaceVariant = Mute,
    outline = SageRule,
    outlineVariant = Faint,
    error = Flow,
    onError = Chalk,
)

private val budlumDarkColors = darkColorScheme(
    primary = Sage,
    onPrimary = Ink,
    primaryContainer = DarkSurface,
    onPrimaryContainer = Page,
    secondary = Sage,
    onSecondary = Ink,
    secondaryContainer = DarkRule,
    onSecondaryContainer = Page,
    background = Ground,
    onBackground = Page,
    surface = DarkSurface,
    onSurface = Page,
    surfaceVariant = DarkRule,
    onSurfaceVariant = DarkMute,
    outline = SageRule,
    outlineVariant = DarkRule,
    error = FlowLight,
    onError = Ink,
)

/**
 * The measured radii: 16 for panels and rows, 32 for the widest shell, 8 for
 * controls and chips. The file's chat and wallet frames carry 16 and 32 and
 * nothing else; 6 and 4 were this theme's own invention.
 */
private val budlumShapes = Shapes(
    extraSmall = RoundedCornerShape(0.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(32.dp),
)

/**
 * Two families, each kept to its own job.
 *
 * `budlum_regular` is the house display face (79 glyphs, display/headline/title).
 * Mako is the text face, and it is the only one the Garden frames use: the
 * chat, wallet and seed frames of the design file name `Mako` at 24/32/40 with
 * zero letter-spacing, so a body set in Bricolage was never the sheet's type.
 * Mako ships one weight; Android synthesises nothing here, and the design does
 * not ask for a bolder one.
 *
 * The OFL text ships beside it at `mobile/android/LICENSES/mako-OFL.txt`.
 */
private val budlum = FontFamily(Font(R.font.budlum_regular))

private val mako = FontFamily(Font(R.font.mako_regular))

private val budlumType = Typography().run {
    val heading = TextStyle(fontFamily = budlum)
    val text = TextStyle(fontFamily = mako)
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
            // Figma sets letter-spacing 0 on every frame of this surface.
            letterSpacing = 0.sp,
            fontSize = 11.sp,
        ),
    )
}

@Composable
fun GardenTheme(
    skin: Skin = Skin.Page,
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (skin.isDark) budlumDarkColors else budlumLightColors,
        shapes = budlumShapes,
        typography = budlumType,
        content = content,
    )
}
