package network.budlum.validator.garden

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import network.budlum.validator.R

/**
 * The sheet primitives measured directly from the Budlum Figma file
 * (7tASYNmfotWyIrXpJ4ktrW): floating panels over the cube lattice, numbered
 * phrase cells, pill buttons, local spotlight jump bar and unified header.
 */

/** The panel radius, 16 px in the file at 3x density. */
internal val SHEET_RADIUS = 16.dp

/** The control radius the buttons and word boxes use. */
internal val CONTROL_RADIUS = 8.dp

/** The portrait square beside a name, 100 px in the wallet sheets. */
internal val PORTRAIT = 34.dp

/** The round portrait in chat and people lists, 80 px on the 1080 px sheet. */
internal val PORTRAIT_ROUND = 26.7.dp

/** One jump target surfaced by the local spotlight bar (zero network traffic). */
data class SpotlightEntry(
    val title: String,
    val detail: String = "",
    val keywords: String = "",
    val onSelect: () -> Unit,
)

/** A floating panel lifted cleanly over the cube floor in every skin. */
@Composable
fun Sheet(
    skin: Skin,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .background(skin.surface, RoundedCornerShape(SHEET_RADIUS))
            .border(1.dp, skin.surfaceRule, RoundedCornerShape(SHEET_RADIUS))
            .padding(horizontal = 18.dp, vertical = 18.dp),
    ) {
        content()
    }
}

/** The portrait beside a name: square on wallet sheets, 80 px circle in chat/people. */
@Composable
fun Portrait(
    modifier: Modifier = Modifier,
    fill: Color = Sage,
    round: Boolean = false,
) {
    val shape = if (round) CircleShape else RoundedCornerShape(CONTROL_RADIUS)
    Box(
        modifier = modifier
            .size(if (round) PORTRAIT_ROUND else PORTRAIT)
            .background(fill, shape)
            .border(1.dp, SageRule, shape),
    )
}

/** Header row of a sheet: portrait, name, address/subtext and optional trailing control. */
@Composable
fun SheetHead(
    name: String,
    address: String,
    under: String,
    skin: Skin,
    trailing: (@Composable () -> Unit)? = null,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Portrait()
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = name,
                style = MaterialTheme.typography.bodyLarge,
                color = skin.surfaceInk,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (address.isNotEmpty()) {
                Text(
                    text = address,
                    style = MaterialTheme.typography.bodyMedium,
                    color = skin.surfaceInk,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (under.isNotEmpty()) {
                Text(
                    text = under,
                    style = MaterialTheme.typography.bodySmall,
                    color = skin.accentOnSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        if (trailing != null) {
            trailing()
        }
    }
}

/** A line of a panel: square mark on the left, one or two facts stacked beside it. */
@Composable
fun SheetRow(
    first: String,
    second: String,
    skin: Skin,
    markFill: Color = Sage,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(24.dp)
                .background(markFill, RoundedCornerShape(2.dp)),
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(first, style = MaterialTheme.typography.bodyMedium, color = skin.surfaceInk)
            if (second.isNotEmpty()) {
                Text(second, style = MaterialTheme.typography.bodySmall, color = skin.surfaceMuted)
            }
        }
    }
}

/** Outlined or primary pill button matching the Figma wallet panels. */
@Composable
fun PillButton(
    text: String,
    onTap: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    skin: Skin = Skin.Page,
    primary: Boolean = false,
) {
    val haptic = LocalHapticFeedback.current
    val activeEdge = skin.accentOnSurface
    val disabledColor = if (skin.isDark) Color(0xFF4A5047) else Color(0xFFA7ACA4)
    val edge = if (enabled) activeEdge else disabledColor
    val fill = when {
        !primary -> Color.Transparent
        enabled -> activeEdge
        else -> disabledColor.copy(alpha = 0.25f)
    }
    val textColor = when {
        !enabled -> disabledColor
        primary -> if (skin.isDark) Ink else Chalk
        else -> activeEdge
    }
    Box(
        modifier = modifier
            .background(fill, RoundedCornerShape(CONTROL_RADIUS))
            .border(BorderStroke(1.dp, edge), RoundedCornerShape(CONTROL_RADIUS))
            .clickable(enabled = enabled, role = Role.Button) {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onTap()
            }
            .padding(horizontal = 16.dp, vertical = 10.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = textColor,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

/** One cell of the 24-word recovery grid: position index box + word box. */
@Composable
fun WordCell(
    number: Int,
    word: String,
    skin: Skin,
    modifier: Modifier = Modifier,
    masked: Boolean = false,
) {
    // One box per word, number inside it: the seed frame draws a single thin
    // chip with the position in front, not a number plate beside a field.
    Row(
        modifier = modifier
            .height(28.dp)
            .border(1.dp, skin.surfaceRule, RoundedCornerShape(CONTROL_RADIUS))
            .padding(horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(
            "$number.",
            style = MaterialTheme.typography.labelSmall,
            color = skin.surfaceMuted,
        )
        Text(
            text = if (masked) "******" else word,
            style = MaterialTheme.typography.bodySmall,
            color = if (masked) skin.surfaceMuted else skin.surfaceInk,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

/** Typeable cell for recovery-word verification with instant match feedback. */
@Composable
fun WordField(
    number: Int,
    value: String,
    onValue: (String) -> Unit,
    skin: Skin,
    modifier: Modifier = Modifier,
    matched: Boolean = false,
) {
    val border = if (matched) skin.accentOnSurface else skin.surfaceRule
    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(
            modifier = Modifier
                .width(34.dp)
                .height(38.dp)
                .border(1.dp, border, RoundedCornerShape(CONTROL_RADIUS)),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                "$number.",
                style = MaterialTheme.typography.labelSmall,
                color = if (matched) skin.accentOnSurface else skin.surfaceMuted,
            )
        }
        Box(
            modifier = Modifier
                .weight(1f)
                .height(38.dp)
                .border(if (matched) 1.5.dp else 1.dp, border, RoundedCornerShape(CONTROL_RADIUS))
                .padding(horizontal = 10.dp),
            contentAlignment = Alignment.CenterStart,
        ) {
            BasicTextField(
                value = value,
                onValueChange = onValue,
                singleLine = true,
                textStyle = MaterialTheme.typography.bodyMedium.copy(color = skin.surfaceInk),
                cursorBrush = SolidColor(skin.accentOnSurface),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

/** The Budlum wordmark, tinted to stay crisp on every skin (including Sage). */
@Composable
fun Wordmark(
    skin: Skin = Skin.Page,
    modifier: Modifier = Modifier,
) {
    val tint = when {
        skin.isDark -> Sage
        skin.behind == Sage -> Ink
        else -> null
    }
    Image(
        painter = painterResource(R.drawable.budlum_wordmark),
        contentDescription = stringResource(R.string.app_name),
        colorFilter = tint?.let { ColorFilter.tint(it) },
        modifier = modifier.height(14.dp),
    )
}

/**
 * Local spotlight bar matching the Figma top search strip.
 *
 * Strictly local: never touches the network. Typing filters local destinations
 * so every screen and action is one tap away.
 */
@Composable
fun SpotlightBar(
    hint: String,
    skin: Skin,
    entries: List<SpotlightEntry>,
    modifier: Modifier = Modifier,
) {
    if (entries.isEmpty()) return
    var query by remember { mutableStateOf("") }
    val trimmed = query.trim().lowercase()
    val matches = remember(trimmed, entries) {
        if (trimmed.isEmpty()) {
            emptyList()
        } else {
            entries.filter { item ->
                item.title.lowercase().contains(trimmed) ||
                    item.detail.lowercase().contains(trimmed) ||
                    item.keywords.lowercase().contains(trimmed)
            }
        }
    }

    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(38.dp)
                // On the dark skin the sheet draws this strip at #0E100C
                // against a #060705 floor with no visible edge: it is felt
                // rather than seen. A full-strength rule here boxed it in.
                .background(skin.surface.copy(alpha = 0.92f), RoundedCornerShape(CONTROL_RADIUS))
                .border(
                    1.dp,
                    skin.surfaceRule.copy(alpha = if (skin.isDark) 0.45f else 1f),
                    RoundedCornerShape(CONTROL_RADIUS),
                )
                .padding(horizontal = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            GardenBrandMark(skin = skin, height = 11.dp, onSurface = true)
            Box(modifier = Modifier.weight(1f), contentAlignment = Alignment.CenterStart) {
                if (query.isEmpty()) {
                    Text(
                        text = hint,
                        style = MaterialTheme.typography.bodySmall,
                        color = skin.surfaceMuted,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                BasicTextField(
                    value = query,
                    onValueChange = { query = it },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodySmall.copy(color = skin.surfaceInk),
                    cursorBrush = SolidColor(skin.accentOnSurface),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            if (query.isNotEmpty()) {
                Label(
                    text = stringResource(R.string.g_close),
                    skin = skin,
                    color = skin.accentOnSurface,
                    modifier = Modifier.clickable { query = "" },
                )
            }
        }

        AnimatedVisibility(visible = trimmed.isNotEmpty()) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 4.dp)
                    .background(skin.surface, RoundedCornerShape(CONTROL_RADIUS))
                    .border(1.dp, skin.surfaceRule, RoundedCornerShape(CONTROL_RADIUS)),
            ) {
                if (matches.isEmpty()) {
                    Label(
                        text = stringResource(R.string.g_search_no_results),
                        skin = skin,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                    )
                } else {
                    matches.take(5).forEachIndexed { idx, item ->
                        if (idx > 0) Rule(skin = skin)
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    query = ""
                                    item.onSelect()
                                }
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = item.title,
                                style = MaterialTheme.typography.bodySmall,
                                color = skin.surfaceInk,
                            )
                            if (item.detail.isNotEmpty()) {
                                Label(item.detail, skin = skin, color = skin.accentOnSurface)
                            }
                        }
                    }
                }
            }
        }
    }
}

/**
 * The shared Budlum page chrome with edge-to-edge system bar insets, unified
 * header (optional back button, centered wordmark, always-reachable 3-square
 * skin switch), optional local spotlight bar, scrollable body, and brand crest.
 */
@Composable
fun BudlumPage(
    skin: Skin,
    onSkinChange: (Skin) -> Unit,
    onBack: (() -> Unit)? = null,
    searchHint: String = "",
    spotlight: List<SpotlightEntry> = emptyList(),
    content: @Composable ColumnScope.() -> Unit,
) {
    CubeFloor(skin) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 18.dp, vertical = 14.dp),
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 14.dp),
            ) {
                if (onBack != null) {
                    Row(
                        modifier = Modifier
                            .align(Alignment.CenterStart)
                            .clickable(role = Role.Button, onClick = onBack)
                            .padding(vertical = 6.dp, horizontal = 2.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        BackChevronIcon(tint = skin.ink)
                        Label(
                            text = stringResource(R.string.g_back),
                            skin = skin,
                            color = skin.ink,
                        )
                    }
                }
                Wordmark(
                    skin = skin,
                    modifier = Modifier.align(Alignment.Center),
                )
                SkinSwitch(
                    current = skin,
                    onSelect = onSkinChange,
                    modifier = Modifier.align(Alignment.CenterEnd),
                )
            }

            if (spotlight.isNotEmpty() && searchHint.isNotEmpty()) {
                SpotlightBar(
                    hint = searchHint,
                    skin = skin,
                    entries = spotlight,
                    modifier = Modifier.padding(bottom = 16.dp),
                )
            }

            content()

            Spacer(modifier = Modifier.height(24.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp),
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                GardenBrandMark(skin = skin, height = 16.dp, onSurface = false)
            }
        }
    }
}
