package network.budlum.validator.garden

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * The parts the design sheets are actually built from.
 *
 * The rest of this app is drawn with `Slab`, which is a square box with
 * one hairline, because the chat sheets are laid out on a hard grid.
 * The wallet sheets are not: they put a single soft-cornered panel over
 * the floor, fill it with a portrait and a few facts, and finish with a
 * rounded outlined button. Drawing those screens out of `Slab` produced
 * something that belonged to neither sheet.
 *
 * Measurements are the file's own, divided by three: the frames are
 * 1080 wide at three times density, so 1080 px is 360 dp.
 */

/** The panel radius, 16 px in the file. */
private val SHEET_RADIUS = 6.dp

/** The control radius the buttons and word boxes use, 12 px in the file. */
private val CONTROL_RADIUS = 4.dp

/** The portrait square beside a name, 100 px in the file. */
val PORTRAIT = 34.dp

/**
 * The panel the wallet sheets hang everything on.
 *
 * In the file it is docked to the right edge of a wide canvas. A phone
 * has no right edge to spare, so it spans the width and keeps its own
 * fill, radius and hairline, which is what makes it read as a panel
 * floating over the floor rather than as the screen itself.
 */
@Composable
fun Sheet(
    skin: Skin,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .background(sheetFill(skin), RoundedCornerShape(SHEET_RADIUS))
            .border(1.dp, skin.rule, RoundedCornerShape(SHEET_RADIUS))
            .padding(horizontal = 18.dp, vertical = 20.dp),
    ) {
        content()
    }
}

/**
 * The panel sits on the floor, so it cannot be the floor's own colour.
 * On the dark skin the file lifts it a little; on the light one it is
 * the page white against a tinted floor.
 */
private fun sheetFill(skin: Skin): Color = when (skin) {
    Skin.Page -> Color(0xFFFBFCFA)
    Skin.Sage -> Color(0xFFFBFCFA)
    Skin.Ground -> Color(0xFF0E0F0C)
}

/**
 * The square portrait the file puts beside a name: flat sage, soft
 * corners, no picture in it.
 */
@Composable
fun Portrait(modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .size(PORTRAIT)
            .background(Sage, RoundedCornerShape(CONTROL_RADIUS)),
    )
}

/**
 * Who this is: the portrait, the name, and the address under it broken
 * the way the file breaks it.
 */
@Composable
fun SheetHead(name: String, address: String, under: String, skin: Skin) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Portrait()
        Column(modifier = Modifier.weight(1f)) {
            Text(
                name,
                style = MaterialTheme.typography.bodyLarge,
                color = skin.ink,
            )
            Text(
                address,
                style = MaterialTheme.typography.bodyMedium,
                color = skin.ink,
            )
            if (under.isNotEmpty()) {
                Text(
                    under,
                    style = MaterialTheme.typography.bodySmall,
                    color = Sage,
                )
            }
        }
    }
}

/**
 * A line of the panel: a small square mark on the left, then one or two
 * facts stacked beside it. The file uses it for the token counts and
 * for the balance.
 */
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
            Text(first, style = MaterialTheme.typography.bodyMedium, color = skin.ink)
            if (second.isNotEmpty()) {
                Text(second, style = MaterialTheme.typography.bodyMedium, color = skin.ink)
            }
        }
    }
}

/**
 * The button the file ends every panel with: a rounded hairline box,
 * sage on both the edge and the text, nothing filled in.
 *
 * `RuleButton` is the same idea with square corners, which is right for
 * the chat sheets and wrong for these.
 */
@Composable
fun PillButton(
    text: String,
    onTap: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val edge = if (enabled) Sage else Mute
    Box(
        modifier = modifier
            .border(BorderStroke(1.dp, edge), RoundedCornerShape(CONTROL_RADIUS))
            .clickable(enabled = enabled, onClick = onTap)
            .padding(horizontal = 18.dp, vertical = 9.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = edge,
        )
    }
}

/**
 * One cell of the phrase grid: the position in a small box on the left,
 * the word in a wider box beside it, both hairline and soft-cornered.
 *
 * The file draws twelve of these in two columns. There are twenty-four
 * here because a Budlum phrase is twenty-four words; the cell is the
 * file's, the count is the chain's.
 */
@Composable
fun WordCell(
    number: Int,
    word: String,
    skin: Skin,
    modifier: Modifier = Modifier,
) {
    Row(modifier = modifier, verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .border(1.dp, skin.rule, RoundedCornerShape(CONTROL_RADIUS))
                .padding(horizontal = 5.dp, vertical = 5.dp),
        ) {
            Text(
                "$number.",
                style = MaterialTheme.typography.labelSmall,
                color = skin.ink,
            )
        }
        Box(
            modifier = Modifier
                .weight(1f)
                .height(30.dp)
                .border(1.dp, skin.rule, RoundedCornerShape(CONTROL_RADIUS))
                .padding(horizontal = 8.dp),
            contentAlignment = Alignment.CenterStart,
        ) {
            Text(
                word,
                style = MaterialTheme.typography.bodySmall,
                color = skin.ink,
            )
        }
    }
}

/**
 * The same cell with the word box empty and typeable, which is how the
 * file asks the phrase back.
 */
@Composable
fun WordField(
    number: Int,
    value: String,
    onValue: (String) -> Unit,
    skin: Skin,
    modifier: Modifier = Modifier,
) {
    Row(modifier = modifier, verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .border(1.dp, skin.rule, RoundedCornerShape(CONTROL_RADIUS))
                .padding(horizontal = 5.dp, vertical = 5.dp),
        ) {
            Text(
                "$number.",
                style = MaterialTheme.typography.labelSmall,
                color = skin.ink,
            )
        }
        Box(
            modifier = Modifier
                .weight(1f)
                .height(30.dp)
                .border(1.dp, skin.rule, RoundedCornerShape(CONTROL_RADIUS))
                .padding(horizontal = 8.dp),
            contentAlignment = Alignment.CenterStart,
        ) {
            BasicTextField(
                value = value,
                onValueChange = onValue,
                singleLine = true,
                textStyle = MaterialTheme.typography.bodySmall.copy(color = skin.ink),
                cursorBrush = SolidColor(Sage),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

/**
 * The faint search bar the file runs under the wordmark. It is not a
 * control yet; it is part of how the page reads, so it is drawn and
 * left alone rather than left out and missed.
 */
@Composable
fun SearchBar(hint: String, skin: Skin, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(26.dp)
            .background(skin.rule.copy(alpha = 0.35f), RoundedCornerShape(CONTROL_RADIUS)),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            hint,
            style = MaterialTheme.typography.labelSmall,
            color = skin.ink.copy(alpha = 0.45f),
            textAlign = TextAlign.Center,
        )
    }
}

/**
 * The menu the file keeps in the bottom left corner of every sheet:
 * four lowercase words, no box, no icons.
 */
@Composable
fun CornerMenu(words: List<String>, skin: Skin, modifier: Modifier = Modifier) {
    Column(modifier = modifier.width(160.dp)) {
        words.forEach { word ->
            Text(
                word.lowercase(),
                style = MaterialTheme.typography.titleSmall,
                color = skin.ink,
            )
        }
    }
}
