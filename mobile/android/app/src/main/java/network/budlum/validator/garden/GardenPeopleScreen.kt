package network.budlum.validator.garden

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import network.budlum.validator.R

/**
 * Who is in this network, and who is asking to be.
 *
 * This screen is the design's right-hand panel: a square per person, a
 * name, the short form of their key, and one thing you can do to them.
 * The sheets show it as a list of accounts with a send arrow; here the
 * one thing is admitting somebody, because that is what this group
 * needs a person for.
 *
 * Every network is host-approved now. An invite - or the six digits
 * standing in for one - gets a key into the record as Waiting. It is
 * not in the group and has no vote until the phone that started the
 * network says so. That is the step whose absence made the invite look
 * broken: there was nowhere for the answer to come from.
 */
@Composable
fun PeopleScreen(model: GardenModel) {
    val state = model.state

    LaunchedEffect(Unit) { model.readChat() }

    Column(modifier = Modifier.fillMaxSize()) {
        if (state.iAmHost) {
            CodeRow(model)
            Rule()
        }
        if (state.waitingForHost) {
            Sheet(model.skin, modifier = Modifier.padding(14.dp)) {
                Label(
                    stringResource(R.string.g_waiting_for_host),
                    modifier = Modifier.padding(14.dp),
                    color = Ink,
                )
            }
        }
        if (state.people.isEmpty()) {
            Label(
                stringResource(R.string.g_nobody_yet),
                modifier = Modifier.padding(16.dp),
            )
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(state.people, key = { it.key }) { person ->
                    PersonRow(person, canAnswer = state.iAmHost, model = model)
                    Rule()
                }
            }
        }
    }
}

/**
 * The six digits, and how long they last.
 *
 * Short because a person has to read it out across a table, and no
 * longer than an hour because an invite that never expires is not an
 * invite. The code is answered on the local network only, which the
 * screen says in three words rather than a paragraph.
 */
@Composable
private fun CodeRow(model: GardenModel) {
    val state = model.state
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column {
            Label(stringResource(R.string.g_code_label))
            Text(
                text = state.code.ifBlank { "------" },
                style = MaterialTheme.typography.headlineSmall,
                color = Ink,
            )
            Label(
                if (state.code.isBlank()) {
                    stringResource(R.string.g_code_same_wifi)
                } else {
                    stringResource(R.string.g_code_minutes, state.codeSecondsLeft / 60) +
                        " - " + stringResource(R.string.g_code_same_wifi)
                },
            )
        }
        Column(horizontalAlignment = Alignment.End) {
            RuleButton(
                text = stringResource(R.string.g_code_new),
                onTap = { model.openCode() },
                enabled = !state.busy,
            )
            if (state.record.isNotEmpty()) {
                // Six digits only reach as far as the Wi-Fi does. For
                // somebody on another network the full record still
                // works, so the way to hand it over stays - out of the
                // way, because it is the rarer case.
                val context = LocalContext.current
                Label(
                    stringResource(R.string.g_or) + " " +
                        stringResource(R.string.g_long_invite),
                    modifier = Modifier
                        .padding(top = 6.dp)
                        .clickable { shareInvite(context, state.record) },
                )
            }
        }
    }
}

/** Hand the full invite to whatever the phone can share with. */
private fun shareInvite(context: android.content.Context, record: String) {
    val sending = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(android.content.Intent.EXTRA_TEXT, record)
    }
    context.startActivity(android.content.Intent.createChooser(sending, null))
}

/** One person: square, name, key, and the answer they are owed. */
@Composable
private fun PersonRow(person: Person, canAnswer: Boolean, model: GardenModel) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // The file draws a person as a round portrait 80 px across,
        // which is 26.7 dp. This was a 34 dp square, which is neither
        // the shape nor the size.
        Portrait(round = true)
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = if (person.isMe) stringResource(R.string.g_you) else person.name,
                style = MaterialTheme.typography.bodyMedium,
                color = Ink,
            )
            Label(person.shortKey)
            if (person.waiting) {
                Label(
                    if (canAnswer) {
                        stringResource(R.string.g_waiting_for_you)
                    } else {
                        stringResource(R.string.g_waiting)
                    },
                    color = Flow,
                )
            }
        }
        if (person.waiting && canAnswer) {
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                RuleButton(
                    text = stringResource(R.string.g_let_in),
                    onTap = { model.answerRequest(person.key, true) },
                )
                RuleButton(
                    text = stringResource(R.string.g_turn_away),
                    onTap = { model.answerRequest(person.key, false) },
                    rule = Flow,
                    ink = Flow,
                )
            }
        }
    }
}

/**
 * Typing somebody else's six digits.
 *
 * The design's key screen is a label, a box and one button; this is the
 * same three things. Asking the network for the record and joining with
 * it are one tap, because to the person they are one act.
 */
@Composable
fun CodeJoinScreen(model: GardenModel) {
    var typed by remember { mutableStateOf("") }
    val state = model.state
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(18.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Label(stringResource(R.string.g_code_label))
        OutlinedTextField(
            value = typed,
            onValueChange = { fresh -> typed = fresh.filter { it.isDigit() }.take(6) },
            placeholder = { Label(stringResource(R.string.g_code_enter)) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
            modifier = Modifier.fillMaxWidth(),
        )
        Label(stringResource(R.string.g_code_same_wifi))
        RuleButton(
            text = stringResource(R.string.g_done),
            onTap = { model.joinWithCode(typed) },
            enabled = typed.length == 6 && !state.busy,
        )

        // Six digits only carry across one Wi-Fi. A QR holds the whole
        // signed record, so it still works from a photograph or across
        // networks, and section 2.6 asks for it. A tapped link lands in
        // the same place: the core reads it, says who it is from, and
        // nothing happens until the one button is pressed.
        Label(stringResource(R.string.g_or) + " " + stringResource(R.string.g_scan_qr),
            modifier = Modifier.clickable { model.scan() })

        if (state.preview.isNotEmpty()) {
            Rule()
            Fact(stringResource(R.string.g_invited_by), state.preview)
            RuleButton(
                text = stringResource(R.string.g_done),
                onTap = { model.join(state.previewRecord) },
                enabled = !state.busy,
            )
        }

        if (state.message.isNotEmpty()) {
            Label(state.message, color = Flow)
        }
    }
}
