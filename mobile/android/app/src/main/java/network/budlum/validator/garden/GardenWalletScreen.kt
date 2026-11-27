package network.budlum.validator.garden

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import network.budlum.validator.R
import network.budlum.validator.core.MobileConstants

/**
 * The phone's own wallet.
 *
 * One phone holds one wallet, so there is no account list here and
 * nothing to add to it. A key is not a profile: either this phone has
 * one or it does not, and the three screens below are the three states
 * that follow from that.
 *
 * None of this screen knows how a key is made. Every call goes to the
 * core's own wallet module through the model, so the wallet a person
 * writes down here is the same wallet the desktop tools would derive
 * from the same twenty-four words.
 */

/** The shortest password the core will seal under, repeated here so the
 *  button can be dark before the call is made rather than after it. */
private const val MIN_PASSWORD = 8

/** How many of the twenty-four are asked back before the wallet is let go. */
private const val CHECKED_WORDS = 3

/**
 * No wallet yet: make one, or put back one the person already has.
 *
 * The two paths are one screen because they are one decision, and a
 * person who has words already should not have to find a second place
 * to type them.
 */
@Composable
fun WalletStartScreen(model: GardenModel) {
    var password by remember { mutableStateOf("") }
    var words by remember { mutableStateOf("") }
    var restoring by remember { mutableStateOf(false) }
    val state = model.state

    CubeFloor(model.skin) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Label(stringResource(R.string.w_wallet))
            Text(
                stringResource(R.string.w_what_a_wallet_is),
                style = MaterialTheme.typography.bodySmall,
                color = Ink,
                modifier = Modifier.padding(bottom = 10.dp),
            )

            if (restoring) {
                Label(stringResource(R.string.w_your_words))
                OutlinedTextField(
                    value = words,
                    onValueChange = { fresh -> words = fresh },
                    placeholder = { Label(stringResource(R.string.w_words_hint)) },
                    singleLine = false,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            Label(stringResource(R.string.w_password))
            OutlinedTextField(
                value = password,
                onValueChange = { fresh -> password = fresh },
                placeholder = { Label(stringResource(R.string.w_password_hint)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            Label(stringResource(R.string.w_password_floor))

            Rule()

            if (restoring) {
                RuleButton(
                    text = stringResource(R.string.w_restore),
                    onTap = { model.restoreWallet(words, password) },
                    enabled = !state.busy &&
                        password.length >= MIN_PASSWORD &&
                        words.trim().split(" ").filter { it.isNotEmpty() }.size ==
                        model.wordCount(),
                )
                RuleButton(
                    text = stringResource(R.string.w_make_instead),
                    onTap = { restoring = false },
                    enabled = !state.busy,
                )
            } else {
                RuleButton(
                    text = stringResource(R.string.w_make),
                    onTap = { model.createWallet(password) },
                    enabled = !state.busy && password.length >= MIN_PASSWORD,
                )
                RuleButton(
                    text = stringResource(R.string.w_restore_instead),
                    onTap = { restoring = true },
                    enabled = !state.busy,
                )
            }

            if (state.message.isNotEmpty()) {
                Label(state.message, color = Flow)
            }
        }
    }
}

/**
 * The twenty-four words, shown once.
 *
 * They are not read back off disk afterwards, because the sealed file
 * holds no clear copy of them. That is the point of the screen and the
 * reason it will not move on until it has been told they are written
 * down.
 */
@Composable
fun SeedPhraseScreen(model: GardenModel, onWritten: () -> Unit) {
    var confirmed by remember { mutableStateOf(false) }
    val state = model.state
    val words = state.mnemonic

    CubeFloor(model.skin) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Label(stringResource(R.string.w_seed_phrase))
            Text(
                stringResource(R.string.w_seed_warning),
                style = MaterialTheme.typography.bodySmall,
                color = Ink,
                modifier = Modifier.padding(bottom = 10.dp),
            )

            // Two columns, the way the design file lays them out: the
            // left column counts one upward and the right column carries
            // on from it, so a person reads down and then down again
            // rather than zig-zagging across the page.
            val half = (words.size + 1) / 2
            Slab(modifier = Modifier.fillMaxWidth()) {
                Column {
                    for (row in 0 until half) {
                        if (row > 0) {
                            Rule()
                        }
                        Row(modifier = Modifier.fillMaxWidth()) {
                            SeedWord(row + 1, words.getOrNull(row), Modifier.weight(1f))
                            SeedWord(
                                row + 1 + half,
                                words.getOrNull(row + half),
                                Modifier.weight(1f),
                            )
                        }
                    }
                }
            }

            Rule()

            RuleButton(
                text = if (confirmed) {
                    stringResource(R.string.w_written_down_yes)
                } else {
                    stringResource(R.string.w_written_down)
                },
                onTap = { confirmed = true },
                enabled = !confirmed,
            )
            RuleButton(
                text = stringResource(R.string.w_done),
                onTap = onWritten,
                enabled = confirmed,
            )
        }
    }
}

/**
 * Three of the words, asked back.
 *
 * A person who taps past the phrase screen without writing anything
 * down has a wallet they will lose, and they will not find that out
 * until the day it matters. Asking for three positions at random is
 * the cheapest way to make the claim true at the moment it is made.
 *
 * The positions are drawn once and remembered, so they do not shuffle
 * underneath somebody who is part way through typing.
 */
@Composable
fun SeedVerifyScreen(model: GardenModel, onVerified: () -> Unit) {
    val words = model.state.mnemonic
    val asked = remember(words.size) {
        if (words.size < CHECKED_WORDS) {
            words.indices.toList()
        } else {
            words.indices.shuffled().take(CHECKED_WORDS).sorted()
        }
    }
    var typed by remember { mutableStateOf(List(asked.size) { "" }) }
    val right = asked.indices.all { slot ->
        typed[slot].trim().equals(words.getOrNull(asked[slot]) ?: "", ignoreCase = true)
    }

    CubeFloor(model.skin) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Label(stringResource(R.string.w_verify))
            Text(
                stringResource(R.string.w_verify_why),
                style = MaterialTheme.typography.bodySmall,
                color = Ink,
                modifier = Modifier.padding(bottom = 10.dp),
            )

            asked.forEachIndexed { slot, position ->
                OutlinedTextField(
                    value = typed[slot],
                    onValueChange = { fresh ->
                        typed = typed.toMutableList().also { it[slot] = fresh }
                    },
                    label = { Label(stringResource(R.string.w_word_number, position + 1)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            Rule()

            RuleButton(
                text = stringResource(R.string.w_done),
                onTap = {
                    model.forgetMnemonic()
                    onVerified()
                },
                enabled = right,
            )
            if (!right && typed.any { it.isNotEmpty() }) {
                Label(stringResource(R.string.w_not_those_words), color = Flow)
            }
        }
    }
}

/** One numbered word of the phrase. */
@Composable
private fun SeedWord(number: Int, word: String?, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.padding(horizontal = 14.dp, vertical = 7.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Label(number.toString(), color = Mute)
        Text(
            word ?: "",
            style = MaterialTheme.typography.bodySmall,
            color = Ink,
        )
    }
}

/**
 * The wallet this phone holds.
 *
 * The address is read without the password, because the sealed file
 * keeps it in the clear for exactly this: a person should be able to
 * see which wallet their phone is carrying without unlocking it.
 */
@Composable
fun WalletScreen(model: GardenModel) {
    var password by remember { mutableStateOf("") }
    val state = model.state

    CubeFloor(model.skin) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Label(stringResource(R.string.w_wallet))

            Slab(modifier = Modifier.fillMaxWidth()) {
                Column {
                    Fact(stringResource(R.string.faucet_wallet_address), state.walletAddress)
                    Rule()
                    // The chain this wallet belongs to, read from the
                    // one constant the rest of the app reads it from
                    // rather than typed into a string file twice.
                    Fact(
                        stringResource(R.string.w_chain),
                        MobileConstants.TESTNET_CHAIN_ID.toString(),
                    )
                    Rule()
                    Fact(
                        stringResource(R.string.w_locked_or_not),
                        if (state.walletUnlocked) {
                            stringResource(R.string.w_unlocked)
                        } else {
                            stringResource(R.string.w_locked)
                        },
                    )
                }
            }

            if (!state.walletUnlocked) {
                Rule()
                Label(stringResource(R.string.w_password))
                OutlinedTextField(
                    value = password,
                    onValueChange = { fresh -> password = fresh },
                    placeholder = { Label(stringResource(R.string.w_password_hint)) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                RuleButton(
                    text = stringResource(R.string.w_unlock),
                    onTap = { model.unlockWallet(password) },
                    enabled = !state.busy && password.isNotEmpty(),
                )
            }

            if (state.message.isNotEmpty()) {
                Label(state.message, color = Flow)
            }
        }
    }
}
