package network.budlum.validator.garden

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import network.budlum.validator.R
import network.budlum.validator.core.MobileConstants

/**
 * The wallet sheets, laid out the way the design file lays them out.
 *
 * The file puts a wordmark at the top of the floor, a faint search bar
 * under it, a lowercase menu in the bottom left corner, and one panel
 * carrying everything the screen is actually about. These screens are
 * that, with the phone's width standing in for the file's right-hand
 * dock. The words on the buttons are lifted from the file rather than
 * invented here, which is why they live in the Turkish resources and
 * are reached only through stringResource.
 *
 * One phone holds one wallet, so there is no account list anywhere in
 * this file and nothing that adds a second.
 */

/** The shortest password the core will seal under. */
private const val MIN_PASSWORD = 8

/** How many of the words are asked back before the wallet is let go. */
private const val CHECKED_WORDS = 3

/** The corner menu the file prints on every sheet. */
@Composable
private fun pageMenu(): List<String> = listOf(
    stringResource(R.string.w_menu_ao),
    stringResource(R.string.w_menu_market),
    stringResource(R.string.w_menu_ecosystem),
    stringResource(R.string.w_menu_participation),
)

/** The wallet sheets all stand on the same page as everything else. */
@Composable
private fun WalletFloor(
    model: GardenModel,
    panel: @Composable () -> Unit,
) {
    BudlumPage(
        skin = model.skin,
        menu = pageMenu(),
        searchHint = stringResource(R.string.w_search_hint),
    ) {
        panel()
    }
}

/**
 * No wallet yet: make one, or put back one the person already has.
 *
 * Both paths are one panel because to the person they are one decision.
 */
@Composable
fun WalletStartScreen(model: GardenModel) {
    var password by remember { mutableStateOf("") }
    var words by remember { mutableStateOf("") }
    var restoring by remember { mutableStateOf(false) }
    val state = model.state
    val skin = model.skin

    WalletFloor(model) {
        Sheet(skin) {
            Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
                SheetHead(
                    name = stringResource(R.string.w_wallet),
                    address = stringResource(R.string.w_no_wallet_yet),
                    under = "",
                    skin = skin,
                )
                Text(
                    stringResource(R.string.w_what_a_wallet_is),
                    style = MaterialTheme.typography.bodySmall,
                    color = skin.ink,
                )

                if (restoring) {
                    OutlinedTextField(
                        value = words,
                        onValueChange = { fresh -> words = fresh },
                        placeholder = { Label(stringResource(R.string.w_words_hint)) },
                        singleLine = false,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                OutlinedTextField(
                    value = password,
                    onValueChange = { fresh -> password = fresh },
                    placeholder = { Label(stringResource(R.string.w_password_hint)) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    stringResource(R.string.w_password_floor),
                    style = MaterialTheme.typography.labelSmall,
                    color = Mute,
                )

                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    if (restoring) {
                        PillButton(
                            text = stringResource(R.string.w_restore),
                            onTap = { model.restoreWallet(words, password) },
                            enabled = !state.busy &&
                                password.length >= MIN_PASSWORD &&
                                words.trim().split(" ").filter { it.isNotEmpty() }.size ==
                                model.wordCount(),
                        )
                        PillButton(
                            text = stringResource(R.string.w_make_instead),
                            onTap = { restoring = false },
                            enabled = !state.busy,
                        )
                    } else {
                        PillButton(
                            text = stringResource(R.string.w_make),
                            onTap = { model.createWallet(password) },
                            enabled = !state.busy && password.length >= MIN_PASSWORD,
                        )
                        PillButton(
                            text = stringResource(R.string.w_restore_instead),
                            onTap = { restoring = true },
                            enabled = !state.busy,
                        )
                    }
                }

                if (state.message.isNotEmpty()) {
                    Text(
                        state.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = Flow,
                    )
                }
            }
        }
    }
}

/**
 * The words, shown once, in the file's two-column grid of numbered
 * boxes. The button under them carries the file's own wording.
 */
@Composable
fun SeedPhraseScreen(model: GardenModel, onWritten: () -> Unit) {
    val skin = model.skin
    val words = model.state.mnemonic

    WalletFloor(model) {
        Sheet(skin) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    stringResource(R.string.w_seed_warning),
                    style = MaterialTheme.typography.bodySmall,
                    color = skin.ink,
                )

                // Two columns, counting across the way the file counts:
                // 1 and 2 on the first line, 3 and 4 on the second.
                val lines = (words.size + 1) / 2
                for (line in 0 until lines) {
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        val left = line * 2
                        WordCell(
                            left + 1,
                            words.getOrNull(left) ?: "",
                            skin,
                            Modifier.weight(1f),
                        )
                        if (left + 1 < words.size) {
                            WordCell(
                                left + 2,
                                words[left + 1],
                                skin,
                                Modifier.weight(1f),
                            )
                        } else {
                            Spacer(modifier = Modifier.weight(1f))
                        }
                    }
                }

                Box(modifier = Modifier.fillMaxWidth()) {
                    PillButton(
                        text = stringResource(R.string.w_noted_go_on),
                        onTap = onWritten,
                        modifier = Modifier.align(Alignment.Center),
                    )
                }
            }
        }
    }
}

/**
 * Three of the words, asked back, in the same grid with the boxes
 * empty, under the file's own wording for the button.
 *
 * The positions are drawn once and remembered, so they do not shuffle
 * underneath somebody part way through typing.
 */
@Composable
fun SeedVerifyScreen(model: GardenModel, onVerified: () -> Unit) {
    val skin = model.skin
    val words = model.state.mnemonic
    val asked = remember(words.size) {
        if (words.size <= CHECKED_WORDS) {
            words.indices.toList()
        } else {
            words.indices.shuffled().take(CHECKED_WORDS).sorted()
        }
    }
    var typed by remember { mutableStateOf(List(asked.size) { "" }) }
    val right = asked.isNotEmpty() && asked.indices.all { slot ->
        typed[slot].trim().equals(words.getOrNull(asked[slot]) ?: "", ignoreCase = true)
    }

    WalletFloor(model) {
        Sheet(skin) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    stringResource(R.string.w_verify_why),
                    style = MaterialTheme.typography.bodySmall,
                    color = skin.ink,
                )

                asked.forEachIndexed { slot, position ->
                    WordField(
                        number = position + 1,
                        value = typed[slot],
                        onValue = { fresh ->
                            typed = typed.toMutableList().also { it[slot] = fresh }
                        },
                        skin = skin,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                if (!right && typed.any { it.isNotEmpty() }) {
                    Text(
                        stringResource(R.string.w_not_those_words),
                        style = MaterialTheme.typography.bodySmall,
                        color = Flow,
                    )
                }

                Box(modifier = Modifier.fillMaxWidth()) {
                    PillButton(
                        text = stringResource(R.string.w_thats_it),
                        onTap = {
                            model.forgetMnemonic()
                            onVerified()
                        },
                        enabled = right,
                        modifier = Modifier.align(Alignment.Center),
                    )
                }
            }
        }
    }
}

/**
 * The wallet this phone holds, in the file's own panel: portrait, who
 * this is, the address, then the counts and the balance.
 *
 * The address is read without the password, because the sealed file
 * keeps it in the clear for exactly this.
 */
@Composable
fun WalletScreen(model: GardenModel) {
    var password by remember { mutableStateOf("") }
    val state = model.state
    val skin = model.skin

    WalletFloor(model) {
        Sheet(skin) {
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                SheetHead(
                    name = stringResource(R.string.w_you),
                    address = shortAddress(state.walletAddress),
                    under = stringResource(R.string.w_chain) + " " +
                        MobileConstants.TESTNET_CHAIN_ID.toString(),
                    skin = skin,
                )

                SheetRow(
                    first = stringResource(R.string.w_tokens_none),
                    second = stringResource(R.string.w_nft_none),
                    skin = skin,
                    markFill = skin.rule,
                )

                SheetRow(
                    first = stringResource(R.string.w_bud_zero),
                    second = "",
                    skin = skin,
                )

                if (!state.walletUnlocked) {
                    OutlinedTextField(
                        value = password,
                        onValueChange = { fresh -> password = fresh },
                        placeholder = { Label(stringResource(R.string.w_password_hint)) },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                Box(modifier = Modifier.fillMaxWidth()) {
                    PillButton(
                        text = if (state.walletUnlocked) {
                            stringResource(R.string.w_open_transfers)
                        } else {
                            stringResource(R.string.w_sign_in)
                        },
                        onTap = {
                            if (!state.walletUnlocked) {
                                model.unlockWallet(password)
                            }
                        },
                        enabled = state.walletUnlocked ||
                            (!state.busy && password.isNotEmpty()),
                        modifier = Modifier.align(Alignment.Center),
                    )
                }

                if (state.message.isNotEmpty()) {
                    Text(
                        state.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = Flow,
                    )
                }
            }
        }
    }
}

/**
 * An address the way the file shows one: the head, an ellipsis, the
 * tail. Thirty-two bytes of hex does not fit a panel and nobody reads
 * the middle of it anyway.
 */
private fun shortAddress(address: String): String = when {
    address.isEmpty() -> ""
    address.length <= 18 -> address
    else -> address.take(10) + "…" + address.takeLast(6)
}
