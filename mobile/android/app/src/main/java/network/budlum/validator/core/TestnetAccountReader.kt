package network.budlum.validator.core

import java.io.IOException
import java.math.BigDecimal
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONException
import org.json.JSONObject

/** Unverified node report, not a finalized state proof or proof of key ownership. */
sealed interface AccountBalanceResult {
    data class RpcReported(val address: String, val atoms: BigInteger) : AccountBalanceResult {
        val bud: String get() = BigDecimal(atoms).movePointLeft(6).stripTrailingZeros().toPlainString()
    }
    enum class Failure : AccountBalanceResult {
        InvalidEndpoint, InvalidAddress, WrongChain, Unavailable, InvalidResponse, NetworkError,
    }
}

/**
 * Read-only JSON-RPC query for an externally owned wallet address. This does
 * not load a wallet, trust a balance for spending, or enable validator duties.
 * A node's answer is not an account proof or a finalized balance.
 */
class TestnetAccountReader(
    private val open: (URL) -> HttpURLConnection = { it.openConnection() as HttpURLConnection },
) {
    private class Refusal(val reason: AccountBalanceResult.Failure) : Exception()

    companion object {
        private const val MAX_RESPONSE_BYTES = 4096
        private val MAX_SUPPLY_ATOMS = BigInteger("100000000000000") // 100M BUD * 10^6 atoms
        private val hexAmount = Regex("0x[0-9a-fA-F]{1,16}")
        private val decimalAmount = Regex("[0-9]{1,20}")

        /** Reuse the faucet's strict HTTPS-origin validation; RPC is at /. */
        fun rpcUrl(origin: String): URL? = TestnetFaucetClient.requestUrl(origin)
            ?.toURI()?.resolve("/")?.toURL()

        private fun unsignedAmount(raw: String): BigInteger? {
            val value = when {
                hexAmount.matches(raw) -> BigInteger(raw.substring(2), 16)
                decimalAmount.matches(raw) -> BigInteger(raw, 10)
                else -> return null
            }
            return value.takeIf { it.signum() >= 0 && it <= MAX_SUPPLY_ATOMS }
        }
    }

    /** Blocking I/O; call from Dispatchers.IO, not the UI thread. */
    fun read(origin: String, rawAddress: String): AccountBalanceResult {
        val url = rpcUrl(origin) ?: return AccountBalanceResult.Failure.InvalidEndpoint
        val address = TestnetFaucetClient.walletAddress(rawAddress)
            ?: return AccountBalanceResult.Failure.InvalidAddress
        return try {
            val chainId = rpc(url, "bud_chainId", emptyList())
            if (unsignedAmount(chainId)?.toLong() != MobileConstants.TESTNET_CHAIN_ID) {
                AccountBalanceResult.Failure.WrongChain
            } else {
                val atoms = unsignedAmount(rpc(url, "bud_getBalance", listOf(address)))
                    ?: return AccountBalanceResult.Failure.InvalidResponse
                AccountBalanceResult.RpcReported(address, atoms)
            }
        } catch (refusal: Refusal) {
            refusal.reason
        } catch (_: IOException) {
            AccountBalanceResult.Failure.NetworkError
        } catch (_: JSONException) {
            AccountBalanceResult.Failure.InvalidResponse
        }
    }

    private fun rpc(url: URL, method: String, params: List<String>): String {
        val body = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", 1)
            .put("method", method)
            .put("params", org.json.JSONArray(params))
            .toString().toByteArray(Charsets.UTF_8)
        val conn = open(url)
        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = 10_000
            conn.readTimeout = 15_000
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json")
            conn.doOutput = true
            conn.setFixedLengthStreamingMode(body.size)
            conn.outputStream.use { it.write(body) }
            if (conn.responseCode != HttpURLConnection.HTTP_OK) throw Refusal(AccountBalanceResult.Failure.Unavailable)
            val bytes = ByteArray(MAX_RESPONSE_BYTES + 1)
            var size = 0
            conn.inputStream.use { input ->
                while (size < bytes.size) {
                    val count = input.read(bytes, size, bytes.size - size)
                    if (count < 0) break
                    if (count == 0) throw IOException("RPC response did not advance")
                    size += count
                }
            }
            if (size > MAX_RESPONSE_BYTES) throw Refusal(AccountBalanceResult.Failure.InvalidResponse)
            val response = JSONObject(String(bytes, 0, size, Charsets.UTF_8))
            val id = response.opt("id")
            if (response.optString("jsonrpc") != "2.0" || (id !is Int && id !is Long) ||
                (id as Number).toLong() != 1L || response.has("error") || response.opt("result") !is String
            ) throw Refusal(AccountBalanceResult.Failure.InvalidResponse)
            return response.getString("result")
        } finally {
            conn.disconnect()
        }
    }
}
