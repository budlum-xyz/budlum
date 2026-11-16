package network.budlum.validator.core

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import org.json.JSONException
import org.json.JSONObject

/** A submitted transfer is not a confirmed transaction or an observed wallet balance. */
sealed interface FaucetResult {
    data class Submitted(val txHash: String) : FaucetResult
    enum class Failure : FaucetResult {
        InvalidEndpoint, InvalidAddress, InvalidChallenge, ProofTooHard, RateLimited,
        Unavailable, Rejected, NetworkError, InvalidReceipt,
    }
}

/**
 * HTTPS faucet client. The wallet is not connected to this app: the caller
 * supplies an address from a wallet it controls. No local balance is touched.
 * Solves the server's bounded per-request challenge on a background thread.
 */
class TestnetFaucetClient(
    private val nowSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
    private val open: (URL) -> HttpURLConnection = { it.openConnection() as HttpURLConnection },
) {
    private data class Challenge(val hex: String, val bytes: ByteArray, val difficulty: Int, val expires: Long)
    private class Refusal(val reason: FaucetResult.Failure) : Exception()

    companion object {
        private const val MAX_RESPONSE_BYTES = 4096
        private const val AMOUNT_ATOMS = 100_000_000L // 100 BUD, 10^6 atoms/BUD
        private const val MAX_DIFFICULTY = 20
        private const val MAX_ATTEMPTS = 8_000_000L
        private val hex32 = Regex("[0-9a-fA-F]{64}")
        private val hex16 = Regex("[0-9a-fA-F]{32}")

        /** Only an HTTPS origin, not an arbitrary path, query or redirect destination. */
        fun requestUrl(origin: String): URL? {
            val uri = try { URI(origin.trim()) } catch (_: IllegalArgumentException) { return null }
            if (uri.scheme != "https" || uri.host.isNullOrBlank() || uri.userInfo != null ||
                uri.rawQuery != null || uri.rawFragment != null || uri.rawPath !in listOf("", "/") ||
                uri.port == 0 || uri.port > 65535 || uri.port < -1
            ) return null
            return try { uri.resolve("/request").toURL() } catch (_: IllegalArgumentException) { null }
        }

        fun walletAddress(raw: String): String? {
            val hex = raw.trim().removePrefix("0x")
            if (!hex32.matches(hex) || hex.all { it == '0' }) return null
            return "0x${hex.lowercase()}"
        }

        private fun hexBytes(hex: String): ByteArray = ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }

        private fun leU64(value: Long): ByteArray =
            ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array()

        private fun hasLeadingZeroBits(digest: ByteArray, required: Int): Boolean {
            var found = 0
            for (byte in digest) {
                val leading = Integer.numberOfLeadingZeros(byte.toInt() and 0xff) - 24
                found += leading
                if (found >= required) return true
                if (leading != 8) return false
            }
            return false
        }
    }

    /** Blocking I/O and bounded proof work; call from Dispatchers.IO, never UI. */
    fun request(origin: String, rawAddress: String): FaucetResult {
        val url = requestUrl(origin) ?: return FaucetResult.Failure.InvalidEndpoint
        val address = walletAddress(rawAddress) ?: return FaucetResult.Failure.InvalidAddress
        return try {
            val challengeUrl = url.toURI().resolve("/challenge?address=$address").toURL()
            val challenge = fetchChallenge(challengeUrl)
            if (challenge.difficulty !in 1..MAX_DIFFICULTY) return FaucetResult.Failure.ProofTooHard
            val addressBytes = hexBytes(address.substring(2))
            val preimage = "budlum-faucet-v1".toByteArray(Charsets.US_ASCII) +
                leU64(MobileConstants.TESTNET_CHAIN_ID) + challenge.bytes + addressBytes
            val digest = MessageDigest.getInstance("SHA-256")
            val candidate = preimage + ByteArray(8)
            var nonce = 0L
            while (nonce < MAX_ATTEMPTS && (nonce % 1024L != 0L || nowSeconds() < challenge.expires)) {
                for (i in 0..7) candidate[preimage.size + i] = (nonce ushr (8 * i)).toByte()
                if (hasLeadingZeroBits(digest.digest(candidate), challenge.difficulty)) break
                nonce++
            }
            if (nonce >= MAX_ATTEMPTS || nowSeconds() >= challenge.expires) {
                FaucetResult.Failure.ProofTooHard
            } else {
                val body = JSONObject()
                    .put("address", address)
                    .put("challenge", challenge.hex)
                    .put("nonce", nonce)
                    .toString().toByteArray(Charsets.UTF_8)
                submit(url, body, address)
            }
        } catch (refusal: Refusal) {
            refusal.reason
        } catch (_: IOException) {
            // A transfer may have been submitted even if its reply was lost.
            FaucetResult.Failure.NetworkError
        } catch (_: JSONException) {
            FaucetResult.Failure.InvalidReceipt
        }
    }

    private fun connection(url: URL, method: String): HttpURLConnection = open(url).apply {
        requestMethod = method
        connectTimeout = 10_000
        readTimeout = 15_000
        instanceFollowRedirects = false
        setRequestProperty("Accept", "application/json")
    }

    private fun response(conn: HttpURLConnection, invalid: FaucetResult.Failure): String {
        when (conn.responseCode) {
            HttpURLConnection.HTTP_OK -> Unit
            429 -> throw Refusal(FaucetResult.Failure.RateLimited)
            503 -> throw Refusal(FaucetResult.Failure.Unavailable)
            else -> throw Refusal(FaucetResult.Failure.Rejected)
        }
        val bytes = ByteArray(MAX_RESPONSE_BYTES + 1)
        var size = 0
        conn.inputStream.use { input ->
            while (size < bytes.size) {
                val read = input.read(bytes, size, bytes.size - size)
                if (read < 0) break
                if (read == 0) throw IOException("faucet reply did not advance")
                size += read
            }
        }
        if (size > MAX_RESPONSE_BYTES) throw Refusal(invalid)
        return String(bytes, 0, size, Charsets.UTF_8)
    }

    private fun fetchChallenge(url: URL): Challenge {
        val conn = connection(url, "GET")
        try {
            val data = try { JSONObject(response(conn, FaucetResult.Failure.InvalidChallenge)) }
                catch (_: JSONException) { throw Refusal(FaucetResult.Failure.InvalidChallenge) }
            val hex = data.optString("challenge")
            val difficulty = data.opt("difficulty_bits")
            val expires = data.opt("expires_at")
            val chainId = data.opt("chain_id")
            if (!hex16.matches(hex) || difficulty !is Int ||
                (expires !is Long && expires !is Int) ||
                (chainId !is Long && chainId !is Int) ||
                (chainId as Number).toLong() != MobileConstants.TESTNET_CHAIN_ID ||
                (expires as Number).toLong() <= nowSeconds()
            ) throw Refusal(FaucetResult.Failure.InvalidChallenge)
            return Challenge(hex, hexBytes(hex), difficulty, (expires as Number).toLong())
        } finally {
            conn.disconnect()
        }
    }

    private fun submit(url: URL, body: ByteArray, address: String): FaucetResult {
        val conn = connection(url, "POST")
        try {
            conn.setRequestProperty("Content-Type", "application/json")
            conn.doOutput = true
            conn.setFixedLengthStreamingMode(body.size)
            conn.outputStream.use { it.write(body) }
            val receipt = JSONObject(response(conn, FaucetResult.Failure.InvalidReceipt))
            val to = receipt.optString("to")
            val amount = receipt.opt("amount_atoms")
            val hash = receipt.optString("tx_hash")
            return if (walletAddress(to) == address && (amount is Long || amount is Int) &&
                (amount as Number).toLong() == AMOUNT_ATOMS &&
                hash.startsWith("0x") && hex32.matches(hash.substring(2))
            ) FaucetResult.Submitted(hash) else FaucetResult.Failure.InvalidReceipt
        } finally {
            conn.disconnect()
        }
    }
}
