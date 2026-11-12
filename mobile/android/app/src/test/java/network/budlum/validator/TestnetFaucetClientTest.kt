package network.budlum.validator

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.security.MessageDigest
import network.budlum.validator.core.FaucetResult
import network.budlum.validator.core.JvmMemoryWrappingKeyProvider
import network.budlum.validator.core.KeystoreKeyVault
import network.budlum.validator.core.MobileConstants
import network.budlum.validator.core.MobileValidatorEngine
import network.budlum.validator.core.ShareCustodyDirectory
import network.budlum.validator.core.TestnetFaucetClient
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TestnetFaucetClientTest {
    private val address = "0x" + "ab".repeat(32)
    private val hash = "0x" + "cd".repeat(32)
    private val challengeHex = "1234567890abcdef".repeat(2)
    private val now = 1_000_000L

    private class FakeConnection(url: URL, private val status: Int, private val reply: String) : HttpURLConnection(url) {
        val sent = ByteArrayOutputStream()
        var disconnected = false
        override fun connect() = Unit
        override fun disconnect() { disconnected = true }
        override fun usingProxy(): Boolean = false
        override fun getOutputStream() = sent
        override fun getInputStream() = ByteArrayInputStream(reply.toByteArray(Charsets.UTF_8))
        override fun getResponseCode(): Int = status
    }

    private fun receipt(to: String = address, atoms: Long = 100_000_000L, txHash: String = hash) =
        JSONObject().put("to", to).put("amount_atoms", atoms).put("tx_hash", txHash).toString()

    private fun challenge(
        hex: String = challengeHex, difficulty: Int = 1, expires: Long = now + 120,
        chainId: Long = MobileConstants.TESTNET_CHAIN_ID,
    ) = JSONObject().put("challenge", hex).put("difficulty_bits", difficulty)
        .put("expires_at", expires).put("chain_id", chainId).toString()

    private fun fakeClient(
        challengeReply: String = challenge(), postReply: String = receipt(),
        challengeStatus: Int = 200, postStatus: Int = 200,
        calls: MutableList<FakeConnection>,
    ) = TestnetFaucetClient(nowSeconds = { now }) { url ->
        val connection = when (url.path) {
            "/challenge" -> FakeConnection(url, challengeStatus, challengeReply)
            "/request" -> FakeConnection(url, postStatus, postReply)
            else -> error("unexpected endpoint")
        }
        calls.add(connection)
        connection
    }

    private fun le64(value: Long): ByteArray = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array()
    private fun bytes(hex: String) = ByteArray(hex.length / 2) { index ->
        hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }

    @Test fun rejectsInvalidOriginsAndAddressesBeforeOpeningConnection() {
        var opened = 0
        val client = TestnetFaucetClient(open = { opened++; error("network should not be called") })
        for (origin in listOf("", "http://faucet.test", "https://user@faucet.test", "https://faucet.test/evil",
                "https://faucet.test/?a=b", "https://faucet.test/#fragment", "https://faucet.test.evil/abc")) {
            assertEquals(FaucetResult.Failure.InvalidEndpoint, client.request(origin, address))
        }
        for (bad in listOf("", "0x" + "00".repeat(32), "0x123", "0x" + "gg".repeat(32))) {
            assertEquals(FaucetResult.Failure.InvalidAddress, client.request("https://faucet.test", bad))
        }
        assertEquals(0, opened)
    }

    @Test fun fetchesChallengeSolvesSha256AndPostsVerifiedReceipt() {
        val calls = mutableListOf<FakeConnection>()
        val client = fakeClient(calls = calls)
        assertEquals(FaucetResult.Submitted(hash), client.request("https://faucet.test/", "0x" + "AB".repeat(32)))
        assertEquals(2, calls.size)
        val get = calls[0]
        val post = calls[1]
        assertEquals("GET", get.requestMethod)
        assertEquals("https://faucet.test/challenge?address=$address", get.url.toString())
        assertEquals("POST", post.requestMethod)
        assertEquals("https://faucet.test/request", post.url.toString())
        assertEquals("application/json", post.getRequestProperty("Content-Type"))
        assertFalse(get.instanceFollowRedirects)
        assertFalse(post.instanceFollowRedirects)
        val payload = JSONObject(post.sent.toString("UTF-8"))
        assertEquals(setOf("address", "challenge", "nonce"), payload.keySet())
        assertEquals(address, payload.getString("address"))
        assertEquals(challengeHex, payload.getString("challenge"))
        val nonce = payload.getLong("nonce")
        val digest = MessageDigest.getInstance("SHA-256").digest(
            "budlum-faucet-v1".toByteArray(Charsets.US_ASCII) + le64(MobileConstants.TESTNET_CHAIN_ID) +
                bytes(challengeHex) + bytes(address.substring(2)) + le64(nonce)
        )
        assertTrue((digest[0].toInt() and 0x80) == 0) // difficulty 1: one leading zero bit
        assertTrue(get.connectTimeout > 0 && post.readTimeout > 0)
        assertTrue(calls.all { it.disconnected })
    }

    @Test fun challengeMatchesIndependentServerWorkVector() {
        val calls = mutableListOf<FakeConnection>()
        val client = fakeClient(challengeReply = challenge(hex = "01".repeat(16), difficulty = 8), calls = calls)
        assertEquals(FaucetResult.Submitted(hash), client.request("https://faucet.test", address))
        assertEquals(2, calls.size)
        val body = JSONObject(calls[1].sent.toString("UTF-8"))
        // Python hashlib and src/bin/support/faucet_pow.rs independently pin
        // the first valid SHA-256 nonce for chain 45261, [1;16], [0xab;32].
        assertEquals(93L, body.getLong("nonce"))
    }

    @Test fun invalidAndExcessiveChallengesNeverReachPost() {
        for ((challengeReply, expected) in listOf(
            "not json" to FaucetResult.Failure.InvalidChallenge,
            challenge(hex = "1") to FaucetResult.Failure.InvalidChallenge,
            challenge(chainId = 1) to FaucetResult.Failure.InvalidChallenge,
            challenge(expires = now) to FaucetResult.Failure.InvalidChallenge,
            challenge(difficulty = 21) to FaucetResult.Failure.ProofTooHard,
            "x".repeat(4097) to FaucetResult.Failure.InvalidChallenge,
        )) {
            val calls = mutableListOf<FakeConnection>()
            assertEquals(expected, fakeClient(challengeReply = challengeReply, calls = calls)
                .request("https://faucet.test", address))
            assertEquals(1, calls.size)
            assertTrue(calls[0].disconnected)
        }
    }

    @Test fun invalidReceiptsDoNotBecomeFundingOrBalances() {
        for (reply in listOf(
            "not json", "{}", receipt(to = "0x" + "ef".repeat(32)),
            receipt(atoms = 1), receipt(txHash = "missing"), "x".repeat(4097),
        )) {
            val calls = mutableListOf<FakeConnection>()
            assertEquals(FaucetResult.Failure.InvalidReceipt, fakeClient(postReply = reply, calls = calls)
                .request("https://faucet.test", address))
        }
        val dir = Files.createTempDirectory("faucet-no-local-credit").toFile()
        try {
            val engine = MobileValidatorEngine(
                ownerAddressHex = "01".repeat(32),
                keyVault = KeystoreKeyVault(JvmMemoryWrappingKeyProvider()),
                custodyDir = ShareCustodyDirectory(dir) { Long.MAX_VALUE },
                relays = emptyList(),
                initialAvailableBytes = 8 * MobileConstants.GIB_BYTES,
            )
            assertEquals(0L, engine.status().liquidBud)
            assertEquals(FaucetResult.Submitted(hash), fakeClient(calls = mutableListOf())
                .request("https://faucet.test", address))
            assertEquals(0L, engine.status().liquidBud)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun reportsRateLimitsFailuresRedirectsAndAmbiguousNetworkErrors() {
        for ((status, expected) in listOf(
            429 to FaucetResult.Failure.RateLimited, 503 to FaucetResult.Failure.Unavailable,
            400 to FaucetResult.Failure.Rejected, 302 to FaucetResult.Failure.Rejected,
        )) {
            val getCalls = mutableListOf<FakeConnection>()
            assertEquals(expected, fakeClient(challengeStatus = status, calls = getCalls)
                .request("https://faucet.test", address))
            assertEquals(1, getCalls.size)
            val postCalls = mutableListOf<FakeConnection>()
            assertEquals(expected, fakeClient(postStatus = status, calls = postCalls)
                .request("https://faucet.test", address))
            assertEquals(2, postCalls.size)
        }
        assertEquals(FaucetResult.Failure.NetworkError,
            TestnetFaucetClient(open = { throw IOException("reply lost after possible submission") })
                .request("https://faucet.test", address))
    }
}
