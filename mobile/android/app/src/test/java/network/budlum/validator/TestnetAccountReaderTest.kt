package network.budlum.validator

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import network.budlum.validator.core.AccountBalanceResult
import network.budlum.validator.core.TestnetAccountReader
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TestnetAccountReaderTest {
    private val address = "0x" + "ab".repeat(32)

    private class FakeConnection(url: URL, private val code: Int, private val reply: String) : HttpURLConnection(url) {
        val sent = ByteArrayOutputStream()
        var disconnected = false
        override fun connect() = Unit
        override fun disconnect() { disconnected = true }
        override fun usingProxy(): Boolean = false
        override fun getOutputStream() = sent
        override fun getInputStream() = ByteArrayInputStream(reply.toByteArray(Charsets.UTF_8))
        override fun getResponseCode(): Int = code
    }

    private fun rpcReply(value: Any): String = JSONObject()
        .put("jsonrpc", "2.0").put("id", 1).put("result", value).toString()

    @Test fun checksChainBeforeReportingTheExactAccountBalance() {
        val connections = mutableListOf<FakeConnection>()
        val reader = TestnetAccountReader { url ->
            FakeConnection(url, 200, rpcReply(if (connections.isEmpty()) "0xb0cd" else "0x5f5e100"))
                .also(connections::add)
        }
        val result = reader.read("https://rpc.test/", address) as AccountBalanceResult.RpcReported
        assertEquals(address, result.address)
        assertEquals(BigInteger.valueOf(100_000_000), result.atoms)
        assertEquals("100", result.bud)
        assertEquals(2, connections.size)
        assertTrue(connections.all { it.url.toString() == "https://rpc.test/" && it.disconnected })
        assertTrue(connections.all { it.requestMethod == "POST" && !it.instanceFollowRedirects })
        val chain = JSONObject(connections[0].sent.toString("UTF-8"))
        val balance = JSONObject(connections[1].sent.toString("UTF-8"))
        assertEquals("bud_chainId", chain.getString("method"))
        assertEquals(0, chain.getJSONArray("params").length())
        assertEquals("bud_getBalance", balance.getString("method"))
        assertEquals(address, balance.getJSONArray("params").getString(0))
    }

    @Test fun wrongChainMalformedAmountsAndRpcErrorsNeverReportFunding() {
        val calls = mutableListOf<FakeConnection>()
        val wrongChain = TestnetAccountReader { url -> FakeConnection(url, 200, rpcReply("0x1")).also(calls::add) }
        assertEquals(AccountBalanceResult.Failure.WrongChain, wrongChain.read("https://rpc.test", address))
        assertEquals(1, calls.size)
        for (bad in listOf("-1", "0x10000000000000000", "100000000000001", "NaN", "")) {
            var n = 0
            val reader = TestnetAccountReader { url -> FakeConnection(url, 200, rpcReply(if (n++ == 0) "0xb0cd" else bad)) }
            assertEquals(AccountBalanceResult.Failure.InvalidResponse, reader.read("https://rpc.test", address))
        }
        val rpcError = TestnetAccountReader { FakeConnection(it, 200, """{"jsonrpc":"2.0","id":1,"error":{"code":-1}}""") }
        assertEquals(AccountBalanceResult.Failure.InvalidResponse, rpcError.read("https://rpc.test", address))
    }

    @Test fun zeroIsARealRpcAnswerAndBalanceIsNeverCreditedLocally() {
        var query = 0
        val reader = TestnetAccountReader { url ->
            FakeConnection(url, 200, rpcReply(if (query++ % 2 == 0) "0xb0cd" else "0x0"))
        }
        val result = reader.read("https://rpc.test", address) as AccountBalanceResult.RpcReported
        assertEquals(BigInteger.ZERO, result.atoms)
        assertEquals("0", result.bud)
        // No local wallet balance is kept or incremented; a second press must query again.
        assertEquals(BigInteger.ZERO, (reader.read("https://rpc.test", address) as AccountBalanceResult.RpcReported).atoms)
        assertEquals(4, query)
    }

    @Test fun invalidOriginsAndAddressesNeverCallTheNode() {
        var opened = false
        val reader = TestnetAccountReader { opened = true; error("should not open") }
        assertEquals(AccountBalanceResult.Failure.InvalidEndpoint, reader.read("http://rpc.test", address))
        assertEquals(AccountBalanceResult.Failure.InvalidEndpoint, reader.read("https://rpc.test/evil", address))
        assertEquals(AccountBalanceResult.Failure.InvalidAddress, reader.read("https://rpc.test", "0x0"))
        assertFalse(opened)
    }

    @Test fun refusedRedirectOversizeAndNetworkFailureAreNotBalances() {
        for (status in listOf(302, 401, 429, 503)) {
            assertEquals(AccountBalanceResult.Failure.Unavailable,
                TestnetAccountReader { FakeConnection(it, status, "") }.read("https://rpc.test", address))
        }
        assertEquals(AccountBalanceResult.Failure.InvalidResponse,
            TestnetAccountReader { FakeConnection(it, 200, "a".repeat(4097)) }
                .read("https://rpc.test", address))
        assertEquals(AccountBalanceResult.Failure.NetworkError,
            TestnetAccountReader { throw IOException("timeout") }.read("https://rpc.test", address))
    }
}
