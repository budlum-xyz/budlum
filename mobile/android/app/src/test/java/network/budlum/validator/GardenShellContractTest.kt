package network.budlum.validator

import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import network.budlum.validator.garden.GardenLocalShare
import network.budlum.validator.garden.GardenModel
import network.budlum.validator.garden.QrScanActivity
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM contract and utility tests for the Garden Android shell.
 */
class GardenShellContractTest {

    private fun readRepoFile(relPath: String): String {
        val candidates = listOf(
            File(relPath),
            File("../../$relPath"),
        )
        val found = candidates.firstOrNull { it.isFile }
            ?: error("Could not locate $relPath from ${File(".").absolutePath}")
        return found.readText()
    }

    @Test
    fun localShareChunksAndAssemblesMdnsTxtAttributesInOrder() {
        val longRecord = "budlum://garden/join#" + "ab".repeat(350)
        val chunks = GardenLocalShare.chunkRecord(longRecord)
        assertTrue(chunks.size in 4..8)
        val attrMap = chunks.mapIndexed { idx, part ->
            "r$idx" to part.toByteArray(StandardCharsets.UTF_8)
        }.toMap()
        assertEquals(longRecord, GardenLocalShare.assembleTxtRecord(attrMap))
        assertEquals("", GardenLocalShare.assembleTxtRecord(emptyMap()))
    }

    @Test
    fun inviteHtmlPageEscapesHtmlMetacharactersAndKeepsApkRoute() {
        val page = GardenLocalShare.inviteHtmlPage("budlum://garden/join#<script>alert(1)</script>\"'")
        assertFalse(page.contains("<script>alert(1)</script>"))
        assertTrue(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"))
        assertTrue(page.contains("href=\"${GardenLocalShare.APK_PATH}\""))
        assertTrue(page.contains("window.location.hash"))
    }

    @Test
    fun localIpLiteralAllowsOnlyPrivateLoopbackCgnatWithoutDns() {
        assertTrue(GardenModel.isLocalIpLiteral("192.168.1.42"))
        assertTrue(GardenModel.isLocalIpLiteral("10.0.0.5"))
        assertTrue(GardenModel.isLocalIpLiteral("172.16.12.3"))
        assertTrue(GardenModel.isLocalIpLiteral("100.64.5.9"))
        assertTrue(GardenModel.isLocalIpLiteral("127.0.0.1"))
        assertTrue(GardenModel.isLocalIpLiteral("[::1]"))

        assertFalse(GardenModel.isLocalIpLiteral("8.8.8.8"))
        assertFalse(GardenModel.isLocalIpLiteral("1.1.1.1"))
        assertFalse(GardenModel.isLocalIpLiteral("0.0.0.0"))
        assertFalse(GardenModel.isLocalIpLiteral("224.0.0.1"))
        assertFalse(GardenModel.isLocalIpLiteral("attacker.example"))
        assertFalse(GardenModel.isLocalIpLiteral("localhost"))
        assertFalse(GardenModel.isLocalIpLiteral(""))
        assertFalse(GardenModel.isLocalIpLiteral(null))
    }

    @Test
    fun qrLuminanceExtractionHandlesPaddedAndInterleavedRowsSafely() {
        // 3x2 image with rowStride=5 and pixelStride=2: row0=[1,9,2,9,3], row1=[4,9,5,9,6]
        val raw = byteArrayOf(
            1, 9, 2, 9, 3,
            4, 9, 5, 9, 6,
        )
        val out = QrScanActivity.extractLuminanceFromBuffer(
            src = ByteBuffer.wrap(raw),
            rowStride = 5,
            pixelStride = 2,
            width = 3,
            height = 2,
        )
        assertNotNull(out)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5, 6), out)
        assertNull(
            QrScanActivity.extractLuminanceFromBuffer(
                src = ByteBuffer.wrap(raw),
                rowStride = 2,
                pixelStride = 1,
                width = 3,
                height = 2,
            ),
        )
    }

    @Test
    fun androidManifestUsesHostWildcardForLocalInvitePathAndMulticastPermissions() {
        val manifest = readRepoFile("mobile/android/app/src/main/AndroidManifest.xml")
        assertTrue(manifest.contains("android.permission.ACCESS_WIFI_STATE"))
        assertTrue(manifest.contains("android.permission.CHANGE_WIFI_MULTICAST_STATE"))
        assertTrue(manifest.contains("android:host=\"*\""))
        assertTrue(manifest.contains("android:path=\"/g\""))
        assertTrue(manifest.contains("android:scheme=\"budlum\""))
        assertTrue(manifest.contains("GardenValidatorService"))
        assertFalse(manifest.contains("REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"))
    }

    @Test
    fun gardenUiAndModelPreserveReadinessDeepLinksAndLifecycleGuards() {
        val model = readRepoFile(
            "mobile/android/app/src/main/java/network/budlum/validator/garden/GardenModel.kt",
        )
        val activity = readRepoFile(
            "mobile/android/app/src/main/java/network/budlum/validator/garden/GardenActivity.kt",
        )
        val screens = readRepoFile(
            "mobile/android/app/src/main/java/network/budlum/validator/garden/GardenScreens.kt",
        )
        val qr = readRepoFile(
            "mobile/android/app/src/main/java/network/budlum/validator/garden/QrScanActivity.kt",
        )
        val nav = readRepoFile(
            "mobile/android/app/src/main/java/network/budlum/validator/garden/GardenNavigation.kt",
        )
        val data = readRepoFile(
            "mobile/android/app/src/main/java/network/budlum/validator/garden/GardenDataScreen.kt",
        )

        assertTrue(model.contains("opMutex.withLock"))
        assertTrue(model.contains("Dispatchers.Main.immediate"))
        assertTrue(model.contains("readiness = currentReadiness"))
        assertTrue(model.contains("pendingJoinRecord = trimmed"))
        assertTrue(model.contains("localShare.stopShare()"))
        assertTrue(model.contains("parseStatusFlags"))
        assertTrue(model.contains("fun send(text: String, caption: String, onSent: () -> Unit = {})"))
        assertFalse(model.contains("\"\\\"can_return\\\":true\""))
        assertFalse(model.contains("\"\\\"status\\\":\\\"Away\\\"\""))
        assertFalse(model.contains("\"\\\"chain_id\\\"\""))

        assertTrue(activity.contains("extractAllowedInviteFromUri"))
        assertTrue(activity.contains("onBackground()"))
        assertTrue(activity.contains("shutdown()"))

        assertTrue(screens.contains("FLAG_KEEP_SCREEN_ON"))
        assertTrue(screens.contains("state.pendingJoinRecord"))
        assertTrue(screens.contains("state.canReturn"))
        assertTrue(screens.contains("state.inGarden"))
        assertTrue(screens.contains("setInviteVisible(true)"))
        assertTrue(screens.contains("setInviteVisible(false)"))
        assertTrue(screens.contains("internal fun GardenCard("))
        assertFalse(screens.contains("\"\\\"can_return\\\":true\""))
        assertFalse(screens.contains("\"\\\"chain_id\\\"\""))

        assertTrue(nav.contains("state.hasSeat"))
        assertFalse(nav.contains("\"\\\"chain_id\\\"\""))

        assertTrue(data.contains("GardenCard(\"FETCHED\")"))
        assertTrue(data.contains("model.send(text.trim(), caption.trim()) {"))

        assertTrue(qr.contains("AtomicBoolean"))
        assertTrue(qr.contains("var source: LuminanceSource"))
        assertTrue(qr.contains("finally {\n            image.close()\n        }"))
    }

    @Test
    fun parseStatusFlagsIgnoresSpoofedTitleSubstringsAndReadsStructuredFields() {
        val spoofedActive = """
            {
              "garden": {
                "chain_id": "4741000000000001",
                "title": "my \"can_return\":true and \"status\":\"Away\" title",
                "status": "Active",
                "can_return": false
              }
            }
        """.trimIndent()
        val activeFlags = GardenModel.parseStatusFlags(spoofedActive)
        assertTrue(activeFlags.hasSeat)
        assertTrue(activeFlags.hasChainId)
        assertFalse(activeFlags.isAway)
        assertFalse(activeFlags.canReturn)

        val away = """
            {
              "garden": {
                "chain_id": "4741000000000001",
                "status": "Away"
              }
            }
        """.trimIndent()
        val awayFlags = GardenModel.parseStatusFlags(away)
        assertTrue(awayFlags.hasSeat)
        assertTrue(awayFlags.hasChainId)
        assertTrue(awayFlags.isAway)
        assertTrue(awayFlags.canReturn)

        val empty = GardenModel.parseStatusFlags("""{"garden": null}""")
        assertFalse(empty.hasSeat)
        assertFalse(empty.hasChainId)
        assertFalse(empty.isAway)
        assertFalse(empty.canReturn)
    }
}
