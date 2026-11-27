package network.budlum.validator.garden

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure JVM unit tests for Budlum Garden logic, routing and resource integrity. */
class GardenLogicTest {

    @Test
    fun normalizeMnemonicHandlesWhitespaceAndCase() {
        val raw = "  Apple\n  BANANA\t cherry   Date  "
        assertEquals(listOf("apple", "banana", "cherry", "date"), GardenLogic.normalizeMnemonicWords(raw))
        assertEquals(emptyList<String>(), GardenLogic.normalizeMnemonicWords("   \n\t  "))
    }

    @Test
    fun clipboardInviteOnlyAcceptsGardenPrefixes() {
        assertEquals(
            "budlum://garden/abc123",
            GardenLogic.extractClipboardInvite("  budlum://garden/abc123  "),
        )
        assertEquals(
            "https://budlum.xyz/g#payload",
            GardenLogic.extractClipboardInvite("https://budlum.xyz/g#payload"),
        )
        assertEquals(
            "budlum-garden-invite:v1:deadbeef",
            GardenLogic.extractClipboardInvite("budlum-garden-invite:v1:deadbeef"),
        )
        // Privacy check: ordinary clipboard text and URLs must be ignored.
        assertNull(GardenLogic.extractClipboardInvite(null))
        assertNull(GardenLogic.extractClipboardInvite(""))
        assertNull(GardenLogic.extractClipboardInvite("secret password 123"))
        assertNull(GardenLogic.extractClipboardInvite("https://example.com/other"))
        assertNull(GardenLogic.extractClipboardInvite("budlum://wallet/0x1234"))
    }

    @Test
    fun gardenSeatAndReturnFlagsParseReliably() {
        val seated = """{"garden":{"chain_id":"0xabc","status":"Active","title":"My Garden"}}"""
        val nestedAway = """{"garden":{"chain_id":"0xabc","status":"Running","budlum":{"status":"Away"}}}"""
        val steppedOutAway = """{"garden":{"chain_id":"0xabc","status":"Away"}}"""
        val steppedOutLeave = """{"can_return":true,"status":"Away"}"""
        val endedFalsePositive = """{"garden":null,"ended":{"chain_id":"0xdeadbeef","title":"Old"}}"""
        val retired = """{"garden":null,"can_return":false}"""

        assertTrue(GardenLogic.isGardenSeated(seated))
        assertFalse(GardenLogic.canReturnToGarden(seated))
        assertTrue(GardenLogic.hasGardenSeat(seated))

        assertTrue(GardenLogic.isGardenSeated(nestedAway))
        assertFalse(GardenLogic.canReturnToGarden(nestedAway))
        assertTrue(GardenLogic.hasGardenSeat(nestedAway))

        assertFalse(GardenLogic.isGardenSeated(steppedOutAway))
        assertTrue(GardenLogic.canReturnToGarden(steppedOutAway))
        assertTrue(GardenLogic.hasGardenSeat(steppedOutAway))

        assertFalse(GardenLogic.isGardenSeated(steppedOutLeave))
        assertTrue(GardenLogic.canReturnToGarden(steppedOutLeave))
        assertTrue(GardenLogic.hasGardenSeat(steppedOutLeave))

        assertFalse(GardenLogic.isGardenSeated(endedFalsePositive))
        assertFalse(GardenLogic.canReturnToGarden(endedFalsePositive))
        assertFalse(GardenLogic.hasGardenSeat(endedFalsePositive))

        assertFalse(GardenLogic.isGardenSeated(retired))
        assertFalse(GardenLogic.canReturnToGarden(retired))
        assertFalse(GardenLogic.hasGardenSeat(retired))

        assertFalse(GardenLogic.isGardenSeated(""))
        assertFalse(GardenLogic.canReturnToGarden("not-json"))
        assertFalse(GardenLogic.hasGardenSeat("not-json"))
    }

    @Test
    fun initialStepRoutingHonoursDeepLinkSeatAndBlockFieldHome() {
        assertEquals(
            Step.Join,
            GardenLogic.resolveInitialStep(
                hasPendingLink = true,
                seated = true,
                walletExists = true,
                canValidate = true,
            ),
        )
        assertEquals(
            Step.Garden,
            GardenLogic.resolveInitialStep(
                hasPendingLink = false,
                seated = true,
                walletExists = true,
                canValidate = false,
            ),
        )
        assertEquals(
            Step.Blocks,
            GardenLogic.resolveInitialStep(
                hasPendingLink = false,
                seated = false,
                walletExists = true,
                canValidate = true,
            ),
        )
        assertEquals(
            Step.Blocks,
            GardenLogic.resolveInitialStep(
                hasPendingLink = false,
                seated = false,
                walletExists = false,
                canValidate = false,
            ),
        )
    }

    @Test
    fun formattingHelpersProduceCleanDisplayValues() {
        assertEquals("482 910", GardenLogic.formatCode("482910"))
        assertEquals("482 910", GardenLogic.formatCode("482-910"))
        assertEquals("5:09", GardenLogic.formatCountdown(309))
        assertEquals("0:00", GardenLogic.formatCountdown(-5))
        assertEquals("0x12345678...bcdef9", GardenLogic.shortAddress("0x1234567890abcdef9"))
        assertEquals("short", GardenLogic.shortAddress("short"))
        assertEquals("512 B", GardenLogic.formatBytes(512))
        assertEquals("2 KB", GardenLogic.formatBytes(2048))
        assertEquals("3.5 MB", GardenLogic.formatBytes((3.5 * 1024 * 1024).toLong()))
        assertEquals(Skin.Sage, Skin.fromName("sage"))
        assertEquals(Skin.Ground, Skin.fromName("GROUND"))
        assertEquals(Skin.Page, Skin.fromName(null))
        assertEquals(Skin.Page, Skin.fromName("unknown"))
    }

    @Test
    fun englishAndTurkishStringsHaveMatchingKeys() {
        val enPath = resolveProjectFile("mobile/android/app/src/main/res/values/strings.xml")
        val trPath = resolveProjectFile("mobile/android/app/src/main/res/values-tr/strings.xml")
        val enKeys = readStringKeys(enPath)
        val trKeys = readStringKeys(trPath)
        val missingInTr = enKeys - trKeys
        val extraInTr = trKeys - enKeys
        assertTrue("Missing Turkish string keys: $missingInTr", missingInTr.isEmpty())
        assertTrue("Extra Turkish string keys: $extraInTr", extraInTr.isEmpty())
    }

    private fun resolveProjectFile(relativeFromRepoRoot: String): File {
        val direct = File(relativeFromRepoRoot)
        if (direct.exists()) return direct
        val fromModule = File(relativeFromRepoRoot.removePrefix("mobile/android/"))
        if (fromModule.exists()) return fromModule
        return File(relativeFromRepoRoot.removePrefix("mobile/android/app/"))
    }

    private fun readStringKeys(file: File): Set<String> {
        val factory = DocumentBuilderFactory.newInstance()
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        factory.isXIncludeAware = false
        factory.setExpandEntityReferences(false)
        val doc = factory.newDocumentBuilder().parse(file)
        val nodes = doc.getElementsByTagName("string")
        val keys = mutableSetOf<String>()
        for (i in 0 until nodes.length) {
            val name = nodes.item(i).attributes?.getNamedItem("name")?.nodeValue
            if (!name.isNullOrBlank()) keys.add(name)
        }
        return keys
    }
}
