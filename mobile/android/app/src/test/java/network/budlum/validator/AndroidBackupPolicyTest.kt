package network.budlum.validator

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

/** The debug APK must not silently export key/custody files on migration. */
class AndroidBackupPolicyTest {
    @Test
    fun cloudAndDeviceTransferExcludeAllAppData() {
        val manifest = File("mobile/android/app/src/main/AndroidManifest.xml").readText()
        assertTrue(manifest.contains("android:allowBackup=\"false\""))
        assertTrue(manifest.contains("android:fullBackupContent=\"false\""))
        assertTrue(manifest.contains("android:dataExtractionRules=\"@xml/data_extraction_rules\""))

        val factory = DocumentBuilderFactory.newInstance()
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        factory.isXIncludeAware = false
        factory.setExpandEntityReferences(false)
        val rules = factory.newDocumentBuilder().parse(
            File("mobile/android/app/src/main/res/xml/data_extraction_rules.xml"),
        )
        for (target in listOf("cloud-backup", "device-transfer")) {
            val sections = rules.getElementsByTagName(target)
            assertEquals("$target must have explicit exclusions", 1, sections.length)
            val exclude = (sections.item(0) as Element).getElementsByTagName("exclude")
            val paths = (0 until exclude.length).map { i ->
                val item = exclude.item(i) as Element
                item.getAttribute("domain") to item.getAttribute("path")
            }.toSet()
            assertTrue("$target must refuse private app files and databases", "root" to "." in paths)
            assertTrue("$target must refuse external app files", "external" to "." in paths)
        }
    }
}
