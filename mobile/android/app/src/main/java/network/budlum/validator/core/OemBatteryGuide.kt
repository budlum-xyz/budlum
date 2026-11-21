package network.budlum.validator.core

import java.io.File

/**
 * Per-OEM battery setting instructions (Section 7.9.11).
 *
 * The app never declares or requests `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`.
 * Crash logs are written locally only after explicit user consent.
 */
data class OemBatteryInstruction(
    val manufacturerFamily: String,
    val settingsPath: String,
    val usesIgnoreBatteryPermission: Boolean = false,
)

object OemBatteryGuide {
    fun forManufacturer(rawManufacturer: String): OemBatteryInstruction {
        return when (rawManufacturer.trim().lowercase()) {
            "google" -> OemBatteryInstruction(
                manufacturerFamily = "Google Pixel",
                settingsPath = "Settings -> Apps -> Budlum Validator -> App battery usage -> Allow background usage -> Unrestricted",
            )
            "samsung" -> OemBatteryInstruction(
                manufacturerFamily = "Samsung One UI",
                settingsPath = "Settings -> Apps -> Budlum Validator -> Battery -> Unrestricted (do not add to Deep sleeping apps)",
            )
            "xiaomi", "redmi", "poco" -> OemBatteryInstruction(
                manufacturerFamily = "Xiaomi HyperOS / MIUI",
                settingsPath = "Settings -> Apps -> Manage apps -> Budlum Validator -> Battery saver -> No restrictions",
            )
            "oneplus", "oppo", "vivo", "realme", "iqoo" -> OemBatteryInstruction(
                manufacturerFamily = "BBK (ColorOS / OxygenOS / FuntouchOS)",
                settingsPath = "Settings -> Apps -> App management -> Budlum Validator -> Battery usage -> Allow background activity",
            )
            "motorola", "lenovo" -> OemBatteryInstruction(
                manufacturerFamily = "Motorola MyUX",
                settingsPath = "Settings -> Apps -> See all apps -> Budlum Validator -> App battery usage -> Unrestricted",
            )
            else -> OemBatteryInstruction(
                manufacturerFamily = "Android Standard",
                settingsPath = "Settings -> Apps -> Budlum Validator -> Battery -> Unrestricted",
            )
        }
    }

    fun exportCrashReportIfConsented(
        userConsented: Boolean,
        targetFile: File,
        stackTraceSummary: String,
    ): Boolean {
        if (!userConsented) {
            return false
        }
        targetFile.parentFile?.mkdirs()
        targetFile.writeText(
            buildString {
                appendLine("Budlum Validator Local Diagnostic Report")
                appendLine("Third-party analytics SDKs: NONE")
                appendLine(stackTraceSummary.trim())
            }
        )
        return true
    }
}
