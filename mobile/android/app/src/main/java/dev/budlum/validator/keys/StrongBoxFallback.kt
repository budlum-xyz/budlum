package dev.budlum.validator.keys

/** Retry without StrongBox only for the platform's explicit unavailable error. */
internal fun <T> generatePreferStrongBox(
    generate: (strongBox: Boolean) -> T,
    isUnavailable: (Exception) -> Boolean,
): T = try {
    generate(true)
} catch (error: Exception) {
    if (!isUnavailable(error)) throw error
    generate(false)
}
