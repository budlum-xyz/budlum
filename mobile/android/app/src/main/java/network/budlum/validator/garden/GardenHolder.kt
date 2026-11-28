package network.budlum.validator.garden

import android.content.Context
import uniffi.budlum_garden_ffi.GardenPhone

/**
 * The one validator this process runs.
 *
 * Two `GardenPhone` instances over the same directory would be two
 * validators sharing one key and one store, which is a way to corrupt
 * both. The screen and the foreground service are two views of a single
 * validator, so they share this one.
 */
object GardenHolder {

    private var instance: GardenPhone? = null

    /** The validator, made on first ask and kept for the life of the process. */
    @Synchronized
    fun phone(context: Context): GardenPhone {
        val made = instance
            ?: GardenPhone(context.applicationContext.filesDir.resolve("garden").absolutePath)
        instance = made
        return made
    }

    /**
     * Whether this phone holds a seat at all, running or stepped out.
     *
     * The seat outlives the process, so the answer comes from the
     * validator rather than from anything a screen remembers. An empty
     * phone answers with a null Garden; a phone with a seat names its
     * chain either way.
     */
    fun hasGarden(context: Context): Boolean =
        runCatching { GardenSeat.seated(phone(context).status().json) }
            .getOrDefault(false)

    /** Whether the validator is stepped out and could return right now. */
    fun isAway(context: Context): Boolean =
        runCatching { GardenSeat.away(phone(context).status().json) }
            .getOrDefault(false)
}
