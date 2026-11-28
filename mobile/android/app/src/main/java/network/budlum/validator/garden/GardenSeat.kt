package network.budlum.validator.garden

import org.json.JSONObject

/**
 * The one reader of the status answer's shape.
 *
 * The core answers status() with `{"garden": {...}}` while a seat exists,
 * `{"garden": null}` on an empty phone, and `{"garden": null, "ended":
 * {...}}` when the Garden ended without this validator. The ended answer
 * still names a chain_id, so a substring search for chain_id mistakes a
 * dead Garden for a seat - and then the app offers "Open my Garden" and
 * restarts a background validator for a chain that no longer exists.
 *
 * This object parses instead of searching, and it refuses rather than
 * guesses: an answer it cannot read is no seat.
 */
object GardenSeat {

    /** Whether this status answer names a seat, running or stepped out. */
    fun seated(statusJson: String): Boolean = garden(statusJson) != null

    /** Whether the seat is stepped out and could be returned to right now. */
    fun away(statusJson: String): Boolean =
        garden(statusJson)?.optString("status") == "Away"

    /**
     * Whether this phone is in the Garden but has not been admitted yet.
     *
     * A Garden object exists before a seat does, so "there is a garden here"
     * is not the same question as "this phone is validating". Home read only
     * the first one and drew a waiting phone as if it were working.
     */
    fun waiting(statusJson: String): Boolean =
        garden(statusJson)?.optString("status") == "Waiting"

    /** Whether this leave answer kept the way back open. */
    fun canReturn(leaveJson: String): Boolean =
        runCatching { JSONObject(leaveJson).optBoolean("can_return", false) }
            .getOrDefault(false)

    /** The garden object of a status answer, or null when there is no seat. */
    private fun garden(statusJson: String): JSONObject? =
        runCatching { JSONObject(statusJson).optJSONObject("garden") }
            .getOrNull()
}
