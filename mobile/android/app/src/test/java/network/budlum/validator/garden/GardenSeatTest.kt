package network.budlum.validator.garden

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The status answer comes in four shapes: a running seat, a seat stepped
 * out, an empty phone, and a Garden that ended without this validator.
 * The ended shape is the trap - it still names a chain_id even though
 * nobody holds a seat - so these tests pin the reading to the garden
 * object itself rather than to any substring of the answer.
 */
class GardenSeatTest {

    @Test
    fun runningGardenIsASeat() {
        val status = """{"garden":{"chain_id":"00000000000004d2","status":"Running","height":7}}"""
        assertTrue(GardenSeat.seated(status))
        assertFalse(GardenSeat.away(status))
    }

    @Test
    fun steppedOutGardenIsASeatAndAway() {
        val status = """{"garden":{"chain_id":"00000000000004d2","status":"Away","budlum":null}}"""
        assertTrue(GardenSeat.seated(status))
        assertTrue(GardenSeat.away(status))
    }

    @Test
    fun emptyPhoneIsNoSeat() {
        val status = """{"garden":null}"""
        assertFalse(GardenSeat.seated(status))
        assertFalse(GardenSeat.away(status))
    }

    @Test
    fun endedGardenIsNoSeatEvenThoughItNamesAChain() {
        val status =
            """{"garden":null,"ended":{"chain_id":"00000000000004d2","budlum":{"status":"Retired"}}}"""
        assertFalse(GardenSeat.seated(status))
        assertFalse(GardenSeat.away(status))
    }

    @Test
    fun nestedRecordStatusDoesNotStepTheSeatOut() {
        val status =
            """{"garden":{"chain_id":"00000000000004d2","status":"Running","budlum":{"status":"Away"}}}"""
        assertTrue(GardenSeat.seated(status))
        assertFalse(GardenSeat.away(status))
    }

    @Test
    fun plainSentenceIsNoSeat() {
        val status = "This phone is in no Garden."
        assertFalse(GardenSeat.seated(status))
        assertFalse(GardenSeat.away(status))
    }

    @Test
    fun emptyAnswerIsNoSeat() {
        assertFalse(GardenSeat.seated(""))
        assertFalse(GardenSeat.away(""))
    }

    @Test
    fun leaveThatStepsOutKeepsTheWayBack() {
        val answer =
            """{"left":true,"retired":false,"can_return":true,"chain_id":"00000000000004d2","height":9}"""
        assertTrue(GardenSeat.canReturn(answer))
    }

    @Test
    fun leaveThatRetiresClosesTheWayBack() {
        val answer =
            """{"left":true,"retired":true,"can_return":false,"chain_id":"00000000000004d2"}"""
        assertFalse(GardenSeat.canReturn(answer))
    }

    @Test
    fun unreadableLeaveAnswerClosesTheWayBack() {
        assertFalse(GardenSeat.canReturn("the validator went away mid-sentence"))
        assertFalse(GardenSeat.canReturn(""))
    }

    @Test
    fun aWaitingGardenIsASeatThatIsNotAdmittedYet() {
        // The core answers a garden object before the host admits the phone.
        // "There is a garden here" is not "this phone is validating", and the
        // home panel drew the waiting shape as a working seat.
        val status = """{"garden":{"chain_id":"00000000000004d2","status":"Waiting"}}"""
        assertTrue(GardenSeat.seated(status))
        assertTrue(GardenSeat.waiting(status))
        assertFalse(GardenSeat.away(status))
    }

    @Test
    fun aRunningGardenIsNotWaiting() {
        val status = """{"garden":{"chain_id":"00000000000004d2","status":"Running"}}"""
        assertFalse(GardenSeat.waiting(status))
    }
}
