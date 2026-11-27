package network.budlum.validator.garden

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The status word the core answers with becomes a sentence a person reads.
 *
 * The mapping is the one place a bare word like `Active` turns into
 * something a screen can show. A wrong sentence is a wrong claim about the
 * work this phone is doing, so each word is pinned rather than trusted to
 * fall through to the default.
 */
class GardenStatusSentenceTest {

    @Test
    fun everyStatusWordTheCoreAnswersWithHasItsOwnSentence() {
        assertEquals("Validating in the background.", gardenSentence("Active"))
        assertEquals("Stepped out. The seat is kept.", gardenSentence("Away"))
        assertEquals("Suspended: this phone has been absent too long.", gardenSentence("Suspended"))
        assertEquals("Waiting for the host to admit this phone.", gardenSentence("Waiting"))
        assertEquals("This phone is in no Garden.", gardenSentence(""))
    }

    @Test
    fun anUnknownWordIsNotInventedIntoASentence() {
        // A status this screen has not been taught must survive as itself:
        // inventing a friendly sentence for it would be a claim, and the
        // core is the only thing allowed to make one.
        assertEquals("Frozen", gardenSentence("Frozen"))
    }

    @Test
    fun theSentenceForAnActiveSeatSaysWhatThePhoneIsDoing() {
        // The one sentence a person reads on the home panel. It says the
        // work is happening, not that the app is open, because the
        // validator runs with the app closed.
        val active = gardenSentence("Active")
        assertEquals(true, active.contains("Validating"))
        assertEquals(false, active.contains("open"))
    }
}
