package network.budlum.validator

import org.junit.Test

/** Runs the complete existing fail-closed Kotlin safety specification in Gradle. */
class MobileValidatorJUnitTest {
    @Test
    fun disconnectedValidatorSafetySpecification() {
        MobileValidatorUnitTest.main(emptyArray())
    }
}
