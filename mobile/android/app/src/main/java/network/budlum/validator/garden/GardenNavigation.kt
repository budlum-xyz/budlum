package network.budlum.validator.garden

/**
 * Where in the app the person is. Nothing is a dead end.
 *
 * The Garden screens are not a second flow of their own: they hang off
 * the rail of the shell, which is what `Garden` names. `Setup` and
 * `Choose` sit in front of it because a phone that is not allowed to do
 * the work has no business being offered a seat.
 */
enum class Step {
    /** What this phone must be allowed to do before it validates anything. */
    Setup,

    /** Which network this validator serves. */
    Choose,

    /** The Garden shell: the rail and the screens beside it. */
    Garden,
}
