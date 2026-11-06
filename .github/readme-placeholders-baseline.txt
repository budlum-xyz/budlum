# Unfilled placeholders recorded in the READMEs, so
# `readme-has-no-placeholders` can ratchet instead of fail on day one.
#
# One line per finding: `file:line|slot|the sentence that carries it`. The list
# only shrinks. Fill the slot from the run that produced the number, or delete
# the sentence, and lower the line in the same change; a line that no longer
# matches the README fails the gate, so this file cannot rot into an excuse.
#
# A to-do marker (TODO, TBD, FIXME) is never recorded: it is removed.
#
# Measured 2026-11-06: both READMEs carry zero `{{...}}` slots and zero to-do
# markers. The file is kept so that the first slot a later pass introduces is a
# red gate rather than a silent one, and so the shape of a record is written
# down before somebody needs it.
