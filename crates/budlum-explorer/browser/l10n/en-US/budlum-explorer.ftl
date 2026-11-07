# Budlum Explorer address-bar badge - English.
#
# Four values, one-to-one with budlum_explorer::evidence::Strength. Merging any two
# would hide a distinction the core measured.

explorer-badge-verified =
    .value = verified
    .tooltiptext = The digest of the fetched bytes equals the expected identity.

explorer-badge-transport-only =
    .value = transport only
    .tooltiptext = TLS says who sent the bytes, not what was sent. This is the ordinary web.

explorer-badge-claim-only =
    .value = claim only
    .tooltiptext = A node answered but no proof was verified. The bytes may be self-consistent and still not belong to this name.

explorer-badge-refused =
    .value = refused
    .tooltiptext = The content is not being shown. The reason is on this badge.

# Refusal pages

explorer-refusal-title = This address did not open

explorer-refusal-name-rule = The name rule refused this name: { $reason }

explorer-refusal-scheme = The { $scheme } scheme is never opened from the address bar.

explorer-refusal-hash-mismatch =
    The fetched bytes did not produce the expected identity.
    Expected: { $expected }
    Got: { $produced }

explorer-refusal-no-fetcher =
    There is no fetcher for this target. Falling back to HTTPS would show
    unverified content as if it had been verified.

explorer-refusal-expired = This name belongs to an expired record.

explorer-refusal-ambiguous =
    What was typed matches more than one thing, and it is not guessed:
    { $candidates }
