# Budscan address-bar badge - English.
#
# Four values, one-to-one with budscan::evidence::Strength. Merging any two
# would hide a distinction the core measured.

budscan-badge-verified =
    .value = verified
    .tooltiptext = The digest of the fetched bytes equals the expected identity.

budscan-badge-transport-only =
    .value = transport only
    .tooltiptext = TLS says who sent the bytes, not what was sent. This is the ordinary web.

budscan-badge-claim-only =
    .value = claim only
    .tooltiptext = A node answered but no proof was verified. The bytes may be self-consistent and still not belong to this name.

budscan-badge-refused =
    .value = refused
    .tooltiptext = The content is not being shown. The reason is on this badge.

# Refusal pages

budscan-refusal-title = This address did not open

budscan-refusal-name-rule = The name rule refused this name: { $reason }

budscan-refusal-scheme = The { $scheme } scheme is never opened from the address bar.

budscan-refusal-hash-mismatch =
    The fetched bytes did not produce the expected identity.
    Expected: { $expected }
    Got: { $produced }

budscan-refusal-no-fetcher =
    There is no fetcher for this target. Falling back to HTTPS would show
    unverified content as if it had been verified.

budscan-refusal-expired = This name belongs to an expired record.

budscan-refusal-ambiguous =
    What was typed matches more than one thing, and it is not guessed:
    { $candidates }
