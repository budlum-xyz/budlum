#!/usr/bin/env python3
"""Turn a clippy-extra ratchet count into an address.

`check-clippy-extra.sh` reports a single number: how many pedantic/nursery
warnings the tree has, against a baseline that must not rise. When it trips,
the number alone does not say *which* warnings are new - and the JSON it
counts is written to /tmp inside the runner, so there is nothing to inspect
after the job ends.

This prints the per-lint tally and the file:line of every hit under `src/`,
straight into the CI log. It reads the same JSON the gate reads and writes
nothing, so it cannot change the gate's verdict; it runs immediately before
it.

Usage: python3 scripts/clippy-extra-report.py <clippy-json> [max-per-lint]
"""

import collections
import json
import sys


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: clippy-extra-report.py <clippy-json> [max-per-lint]", file=sys.stderr)
        return 2
    path = sys.argv[1]
    cap = int(sys.argv[2]) if len(sys.argv) > 2 else 40

    per_lint: collections.Counter = collections.Counter()
    hits: dict = collections.defaultdict(list)

    try:
        handle = open(path, encoding="utf-8", errors="replace")
    except OSError as error:
        # A missing file is the gate's problem to report, not this script's.
        print(f"clippy-extra-report: cannot read {path}: {error}")
        return 0

    with handle:
        for line in handle:
            try:
                record = json.loads(line)
            except Exception:
                continue
            if record.get("reason") != "compiler-message":
                continue
            message = record["message"]
            code = (message.get("code") or {}).get("code", "")
            if message.get("level") != "warning" or not code.startswith("clippy::"):
                continue
            per_lint[code] += 1
            spans = message.get("spans") or []
            if spans:
                hits[code].append(f"{spans[0]['file_name']}:{spans[0]['line_start']}")

    total = sum(per_lint.values())
    print(f"--- clippy-extra: {total} warnings across {len(per_lint)} lints ---")
    for code, count in per_lint.most_common(30):
        print(f"{count:6d}  {code}")

    # One address per line, sorted, uncapped. The first version truncated at
    # 40 per lint and hid over 2000 addresses - including, on the run that
    # mattered, every remaining warning this branch was accountable for.
    # Diffing two runs is the whole point, and a truncated list cannot be
    # diffed.
    print("--- first-party hits (src/, kani/), one per line ---")
    flat = sorted(
        f"{place}\t{code}"
        for code, places in hits.items()
        for place in set(places)
        if place.startswith(("src/", "kani/"))
    )
    for row in flat:
        print(row)
    print(f"--- {len(flat)} first-party addresses ---")
    _ = cap
    return 0


if __name__ == "__main__":
    sys.exit(main())
