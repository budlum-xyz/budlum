#!/usr/bin/env python3
"""Run OSV over every Cargo.lock in the checkout, including new workspaces."""
import argparse
import os
from pathlib import Path
import subprocess
import sys


def lockfiles(root: Path) -> list[str]:
    found = []

    def walk_error(error: OSError) -> None:
        raise error

    for directory, dirs, files in os.walk(root, onerror=walk_error, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in {".git", "target"})
        for name in sorted(files):
            if name != "Cargo.lock":
                continue
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Lockfile must be a regular file: {path}")
            found.append(path.relative_to(root).as_posix())
    if not found:
        raise ValueError("No Cargo.lock files found; refusing an empty scan")
    return sorted(found)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("report", "gate"))
    args = parser.parse_args()
    root = Path.cwd()
    try:
        locks = lockfiles(root)
        cmd = ["osv-scanner", "scan", "source", "--config=osv-scanner.toml"]
        if args.mode == "report":
            # A stale report must never turn a failed scanner run into success.
            Path("osv-scanner.sarif").unlink(missing_ok=True)
            cmd += ["--format=sarif", "--output=osv-scanner.sarif"]
        cmd += [f"--lockfile={path}" for path in locks]
        print(f"Scanning {len(locks)} Cargo.lock files:", flush=True)
        for path in locks:
            print(f"  {path}", flush=True)
        result = subprocess.run(cmd, check=False)
        if args.mode == "report":
            report = Path("osv-scanner.sarif")
            if result.returncode not in (0, 1) or not report.is_file() or not report.stat().st_size:
                print(f"OSV failed to produce a report (status {result.returncode})", file=sys.stderr)
                return 1
            # A report with findings is uploaded; the separate gate rejects them.
            return 0
        return result.returncode if result.returncode >= 0 else 1
    except (OSError, ValueError) as error:
        print(f"OSV scan setup failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
