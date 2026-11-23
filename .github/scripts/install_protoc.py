#!/usr/bin/env python3
"""protoc 29.3 installer shared by every CI job.

Two-path acquisition, following the repository's rule for pinned binaries
(the cargo-machete install in extra-tooling.yml is the sibling): the pinned
release asset and its sha256 are the first path; when the asset host refuses
the bytes, the same pinned version is built from the pinned source tree at
tag v29.3 - a different failure domain.

The split is deliberate and is the whole point of this file:

  refused connection  -> fall back to the source build (availability)
  wrong bytes         -> stop the job (security)

A sha256 written in a workflow cannot protect against a host that refuses to
serve the bytes; it can only protect against a host that serves different
bytes. Those are two problems and they get two answers.

Why Python and not shell: the repository's `no-new-shell-gates` gate is a
closed set that only shrinks - shell inside the trust boundary is a place
where a misspelt variable is an empty string rather than an error, so a check
can examine nothing and report OK. A `.sh` file anywhere in the tree fails
that gate by design. The tree already ships Python under `ops/` and
`mobile/ios/Scripts/`, so Python here is the shape the repository already
accepts, and the acquisition logic keeps the one-source-of-truth property
that motivated sharing the step at all.

Usage (from any CI job):

    python3 .github/scripts/install_protoc.py

Exit codes: 0 installed or already at the pinned version, 1 any failure.
Nothing here is allowed to exit 0 on an unverified binary.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

PROTOC_VERSION = "29.3"

# (zip name, sha256) per machine architecture. The x86_64 pin is the one the
# workflow step carried before the acquisition was shared; the aarch64 pin is
# the same release, verified against the published checksum list.
PINS = {
    "aarch64": (
        f"protoc-{PROTOC_VERSION}-linux-aarch_64.zip",
        "6427349140e01f06e049e707a58709a4f221ae73ab9a0425bc4a00c8d0e1ab32",
    ),
    "x86_64": (
        f"protoc-{PROTOC_VERSION}-linux-x86_64.zip",
        "3e866620c5be27664f3d2fa2d656b5f3e09b5152b42f1bedbf427b333e90021a",
    ),
}

ASSET_URL = (
    "https://github.com/protocolbuffers/protobuf/releases/download/"
    "v{version}/{zip_name}"
)

# fetch_pinned outcomes
OK = 0
UNREACHABLE = 1
WRONG_BYTES = 2


def die(msg: str) -> "NoReturn":  # noqa: F821 - py3.13 + future annotations
    print(f"FATAL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def note(msg: str) -> None:
    print(f"protoc: {msg}", file=sys.stderr)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def already_pinned() -> bool:
    protoc = shutil.which("protoc")
    if protoc is None:
        return False
    try:
        out = subprocess.run(
            [protoc, "--version"], capture_output=True, text=True, check=False
        ).stdout.strip()
    except OSError:
        return False
    # `protoc --version` prints "libprotoc 29.3".
    return out.split()[-1:] == [PROTOC_VERSION]


def fetch_pinned(url: str, out: Path, expected: str) -> int:
    """Fetch url into out and verify it against the pin.

    Returns OK, UNREACHABLE (the host refused or could not serve the bytes -
    fall back) or WRONG_BYTES (the bytes arrived and are not the pinned ones -
    stop: that is a security event, not an availability problem).
    """
    if out.exists():
        out.unlink()
    try:
        with urllib.request.urlopen(url, timeout=60) as resp, out.open("wb") as fh:
            shutil.copyfileobj(resp, fh, length=1 << 20)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        note(f"the pinned asset could not be fetched ({exc}); falling back")
        return UNREACHABLE
    got = sha256_of(out)
    if got != expected:
        out.unlink(missing_ok=True)
        note(f"{url} hashed {got}, not the pinned {expected}; stopping")
        return WRONG_BYTES
    return OK


def run(cmd: list[str]) -> None:
    print(f"+ {' '.join(cmd)}", file=sys.stderr)
    subprocess.run(cmd, check=True)


def install_from_asset(zip_path: Path) -> None:
    # `unzip` is present on the GitHub-hosted Ubuntu runners and on the
    # self-hosted pool the workflows target; the zip is verified before this
    # point, so an extractor failure is a hard failure.
    run(["sudo", "unzip", "-q", "-o", str(zip_path), "-d", "/usr/local", "bin/protoc"])
    # The include tree is part of the contract: `protoc --cpp_out` and the
    # well-known types resolve against it.
    run(
        [
            "sudo",
            "sh",
            "-c",
            f"cd /usr/local && unzip -q -o {zip_path} 'include/*'",
        ]
    )
    zip_path.unlink(missing_ok=True)


def install_from_source() -> None:
    note(f"the release asset could not be fetched; building {PROTOC_VERSION} from the pinned source tree")

    if shutil.which("cmake") is None:
        run(["sudo", "apt-get", "update", "-qq"])
        run(["sudo", "apt-get", "install", "-y", "-qq", "cmake"])

    src = Path("/tmp/protobuf-src")
    build = Path("/tmp/protobuf-build")
    for p in (src, build):
        shutil.rmtree(p, ignore_errors=True)

    # The codeload tarball is not used here: it does not carry the git
    # submodules (abseil-cpp, upb) the build needs. A shallow clone of the
    # pinned tag with shallow submodules is a different failure domain from
    # the release asset CDN, and the resulting binary is the same pinned
    # version.
    run(
        [
            "git", "clone", "--depth", "1", "--branch", f"v{PROTOC_VERSION}",
            "--recurse-submodules", "--shallow-submodules",
            "https://github.com/protocolbuffers/protobuf", str(src),
        ]
    )
    run(
        [
            "cmake", "-S", str(src), "-B", str(build),
            "-DCMAKE_BUILD_TYPE=Release",
            "-Dprotobuf_BUILD_TESTS=OFF",
            "-Dprotobuf_BUILD_SHARED_LIBS=OFF",
            "-Dprotobuf_WITH_ZLIB=OFF",
        ]
    )
    run(["cmake", "--build", str(build), "--target", "protoc", "-j", str(os.cpu_count() or 1)])

    # The build names the binary protoc-<version> at the build root.
    candidates = sorted(
        p for p in build.glob("protoc-*") if p.is_file() and os.access(p, os.X_OK)
    )
    if not candidates:
        die("the source build did not produce a protoc binary")
    run(["sudo", "install", "-m", "0755", str(candidates[0]), "/usr/local/bin/protoc"])

    include_target = Path("/usr/local/include/google/protobuf")
    run(["sudo", "mkdir", "-p", str(include_target)])
    run(
        [
            "sudo", "sh", "-c",
            f"cp {src}/src/google/protobuf/*.proto {include_target}/",
        ]
    )
    for p in (src, build):
        shutil.rmtree(p, ignore_errors=True)


def main() -> int:
    machine = platform.machine()
    key = "aarch64" if machine in ("aarch64", "arm64") else "x86_64"
    zip_name, expected = PINS[key]

    if already_pinned():
        note(f"already at the pinned version {PROTOC_VERSION}")
        return 0

    url = ASSET_URL.format(version=PROTOC_VERSION, zip_name=zip_name)
    out = Path(f"/tmp/{zip_name}")

    # Path 1: the pinned release asset.
    rc = fetch_pinned(url, out, expected)
    if rc == OK:
        install_from_asset(out)
        note(f"installed {PROTOC_VERSION} from the pinned release asset")
        verify_final()
        return 0
    if rc == WRONG_BYTES:
        return 1

    # Path 2: the same pinned version, built from the pinned source tree.
    install_from_source()
    verify_final()
    note(f"installed {PROTOC_VERSION} from the pinned source tree")
    return 0


def verify_final() -> None:
    if not already_pinned():
        die(f"the installed binary is not protoc {PROTOC_VERSION}")


if __name__ == "__main__":
    raise SystemExit(main())
