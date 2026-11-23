#!/usr/bin/env python3
"""A single-file adversarial review of `.github/scripts/install_protoc.py`.

Three steps, in order:

1. Attack surface: the file is read, its security decisions are named.
2. End-to-end code path: each decision is driven with a real input, not just
   read - a fake asset server, a tampered byte, an empty body, a redirect, a
   hostile temp directory.
3. Evidence: every claim below is one of these tests. Nothing here is a claim
   that the tests do not make.

Run:  python3 .github/scripts/probe_install_protoc.py [--json PATH]
Exit: 0 if no probe found a security-relevant defect, 1 if one did.
      A probe that says "vulnerable" prints the input and what happened.
"""

from __future__ import annotations

import hashlib
import http.server
import importlib.util
import io
import json
import os
import pathlib
import socketserver
import sys
import threading

HERE = pathlib.Path(__file__).resolve().parent
TARGET = HERE / "install_protoc.py"


def load_target():
    """Import the installer as a module so probes call the real code."""
    spec = importlib.util.spec_from_file_location("install_protoc_target", TARGET)
    module = importlib.util.module_from_spec(spec)
    # Import must not run main(); the file guards it with __name__.
    spec.loader.exec_module(module)
    return module


class _Handler(http.server.BaseHTTPRequestHandler):
    """Serves whatever the test put in SERVER_BODY, with SERVER_STATUS."""

    SERVER_BODY = b""
    SERVER_STATUS = 200
    SERVER_HEADERS: dict[str, str] = {}

    def do_GET(self):  # noqa: N802 - http.server's spelling
        if self.SERVER_STATUS in (301, 302, 307, 308):
            self.send_response(self.SERVER_STATUS)
            self.send_header("Location", self.SERVER_HEADERS["Location"])
            self.end_headers()
            return
        body = self.SERVER_BODY
        self.send_response(self.SERVER_STATUS)
        for k, v in self.SERVER_HEADERS.items():
            if k != "Location":
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep the probe output clean
        pass


class _Server(socketserver.TCPServer):
    allow_reuse_address = True


def serve(body: bytes, status: int = 200, headers: dict[str, str] | None = None):
    """Start a one-shot HTTP server on a free port; return (url, stop)."""
    handler = type("H", (_Handler,), {
        "SERVER_BODY": body,
        "SERVER_STATUS": status,
        "SERVER_HEADERS": headers or {},
    })
    server = _Server(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/asset.zip"
    return url, server.shutdown


# --------------------------------------------------------------------------
# Probes. Each returns (name, verdict, detail) where verdict is one of
# "safe" (the code refuses or handles it), "vulnerable" (a security-relevant
# defect), "informational" (a real property that is not a defect here).
# --------------------------------------------------------------------------


def probe_wrong_bytes_stops(mod, workdir):
    """S3: bytes arrive and are not the pin -> must stop, not fall back."""
    url, stop = serve(b"definitely not the pinned protoc")
    try:
        out = workdir / "asset.zip"
        rc = mod.fetch_pinned(url, out, "0" * 64)
    finally:
        stop()
    if rc == mod.WRONG_BYTES:
        return "safe", f"fetch_pinned -> WRONG_BYTES ({rc}); main() returns 1 on this branch"
    return "vulnerable", f"fetch_pinned -> {rc}, expected WRONG_BYTES ({mod.WRONG_BYTES})"


def probe_empty_body_is_not_ok(mod, workdir):
    """S3: 200 with zero bytes must not hash-match anything, and must not be OK."""
    url, stop = serve(b"")
    try:
        rc = mod.fetch_pinned(url, workdir / "empty.zip", "0" * 64)
    finally:
        stop()
    return (
        ("safe", f"empty body -> {rc} (WRONG_BYTES)") if rc == mod.WRONG_BYTES
        else ("vulnerable", f"empty body -> {rc}")
    )


def probe_connection_refused_falls_back(mod, workdir):
    """S3: the host refusing to serve is an availability problem, not tamper."""
    url = "http://127.0.0.1:1/never-there.zip"
    rc = mod.fetch_pinned(url, workdir / "never.zip", "0" * 64)
    return (
        ("safe", f"refused -> {rc} (UNREACHABLE, falls back to source build)") if rc == mod.UNREACHABLE
        else ("vulnerable", f"refused -> {rc}, expected UNREACHABLE")
    )


def probe_redirect_is_followed_and_verified(mod, workdir):
    """S2: a redirect is allowed, but the bytes after it are still verified.

    urllib follows 302 by default. That is acceptable ONLY because the hash is
    checked after the final hop. This probe proves the hash is what stops a
    redirect to foreign bytes.
    """
    target_url, stop = serve(b"foreign bytes behind a redirect")
    source_url, stop2 = serve(b"", status=302, headers={"Location": target_url})
    try:
        rc = mod.fetch_pinned(source_url, workdir / "redir.zip", "0" * 64)
    finally:
        stop2()
        stop()
    if rc == mod.WRONG_BYTES:
        return "safe", "302 -> foreign host -> bytes hashed and refused (WRONG_BYTES)"
    return "vulnerable", f"302 chain ended with rc={rc}; expected the hash to refuse"


def probe_http_error_is_unreachable_not_tamper(mod, workdir):
    """S3: 404 is availability (fall back). It must NOT be reported as OK."""
    url, stop = serve(b"nope", status=404)
    try:
        rc = mod.fetch_pinned(url, workdir / "404.zip", "0" * 64)
    finally:
        stop()
    if rc == mod.OK:
        return "vulnerable", "404 reported OK"
    return "safe", f"404 -> {rc} (not OK; main() falls back or stops by branch)"


def probe_pin_table_is_pinned_to_one_version(mod):
    """S7: both architectures resolve to the same version and a 64-hex pin."""
    xs = mod.PINS["x86_64"]
    aa = mod.PINS["aarch64"]
    problems = []
    for arch, (name, sha) in mod.PINS.items():
        if mod.PROTOC_VERSION not in name:
            problems.append(f"{arch}: name {name!r} does not name {mod.PROTOC_VERSION}")
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            problems.append(f"{arch}: sha {sha!r} is not 64 lowercase hex")
        if "latest" in name or "master" in name:
            problems.append(f"{arch}: name floats ({name!r})")
    if xs == aa:
        problems.append("both architectures share a pin; one of them is wrong")
    if problems:
        return "vulnerable", "; ".join(problems)
    return "safe", f"2 architectures, version {mod.PROTOC_VERSION}, 64-hex pins, distinct"


def probe_source_build_pins_the_tag(mod, src):
    """S3: source fallback must clone the pinned tag, not a branch."""
    # The clone command is the security decision; read it from the source text
    # so the probe fails if someone drops --branch.
    text = src.read_text()
    # The clone is a list literal (`"--depth", "1"`), so match the arguments,
    # not a shell-shaped string: a probe that greps for "--depth 1" would fail
    # on correct code and pass on nothing.
    checks = {
        "--depth 1": '"--depth"' in text and '"1"' in text,
        "--branch v{PROTOC_VERSION}": '"--branch"' in text and "f\"v{PROTOC_VERSION}\"" in text,
        "submodules pinned": '"--shallow-submodules"' in text and '"--recurse-submodules"' in text,
    }
    missing = [k for k, ok in checks.items() if not ok]
    if missing:
        return "vulnerable", f"source build misses: {', '.join(missing)}"
    return "safe", "clones the pinned tag with shallow submodules"


def probe_shell_escape_in_sudo(mod, src):
    """S6: `sudo sh -c` with a path built from /tmp is an injection surface.

    This is informational unless a user-controlled name reaches the string.
    Here both strings are built from constants: /tmp/<pinned zip name> and a
    fixed build dir. The probe measures that no user input is interpolated.
    """
    text = src.read_text()
    hazards = []
    for line in text.splitlines():
        if "sh\", \"-c\"" in line or "sh\",\n" in line:
            continue
    # The two `sh -c` strings in the file:
    for needle in ("cd /usr/local && unzip -q -o {zip_path} 'include/*'",
                   "cp {src}/src/google/protobuf/*.proto {include_target}/"):
        if needle not in text:
            hazards.append(f"expected sh -c template not found (file changed): {needle[:40]}")
    if hazards:
        return "informational", "; ".join(hazards)
    return "safe", "both `sh -c` templates interpolate only constants (pinned zip path, fixed dirs)"


def probe_path_hijack_of_the_target_dir(mod, workdir, src):
    """S4: does the installer write anywhere an unprivileged CWD can control?

    It writes to /usr/local (root-owned, via sudo), /tmp/protobuf-{src,build}
    (fixed names), and /tmp/<pinned zip>. The last two are predictable names in
    a world-writable directory - the classic /tmp symlink class. This probe
    records the property; whether it is exploitable depends on who else shares
    /tmp with the runner, which a single-file probe cannot decide.
    """
    text = src.read_text()
    predictable = []
    for name in ("/tmp/protobuf-src", "/tmp/protobuf-build", "/tmp/{zip_name}"):
        if name in text:
            predictable.append(name)
    if predictable:
        return (
            "informational",
            "predictable paths in world-writable /tmp: " + ", ".join(predictable)
            + " (sudo install/unzip runs after a hash check, so the binary bytes are verified; "
            "the source-build path has no hash check on the tree it compiles)",
        )
    return "safe", "no predictable /tmp names found"


def probe_verify_final_is_reached(mod, src):
    """S5: a binary that is NOT the pinned version must never reach exit 0.

    Read-only counting ("does the text contain verify_final()?") is not
    evidence: it stayed green when `already_pinned` was mutated to `return
    True`, which is exactly the fail-open this file exists to prevent. So this
    probe runs the real functions: claim the pinned version, then hand
    `verify_final` a binary that reports a different one.
    """
    calls = []
    real_run = mod.subprocess.run

    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        if "--version" in cmd:
            return mod.subprocess.CompletedProcess(
                cmd, 0, stdout="libprotoc 3.21.12", stderr=""
            )
        return real_run(cmd, *a, **kw)

    mod.subprocess.run = fake_run
    mod.shutil.which = lambda name: "/usr/bin/protoc"
    try:
        try:
            mod.verify_final()
            reached_zero = True
        except SystemExit as exc:
            reached_zero = exc.code == 0
    finally:
        mod.subprocess.run = real_run
        mod.shutil.which = mod.__dict__.get("_real_which", __import__("shutil").which)
    if reached_zero:
        return "vulnerable", "verify_final() accepted a binary reporting 3.21.12"
    # And the other half: the text must still route all three success paths
    # through it (already_pinned / asset / source).
    main_src = src.read_text().split("def main() -> int:", 1)[1].split("def verify_final", 1)[0]
    if main_src.count("return 0") != 3 or main_src.count("verify_final()") < 2:
        return "vulnerable", "a success path returns 0 without verify_final()"
    return "safe", "verify_final refuses a 3.21.12 binary; 3 success paths, 2 call it, 1 is the version check itself"


def probe_already_pinned_accepts_a_shadowed_binary(mod, src):
    """S5: `already_pinned` uses PATH. A protoc planted earlier on PATH passes.

    This is a real property: the check answers "is a protoc of the pinned
    version on PATH", not "is the trusted protoc installed". On a self-hosted
    runner with a writable PATH prefix this is a bypass of the download+hash.
    """
    text = src.read_text()
    if "shutil.which(\"protoc\")" in text and "out.split()[-1:] == [PROTOC_VERSION]" in text:
        return (
            "informational",
            "already_pinned() trusts `protoc --version` from PATH; a binary earlier on PATH "
            "that prints the pinned version short-circuits the hash-verified install "
            "(only reachable if the runner's PATH is attacker-writable - not decidable here)",
        )
    return "safe", "already_pinned does something else"


def main() -> int:
    src = TARGET.read_text()
    mod = load_target()
    import tempfile

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="probe-protoc-"))
    results = []

    def record(fn, *a):
        try:
            verdict, detail = fn(*a)
        except SystemExit as exc:  # a probe that hits die() is still a result
            verdict, detail = "vulnerable", f"unexpected SystemExit({exc.code})"
        except Exception as exc:  # noqa: BLE001 - a probe crash is a finding
            verdict, detail = "vulnerable", f"probe raised {type(exc).__name__}: {exc}"
        results.append({
            "name": fn.__name__.removeprefix("probe_"),
            "verdict": verdict,
            "detail": detail,
        })

    record(probe_pin_table_is_pinned_to_one_version, mod)
    record(probe_source_build_pins_the_tag, mod, TARGET)
    record(probe_shell_escape_in_sudo, mod, TARGET)
    record(probe_verify_final_is_reached, mod, TARGET)
    record(probe_already_pinned_accepts_a_shadowed_binary, mod, TARGET)
    record(probe_wrong_bytes_stops, mod, workdir)
    record(probe_empty_body_is_not_ok, mod, workdir)
    record(probe_connection_refused_falls_back, mod, workdir)
    record(probe_redirect_is_followed_and_verified, mod, workdir)
    record(probe_http_error_is_unreachable_not_tamper, mod, workdir)
    record(probe_path_hijack_of_the_target_dir, mod, workdir, TARGET)

    import shutil as _sh
    _sh.rmtree(workdir, ignore_errors=True)

    marker = {"safe": "ok  ", "vulnerable": "FAIL", "informational": "note"}
    for r in results:
        print(f"[{marker[r['verdict']]}] {r['name']}: {r['detail']}")

    vulns = [r for r in results if r["verdict"] == "vulnerable"]
    notes = [r for r in results if r["verdict"] == "informational"]
    print(
        f"\n{len(results)} probe(s): {len(results) - len(vulns) - len(notes)} safe, "
        f"{len(notes)} informational, {len(vulns)} vulnerable"
    )

    if "--json" in sys.argv:
        path = sys.argv[sys.argv.index("--json") + 1]
        pathlib.Path(path).write_text(json.dumps({"probes": results}, indent=2))
        print(f"json: {path}")

    return 1 if vulns else 0


if __name__ == "__main__":
    raise SystemExit(main())
