#!/usr/bin/env python3
"""arena_claude.py - run Claude Code through the Arena API's Arena Router.

There is no model selection: every Claude Code model field is bound to a router
mode (auto / fast); Arena decides which model answers.
Uses only the standard library (Python 3.8+).

Key: the ARENA_API_KEY environment variable (otherwise prompted hidden in the terminal).

Commands:
  check      test the key and router, show which model answered
  run        start Claude Code with the router (extra arguments pass to claude)
             example: python arena_claude.py run --resume
  install    write settings to ~/.claude/settings.json; plain `claude` also uses the router
  uninstall  remove what install wrote

Optional environment variables:
  ARENA_GATEWAY_URL  default https://api.preview.arena.ai (without a trailing /v1)
  ARENA_MODE         main router mode, default auto
  ARENA_FAST_MODE    mode for lightweight / background work, default fast
"""
import getpass
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

GATEWAY = os.environ.get("ARENA_GATEWAY_URL", "https://api.preview.arena.ai").rstrip("/")
if GATEWAY.endswith("/v1"):  # Claude Code appends the /v1/messages path itself
    GATEWAY = GATEWAY[:-3]
MODE = os.environ.get("ARENA_MODE", "auto")
FAST_MODE = os.environ.get("ARENA_FAST_MODE", "fast")
SETTINGS = Path.home() / ".claude" / "settings.json"


def claude_env(key):
    """Claude Code environment: every model field is bound to a router mode, no model name."""
    return {
        "ANTHROPIC_BASE_URL": GATEWAY,
        "ANTHROPIC_AUTH_TOKEN": key,
        "ANTHROPIC_API_KEY": "",  # must stay empty; otherwise Claude Code goes directly to Anthropic
        "ANTHROPIC_MODEL": MODE,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": MODE,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": MODE,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": FAST_MODE,
        "ANTHROPIC_SMALL_FAST_MODEL": FAST_MODE,
        "CLAUDE_CODE_SUBAGENT_MODEL": MODE,
    }


def get_key():
    key = os.environ.get("ARENA_API_KEY", "").strip()
    if not key and sys.stdin.isatty():
        key = getpass.getpass("Arena API key (hidden while typing): ").strip()
    if not key:
        sys.exit(
            "ARENA_API_KEY is not defined.\n"
            "  bash/zsh:   export ARENA_API_KEY=...\n"
            "  PowerShell: $env:ARENA_API_KEY='...'"
        )
    return key


def check(key):
    """Send a small request to the router and print who answered. Return True on success."""
    body = json.dumps({
        "model": MODE,
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "Say hello in exactly five words"}],
    }).encode()
    req = urllib.request.Request(
        GATEWAY + "/v1/messages",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
            "x-api-key": key,
            "User-Agent": "arena-claude/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            headers = resp.headers
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        if e.code == 401:
            hint = "Key rejected. Check the Keys page in the Arena panel to see whether the key is active."
        elif e.code == 403:
            hint = "No access. Make sure the key is authorized for this endpoint."
        elif e.code == 404:
            hint = "Address not found. ARENA_GATEWAY_URL must be the root address (without a trailing /v1)."
        elif e.code == 429:
            hint = "Rate limit. Wait a little and try again."
        elif e.code >= 500:
            hint = "There may be a temporary error on the Arena side; try again later."
        else:
            hint = ""
        print(f"ERROR {e.code}: {detail}\n{hint}".rstrip(), file=sys.stderr)
        return False
    except OSError as e:  # URLError, timeout, connection refusal
        print(f"Could not connect: {getattr(e, 'reason', e)}", file=sys.stderr)
        return False

    try:
        data = json.loads(raw)
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict)).strip()
        body_model = data.get("model")
    except (ValueError, AttributeError):
        print(f"Unexpected response: {raw[:200]}", file=sys.stderr)
        return False

    resolved = headers.get("X-Arena-Resolved-Model") or body_model or "?"
    print(f"OK  mode: {headers.get('X-Arena-Routing-Mode') or MODE}")
    print(f"    answering model: {resolved}")
    print(f"    tier: {headers.get('X-Arena-Routing-Tier') or '?'}")
    print(f"    response: {text or '(empty)'}")
    if resolved != "?" and "claude" not in resolved.lower():
        print("    note: for this request the router chose a non-Claude model (router decision).")
    return True


def cmd_run(args):
    skip_check = bool(args) and args[0] == "--no-check"
    claude_args = args[1:] if skip_check else args
    key = get_key()
    if not skip_check and not check(key):
        sys.exit("Router test failed; Claude Code was not started (to skip: run --no-check).")
    exe = shutil.which("claude")
    if not exe:
        sys.exit("The `claude` command is not on PATH; is Claude Code installed?")
    env = {**os.environ, **claude_env(key)}
    if os.name == "nt":
        return subprocess.call([exe, *claude_args], env=env)
    os.execvpe(exe, [exe, *claude_args], env)


def load_settings():
    if not SETTINGS.exists():
        return {}
    try:
        data = json.loads(SETTINGS.read_text(encoding="utf-8") or "{}")
    except ValueError:
        sys.exit(f"{SETTINGS} is not valid JSON; fix it first.")
    if not isinstance(data, dict) or not isinstance(data.get("env", {}), dict):
        sys.exit(f"{SETTINGS} is not in the expected shape (root and env must be objects).")
    return data


def save_settings(data):
    SETTINGS.parent.mkdir(parents=True, exist_ok=True)
    if SETTINGS.exists():
        backup = SETTINGS.with_name(SETTINGS.name + ".bak")
        if not backup.exists():  # preserve the first (original) state once
            shutil.copy2(SETTINGS, backup)
    tmp = SETTINGS.with_name(SETTINGS.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)  # contains a key: read only by you
    except OSError:
        pass
    os.replace(tmp, SETTINGS)


def cmd_install():
    key = get_key()
    if not check(key):
        sys.exit("Router test failed; settings were not written.")
    data = load_settings()
    data.setdefault("env", {}).update(claude_env(key))
    save_settings(data)
    print(f"Wrote: {SETTINGS}")
    print("The key is stored as plain text in this file; do not share the file or put it in git.")
    print("Close and reopen open Claude Code sessions; plain `claude` now uses the router.")
    return 0


def cmd_uninstall():
    if not SETTINGS.exists():
        print("There is no settings file; nothing left to do.")
        return 0
    data = load_settings()
    env = data.get("env", {})
    removed = [name for name in claude_env("") if name in env]
    for name in removed:
        del env[name]
    if "env" in data and not env:
        del data["env"]
    save_settings(data)
    print("Removed: " + (", ".join(removed) or "(already absent)"))
    return 0


def main(argv):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    cmd, rest = (argv[0], argv[1:]) if argv else ("help", [])
    try:
        if cmd == "check":
            return 0 if check(get_key()) else 1
        if cmd == "run":
            return cmd_run(rest)
        if cmd == "install":
            return cmd_install()
        if cmd == "uninstall":
            return cmd_uninstall()
    except KeyboardInterrupt:
        return 130
    print(__doc__)
    return 0 if cmd in ("help", "-h", "--help") else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
