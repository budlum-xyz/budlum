"""Offline behavior checks for the standalone router launcher."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("router_launcher", ROOT / "arena_claude.py")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


class RouterLauncherTests(unittest.TestCase):
    def test_environment_keeps_all_model_routes(self):
        env = launcher.claude_env("test-key")
        self.assertEqual(env["ANTHROPIC_AUTH_TOKEN"], "test-key")
        self.assertEqual(env["ANTHROPIC_API_KEY"], "")
        for name in (
            "ANTHROPIC_MODEL",
            "ANTHROPIC_DEFAULT_OPUS_MODEL",
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
            "CLAUDE_CODE_SUBAGENT_MODEL",
        ):
            self.assertEqual(env[name], launcher.MODE)
        for name in ("ANTHROPIC_DEFAULT_HAIKU_MODEL", "ANTHROPIC_SMALL_FAST_MODEL"):
            self.assertEqual(env[name], launcher.FAST_MODE)

    def test_check_posts_to_messages_and_reads_response(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.headers = {"X-Arena-Resolved-Model": "test-model"}
        response.read.return_value = b'{"content":[{"text":"hello"}]}'
        with mock.patch.object(launcher.urllib.request, "urlopen", return_value=response) as open_url:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(launcher.check("test-key"))
        request = open_url.call_args.args[0]
        self.assertEqual(request.full_url, launcher.GATEWAY + "/v1/messages")
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.get_header("X-api-key"), "test-key")
        self.assertEqual(json.loads(request.data)["model"], launcher.MODE)
        self.assertEqual(open_url.call_args.kwargs["timeout"], 60)

    def test_http_failure_does_not_succeed(self):
        error = urllib.error.HTTPError("https://example.invalid", 401, "refused", {}, io.BytesIO(b"refused"))
        with mock.patch.object(launcher.urllib.request, "urlopen", side_effect=error):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertFalse(launcher.check("test-key"))

    def test_install_and_uninstall_preserve_unrelated_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Path(directory) / "settings.json"
            original = {"env": {"OTHER_SETTING": "kept"}, "other": [1, 2]}
            settings.write_text(json.dumps(original), encoding="utf-8")
            with mock.patch.object(launcher, "SETTINGS", settings), \
                 mock.patch.object(launcher, "get_key", return_value="test-key"), \
                 mock.patch.object(launcher, "check", return_value=True), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(launcher.cmd_install(), 0)
                installed = json.loads(settings.read_text(encoding="utf-8"))
                self.assertEqual(installed["env"]["OTHER_SETTING"], "kept")
                self.assertEqual(installed["env"]["ANTHROPIC_AUTH_TOKEN"], "test-key")
                self.assertEqual(json.loads(settings.with_name("settings.json.bak").read_text()), original)
                if os.name != "nt":
                    self.assertEqual(settings.stat().st_mode & 0o777, 0o600)
                self.assertEqual(launcher.cmd_uninstall(), 0)
                self.assertEqual(json.loads(settings.read_text(encoding="utf-8")), original)
                self.assertEqual(json.loads(settings.with_name("settings.json.bak").read_text()), original)

    def test_failed_check_never_writes_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Path(directory) / "settings.json"
            with mock.patch.object(launcher, "SETTINGS", settings), \
                 mock.patch.object(launcher, "get_key", return_value="test-key"), \
                 mock.patch.object(launcher, "check", return_value=False):
                with self.assertRaises(SystemExit):
                    launcher.cmd_install()
            self.assertFalse(settings.exists())

    @unittest.skipIf(os.name == "nt", "execvpe is used on POSIX")
    def test_run_forwards_arguments_and_honors_no_check(self):
        with mock.patch.object(launcher, "get_key", return_value="test-key"), \
             mock.patch.object(launcher, "check") as check, \
             mock.patch.object(launcher.shutil, "which", return_value="/bin/claude"), \
             mock.patch.object(launcher.os, "execvpe") as execute:
            launcher.cmd_run(["--no-check", "--resume"])
        check.assert_not_called()
        exe, args, env = execute.call_args.args
        self.assertEqual(exe, "/bin/claude")
        self.assertEqual(args, ["/bin/claude", "--resume"])
        self.assertEqual(env["ANTHROPIC_AUTH_TOKEN"], "test-key")


if __name__ == "__main__":
    unittest.main()
