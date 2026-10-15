"""Checks for native WBA adapters and subprocess dispatch."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from generate_wba_fixtures import NEXT_KEY
from py_adapter import FixtureKeyProvider
from run import SubprocessAdapter, evaluate_result
from wba_adapters import verify_go
from wba_vectors import VECTOR_PATH, load_wba_suite


class WbaAdaptersTest(unittest.TestCase):
    def setUp(self):
        self.vectors = json.loads(VECTOR_PATH.read_text())

    def test_fixture_key_activation_changes_metadata_and_signature(self):
        try:
            old = FixtureKeyProvider(self.vectors["key"])
            next_key = FixtureKeyProvider(NEXT_KEY)
        except ImportError:
            self.skipTest("Python SDK is not installed")
        selected = old.signing_key()
        old.next_provider = next_key
        payload = b"rotation race"
        signature = old.sign(payload)
        self.assertIs(old.signing_key(), next_key.public)
        self.assertFalse(selected.verify(payload, signature))
        self.assertTrue(next_key.public.verify(payload, signature))
        self.assertEqual(old.sign_calls, 1)

    def test_typescript_stream_crash_is_a_case_failure_not_a_rejection(self):
        def execute(_cmd, **kwargs):
            requests = json.loads(kwargs["input"])
            if requests[0].get("crash"):
                return SimpleNamespace(returncode=1, stdout="", stderr="Controller is already closed")
            if requests[0].get("malformed"):
                return SimpleNamespace(returncode=0, stdout="{}", stderr="")
            return SimpleNamespace(returncode=0, stdout=json.dumps([
                {"ok": True} for _ in requests
            ]), stderr="")

        with patch("run.subprocess.run", side_effect=execute):
            results = SubprocessAdapter("ts", ["unused"]).run([
                {"op": "parse"}, {"op": "wba_verify_request", "crash": True},
                {"op": "wba_verify_request"},
                {"op": "wba_verify_request", "malformed": True},
            ])
        self.assertEqual(results[0], {"ok": True})
        self.assertEqual(results[2], {"ok": True})
        self.assertEqual(results[3]["error"], "AdapterError")
        self.assertEqual(results[1]["error"], "AdapterError")
        self.assertIn("Controller is already closed", results[1]["message"])
        case = {"op": "wba_verify_request", "expect": {"ok": False, "error": "ConformanceError"}}
        self.assertEqual(evaluate_result(case, "ts", results[1])[0], "FAIL")

    def test_go_refresh_does_not_reuse_known_revoked_evidence(self):
        sdk = os.environ.get("DNSID_GO_DIR")
        if not sdk:
            self.skipTest("set DNSID_GO_DIR to run the native core refresh regression")
        with tempfile.TemporaryDirectory() as directory:
            overlay = Path(directory) / "overlay.json"
            root = VECTOR_PATH.parents[3]
            overlay.write_text(json.dumps({"Replace": {
                str(Path(sdk).resolve() / "compliance_wba_refresh_test.go"):
                    str(root / "shims/go/testdata/wba_refresh_test.go"),
            }}))
            proc = subprocess.run(
                ["go", "test", f"-overlay={overlay}", ".", "-run",
                 "^TestComplianceWBARefreshRevocation$", "-count=1"],
                cwd=sdk, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_go_native_batch_dispatch_preserves_other_results(self):
        requests = [{"op": "parse"}, {"op": "wba_verify_request"}]
        native = {"ok": True, "signerDomain": self.vectors["domain"]}
        shim = [{"ok": True}, {"ok": False, "error": "NativeAdapterRequired"}]
        with (
            patch(
                "run.subprocess.run",
                return_value=SimpleNamespace(returncode=0, stdout=json.dumps(shim)),
            ),
            patch("wba_adapters.verify_go", return_value=[native]) as bridge,
        ):
            self.assertEqual(
                SubprocessAdapter("go", ["unused"]).run(requests), [shim[0], native]
            )
            bridge.assert_called_once_with([requests[1]])

    def test_go_overlay_does_not_modify_the_sdk_checkout(self):
        def execute(_cmd, **kwargs):
            output = Path(kwargs["env"]["DNSID_WBA_OUTPUT"])
            output.write_text('[{"ok": true, "signerDomain": "agent.example"}]')
            overlay = json.loads(Path(_cmd[2].split("=", 1)[1]).read_text())
            self.assertTrue(
                next(iter(overlay["Replace"])).endswith(
                    "webbotauth/compliance_adapter_test.go"
                )
            )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"DNSID_GO_DIR": directory}),
            patch("wba_adapters.subprocess.run", side_effect=execute),
        ):
            self.assertEqual(
                verify_go([{"op": "wba_verify_request"}]),
                [{"ok": True, "signerDomain": "agent.example"}],
            )
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_go_bridge_failure_is_an_adapter_error(self):
        with patch(
            "wba_adapters.subprocess.run",
            return_value=SimpleNamespace(
                returncode=1, stdout="", stderr="compile failed"
            ),
        ):
            results = verify_go([{}, {}])
        self.assertEqual(len(results), 2)
        self.assertTrue(all(result["error"] == "AdapterError" for result in results))

    def test_python_adapter_runs_the_native_verifier(self):
        try:
            from dnsid import WBAHttpVerifier
        except ImportError:
            self.skipTest("Python WBA SDK is not installed")
        from wba_adapters import verify_python

        cases = {case["id"]: case for case in load_wba_suite()["cases"]}
        original = WBAHttpVerifier.verify_web_bot_auth_signed_request
        with patch.object(
            WBAHttpVerifier,
            "verify_web_bot_auth_signed_request",
            autospec=True,
            side_effect=original,
        ) as verify:
            self.assertTrue(verify_python(cases["wba-verify-valid"]["input"])["ok"])
            self.assertEqual(
                verify_python(cases["wba-verify-bad-signature"]["input"])["error"],
                "ConformanceError",
            )
            self.assertEqual(verify.call_count, 2)
        with patch.object(
            WBAHttpVerifier,
            "verify_web_bot_auth_signed_request",
            side_effect=RuntimeError("fixture SDK bug"),
        ):
            self.assertEqual(
                verify_python(cases["wba-verify-valid"]["input"])["error"],
                "AdapterError",
            )

    def test_python_transport_preserves_fixture_date(self):
        try:
            from dnsid import WBAHttpVerifier  # noqa: F401
        except ImportError:
            self.skipTest("Python WBA SDK is not installed")
        from http.server import BaseHTTPRequestHandler
        from wba_adapters import verify_python

        dates = []
        original = BaseHTTPRequestHandler.send_header

        def send_header(handler, name, value):
            if name.lower() == "date":
                dates.append(value)
            return original(handler, name, value)

        case = next(case for case in load_wba_suite()["cases"]
                    if case["id"] == "wba-verify-directory-http-date-stale")
        with patch("wba_adapters.BaseHTTPRequestHandler.send_header", new=send_header):
            actual = verify_python(case["input"])
        self.assertEqual(dates, [case["input"]["directory"]["headers"]["date"]])
        self.assertFalse(actual["ok"])
        self.assertEqual(actual["error"], "ConformanceError")


if __name__ == "__main__":
    unittest.main()
