"""Regression checks for native SDK errors and C2SP evidence verification."""

import copy
import unittest
from unittest.mock import patch

from py_adapter import PyAdapter
from run import evaluate_result
from semantic_vectors import load_semantic_suites


class PyAdapterTests(unittest.TestCase):
    def setUp(self):
        try:
            import dnsid  # noqa: F401
        except ImportError:
            self.skipTest("Python SDK is not installed")
        self.adapter = PyAdapter()
        suite = next(s for s in load_semantic_suites() if s["suite"] == "c2sp-lifecycle-selection")
        self.cases = {case["id"]: case for case in suite["cases"]}

    def execute(self, name, **changes):
        case = self.cases[name]
        request = {"op": case["op"], **copy.deepcopy(case["input"]), **changes}
        return self.adapter.run([request])[0]

    def test_runtime_error_is_not_a_valid_rejection(self):
        with patch("dnsid._utils.normalize_fqdn", side_effect=RuntimeError("SDK crash")):
            actual = self.adapter.run([{"op": "normalize_fqdn", "name": ""}])[0]
        self.assertEqual(actual["error"], "AdapterError")
        case = {"op": "normalize_fqdn", "expect": {"ok": False, "error": "ValidationError"}}
        self.assertEqual(evaluate_result(case, "py", actual)[0], "FAIL")

    def test_checkpoint_is_verified_even_when_flag_claims_acceptance(self):
        from dnsid.c2sp_tlog import enforce_checkpoint_policy

        with patch("dnsid.c2sp_tlog.enforce_checkpoint_policy", wraps=enforce_checkpoint_policy) as verify:
            actual = self.execute("invalid-accepted-checkpoint-is-fatal", checkpointAccepted=True)
        verify.assert_called_once()
        self.assertEqual(actual["errorCategory"], "INVALID_EVIDENCE")
        actual = self.execute("es256-signature-only-copy-is-applied-once", checkpoint="not a checkpoint")
        self.assertEqual(actual["errorCategory"], "INVALID_EVIDENCE")

    def test_checkpoint_flag_does_not_manufacture_rejection(self):
        actual = self.execute("es256-signature-only-copy-is-applied-once", checkpointAccepted=False)
        self.assertTrue(actual["ok"], actual)

    def test_incomplete_stream_calls_native_reader(self):
        from dnsid.c2sp_tlog import C2spTlogReader

        original = C2spTlogReader.rebuild_history
        with patch.object(C2spTlogReader, "rebuild_history", autospec=True, side_effect=original) as verify:
            actual = self.execute("incomplete-current-state-view-is-fatal")
        verify.assert_called_once()
        self.assertEqual(actual["errorCategory"], "INCOMPLETE_STREAM")
        with patch.object(C2spTlogReader, "rebuild_history", return_value=[]):
            actual = self.execute("incomplete-current-state-view-is-fatal")
        self.assertTrue(actual["ok"], actual)
        self.assertEqual(evaluate_result(self.cases["incomplete-current-state-view-is-fatal"], "py", actual)[0], "FAIL")

    def test_native_verifier_crash_is_an_adapter_failure(self):
        for target, case in (
            ("enforce_checkpoint_policy", "es256-signature-only-copy-is-applied-once"),
            ("verify_stream_lifecycle", "es256-signature-only-copy-is-applied-once"),
            ("C2spTlogReader.rebuild_history", "incomplete-current-state-view-is-fatal"),
        ):
            with self.subTest(target=target), patch("dnsid.c2sp_tlog." + target, side_effect=RuntimeError("SDK crash")):
                actual = self.execute(case)
            self.assertEqual(actual["error"], "AdapterError")


if __name__ == "__main__":
    unittest.main()
