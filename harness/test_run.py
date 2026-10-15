"""Checks for expectation resolution, compliance reporting, and CI gating."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from run import compare, evaluate_result, render_report
from wba_vectors import VECTOR_PATH, load_wba_suite


class RunnerTests(unittest.TestCase):
    def test_known_deviations(self):
        expected = {"ok": True, "publishProfile": "dnsid-draft-01"}
        for deviations in ([], ["Application-owned publication"]):
            with self.subTest(deviations=deviations):
                self.assertEqual(compare(expected, {**expected, "knownDeviations": deviations}), [])
        for deviations in (None, "limit", [""], [" "], [1]):
            with self.subTest(deviations=deviations):
                self.assertTrue(compare(expected, {**expected, "knownDeviations": deviations}))

    def test_uncached_expectation_requires_actual_rediscovery(self):
        case = next(
            case
            for case in load_wba_suite()["cases"]
            if case["id"] == "wba-verify-cache-hit-http-stale"
        )
        for sdk in ("go", "ts", "py"):
            for count in (1, 2):
                actual = {
                    "ok": True,
                    "signerDomain": case["input"]["verification"]["signerDomain"],
                    "discoveryRequests": count,
                }
                self.assertEqual(
                    evaluate_result(case, sdk, actual)[0],
                    "PASS" if count == 2 else "FAIL",
                )
            self.assertEqual(
                evaluate_result(case, sdk, {"ok": False, "error": "ConformanceError"})[
                    0
                ],
                "FAIL",
            )
        with patch.dict(
            "run.CAPABILITIES", {"go": {"versions": set(), "directory_cache": True}}
        ):
            self.assertEqual(
                evaluate_result(case, "go", {"ok": False, "error": "ConformanceError"})[
                    0
                ],
                "PASS",
            )

    def test_missing_verifier_never_passes_positive_or_negative(self):
        missing = {
            "ok": False,
            "error": "CapabilityMissing",
            "capability": "wba_request_verification",
            "message": "SDK has signing/directory serving only",
        }
        for accepted in (False, True):
            case = {
                "op": "wba_verify_request",
                "expect": {
                    "ok": accepted,
                    **({} if accepted else {"error": "ConformanceError"}),
                },
            }
            self.assertEqual(evaluate_result(case, "go", missing)[0], "MISSING")
            self.assertEqual(
                evaluate_result(case, "go", {"ok": False, "error": "AdapterError"})[0],
                "FAIL",
            )

    def test_missing_is_not_compliant_in_report(self):
        case = {
            "id": "wba-verify-test",
            "description": "test",
            "op": "wba_verify_request",
            "expect": {"ok": False, "error": "ConformanceError"},
        }
        missing = {
            "ok": False,
            "error": "CapabilityMissing",
            "capability": "wba_request_verification",
            "message": "SDK has signing/directory serving only",
        }
        suite = {"suite": "web-bot-auth", "path": "fixture.json", "cases": [case]}
        report = render_report(
            ["go"],
            [suite],
            [("web-bot-auth", case, {"go": evaluate_result(case, "go", missing)})],
            SimpleNamespace(),
        )
        self.assertIn("| go | 0 | 0 | 0 | 0 | 1 | 0/1 (0.0%) | 1 |", report)
        self.assertIn("| `wba-verify-test` | MISSING |", report)

    def test_ci_gate_counts_missing_and_still_detects_failures(self):
        root = VECTOR_PATH.parents[3]
        workflow = yaml.safe_load(
            (root / ".github/workflows/sdk-compliance.yaml").read_text()
        )
        script = next(
            step["run"]
            for step in workflow["jobs"]["compliance"]["steps"]
            if step.get("id") == "compliance_summary"
        )
        case = {
            "id": "wba-verify-test",
            "description": "test",
            "op": "wba_verify_request",
            "expect": {"ok": False, "error": "ConformanceError"},
        }
        missing = {
            "ok": False,
            "error": "CapabilityMissing",
            "capability": "wba_request_verification",
            "message": "SDK has signing/directory serving only",
        }
        suite = {"suite": "web-bot-auth", "path": "fixture.json", "cases": [case]}

        def report(actual):
            return render_report(
                ["go"],
                [suite],
                [("web-bot-auth", case, {"go": evaluate_result(case, "go", actual)})],
                SimpleNamespace(),
            )

        for base in (False, True):
            for failure in (False, True):
                with (
                    self.subTest(base=base, failure=failure),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    path = Path(directory)
                    (path / "report-head.md").write_text(
                        report({"ok": True} if failure else missing)
                    )
                    if base:
                        (path / "report-base.md").write_text(report(missing))
                    env = {
                        **os.environ,
                        "SDK": "go",
                        "GITHUB_STEP_SUMMARY": str(path / "job-summary.md"),
                        "GITHUB_OUTPUT": str(path / "outputs"),
                    }
                    subprocess.run(
                        ["bash", "-c", script],
                        cwd=path,
                        env=env,
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    outputs = (path / "outputs").read_text()
                    self.assertIn("regressed=" + str(base and failure).lower(), outputs)
                    self.assertIn(
                        "strict_fail=" + str(not base and failure).lower(), outputs
                    )
                    summary = (path / "summary.md").read_text()
                    self.assertIn("| Missing |", summary)
                    self.assertIn("do not count as compliant", summary)
                    if base:
                        self.assertLess(
                            summary.index("| Base |"),
                            summary.index("Missing capabilities"),
                        )

    def test_missing_result_cannot_count_as_rejection(self):
        self.assertTrue(compare({"ok": False}, {}))


if __name__ == "__main__":
    unittest.main()
