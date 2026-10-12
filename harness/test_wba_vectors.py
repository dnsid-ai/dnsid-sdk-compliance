"""Checks for the WBA fixture checker and missing-capability reporting."""

import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import yaml

from generate_wba_fixtures import NOW, build_vectors
from run import compare, evaluate_result, render_report
from wba_vectors import (
    VECTOR_PATH,
    check_golden_vectors,
    check_signed_output,
    load_wba_suite,
)


class WbaVectorsTest(unittest.TestCase):
    def setUp(self):
        self.vectors = json.loads(VECTOR_PATH.read_text())

    def signing_case(self, directory=False):
        fixture = self.vectors["directories" if directory else "requests"]["valid"]
        request = self.vectors["directoryRequest"] if directory else fixture["message"]
        case_input = {
            "key": self.vectors["key"],
            "domain": self.vectors["domain"],
            "request": request,
            "operation": "directory" if directory else "request",
        }
        return case_input, {"ok": True, "message": copy.deepcopy(fixture["message"])}

    def test_reproducible_golden_vectors(self):
        self.assertEqual(self.vectors, build_vectors())
        check_golden_vectors(self.vectors)
        self.assertEqual(
            len(load_wba_suite()["cases"]),
            len(self.vectors["requests"])
            + len(self.vectors["signingCases"])
            + len(self.vectors["verificationCases"]),
        )

    def test_valid_signing_and_directory_bytes(self):
        for directory in (False, True):
            with self.subTest(directory=directory):
                case, actual = self.signing_case(directory)
                self.assertEqual(
                    check_signed_output(case, actual, NOW, NOW), {"ok": True}
                )

    def test_modified_signature_is_rejected(self):
        case, actual = self.signing_case()
        actual["message"]["headers"]["signature"] = self.vectors["requests"][
            "bad-signature"
        ]["message"]["headers"]["signature"]
        self.assertFalse(check_signed_output(case, actual, NOW, NOW)["ok"])

    def test_wrong_key_and_removed_coverage_are_rejected(self):
        for fixture in (
            "wrong-thumbprint",
            "missing-authority",
            "wrong-algorithm",
            "wrong-tag",
        ):
            with self.subTest(fixture=fixture):
                case, actual = self.signing_case()
                actual["message"] = copy.deepcopy(
                    self.vectors["requests"][fixture]["message"]
                )
                self.assertFalse(check_signed_output(case, actual, NOW, NOW)["ok"])

    def test_changed_body_and_authorization_are_rejected(self):
        for change in ("body", "authorization"):
            with self.subTest(change=change):
                case, actual = self.signing_case()
                if change == "body":
                    actual["message"]["bodyBase64"] = ""
                else:
                    actual["message"]["headers"]["authorization"] = "Bearer replacement"
                self.assertFalse(check_signed_output(case, actual, NOW, NOW)["ok"])

    def test_bad_directory_signature_digest_and_public_key_are_rejected(self):
        for fixture in (
            "bad-signature",
            "tampered-body",
            "wrong-jwk-kid",
            "private-jwk",
            "missing-coverage",
        ):
            with self.subTest(fixture=fixture):
                case, actual = self.signing_case(directory=True)
                actual["message"] = copy.deepcopy(
                    self.vectors["directories"][fixture]["message"]
                )
                self.assertFalse(check_signed_output(case, actual, NOW, NOW)["ok"])

    def test_stale_creation_time_is_rejected(self):
        case, actual = self.signing_case()
        self.assertFalse(check_signed_output(case, actual, NOW + 10, NOW + 10)["ok"])

    def test_fixture_corruption_aborts_loading(self):
        self.vectors["requests"]["valid"]["signatureBase"] += "\n"
        with self.assertRaisesRegex(ValueError, "golden base"):
            check_golden_vectors(self.vectors)

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
