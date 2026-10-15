"""Checks for expectation resolution, compliance reporting, and CI gating."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from run import ROOT, build_adapters, compare, evaluate_result, load_fixtures, render_report, resolve_expectation
from semantic_vectors import load_semantic_suites
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

    def test_rejections_need_a_specific_error_and_cannot_hide_adapter_failures(self):
        self.assertTrue(compare({"ok": False}, {"ok": False, "error": "RuntimeError"}))
        for error in ("AdapterError", "ShimError"):
            case = {"op": "parse", "expect": {"ok": False, "error": error},
                    "sdk": {"py": {"known_bug": "An existing SDK defect"}}}
            actual = {"ok": False, "error": error, "message": "unexpected failure"}
            self.assertEqual(evaluate_result(case, "py", actual)[0], "FAIL")

    def test_all_negative_fixtures_name_native_errors(self):
        suites = [*load_fixtures(ROOT / "fixtures", None), *load_semantic_suites(), load_wba_suite()]
        for suite in suites:
            for case in suite["cases"]:
                for sdk in ("go", "ts", "py"):
                    expected, _ = resolve_expectation(case, sdk)
                    if expected["ok"] is False:
                        with self.subTest(case=case["id"], sdk=sdk):
                            self.assertTrue(expected.get("error"))

    def test_python_checkout_must_match_the_imported_package(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "selected"
            for imported, matches in ((selected / "dnsid/__init__.py", True),
                                      (Path(directory) / "old/dnsid/__init__.py", False)):
                with (
                    self.subTest(imported=imported),
                    patch.dict(os.environ, {"DNSID_PY_DIR": str(selected)}),
                    patch.dict("sys.modules", {"dnsid": SimpleNamespace(__file__=str(imported))}),
                ):
                    if matches:
                        self.assertIn("py", build_adapters({"py"}))
                    else:
                        with self.assertRaisesRegex(RuntimeError, "not imported from"):
                            build_adapters({"py"})

    def test_setup_rebuilds_and_reinstalls_existing_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "shims/go").mkdir(parents=True)
            for name in ("dnsid-shim", "main.go", "go.mod"):
                (root / "shims/go" / name).touch()
            (root / ".venv/bin").mkdir(parents=True)
            (root / ".venv/bin/python").touch()
            for checkout in ("first", "second"):
                result = subprocess.run(
                    ["make", "-n", "-f", str(ROOT / "Makefile"), "setup",
                     f"DNSID_GO_DIR=/{checkout}/go", f"DNSID_PY_DIR=/{checkout}/py"],
                    cwd=root, capture_output=True, text=True, check=True,
                )
                self.assertIn("go build -o dnsid-shim .", result.stdout)
                self.assertIn(f'go work init . "/{checkout}/go"', result.stdout)
                self.assertIn(f'uv pip install -p .venv pyyaml cryptography -e "/{checkout}/py"', result.stdout)

    def test_ci_gate_rejects_new_failures_even_when_total_does_not_increase(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/sdk-compliance.yaml").read_text())
        script = next(s["run"] for s in workflow["jobs"]["compliance"]["steps"]
                      if s.get("id") == "compliance_summary")
        cases = [{"id": name, "op": "parse", "description": "test", "expect": {"ok": True}}
                 for name in ("old-failure", "new-failure")]
        suites = [{"suite": "test", "path": "test", "cases": cases}]

        def report(failing):
            rows = [("test", case, {"py": evaluate_result(
                case, "py", {"ok": case["id"] not in failing})}) for case in cases]
            return render_report(["py"], suites, rows, SimpleNamespace())

        for head in ({"new-failure"}, set()):
            with self.subTest(head=head), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "report-head.md").write_text(report(head))
                (root / "report-base.md").write_text(report({"old-failure"}))
                subprocess.run(
                    ["bash", "-c", script], cwd=root, check=True, capture_output=True, text=True,
                    env={**os.environ, "SDK": "py", "GITHUB_STEP_SUMMARY": str(root / "summary"),
                         "GITHUB_OUTPUT": str(root / "outputs")},
                )
                self.assertIn("regressed=" + str(bool(head)).lower(), (root / "outputs").read_text())


if __name__ == "__main__":
    unittest.main()
