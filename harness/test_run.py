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
from wba_vectors import load_wba_suite

MISSING = {
    "ok": False, "error": "CapabilityMissing", "capability": "wba_request_verification",
    "message": "SDK has signing/directory serving only",
}


class RunnerTests(unittest.TestCase):
    def report(self, cases, results, sdk="go"):
        cases = [{"description": "test", **case} for case in cases]
        suite = {"suite": "test", "path": "test", "cases": cases}
        rows = [("test", case, {sdk: evaluate_result(case, sdk, result)})
                for case, result in zip(cases, results, strict=True)]
        return render_report([sdk], [suite], rows)

    def gate(self, head, base=None, sdk="go"):
        workflow = yaml.safe_load((ROOT / ".github/workflows/sdk-compliance.yaml").read_text())
        script = next(s["run"] for s in workflow["jobs"]["compliance"]["steps"]
                      if s.get("id") == "compliance_summary")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "report-head.md").write_text(head)
            if base is not None:
                (root / "report-base.md").write_text(base)
            subprocess.run(
                ["bash", "-c", script], cwd=root, check=True, capture_output=True, text=True,
                env={**os.environ, "SDK": sdk, "GITHUB_STEP_SUMMARY": str(root / "summary"),
                     "GITHUB_OUTPUT": str(root / "outputs")},
            )
            return (root / "outputs").read_text(), (root / "summary.md").read_text()

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
        for accepted in (False, True):
            case = {
                "op": "wba_verify_request",
                "expect": {
                    "ok": accepted,
                    **({} if accepted else {"error": "ConformanceError"}),
                },
            }
            self.assertEqual(evaluate_result(case, "go", MISSING)[0], "MISSING")
            self.assertEqual(
                evaluate_result(case, "go", {"ok": False, "error": "AdapterError"})[0],
                "FAIL",
            )

    def test_missing_is_not_compliant_in_report(self):
        case = {"id": "wba-verify-test", "op": "wba_verify_request",
                "expect": {"ok": False, "error": "ConformanceError"}}
        report = self.report([case], [MISSING])
        self.assertIn("| go | 0 | 0 | 0 | 0 | 1 | 0/1 (0.0%) | 1 |", report)
        self.assertIn("| `wba-verify-test` | MISSING |", report)

    def test_report_counts_all_statuses_and_preserves_details(self):
        statuses = ("PASS", "REJ", "FAIL", "XFAIL", "XPASS", "MISSING")
        cases = [{"id": status, "description": "test"} for status in statuses]
        rows = [("test", case, {"go": (case["id"], ["problem"], "note", {})}) for case in cases]
        suites = [{"suite": "test", "path": "test", "cases": cases},
                  {"suite": "empty", "path": "empty", "cases": []}]
        report = render_report(["go"], suites, rows)
        self.assertIn("| go | 2 | 1 | 1 | 1 | 6 | 3/6 (50.0%) | 1 |", report)
        self.assertIn("| test | 3/6 (50.0%); 1 fail, 1 known, 1 missing |", report)
        self.assertIn("| empty | 0/0 (0.0%) |", report)
        for status in statuses:
            mark = f"**{status}**" if status in {"FAIL", "XPASS"} else status
            self.assertIn(f"| `{status}` | {mark}" + (" †" if status != "MISSING" else "") + " |", report)
        self.assertIn("### `FAIL` — go", report)
        self.assertIn("now passes, remove the known_bug marker", report)
        self.assertIn("## Documented divergences", report)

    def test_ci_gate_counts_missing_and_still_detects_failures(self):
        case = {"id": "wba-verify-test", "op": "wba_verify_request",
                "expect": {"ok": False, "error": "ConformanceError"}}
        for base in (False, True):
            for failure in (False, True):
                with self.subTest(base=base, failure=failure):
                    outputs, summary = self.gate(
                        self.report([case], [{"ok": True} if failure else MISSING]),
                        self.report([case], [MISSING]) if base else None,
                    )
                    self.assertIn("regressed=" + str(base and failure).lower(), outputs)
                    self.assertIn("strict_fail=" + str(not base and failure).lower(), outputs)
                    self.assertIn("| Missing |", summary)
                    self.assertIn("do not count as compliant", summary)
                    if base:
                        self.assertLess(summary.index("| Base |"), summary.index("Missing capabilities"))

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
        cases = [{"id": name, "op": "parse", "expect": {"ok": True}}
                 for name in ("old-failure", "new-failure")]
        base = self.report(cases, [{"ok": False}, {"ok": True}], "py")
        for fails in (True, False):
            with self.subTest(fails=fails):
                head = self.report(cases, [{"ok": True}, {"ok": not fails}], "py")
                outputs, _ = self.gate(head, base, "py")
                self.assertIn("regressed=" + str(fails).lower(), outputs)


if __name__ == "__main__":
    unittest.main()
