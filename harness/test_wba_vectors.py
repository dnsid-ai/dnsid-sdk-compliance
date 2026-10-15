"""Checks for the WBA fixture checker and missing-capability reporting."""

import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml
from generate_wba_fixtures import (
    NOW,
    NEXT_KEY,
    build_vectors,
    corrupt_signature,
    sign,
    tls_fixture_files,
)
from run import FixtureKeyProvider, SubprocessAdapter, compare, evaluate_result, render_report
from wba_adapters import verify_go
from wba_vectors import (
    VECTOR_PATH,
    check_golden_vectors,
    check_signed_output,
    load_wba_suite,
    signature_parts,
)


class WbaVectorsTest(unittest.TestCase):
    def setUp(self):
        self.vectors = json.loads(VECTOR_PATH.read_text())

    def signing_case(self, directory=False, ttl=300, backdate=None, cache_age=None):
        fixture = self.vectors["directories" if directory else "requests"]["valid"]
        message = copy.deepcopy(fixture["message"])
        request = self.vectors["directoryRequest"] if directory else fixture["message"]
        case_input = {
            "key": self.vectors["key"],
            "domain": self.vectors["domain"],
            "request": request,
            "operation": "directory" if directory else "request",
        }
        if directory:
            case_input["webBotAuth"] = {"directorySignatureTTL": ttl}
            backdate = min(5, ttl - 1) if backdate is None else backdate
            cache_age = ttl - backdate if cache_age is None else cache_age
            message["headers"]["cache-control"] = (
                f"max-age={cache_age}, must-revalidate"
            )
            sign(
                message,
                request,
                signature_parts(message)[1],
                created=NOW - backdate,
                expires=NOW - backdate + ttl,
                tag="http-message-signatures-directory",
            )
        return case_input, {"ok": True, "message": message}

    def test_reproducible_golden_vectors(self):
        self.assertEqual(self.vectors, build_vectors())
        check_golden_vectors(self.vectors)
        self.assertEqual(
            len(load_wba_suite()["cases"]),
            len(self.vectors["requests"])
            + len(self.vectors["signingCases"])
            + len(self.vectors["verificationCases"]),
        )

    def test_wg_discovery_and_timestamp_cases(self):
        self.assertEqual(
            self.vectors["drafts"], ["draft-ietf-webbotauth-httpsig-protocol-00"]
        )
        cases = {case["id"]: case for case in self.vectors["verificationCases"]}
        for name in (
            "missing-signature-agent",
            "uncovered-agent",
            "directory-path",
            "directory-query",
            "directory-fragment",
        ):
            with self.subTest(name=name):
                self.assertEqual(
                    cases["wba-verify-" + name]["expect"],
                    {"ok": False, "error": "ConformanceError", "discoveryRequests": 0},
                )
        redirect = cases["wba-verify-same-host-public-redirect"]
        self.assertFalse(redirect["expect"]["ok"])
        self.assertEqual(redirect["expect"]["discoveryRequests"], 1)
        self.assertTrue(cases["wba-verify-relabeled"]["expect"]["ok"])
        self.assertTrue(cases["wba-verify-future-within-skew"]["expect"]["ok"])
        self.assertFalse(cases["wba-verify-directory-future-within-skew"]["expect"]["ok"])

    def test_signing_checker_never_permits_discovery_omission(self):
        case, actual = self.signing_case()
        case["webBotAuth"] = {"includeSignatureAgent": False}
        case["options"] = {"signatureAgent": False}
        actual["message"] = self.vectors["requests"]["no-agent"]["message"]
        self.assertFalse(check_signed_output(case, actual, NOW, NOW)["ok"])

    def test_signing_checker_rejects_future_directory_but_allows_request_skew(self):
        for directory in (False, True):
            with self.subTest(directory=directory):
                case, actual = self.signing_case(directory)
                if directory:
                    case, actual = self.signing_case(
                        True, backdate=-1, cache_age=295
                    )
                else:
                    actual["message"] = self.vectors["requests"]["future-within-skew"][
                        "message"
                    ]
                self.assertEqual(
                    check_signed_output(case, actual, NOW, NOW)["ok"], not directory
                )

    def test_directory_backdating_and_remaining_cache_lifetime(self):
        for ttl, backdate in ((300, 5), (60, 5), (5, 4), (1, 0)):
            with self.subTest(ttl=ttl):
                case, actual = self.signing_case(True, ttl=ttl)
                params = signature_parts(actual["message"])[2]
                self.assertEqual(params["created"], NOW - backdate)
                self.assertEqual(params["expires"] - params["created"], ttl)
                self.assertEqual(
                    check_signed_output(case, actual, NOW, NOW), {"ok": True}
                )
                case, actual = self.signing_case(
                    True, ttl=ttl, cache_age=ttl - backdate + 1
                )
                self.assertFalse(check_signed_output(case, actual, NOW, NOW)["ok"])

        for backdate in (0, 4, 6):
            with self.subTest(backdate=backdate):
                case, actual = self.signing_case(
                    True, backdate=backdate, cache_age=295
                )
                result = check_signed_output(case, actual, NOW, NOW)
                self.assertFalse(result["ok"])
                self.assertEqual(result["message"], "backdated directory creation time")

    def test_directory_cache_directives(self):
        for policy, valid in (
            ("max-age=295, must-revalidate", True),
            ("Must-Revalidate, max-age=295", True),
            ("max-age=0, must-revalidate", True),
            ("max-age=295", False),
            ("max-age=295, must-revalidate=0", False),
            ("max-age=295, must-revalidate, stale-while-revalidate=60", False),
            ("max-age=295, must-revalidate, stale-if-error=60", False),
        ):
            with self.subTest(policy=policy):
                case, actual = self.signing_case(True)
                message = actual["message"]
                message["headers"]["cache-control"] = policy
                _, components, params = signature_parts(message)
                sign(message, case["request"], components, **params)
                result = check_signed_output(case, actual, NOW, NOW)
                self.assertEqual(result["ok"], valid)
                if not valid:
                    self.assertIn("directory cache policy", result["message"])

    def test_query_form_encoding_vectors(self):
        for name, value in (
            ("query-form-encoding", "%7E*"), ("query-plus-space", "x%20y"),
            ("query-percent-space", "x%20y"), ("query-empty", ""),
        ):
            with self.subTest(name=name):
                self.assertIn(
                    f'"@query-param";name="q": {value}',
                    self.vectors["requests"][name]["signatureBase"].splitlines(),
                )

    def test_network_age_vectors_have_no_uncached_escape(self):
        cases = {case["id"]: case for case in self.vectors["verificationCases"]}
        for name, valid in (("http-age-stale", False), ("http-date-stale", False),
                            ("http-zero-age-stale", False), ("http-age-fresh", True)):
            case = cases["wba-verify-directory-" + name]
            self.assertEqual(case["expect"]["ok"], valid)
            self.assertNotIn("uncachedExpect", case)
            self.assertTrue(self.vectors["directories"][name]["signatureValid"])

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

    def test_signing_key_change_requires_valid_bytes_or_native_rejection(self):
        for directory in (False, True):
            case, actual = self.signing_case(directory)
            case["signingKeyChange"] = NEXT_KEY
            self.assertEqual(check_signed_output(case, actual, NOW, NOW), {"ok": True})
            actual["message"]["headers"]["signature"] = "sig1=:YWJj:"
            self.assertFalse(check_signed_output(case, actual, NOW, NOW)["ok"])
            for error in ("ArgumentError", "VerificationError", "SigningRejected"):
                self.assertEqual(check_signed_output(
                    case, {"ok": False, "error": error}, NOW, NOW,
                ), {"ok": True})
            for error in ("AdapterError", "TypeError", "CapabilityMissing", "NotImplementedError"):
                self.assertFalse(check_signed_output(
                    case, {"ok": False, "error": error}, NOW, NOW,
                )["ok"])

    def test_keyed_digest_fixture_is_signed_but_has_no_content(self):
        fixture = self.vectors["requests"]["keyed-digest-without-content"]
        self.assertNotIn("bodyBase64", fixture["message"])
        self.assertTrue(fixture["signatureValid"])
        self.assertFalse(fixture["digestValid"])
        self.assertIn(
            '"content-digest";key="sha-256": :YWJj:', fixture["signatureBase"]
        )

    def test_fresh_non_cacheable_directory_vectors_are_positive(self):
        cases = {case["id"]: case for case in self.vectors["verificationCases"]}
        for name in ("no-store", "no-cache", "zero-max-age"):
            with self.subTest(name=name):
                self.assertTrue(cases["wba-verify-directory-" + name]["expect"]["ok"])
                self.assertTrue(self.vectors["directories"][name]["signatureValid"])

    def test_tls_credentials_are_reproducible_and_match_the_fixture(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        files = tls_fixture_files()
        for path, content in files.items():
            self.assertEqual(path.read_bytes(), content)
        cert = x509.load_pem_x509_certificate(
            next(
                content
                for path, content in files.items()
                if path.name == "wba-cert.pem"
            )
        )
        key = serialization.load_pem_private_key(
            next(
                content for path, content in files.items() if path.name == "wba-key.pem"
            ),
            password=None,
        )
        self.assertEqual(
            cert.public_key().public_bytes_raw(), key.public_key().public_bytes_raw()
        )
        self.assertEqual(
            cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName),
            [self.vectors["domain"]],
        )

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
                    "signerDomain": self.vectors["domain"],
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
                actual["message"]["headers"]["cache-control"] = (
                    "max-age=295, must-revalidate"
                )
                sign(
                    actual["message"],
                    case["request"],
                    signature_parts(actual["message"])[1],
                    created=NOW - 5,
                    expires=NOW + 295,
                    tag="http-message-signatures-directory",
                )
                if fixture == "bad-signature":
                    actual["message"] = corrupt_signature(actual)["message"]
                result = check_signed_output(case, actual, NOW, NOW)
                self.assertFalse(result["ok"])
                self.assertEqual(
                    result["message"],
                    {
                        "bad-signature": "cryptographic signature",
                        "tampered-body": "content digest",
                        "wrong-jwk-kid": "directory public key",
                        "private-jwk": "directory public key",
                        "missing-coverage": "covered components",
                    }[fixture],
                )

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
