"""Checks for WBA golden fixtures and independent signing validation."""

import copy
import json
import unittest

from generate_wba_fixtures import (
    NOW,
    NEXT_KEY,
    build_vectors,
    corrupt_signature,
    sign,
    tls_fixture_files,
)
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


if __name__ == "__main__":
    unittest.main()
