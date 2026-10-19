"""Checks for shared golden-bundle verification without repeated writer runs."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

import c2sp_matrix as matrix


class C2spMatrixTests(unittest.TestCase):
    def setUp(self):
        corpus = json.loads(matrix.CORPUS.read_text())
        self.path = matrix.CORPUS.parent / corpus["golden_bundle"]
        self.vector = json.loads(self.path.read_text())
        expected = self.vector["expected"]
        self.result = {
            "eventCount": expected["event_count"],
            "status": expected["status"],
            "activeOperationalThumbprint": expected["active_operational_thumbprint"],
            "bundleSignerKid": expected["bundle_signer_kid"],
        }

    def test_golden_bundle_verified_once_per_sdk(self):
        with (
            patch("c2sp_matrix._verify_python", return_value=self.result) as python,
            patch("c2sp_matrix._run_json", return_value=self.result) as external,
        ):
            matrix._verify_golden_bundle(self.vector, self.path)
        python.assert_called_once_with(self.vector)
        self.assertEqual(external.call_args_list, [
            call(["node", str(matrix.ROOT / "harness/c2sp_verify_ts.mjs"), str(self.path)]),
            call(["go", "run", "./c2spverify", str(self.path)], cwd=matrix.ROOT / "shims/go"),
        ])

    def test_each_verifier_result_must_match(self):
        wrong = {**self.result, "eventCount": self.result["eventCount"] + 1}
        for sdk in ("py", "ts", "go"):
            with (
                self.subTest(sdk=sdk),
                patch("c2sp_matrix._verify_python", return_value=wrong if sdk == "py" else self.result),
                patch("c2sp_matrix._run_json", side_effect=[
                    wrong if sdk == "ts" else self.result,
                    wrong if sdk == "go" else self.result,
                ]),
                self.assertRaisesRegex(AssertionError, f"{sdk} verification result"),
            ):
                matrix._verify_golden_bundle(self.vector, self.path)

    def test_noncanonical_golden_bundle_is_rejected_before_generation(self):
        vector = {**self.vector, "bundle": json.dumps(json.loads(self.vector["bundle"]), indent=2)}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "corpus.json"
            corpus.write_text(json.dumps({"golden_bundle": "golden.json"}))
            (root / "golden.json").write_text(json.dumps(vector))
            with (
                patch("c2sp_matrix.CORPUS", corpus),
                patch("c2sp_matrix._sdk_dir", return_value=root),
                patch("c2sp_matrix._python_artifacts") as generate,
                self.assertRaisesRegex(AssertionError, "not canonical JSON"),
            ):
                matrix.main()
            generate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
