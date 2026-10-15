"""TypeScript shim failures must not satisfy rejection expectations."""

import shutil
import tempfile
import unittest
from pathlib import Path

from run import ROOT, SubprocessAdapter, evaluate_result


@unittest.skipUnless(shutil.which("node"), "Node is not installed")
class TsAdapterTests(unittest.TestCase):
    def test_sdk_crashes_and_missing_packages_are_adapter_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "dist").mkdir()
            (root / "package.json").write_text('{"type":"module"}')
            (root / "dist/index.js").write_text("""
export class ValidationError extends Error { name = 'ValidationError'; }
export function normalizeFQDN(name) {
  if (name === '') throw new ValidationError('empty FQDN');
  throw new TypeError('unexpected SDK crash');
}
""")
            adapter = SubprocessAdapter("ts", ["node", str(ROOT / "shims/ts/shim.mjs")],
                                        env={"DNSID_TS_DIR": str(root)})
            results = adapter.run([
                {"op": "normalize_fqdn", "name": ""},
                {"op": "normalize_fqdn", "name": "crash"},
                {"op": "http_signature_base"},
                {"op": "c2sp_managed_trust_select"},
            ])
        case = {"op": "normalize_fqdn", "expect": {"ok": False, "error": "ValidationError"}}
        self.assertEqual(evaluate_result(case, "ts", results[0])[0], "PASS")
        for result in results[1:]:
            self.assertEqual(result["error"], "AdapterError")
            self.assertEqual(evaluate_result(case, "ts", result)[0], "FAIL")


if __name__ == "__main__":
    unittest.main()
