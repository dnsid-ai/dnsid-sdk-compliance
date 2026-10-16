"""Fixture integrity, native execution, and fail-closed checkpoint reporting."""

import base64
import copy
import hashlib
import os
import unittest
from pathlib import Path

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from generate_c2sp_fixtures import generate_checkpoints
from run import build_adapters, compare, evaluate_result

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/c2sp-checkpoint-continuity.yaml"
# Single-SDK CI runs unit checks before building its shim or installing other SDKs.
NATIVE_READY = all(os.environ.get(f"DNSID_{sdk}_DIR") for sdk in ("GO", "TS", "PY"))
NATIVE_REASON = "native adapter checks require all three SDK directories and built shims"


class CheckpointVectorsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = yaml.safe_load(FIXTURE.read_text())["cases"]

    def test_reproducible_fixtures(self):
        self.assertEqual(generate_checkpoints()[FIXTURE], FIXTURE.read_text())
        ids = [case["id"] for case in self.cases]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue({"LOG_ROLLBACK", "LOG_FORK", "LOG_INCONSISTENT", "CHECKPOINT_STORE_ERROR"}
                        <= {case["expect"].get("errorCategory") for case in self.cases})

    def test_signed_evidence_and_merkle_roots(self):
        seen = set()
        for case in self.cases:
            for evidence in (case["input"]["checkpointCase"]["trusted"], case["input"]["checkpointCase"]["candidate"]):
                if evidence is None or evidence["checkpoint"] in seen:
                    continue
                seen.add(evidence["checkpoint"])
                with self.subTest(case=case["id"]):
                    text, signatures = evidence["checkpoint"].split("\n\n")
                    origin, size, root = text.splitlines()
                    self.assertEqual(origin, "log.example")
                    self.assertTrue(all(set(item) == {"index", "entry", "proof"} for item in evidence["entries"]))
                    leaves = [hashlib.sha256(b"\0" + base64.urlsafe_b64decode(item["entry"] + "==")).digest()
                              for item in evidence["entries"]]
                    self.assertEqual(int(size), len(leaves))
                    calculated = leaves[0] if len(leaves) == 1 else hashlib.sha256(b"\1" + b"".join(leaves)).digest()
                    self.assertEqual(base64.b64decode(root), calculated)
                    log_sig, witness_sig = [base64.b64decode(line.split()[-1]) for line in signatures.strip().splitlines()]
                    log_key = Ed25519PrivateKey.from_private_bytes(bytes([4]) * 32).public_key()
                    note = (text + "\n").encode()
                    if case["id"] == "checkpoint-invalid-checkpoint-signature":
                        with self.assertRaises(InvalidSignature):
                            log_key.verify(log_sig[4:], note)
                    else:
                        log_key.verify(log_sig[4:], note)
                    stamp = int.from_bytes(witness_sig[4:12], "big")
                    witness_key = Ed25519PrivateKey.from_private_bytes(bytes([5]) * 32).public_key()
                    witness_key.verify(witness_sig[12:], f"cosignature/v1\ntime {stamp}\n".encode() + note)

    @unittest.skipUnless(NATIVE_READY, NATIVE_REASON)
    def test_native_sequences_and_state_invariants(self):
        requests = [{"op": case["op"], **case["input"]} for case in self.cases]
        for sdk, adapter in build_adapters({"go", "ts", "py"}).items():
            results = adapter.run(requests)
            for case, result in zip(self.cases, results, strict=True):
                with self.subTest(sdk=sdk, case=case["id"]):
                    status, problems, _, _ = evaluate_result(case, sdk, result)
                    self.assertIn(status, {"PASS", "XFAIL"}, problems)
                    self.assertEqual(result["ok"], case["expect"]["ok"])
                    self.assertEqual(result["stored"], case["expect"]["stored"])
                    if case["input"]["checkpointCase"].get("fault"):
                        self.assertTrue(result["causePreserved"])

    @unittest.skipUnless(NATIVE_READY, NATIVE_REASON)
    def test_bad_seed_is_an_adapter_failure_not_a_negative_pass(self):
        case = copy.deepcopy(next(case for case in self.cases if case["id"] == "checkpoint-rollback"))
        forged = next(case for case in self.cases if case["id"] == "checkpoint-invalid-checkpoint-signature")
        case["input"]["checkpointCase"]["trusted"] = forged["input"]["checkpointCase"]["candidate"]
        for sdk, adapter in build_adapters({"go", "ts", "py"}).items():
            with self.subTest(sdk=sdk):
                result = adapter.run([{"op": case["op"], **case["input"]}])[0]
                self.assertEqual(result["error"], "AdapterError")
                self.assertEqual(evaluate_result(case, sdk, result)[0], "FAIL")

    @unittest.skipUnless(NATIVE_READY, NATIVE_REASON)
    def test_unknown_scenario_flags_fail_the_adapter(self):
        for key, value in (("mode", "unknown"), ("fault", "unknown")):
            case = copy.deepcopy(self.cases[0])
            case["input"]["checkpointCase"][key] = value
            for sdk, adapter in build_adapters({"go", "ts", "py"}).items():
                with self.subTest(sdk=sdk, key=key):
                    result = adapter.run([{"op": case["op"], **case["input"]}])[0]
                    self.assertEqual(result["error"], "AdapterError")
                    self.assertEqual(evaluate_result(case, sdk, result)[0], "FAIL")

    def test_known_taxonomy_gaps_do_not_mask_safety_regressions(self):
        case = copy.deepcopy(next(case for case in self.cases if case["id"] == "checkpoint-store-write-error"))
        case["sdk"] = {"py": {"known_bug": "test-only taxonomy gap"}}
        expected = case["expect"]
        taxonomy_gap = {**expected, "errorCategory": None}
        self.assertEqual(evaluate_result(case, "py", taxonomy_gap)[0], "XFAIL")
        for change in ({"ok": True}, {"stored": None}, {"causePreserved": False}, {"error": "AdapterError"}, {"error": "ShimError"}):
            with self.subTest(change=change):
                self.assertEqual(evaluate_result(case, "py", {**taxonomy_gap, **change})[0], "FAIL")
        self.assertEqual(evaluate_result(case, "py", dict(expected))[0], "XPASS")
        proof_case = copy.deepcopy(next(case for case in self.cases if case["id"] == "checkpoint-invalid-proof"))
        proof_case["sdk"] = {"py": {"known_bug": "test-only taxonomy gap"}}
        no_proof = {**proof_case["expect"], "errorCategory": None, "proofRequested": False}
        self.assertEqual(evaluate_result(proof_case, "py", no_proof)[0], "FAIL")

    def test_diagnostic_assertions_are_not_just_rejection_checks(self):
        case = next(case for case in self.cases if case["id"] == "checkpoint-rollback")
        actual = copy.deepcopy(case["expect"])
        for key in ("origin", "trustedTreeSize", "observedTreeSize", "trustedRootHash", "observedRootHash"):
            with self.subTest(key=key):
                bad = copy.deepcopy(actual)
                del bad["diagnostics"][key]
                self.assertTrue(compare(case["expect"], bad))
        self.assertTrue(compare(case["expect"], {"ok": False, "error": "CheckpointError"}))


if __name__ == "__main__":
    unittest.main()
