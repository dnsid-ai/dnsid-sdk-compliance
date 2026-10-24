"""Check that current C2SP semantics control generated evidence."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import generate_c2sp_fixtures as generator
import semantic_vectors


class SemanticVectorTests(unittest.TestCase):
    def setUp(self):
        self.semantics = json.loads(generator.SEMANTICS.read_text())
        self.name = "byte-identical-complete-entry-is-applied-once"
        self.case = next(c for c in self.semantics["cases"] if c["id"] == self.name)

    def generate(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "semantics.json"
            source.write_text(json.dumps(self.semantics))
            with patch.object(generator, "SEMANTICS", source):
                return json.loads(generator.generate_selection())["cases"][self.name]

    def test_candidate_removal_and_reordering_change_the_evidence(self):
        original = self.generate()
        self.case["candidates"] = ["issuance"]
        reduced = self.generate()
        self.assertEqual(len(reduced["entries"]), 1)
        self.assertNotEqual(reduced["checkpoint"], original["checkpoint"])
        self.case["candidates"] = ["rotation", "issuance"]
        reordered = self.generate()
        self.assertEqual([e["effectId"] for e in reordered["entries"]], ["rotation-1", "issuance-1"])
        self.assertEqual(reordered["entries"][0]["entry"], original["entries"][2]["entry"])

    def test_empty_candidate_list_generates_an_empty_tree(self):
        self.case["candidates"] = []
        self.assertEqual(self.generate()["entries"], [])

    def test_unsupported_candidate_does_not_get_a_new_source_hash(self):
        self.case["candidates"].append("revocation")
        with self.assertRaisesRegex(ValueError, "no evidence recipe"):
            self.generate()

    def test_changed_candidate_definition_cannot_certify_old_bytes(self):
        self.semantics["candidateFixtures"]["rotation"]["domain"] = "other.example"
        with self.assertRaisesRegex(ValueError, "evidence does not match"):
            self.generate()

    def test_current_scenario_flags_control_generated_input(self):
        self.case["completeThroughCheckpoint"] = False
        self.assertFalse(self.generate()["completeThroughCheckpoint"])


class EntityKeyRotationEvidenceTests(unittest.TestCase):
    def test_entity_key_rotation_signatures_match_candidate_authentication(self):
        suite = json.loads(generator.SEMANTICS.read_text())
        evidence = json.loads(generator.OUTPUT.read_text())["cases"]
        keys = {kid: generator.ed_public(kid) for kid in generator.ENTITY_SEEDS}
        checked = 0
        for case in suite["cases"]:
            for item in evidence[case["id"]]["entries"]:
                raw = generator.unb64(item["entry"])
                if b'"type":"ENTITY_KEY_ROTATION"' not in raw:
                    continue
                entry = json.loads(raw)
                definition = next(d for d in suite["candidateFixtures"].values() if d["effectId"] == item["effectId"])
                # Fixture kids name their disposable keys; the SDK instead takes the active
                # entity key from verified predecessor state.
                previous = keys.get(entry["sigs"].get("prev_ae", {}).get("kid"))
                new_key = entry["new_ek"]
                signatures = entry["sigs"]
                # Authentication is cryptographic: prev_ae by the active key and new_ae by new_ek.
                # Structural defects do not prevent it; a private new_ek is never a verification key.
                private = {"d", "p", "q", "dp", "dq", "qi", "k"} & set(new_key)
                verified = previous is not None and not private and set(signatures) == {"prev_ae", "new_ae"}
                verified = verified and signatures["prev_ae"]["kid"] == previous["kid"]
                verified = verified and ("kid" not in new_key or signatures["new_ae"]["kid"] == new_key["kid"])
                if verified:
                    data = generator.canonical(generator.payload(entry))
                    for role, key in (("prev_ae", previous), ("new_ae", new_key)):
                        try:
                            Ed25519PublicKey.from_public_bytes(generator.unb64(key["x"])).verify(
                                generator.unb64(signatures[role]["sig"]), data)
                        except InvalidSignature:
                            verified = False
                # Authenticated means well formed and signed by the previous and new keys.
                authenticated = definition.get("authenticated", definition["valid"])
                self.assertEqual(verified, authenticated, (case["id"], item["effectId"]))
                checked += 1
        self.assertGreater(checked, 20)


class KnownBugMarkerTests(unittest.TestCase):
    def write(self, value):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "markers.json"
        path.write_text(json.dumps(value))
        return path

    def test_markers_map_cases_to_sdk_known_bugs(self):
        path = self.write({"go": [{"reason": "pending", "cases": ["a"]}]})
        self.assertEqual(semantic_vectors.load_known_bugs({"a", "b"}, path), {"a": {"go": {"known_bug": "pending"}}})

    def test_unknown_case_or_sdk_and_repeats_fail(self):
        for value in ({"go": [{"reason": "x", "cases": ["missing"]}]},
                      {"rust": [{"reason": "x", "cases": ["a"]}]},
                      {"go": [{"reason": "", "cases": ["a"]}]},
                      {"go": [{"reason": "x", "cases": ["a"]}, {"reason": "y", "cases": ["a"]}]}):
            with self.assertRaises(ValueError):
                semantic_vectors.load_known_bugs({"a"}, self.write(value))

    def test_committed_markers_load(self):
        semantic_vectors.load_semantic_suites()


if __name__ == "__main__":
    unittest.main()
