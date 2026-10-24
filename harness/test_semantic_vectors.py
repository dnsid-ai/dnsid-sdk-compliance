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
        checked = 0
        for case in suite["cases"]:
            entries = []
            for item in evidence[case["id"]]["entries"]:
                try:
                    entries.append((item, json.loads(generator.unb64(item["entry"]))))
                except ValueError:
                    continue
            by_id = {generator.event_id(entry): entry for _, entry in entries}

            def entity_key(event):
                # Entity key current after `event`, following the fixture's own chain.
                if event["type"] == "ISSUANCE":
                    return event["ek"]
                if event["type"] == "ENTITY_KEY_ROTATION" and self.authenticates(event, by_id):
                    return event["new_ek"]
                return entity_key(by_id[event["prev_event_id"]])

            self.entity_key = entity_key
            for item, entry in entries:
                if entry.get("type") != "ENTITY_KEY_ROTATION" or entry["prev_event_id"] not in by_id:
                    continue  # pre-genesis copies have no predecessor authority to check
                definition = next(d for d in suite["candidateFixtures"].values() if d["effectId"] == item["effectId"])
                authenticated = definition.get("authenticated", definition["valid"])
                self.assertEqual(self.authenticates(entry, by_id), authenticated, (case["id"], item["effectId"]))
                checked += 1
        self.assertGreater(checked, 25)

    def authenticates(self, entry, by_id):
        """prev_ae by the predecessor's entity key and new_ae by a public new_ek it names."""
        predecessor = by_id.get(entry["prev_event_id"])
        if predecessor is None:
            return False
        active = self.entity_key(predecessor)
        new_key, signatures = entry["new_ek"], entry["sigs"]
        if {"d", "p", "q", "dp", "dq", "qi", "k"} & set(new_key) or set(signatures) != {"prev_ae", "new_ae"}:
            return False
        if signatures["prev_ae"]["kid"] != active["kid"]:
            return False
        if not new_key.get("kid") or signatures["new_ae"]["kid"] != new_key["kid"]:
            return False
        data = generator.canonical(generator.payload(entry))
        for role, key in (("prev_ae", active), ("new_ae", new_key)):
            if key["kty"] == "EC":
                if not generator.signatures_valid({**entry, "sigs": {role: signatures[role]}}, {role: key}):
                    return False
                continue
            try:
                Ed25519PublicKey.from_public_bytes(generator.unb64(key["x"])).verify(
                    generator.unb64(signatures[role]["sig"]), data)
            except InvalidSignature:
                return False
        return True


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
