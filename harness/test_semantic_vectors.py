"""Check that current C2SP semantics control generated evidence."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import generate_c2sp_fixtures as generator


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


if __name__ == "__main__":
    unittest.main()
