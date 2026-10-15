"""Conformance metadata permits declared implementation limits."""

import unittest

from run import compare


class ConformanceMetadataTests(unittest.TestCase):
    def test_known_deviations(self):
        expected = {"ok": True, "publishProfile": "dnsid-draft-01"}
        for deviations in ([], ["Application-owned publication"]):
            with self.subTest(deviations=deviations):
                self.assertEqual(compare(expected, {**expected, "knownDeviations": deviations}), [])
        for deviations in (None, "limit", [""], [" "], [1]):
            with self.subTest(deviations=deviations):
                self.assertTrue(compare(expected, {**expected, "knownDeviations": deviations}))


if __name__ == "__main__":
    unittest.main()
