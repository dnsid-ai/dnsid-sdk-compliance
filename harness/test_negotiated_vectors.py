import base64
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from negotiated_vectors import VECTOR_PATH, check_prepare_output, check_sign_output, load_negotiated_suite, signature_base


class NegotiatedVectorTests(unittest.TestCase):
    def setUp(self):
        self.vectors = json.loads(VECTOR_PATH.read_text())
        self.suite = load_negotiated_suite()

    def sign_case(self, tamper: bool = False) -> dict:
        case = next(c for c in self.suite["cases"] if c["id"] == "negotiated-sign-default")
        key = self.vectors["key"]
        private = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(key["seed"] + "="))
        base_case = next(c for c in self.vectors["baseCases"] if c["id"] == "negotiated-base-default")
        response = {"status": 200, "headers": {
            **base_case["response"]["headers"], "signature-input": base_case["signatureInput"],
        }}
        signature = private.sign(signature_base(response, case["input"]["request"], base_case["signatureInput"], "sig1"))
        response["headers"]["signature"] = "sig1=:" + base64.b64encode(signature).decode() + ":"
        if tamper:
            response["status"] = 201
        return check_sign_output(case["input"], {"ok": True, "response": response}, 1700000001, 1700000001)

    def test_independent_checker_accepts_valid_signature(self):
        result = self.sign_case()
        self.assertTrue(result["signatureValid"])
        self.assertEqual(result["lifetime"], 60)
        self.assertEqual(result["keyid"], "service.example#fixture-ku")

    def test_independent_checker_detects_tampering(self):
        self.assertFalse(self.sign_case(tamper=True)["signatureValid"])

    def test_prepare_masks_only_a_canonical_nonce(self):
        expected = next(c for c in self.vectors["prepareCases"] if c["id"] == "negotiated-prepare-default")
        nonce = base64.urlsafe_b64encode(bytes(32)).decode().rstrip("=")
        headers = {
            "accept-signature": expected["expected"]["acceptSignature"].replace("<nonce>", nonce),
            "signature-input": 'sig1=("@method" "@authority" "@target-uri" "accept-signature");created=1',
            "signature": "sig1=:AA==:",
        }
        result = check_prepare_output(expected["input"], {"ok": True, "headers": headers})
        self.assertEqual(result["acceptSignature"], expected["expected"]["acceptSignature"])
        self.assertTrue(result["nonceCanonical"])
        headers["accept-signature"] = headers["accept-signature"].replace(nonce, nonce[:-1] + "B")
        self.assertFalse(check_prepare_output(expected["input"], {"ok": True, "headers": headers})["nonceCanonical"])


if __name__ == "__main__":
    unittest.main()
