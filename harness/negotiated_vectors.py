"""Negotiated response signature vectors and independent checks of SDK output.

This is a constrained fixture checker, not an RFC 9421 or DNSid verifier.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "docs/sdk-design/conformance/negotiated-response-signatures.json"
CAPABILITY = "negotiated_response_signatures"
NONCE = re.compile(r'nonce="([A-Za-z0-9_-]+)"')


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def b64url_canonical(value: str, minimum: int) -> bool:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        return False
    return len(raw) >= minimum and base64.urlsafe_b64encode(raw).decode().rstrip("=") == value


def member(header: str, label: str) -> str | None:
    # shortcut: fixture members contain no commas, expand for full RFC 8941 dictionaries.
    match = re.search(r"(?:^|,\s*)" + re.escape(label) + r"=([^,]+)", header)
    return match.group(1).strip() if match else None


def split_member(value: str) -> tuple[list[str], str]:
    require(value.startswith("("), "member is not an inner list")
    inner, params = value[1:].split(")", 1)
    components = re.findall(r'"[^"\\]+"(?:;(?:key="[^"\\]+"|req))*', inner)
    require(" ".join(components) == inner, "unsupported component serialization")
    return components, params


def params_of(params: str) -> dict:
    out = {}
    for name, raw in re.findall(r';([a-z]+)=("[^"\\]*"|-?[0-9]+)', params):
        require(name not in out, "duplicate signature parameter")
        out[name] = json.loads(raw)
    return out


def signature_base(response: dict, request: dict, signature_input: str, label: str) -> bytes:
    value = member(signature_input, label)
    require(value is not None, "missing response Signature-Input member")
    components, _ = split_member(value)
    lines = []
    for component in components:
        name, *params = component.split(";")
        name = json.loads(name)
        source = request if "req" in params else response
        key = next((json.loads(p[4:]) for p in params if p.startswith("key=")), None)
        if name == "@status":
            field = str(response["status"])
        elif name == "@method":
            field = request["method"].upper()
        elif name == "@authority":
            field = urlsplit(request["url"]).netloc.lower()
        elif name == "@target-uri":
            field = request["url"]
        elif key is not None:
            field = member(source["headers"][name], key)
            require(field is not None, "missing selected dictionary member")
        else:
            require(name in source["headers"], f"missing field {name}")
            field = source["headers"][name].strip()
        lines.append(f"{component}: {field}")
    lines.append(f'"@signature-params": {value}')
    return "\n".join(lines).encode()


def digest(body: bytes) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def check_sign_output(case_input: dict, actual: dict, started: int, finished: int) -> dict:
    """Reduce an SDK-signed response to the fields the vectors compare."""
    if not actual.get("ok"):
        return actual
    try:
        response, request = actual["response"], case_input["request"]
        headers = response["headers"]
        label = re.match(r"\s*([a-z*][a-z0-9_.*-]*)=", request["headers"]["accept-signature"]).group(1)
        value = member(headers["signature-input"], label)
        require(value is not None, "missing requested response label")
        components, params_text = split_member(value)
        params = params_of(params_text)
        signature = member(headers["signature"], label)
        require(signature is not None and signature.startswith(":"), "missing response signature")
        jwk = case_input["key"]
        key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="))
        try:
            key.verify(
                base64.b64decode(signature.strip(":"), validate=True),
                signature_base(response, request, headers["signature-input"], label),
            )
            valid = True
        except InvalidSignature:
            valid = False
        created = params.get("created")
        return {
            "ok": True,
            "label": label,
            "components": " ".join(components),
            "nonce": params.get("nonce"),
            "keyid": params.get("keyid"),
            "alg": params.get("alg"),
            "lifetime": params["expires"] - created if "expires" in params and created is not None else None,
            "createdInWindow": isinstance(created, int) and started - 1 <= created <= finished + 1,
            "contentDigest": headers.get("content-digest"),
            "cacheControl": headers.get("cache-control"),
            "signatureValid": valid,
        }
    except (KeyError, ValueError, AttributeError, TypeError) as exc:
        return {"ok": False, "error": "AdapterError", "message": f"unparseable signed response: {exc}"}


def check_prepare_output(case_input: dict, actual: dict) -> dict:
    """Mask the random challenge and reduce the prepared request to compared fields."""
    if not actual.get("ok"):
        return actual
    try:
        headers = actual["headers"]
        accept = headers["accept-signature"]
        nonces = NONCE.findall(accept)
        require(len(nonces) == 1, "expected one nonce")
        label = case_input.get("label") or "sig1"
        value = member(headers["signature-input"], label)
        require(value is not None and member(headers["signature"], label) is not None, "missing request signature")
        components, _ = split_member(value)
        return {
            "ok": True,
            "acceptSignature": accept.replace(nonces[0], "<nonce>"),
            "nonceCanonical": b64url_canonical(nonces[0], 32) and 43 <= len(nonces[0]) <= 1024,
            "requestComponents": sorted(components),
        }
    except (KeyError, ValueError, TypeError) as exc:
        return {"ok": False, "error": "AdapterError", "message": f"unparseable prepared request: {exc}"}


def _expect(expected: dict, defaults: dict) -> dict:
    if expected.get("error"):
        return {"ok": False, "error": "ConformanceError"}
    return {"ok": True, **defaults, **expected}


def check_golden_vectors(vectors: dict) -> None:
    ids = [c["id"] for g in ("baseCases", "prepareCases", "signingCases") for c in vectors[g]]
    require(len(ids) == len(set(ids)), "duplicate negotiated response case id")
    for case in vectors["baseCases"]:
        request = vectors["requests"][case["request"]]
        if "expectedBase" in case:
            built = signature_base(case["response"], request, case["signatureInput"], case["label"])
            require(built.decode() == case["expectedBase"], f"{case['id']}: stale expectedBase")
    for case in vectors["signingCases"]:
        body = case["input"]["response"].get("bodyBase64")
        expected = case["expected"]
        if "contentDigest" in expected and not expected.get("noContent"):
            raw = base64.b64decode(body or "", validate=True)
            require(expected["contentDigest"] == digest(raw), f"{case['id']}: stale contentDigest")


def load_negotiated_suite() -> dict:
    vectors = json.loads(VECTOR_PATH.read_text())
    check_golden_vectors(vectors)
    common = {"key": vectors["key"], "domain": vectors["domain"]}
    cases = []
    for case in vectors["baseCases"]:
        cases.append({
            "id": case["id"], "description": case["description"],
            "spec_ref": "RFC 9421 sections 2.4 and 2.5; SDK design 02 negotiated response profile",
            "op": "negotiated_response_base",
            "input": {
                **common,
                "request": vectors["requests"][case["request"]],
                "response": case["response"],
                "signature_input": case["signatureInput"],
                "label": case["label"],
            },
            "expect": (
                {"ok": False, "error": "ConformanceError"} if "expectedError" in case
                else {"ok": True, "value": case["expectedBase"]}
            ),
        })
    for case in vectors["prepareCases"]:
        cases.append({
            "id": case["id"], "description": case["description"],
            "spec_ref": "SDK design 02 client request preparation",
            "op": "negotiated_response_prepare",
            "input": {**common, **case["input"]},
            "expect": _expect(case["expected"], {"nonceCanonical": True}),
        })
    for case in vectors["signingCases"]:
        request = vectors["requests"][case["input"]["request"]]
        if "acceptSignature" in case["input"]:
            request = {**request, "headers": {**request["headers"], "accept-signature": case["input"]["acceptSignature"]}}
        expected = {k: v for k, v in case["expected"].items() if k != "noContent"}
        cases.append({
            "id": case["id"], "description": case["description"],
            "spec_ref": "SDK design 02 server response signing",
            "op": "negotiated_response_sign",
            "input": {**common, "request": request, "response": case["input"]["response"]},
            "expect": _expect(expected, {
                "keyid": f"{vectors['domain']}#{vectors['key']['kid']}", "alg": "ed25519",
                "lifetime": 60, "createdInWindow": True, "signatureValid": True,
            }),
        })
    return {"suite": "negotiated-response-signatures", "path": str(VECTOR_PATH.relative_to(ROOT)), "cases": cases}
