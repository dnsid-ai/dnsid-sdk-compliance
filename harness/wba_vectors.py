"""Shared WBA vectors and independent checks of SDK-produced signing bytes.

This is a constrained fixture checker, not a WBA or DNSid identity verifier.
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
VECTOR_PATH = ROOT / "docs/sdk-design/conformance/web-bot-auth.json"
DIRECTORY_TYPE = "application/http-message-signatures-directory+json"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def thumbprint(jwk: dict) -> str:
    public = {name: jwk[name] for name in ("crv", "kty", "x")}
    return b64url(
        hashlib.sha256(
            json.dumps(public, sort_keys=True, separators=(",", ":")).encode()
        ).digest()
    )


def body_bytes(message: dict) -> bytes:
    return base64.b64decode(message.get("bodyBase64") or "", validate=True)


def signature_parts(message: dict, label: str = "sig1") -> tuple[str, list[str], dict]:
    headers = message["headers"]
    # shortcut: only fixture SF grammar is supported, expand for new RFC 8941 cases.
    member = re.search(
        r"(?:^|,\s*)" + re.escape(label) + r"=(\([^)]*\)(?:;[^,]+)?)(?=,|$)",
        headers["signature-input"],
    )
    if member is None:
        raise ValueError("missing selected Signature-Input member")
    value = member.group(1)
    components_text, params_text = value[1:].split(")", 1)
    components = re.findall(r'"[^"\\]+"(?:;(?:key="[^"\\]+"|req))*', components_text)
    if " ".join(components) != components_text:
        raise ValueError("unsupported component serialization")
    params = {}
    for match in re.finditer(r';([a-z][a-z0-9_-]*)=("[^"\\]*"|-?[0-9]+)', params_text):
        name, raw = match.groups()
        if name in params:
            raise ValueError("duplicate signature parameter")
        params[name] = json.loads(raw)
    if (
        "".join(
            match.group(0)
            for match in re.finditer(
                r';([a-z][a-z0-9_-]*)=("[^"\\]*"|-?[0-9]+)', params_text
            )
        )
        != params_text
    ):
        raise ValueError("unsupported signature parameter serialization")
    return value, components, params


def signature_base(message: dict, request: dict, label: str = "sig1") -> bytes:
    value, components, _ = signature_parts(message, label)
    lines = []
    for component in components:
        if component in ('"@authority"', '"@authority";req'):
            field = urlsplit(request["url"]).netloc.lower()
        elif component == '"@method"':
            field = request["method"].upper()
        elif component == '"@target-uri"':
            field = request["url"]
        elif component == '"@status"':
            field = str(message["status"])
        elif ";key=" in component:
            name, key = component.split(";key=", 1)
            key = json.loads(key)
            member = re.search(
                r"(?:^|,\s*)" + re.escape(key) + r"=([^,]+)",
                message["headers"][json.loads(name)],
            )
            if member is None:
                raise ValueError("missing selected dictionary member")
            field = member.group(1).strip()
        else:
            field = message["headers"][json.loads(component)]
        lines.append(f"{component}: {field}")
    lines.append(f'"@signature-params": {value}')
    return "\n".join(lines).encode()


def signature_valid(
    message: dict, request: dict, jwk: dict, label: str = "sig1"
) -> bool:
    member = re.search(
        r"(?:^|,\s*)" + re.escape(label) + r"=:([A-Za-z0-9+/=]+):(?=,|$)",
        message["headers"]["signature"],
    )
    if member is None:
        return False
    signature = base64.b64decode(member.group(1), validate=True)
    key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="))
    try:
        key.verify(signature, signature_base(message, request, label))
        return True
    except InvalidSignature:
        return False


def digest_valid(message: dict) -> bool:
    expected = (
        "sha-256=:"
        + base64.b64encode(hashlib.sha256(body_bytes(message)).digest()).decode()
        + ":"
    )
    return message["headers"].get("content-digest") == expected


def check_signed_output(
    case_input: dict, actual: dict, started: int, finished: int
) -> dict:
    """Check output from a real SDK signer; never manufacture SDK acceptance."""
    if actual.get("ok") is not True:
        return actual
    try:
        request = case_input["request"]
        message = actual["message"]
        config = case_input.get("webBotAuth", {})
        options = case_input.get("options", {})
        directory = case_input["operation"] == "directory"
        public = {"kty": "OKP", "crv": "Ed25519", "x": case_input["key"]["x"]}
        _, components, params = signature_parts(message)
        if directory:
            expected_components = [
                '"@authority";req',
                '"content-type"',
                '"cache-control"',
                '"content-digest"',
            ]
            ttl = config.get("directorySignatureTTL", 300)
            require(message["status"] == 200, "directory status")
            require(
                message["headers"]["content-type"] == DIRECTORY_TYPE,
                "directory media type",
            )
            require(
                message["headers"]["cache-control"] == f"max-age={ttl}",
                "directory cache policy",
            )
            keys = json.loads(body_bytes(message))["keys"]
            require(
                keys
                == [
                    {
                        **public,
                        "kid": thumbprint(public),
                        "alg": "ed25519",
                        "use": "sig",
                    }
                ],
                "directory public key",
            )
        else:
            expected_components = ['"@authority"']
            ttl = options.get("ttl", config.get("signatureTTL", 60))
            require(
                message.get("bodyBase64") == request.get("bodyBase64"),
                "request body changed",
            )
            if request.get("bodyBase64") is not None:
                expected_components.append('"content-digest"')
            include_agent = options.get(
                "signatureAgent", config.get("includeSignatureAgent", True)
            )
            if include_agent:
                expected_components.append('"signature-agent";key="sig1"')
                agent = config.get("signatureAgent", {})
                uri = agent.get("uri", "https://" + case_input["domain"])
                kind = agent.get("type", "directory")
                require(
                    message["headers"]["signature-agent"]
                    == f'sig1="{uri}";type={kind}',
                    "discovery member",
                )
            else:
                require(
                    "signature-agent" not in message["headers"],
                    "unexpected discovery member",
                )
            expected_components.extend(
                '"' + name + '"' for name in options.get("additionalComponents", [])
            )
            for name, value in request["headers"].items():
                if name.lower() == "authorization":
                    require(
                        message["headers"].get("authorization") == value,
                        "Authorization changed",
                    )
        require(components == expected_components, "covered components")
        require(params["keyid"] == thumbprint(public), "thumbprint keyid")
        require(params["alg"] == "ed25519", "HTTP signature algorithm")
        tag = "http-message-signatures-directory" if directory else "web-bot-auth"
        require(params["tag"] == tag, "profile tag")
        require(
            type(params["created"]) is int and type(params["expires"]) is int,
            "integer timestamps",
        )
        require(params["expires"] - params["created"] == ttl, "signature lifetime")
        require(
            started - 5 <= params["created"] <= finished + 5, "signature creation time"
        )
        nonce = params["nonce"]
        require(re.fullmatch(r"[A-Za-z0-9_-]+", nonce) is not None, "nonce encoding")
        require(len(base64.urlsafe_b64decode(nonce + "==")) == 64, "64-byte nonce")
        if directory or request.get("bodyBase64") is not None:
            require(digest_valid(message), "content digest")
        require(signature_valid(message, request, public), "cryptographic signature")
        return {"ok": True}
    except (KeyError, ValueError, TypeError) as exc:
        return {"ok": False, "error": "ConformanceError", "message": str(exc)}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_wba_suite() -> dict:
    vectors = json.loads(VECTOR_PATH.read_text())
    check_golden_vectors(vectors)
    cases = [
        {
            "id": "wba-base-" + name,
            "description": "Exact RFC 9421 request base; not WBA profile acceptance.",
            "spec_ref": "RFC 9421 section 2.5; SDK design 10",
            "op": "http_signature_base",
            "input": {
                "request": fixture["message"],
                "signature_input": fixture["message"]["headers"]["signature-input"],
                "label": fixture.get("label", "sig1"),
            },
            "expect": {"ok": True, "value": fixture["signatureBase"]},
        }
        for name, fixture in vectors["requests"].items()
    ]
    for case in vectors["signingCases"]:
        cases.append(
            {
                **case,
                "op": "wba_sign",
                "input": {
                    "key": vectors["key"],
                    "domain": vectors["domain"],
                    **case["input"],
                },
            }
        )
    for case in vectors["verificationCases"]:
        scenario = case["input"]
        cases.append(
            {
                **case,
                "op": "wba_verify_request",
                "input": {
                    "key": vectors["key"],
                    "request": vectors["requests"][scenario["request"]]["message"],
                    "directoryRequest": vectors["directoryRequest"],
                    "directory": vectors["directories"][scenario["directory"]][
                        "message"
                    ],
                    "verification": {
                        **vectors["verificationDefaults"],
                        **scenario.get("verification", {}),
                    },
                },
            }
        )
    return {
        "suite": "web-bot-auth",
        "path": str(VECTOR_PATH.relative_to(ROOT)),
        "cases": cases,
    }


def check_golden_vectors(vectors: dict) -> None:
    ids = [
        case["id"]
        for group in ("signingCases", "verificationCases")
        for case in vectors[group]
    ]
    require(len(ids) == len(set(ids)), "duplicate WBA case id")
    for collection, request in (
        (vectors["requests"], None),
        (vectors["directories"], vectors["directoryRequest"]),
    ):
        for name, fixture in collection.items():
            message = fixture["message"]
            context = request or message
            label = fixture.get("label", "sig1")
            require(
                signature_base(message, context, label).decode()
                == fixture["signatureBase"],
                f"{name}: golden base",
            )
            require(
                signature_valid(message, context, vectors["key"], label)
                == fixture["signatureValid"],
                f"{name}: golden signature",
            )
            if "digestValid" in fixture:
                require(
                    digest_valid(message) == fixture["digestValid"],
                    f"{name}: golden digest",
                )
    for case in vectors["verificationCases"]:
        require(
            case["input"]["request"] in vectors["requests"], "unknown request fixture"
        )
        require(
            case["input"]["directory"] in vectors["directories"],
            "unknown directory fixture",
        )
        require(
            type(case["expect"]["ok"]) is bool, "invalid expected verification result"
        )


if __name__ == "__main__":
    document = json.loads(VECTOR_PATH.read_text())
    check_golden_vectors(document)
    print(
        f"WBA golden bases, signatures, digests, and {len(load_wba_suite()['cases'])} cases checked (no SDK verification claim)."
    )
