#!/usr/bin/env python3
"""Generate reproducible WBA wire vectors with disposable keys, without SDKs."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from datetime import datetime, timezone
from email.utils import formatdate

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from wba_vectors import (
    DIRECTORY_TYPE,
    VECTOR_PATH,
    b64url,
    check_golden_vectors,
    signature_base,
    thumbprint,
)

NOW = 1700000000
DOMAIN = "agent.example"
SEED = bytes(range(32))
PRIVATE = Ed25519PrivateKey.from_private_bytes(SEED)
PUBLIC = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": b64url(PRIVATE.public_key().public_bytes_raw()),
}
KEY = {**PUBLIC, "kid": "fixture-ku", "seed": b64url(SEED)}
NEXT_SEED = bytes(reversed(range(32)))
NEXT_PRIVATE = Ed25519PrivateKey.from_private_bytes(NEXT_SEED)
NEXT_KEY = {
    "kty": "OKP", "crv": "Ed25519", "kid": "fixture-next", "seed": b64url(NEXT_SEED),
    "x": b64url(NEXT_PRIVATE.public_key().public_bytes_raw()),
}
THUMB = thumbprint(PUBLIC)
NONCE = b64url(bytes(range(64)))
REF = "SDK design 10: request/directory verification; RFC 9421; RFC 9530; draft-ietf-webbotauth-httpsig-protocol-00"


def digest(body: bytes) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def sign(
    message: dict,
    context: dict,
    components: list[str],
    *,
    label: str = "sig1",
    **overrides,
) -> dict:
    params = {
        "created": NOW,
        "expires": NOW + 60,
        "keyid": THUMB,
        "alg": "ed25519",
        "nonce": NONCE,
        "tag": "web-bot-auth",
        **overrides,
    }
    value = (
        "("
        + " ".join(components)
        + ")"
        + "".join(
            ";" + name + "=" + json.dumps(value, separators=(",", ":"))
            for name, value in params.items()
            if value is not None
        )
    )
    message["headers"]["signature-input"] = label + "=" + value
    base = signature_base(message, context, label)
    message["headers"]["signature"] = (
        label + "=:" + base64.b64encode(PRIVATE.sign(base)).decode() + ":"
    )
    result = {
        "message": message,
        "signatureBase": base.decode(),
        "signatureValid": True,
    }
    if label != "sig1":
        result["label"] = label
    if "content-digest" in message["headers"]:
        result["digestValid"] = True
    return result


def request_fixture(
    *,
    label="sig1",
    body=b'{"hello":"world"}',
    agent=True,
    agent_uri=f"https://{DOMAIN}",
    components=None,
    **params,
) -> dict:
    headers = {"authorization": "Bearer application-token"}
    covered = ['"@authority"']
    message = {
        "method": "POST",
        "url": "https://api.example/v1/items?limit=10",
        "headers": headers,
    }
    if body is not None:
        message["bodyBase64"] = base64.b64encode(body).decode()
        headers["content-digest"] = digest(body)
        covered.append('"content-digest"')
    if agent:
        headers["signature-agent"] = f'{label}="{agent_uri}";type=directory'
        covered.append('"signature-agent";key="' + label + '"')
    return sign(
        message,
        message,
        components if components is not None else covered,
        label=label,
        **params,
    )


def corrupt_signature(fixture: dict) -> dict:
    result = copy.deepcopy(fixture)
    label = result.get("label", "sig1")
    raw = bytearray(
        base64.b64decode(result["message"]["headers"]["signature"].split(":")[1])
    )
    raw[0] ^= 1
    result["message"]["headers"]["signature"] = (
        label + "=:" + base64.b64encode(raw).decode() + ":"
    )
    result["signatureValid"] = False
    return result


def build_vectors() -> dict:
    request = {
        "method": "POST",
        "url": "https://api.example/v1/items?limit=10",
        "headers": {},
        "bodyBase64": base64.b64encode(b"\x00\xffbinary\n").decode(),
    }
    get = {
        "method": "GET",
        "url": "https://api.example/v1/items?limit=10",
        "headers": {},
    }
    directory_request = {
        "method": "GET",
        "url": f"https://{DOMAIN}/.well-known/http-message-signatures-directory",
        "headers": {},
    }
    requests = {
        "valid": request_fixture(),
        "non-default-label": request_fixture(label="bot7"),
        "no-agent": request_fixture(agent=False),
        "empty-body": request_fixture(body=b""),
        "operation-bound": request_fixture(
            components=[
                '"@authority"',
                '"content-digest"',
                '"signature-agent";key="sig1"',
                '"@method"',
                '"@target-uri"',
            ]
        ),
        "missing-authority": request_fixture(
            components=['"content-digest"', '"signature-agent";key="sig1"']
        ),
        "uncovered-agent": request_fixture(
            components=['"@authority"', '"content-digest"']
        ),
        "uncovered-body": request_fixture(
            components=['"@authority"', '"signature-agent";key="sig1"']
        ),
        "wrong-tag": request_fixture(tag="http-message-signatures-directory"),
        "wrong-algorithm": request_fixture(alg="EdDSA"),
        "domain-keyid": request_fixture(keyid=DOMAIN + "#fixture-ku"),
        "wrong-thumbprint": request_fixture(keyid=b64url(bytes(32))),
        "expired": request_fixture(created=NOW - 100, expires=NOW - 40),
        "future": request_fixture(created=NOW + 60, expires=NOW + 120),
        "future-within-skew": request_fixture(created=NOW + 1, expires=NOW + 61),
        "excessive-lifetime": request_fixture(expires=NOW + 301),
        "inverted-times": request_fixture(created=NOW + 1, expires=NOW),
        "empty-nonce": request_fixture(nonce=""),
        "missing-created": request_fixture(created=None),
        "missing-expires": request_fixture(expires=None),
    }
    for name, query in (
        ("query-form-encoding", "q=~*"),
        ("query-plus-space", "q=x+y"),
        ("query-percent-space", "q=x%20y"),
        ("query-empty", "q="),
    ):
        message = copy.deepcopy(requests["valid"]["message"])
        message["url"] = "https://api.example/v1/items?" + query
        requests[name] = sign(message, message, [
            '"@authority"', '"content-digest"', '"signature-agent";key="sig1"',
            '"@query-param";name="q"',
        ])
    for name, uri in (
        ("directory-path", f"https://{DOMAIN}/custom"),
        ("directory-query", f"https://{DOMAIN}?keys=1"),
        ("directory-fragment", f"https://{DOMAIN}#keys"),
    ):
        requests[name] = request_fixture(agent_uri=uri)
    requests["relabeled"] = copy.deepcopy(requests["valid"])
    headers = requests["relabeled"]["message"]["headers"]
    for field in ("signature-input", "signature"):
        headers[field] = headers[field].replace("sig1=", "bot7=", 1)
    requests["relabeled"]["label"] = "bot7"
    message = request_fixture(body=None)["message"]
    message["headers"]["content-digest"] = "sha-256=:YWJj:"
    requests["keyed-digest-without-content"] = sign(
        message,
        message,
        [
            '"@authority"',
            '"content-digest";key="sha-256"',
            '"signature-agent";key="sig1"',
        ],
    )
    requests["keyed-digest-without-content"]["digestValid"] = False
    requests["bad-signature"] = corrupt_signature(requests["valid"])
    requests["missing-signature"] = copy.deepcopy(requests["valid"])
    requests["missing-signature"]["message"]["headers"]["signature"] = ""
    requests["missing-signature"]["signatureValid"] = False
    requests["ambiguous-signatures"] = copy.deepcopy(requests["valid"])
    for field in ("signature-input", "signature"):
        original = requests["valid"]["message"]["headers"][field]
        requests["ambiguous-signatures"]["message"]["headers"][field] += (
            ", " + original.replace("sig1=", "bot7=", 1)
        )
    requests["tampered-body"] = copy.deepcopy(requests["valid"])
    requests["tampered-body"]["message"]["bodyBase64"] = base64.b64encode(
        b"modified body"
    ).decode()
    requests["tampered-body"]["digestValid"] = False
    requests["changed-bound-query"] = copy.deepcopy(requests["operation-bound"])
    requests["changed-bound-query"]["message"]["url"] = (
        "https://api.example/v1/items?limit=100"
    )
    requests["changed-bound-query"]["signatureBase"] = signature_base(
        requests["changed-bound-query"]["message"],
        requests["changed-bound-query"]["message"],
    ).decode()
    requests["changed-bound-query"]["signatureValid"] = False
    requests["authority-only-other-operation"] = copy.deepcopy(requests["valid"])
    requests["authority-only-other-operation"]["message"].update(
        method="DELETE", url="https://api.example/other?limit=100"
    )

    directory_components = [
        '"@authority";req',
        '"content-type"',
        '"cache-control"',
        '"content-digest"',
    ]
    directory_key = {**PUBLIC, "kid": THUMB, "alg": "ed25519", "use": "sig"}

    def directory_fixture(
        *, keys=None, components=None, cache_age=300, headers=None, **params
    ):
        body = json.dumps(
            {"keys": keys or [directory_key]}, separators=(",", ":")
        ).encode()
        message = {
            "status": 200,
            "headers": {
                "content-type": DIRECTORY_TYPE,
                "cache-control": f"max-age={cache_age}",
                "content-digest": digest(body),
                **(headers or {}),
            },
            "bodyBase64": base64.b64encode(body).decode(),
        }
        return sign(
            message,
            directory_request,
            components if components is not None else directory_components,
            **{
                "tag": "http-message-signatures-directory",
                "expires": NOW + 300,
                **params,
            },
        )

    directories = {
        "valid": directory_fixture(),
        "http-age-stale": directory_fixture(headers={"age": "300"}),
        "http-age-fresh": directory_fixture(headers={"age": "1"}),
        "http-date-stale": directory_fixture(
            cache_age=60, headers={"date": formatdate(NOW - 61, usegmt=True)}
        ),
        "http-zero-age-stale": directory_fixture(cache_age=0, headers={"age": "1"}),
        "wrong-jwk-kid": directory_fixture(
            keys=[{**directory_key, "kid": "incorrect"}]
        ),
        "private-jwk": directory_fixture(keys=[{**directory_key, "d": b64url(SEED)}]),
        "missing-coverage": directory_fixture(
            components=['"@authority";req', '"content-type"', '"content-digest"']
        ),
        "expired": directory_fixture(created=NOW - 400, expires=NOW - 100),
        "future-within-skew": directory_fixture(created=NOW + 1, expires=NOW + 301),
        "short-cache": directory_fixture(
            cache_age=60, created=NOW - 61, expires=NOW + 239
        ),
    }
    for name, policy in (
        ("no-store", "no-store, max-age=0"),
        ("no-cache", "no-cache"),
        ("zero-max-age", "max-age=0"),
    ):
        directories[name] = directory_fixture(headers={"cache-control": policy})
    directories["status-covered"] = directory_fixture(
        components=[*directory_components, '"@status"']
    )
    directories["coded"] = directory_fixture(headers={"content-encoding": "gzip"})
    for name, operations in (
        ("verify-only", ["verify"]),
        ("sign-verify", ["sign", "verify"]),
        ("empty", []),
        ("sign-only", ["sign"]),
        ("encryption-only", ["encrypt"]),
        ("duplicate", ["verify", "verify"]),
        ("non-string", ["verify", 1]),
        ("not-array", "verify"),
    ):
        directories["key-ops-" + name] = directory_fixture(
            keys=[{**directory_key, "key_ops": operations}]
        )
    for name, metadata in (
        ("wrong-use", {"use": "enc"}),
        ("wrong-alg", {"alg": "EdDSA"}),
        ("omitted-metadata", {}),
    ):
        key = {
            name: value
            for name, value in directory_key.items()
            if name not in {"use", "alg"}
        }
        directories[name] = directory_fixture(keys=[{**key, **metadata}])
    other_public = {
        **PUBLIC,
        "x": b64url(
            Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
            .public_key()
            .public_bytes_raw()
        ),
    }
    other_directory_key = {
        **other_public,
        "kid": thumbprint(other_public),
        "alg": "ed25519",
        "use": "sig",
    }
    directories["distinct-key-candidates"] = directory_fixture(
        keys=[directory_key, other_directory_key]
    )
    other = sign(
        copy.deepcopy(directories["distinct-key-candidates"]["message"]),
        directory_request,
        directory_components,
        label="bot7",
        keyid=other_directory_key["kid"],
        tag="http-message-signatures-directory",
        expires=NOW + 300,
    )
    for field in ("signature-input", "signature"):
        directories["distinct-key-candidates"]["message"]["headers"][field] += (
            ", " + other["message"]["headers"][field]
        )
    directories["bad-signature"] = corrupt_signature(directories["valid"])
    for collection in (requests, directories):
        fixture = copy.deepcopy(collection["valid"])
        for field in ("signature-input", "signature"):
            fixture["message"]["headers"][field] += ", " + collection["bad-signature"][
                "message"
            ]["headers"][field].replace("sig1=", "bot7=", 1)
        collection["valid-plus-invalid"] = fixture
    directories["tampered-body"] = copy.deepcopy(directories["valid"])
    directories["tampered-body"]["message"]["bodyBase64"] = (
        base64.b64decode(directories["valid"]["message"]["bodyBase64"]) + b" "
    )
    directories["tampered-body"]["message"]["bodyBase64"] = base64.b64encode(
        directories["tampered-body"]["message"]["bodyBase64"]
    ).decode()
    directories["tampered-body"]["digestValid"] = False

    signing = []

    def signing_case(
        name,
        operation="request",
        message=request,
        *,
        accepted=True,
        config=None,
        options=None,
        mutation=None,
        signing_key_change=None,
        local_ku="",
    ):
        signing.append(
            {
                "id": "wba-sign-" + name,
                "description": name.replace("-", " "),
                "spec_ref": REF,
                "input": {
                    "operation": operation,
                    "request": copy.deepcopy(message),
                    "webBotAuth": config or {},
                    "options": options or {},
                    **({"configMutation": mutation} if mutation else {}),
                    **({"signingKeyChange": signing_key_change} if signing_key_change else {}),
                    **({"localKu": local_ku} if local_ku else {}),
                },
                "expect": {"ok": True}
                if accepted
                else {"ok": False, "error": "ArgumentError"},
            }
        )

    signing_case(
        "configuration-snapshot-discovery",
        config={"signatureAgent": {"uri": f"https://{DOMAIN}", "type": "directory"}},
        mutation={"signatureAgent": {"uri": "https://other.example"}},
    )
    signing_case("default-get", message=get)
    signing_case("binary-body")
    signing_case("empty-supplied-body", message={**request, "bodyBase64": ""})
    for scheme in ("Basic existing-credentials", "Bearer application-token"):
        signing_case(
            "preserve-" + scheme.split()[0].lower(),
            message={**request, "headers": {"authorization": scheme}},
        )
    signing_case(
        "optional-operation-binding",
        options={"additionalComponents": ["@method", "@target-uri"]},
    )
    signing_case(
        "direct-jwks-uri",
        config={
            "signatureAgent": {
                "uri": "https://agent.example/custom/keys",
                "type": "jwks_uri",
            }
        },
    )
    for operation, message in (("request", get), ("directory", directory_request)):
        signing_case(
            "key-change-during-" + operation, operation=operation, message=message,
            signing_key_change=NEXT_KEY,
        )
    signing_case(
        "reject-local-ku-empty-path", accepted=False,
        config={"signatureAgent": {"uri": f"https://{DOMAIN}/", "type": "jwks_uri"}},
        local_ku=f"https://{DOMAIN}",
    )
    signing_case(
        "separate-local-ku",
        config={"signatureAgent": {"uri": f"https://{DOMAIN}/directory", "type": "jwks_uri"}},
        local_ku=f"https://{DOMAIN}/ku",
    )
    signing_case("directory", operation="directory", message=directory_request)
    signing_case(
        "short-directory-ttl",
        operation="directory",
        message=directory_request,
        config={"directorySignatureTTL": 60},
    )
    for ttl in (-1, 301):
        signing_case(f"reject-request-ttl-{ttl}", accepted=False, options={"ttl": ttl})
        signing_case(
            f"reject-directory-ttl-{ttl}",
            operation="directory",
            message=directory_request,
            accepted=False,
            config={"directorySignatureTTL": ttl},
        )
    signing_case(
        "reject-http-discovery",
        accepted=False,
        config={"signatureAgent": {"uri": "http://agent.example", "type": "directory"}},
    )
    for name, uri in (
        ("path", f"https://{DOMAIN}/custom"),
        ("query", f"https://{DOMAIN}?keys=1"),
        ("fragment", f"https://{DOMAIN}#keys"),
    ):
        signing_case(
            "reject-directory-" + name,
            accepted=False,
            config={"signatureAgent": {"uri": uri, "type": "directory"}},
        )
    signing_case(
        "reject-discovery-type",
        accepted=False,
        config={
            "signatureAgent": {"uri": "https://agent.example", "type": "unsupported"}
        },
    )

    verification = []

    def verify_case(
        name,
        *,
        req="valid",
        directory="valid",
        accepted=False,
        policy=None,
        reason="",
        error="ConformanceError",
        transient=None,
    ):
        verification.append(
            {
                "id": "wba-verify-" + name,
                "description": reason or name.replace("-", " "),
                "spec_ref": REF,
                "input": {
                    "request": req,
                    "directory": directory,
                    "verification": policy or {},
                },
                "expect": {"ok": True, "signerDomain": DOMAIN}
                if accepted
                else {
                    "ok": False,
                    "error": error,
                    **({"transient": transient} if transient is not None else {}),
                },
            }
        )

        if accepted and (policy or {}).get("cacheHit"):
            verification[-1]["uncachedExpect"] = {
                "ok": True,
                "signerDomain": DOMAIN,
                "discoveryRequests": 2,
            }

    verify_case("valid", accepted=True)
    verify_case("non-default-label", req="non-default-label", accepted=True)
    verify_case("empty-supplied-body", req="empty-body", accepted=True)
    verify_case("relabeled", req="relabeled", accepted=True)
    verify_case("future-within-skew", req="future-within-skew", accepted=True)
    verify_case(
        "missing-signature-agent",
        req="no-agent",
        reason="Trusted caller discovery does not make Signature-Agent optional.",
    )
    verify_case("optional-operation-binding", req="operation-bound", accepted=True)
    for name in ("query-form-encoding", "query-plus-space", "query-percent-space", "query-empty"):
        verify_case(name, req=name, accepted=True)
    verify_case(
        "authority-only-other-operation",
        req="authority-only-other-operation",
        accepted=True,
        reason="Current authority-only policy does not bind method, path, or query.",
    )
    for name in (
        "bad-signature",
        "keyed-digest-without-content",
        "valid-plus-invalid",
        "missing-signature",
        "ambiguous-signatures",
        "missing-created",
        "missing-expires",
        "tampered-body",
        "missing-authority",
        "uncovered-agent",
        "directory-path",
        "directory-query",
        "directory-fragment",
        "uncovered-body",
        "wrong-tag",
        "wrong-algorithm",
        "domain-keyid",
        "wrong-thumbprint",
        "expired",
        "future",
        "excessive-lifetime",
        "inverted-times",
        "changed-bound-query",
    ):
        verify_case(name, req=name)
    accepted_directories = {
        "http-age-fresh",
        "no-store",
        "no-cache",
        "zero-max-age",
        "status-covered",
        "key-ops-verify-only",
        "key-ops-sign-verify",
        "omitted-metadata",
        "distinct-key-candidates",
    }
    for name in directories:
        if name not in {"valid", "short-cache"}:
            verify_case(
                "directory-" + name,
                directory=name,
                accepted=name in accepted_directories,
            )
    verify_case(
        "required-operation-coverage",
        policy={"requiredComponents": ["@method", "@target-uri"]},
    )
    verify_case(
        "required-operation-coverage-present",
        req="operation-bound",
        accepted=True,
        policy={"requiredComponents": ["@method", "@target-uri"]},
    )
    verify_case(
        "required-coverage-exact-parameters",
        policy={"requiredComponents": ["signature-agent"]},
    )
    verify_case(
        "response-only-required-coverage",
        policy={"requiredComponents": ["@status"]},
        error="ArgumentError",
    )
    verify_case(
        "malformed-required-coverage",
        policy={"requiredComponents": ["@unknown"]},
        error="ArgumentError",
    )
    verify_case(
        "configuration-snapshot",
        req="expired",
        policy={"configMutation": {"clockSkew": 86400}},
    )
    verify_case("zero-dns-ttl", accepted=True, policy={"dnsTTL": 0})
    verify_case(
        "zero-dns-ttl-next-invocation",
        accepted=True,
        policy={"dnsTTL": 0, "cacheHit": True},
    )
    verify_case("directory-503", policy={"directoryStatus": 503}, transient=True)
    verify_case(
        "directory-timeout",
        policy={"directoryTimeout": True, "timeoutMs": 500},
        transient=True,
    )
    verification[-1]["expect"]["discoveryRequests"] = 1
    for case in verification:
        if case["id"] in {
            "wba-verify-missing-signature-agent",
            "wba-verify-uncovered-agent",
            "wba-verify-directory-path",
            "wba-verify-directory-query",
            "wba-verify-directory-fragment",
            "wba-verify-keyed-digest-without-content",
            "wba-verify-required-operation-coverage",
            "wba-verify-malformed-required-coverage",
            "wba-verify-response-only-required-coverage",
            "wba-verify-required-coverage-exact-parameters",
            "wba-verify-configuration-snapshot",
        }:
            case["expect"]["discoveryRequests"] = 0
    verify_case("directory-only-no-fallback", policy={"dnsidExists": False})
    verify_case(
        "acceptance-denied-no-fallback",
        policy={"acceptanceAllowed": False},
        transient=False,
    )
    verify_case("cache-hit-valid", accepted=True, policy={"cacheHit": True})
    verify_case(
        "cache-hit-acceptance-denied",
        policy={"cacheHit": True, "acceptanceAllowed": False},
    )
    other_key = (
        Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
        .public_key()
        .public_bytes_raw()
    )
    verify_case(
        "auxiliary-non-signing-key",
        policy={
            "currentKu": [
                {**PUBLIC, "x": b64url(other_key)},
                {**PUBLIC, "kid": "auxiliary", "use": "enc"},
            ]
        },
    )
    verify_case(
        "cache-hit-key-rotation",
        policy={"cacheHit": True, "currentKu": [{**PUBLIC, "x": b64url(other_key)}]},
    )
    verify_case(
        "cache-hit-http-stale",
        directory="short-cache",
        policy={"cacheHit": True, "cachedAt": NOW - 61},
    )
    verification[-1]["uncachedExpect"] = {
        "ok": True,
        "signerDomain": DOMAIN,
        "discoveryRequests": 2,
    }
    verify_case(
        "private-discovery-address",
        policy={"resolvedAddresses": ["127.0.0.1"]},
        transient=False,
    )
    verify_case(
        "private-redirect-address",
        transient=False,
        policy={
            "redirects": [
                {
                    "url": "https://agent.example/next",
                    "resolvedAddresses": ["169.254.169.254"],
                }
            ]
        },
    )
    verify_case(
        "same-host-public-redirect",
        policy={
            "timeoutMs": 500,
            "redirects": [
                {
                    "url": f"https://{DOMAIN}/next",
                    "resolvedAddresses": ["93.184.216.34"],
                }
            ],
        },
    )
    verification[-1]["expect"]["discoveryRequests"] = 1
    verify_case("invalid-web-pki", policy={"directoryTlsValid": False}, transient=False)
    verify_case(
        "mtls-missing-current-peer",
        policy={"requiresMtls": True, "peerCertificate": None},
    )
    verify_case("nonce-first-use", accepted=True, policy={"replayEnabled": True})
    verify_case("nonce-reused", policy={"replayEnabled": True, "nonceSeen": True})
    verify_case(
        "nonce-store-failure",
        policy={"replayEnabled": True, "replayStoreAvailable": False},
    )
    verify_case("nonce-missing", req="empty-nonce", policy={"replayEnabled": True})
    verify_case("expires-during-discovery", policy={"finishedAt": NOW + 66})
    return {
        "schemaVersion": 1,
        "drafts": ["draft-ietf-webbotauth-httpsig-protocol-00"],
        "domain": DOMAIN,
        "key": KEY,
        "directoryRequest": directory_request,
        "verificationDefaults": {
            "now": NOW,
            "finishedAt": NOW,
            "clockSkew": 5,
            "signerDomain": DOMAIN,
            "trustedDiscoveryUri": "https://agent.example",
            "dnsidExists": True,
            "acceptanceAllowed": True,
            "currentKu": [PUBLIC],
            "cacheHit": False,
            "cachedAt": NOW,
            "resolvedAddresses": ["93.184.216.34"],
            "redirects": [],
            "directoryTlsValid": True,
            "requiresMtls": False,
            "peerCertificate": None,
            "replayEnabled": False,
            "nonceSeen": False,
            "replayStoreAvailable": True,
        },
        "requests": requests,
        "directories": directories,
        "signingCases": signing,
        "verificationCases": verification,
    }


def tls_fixture_files() -> dict:
    """Disposable deterministic TLS credentials for the native transport adapters."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(PRIVATE.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2100, 1, 1, tzinfo=timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(DOMAIN)]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(PRIVATE, algorithm=None)
    )
    directory = VECTOR_PATH.parents[3] / "shims/testdata"
    return {
        directory / "wba-cert.pem": cert.public_bytes(serialization.Encoding.PEM),
        directory / "wba-key.pem": PRIVATE.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    vectors = build_vectors()
    check_golden_vectors(vectors)
    text = json.dumps(vectors, indent=2) + "\n"
    for path, content in tls_fixture_files().items():
        if args.check:
            if not path.exists() or path.read_bytes() != content:
                raise SystemExit(f"TLS fixture is stale: {path}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    if args.check:
        if VECTOR_PATH.read_text() != text:
            raise SystemExit(
                "WBA fixture is stale; run harness/generate_wba_fixtures.py"
            )
        print("WBA fixture reproducibility and cryptographic checks passed.")
    else:
        VECTOR_PATH.write_text(text)
        print(f"Wrote {VECTOR_PATH}")


if __name__ == "__main__":
    main()
