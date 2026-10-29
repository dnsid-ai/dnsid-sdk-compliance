"""Signed REVOCATION with a deeply nested unknown extension (port of dnsid-formal `nested_revocations`).

C2SP sections 7-8 allow any JSON value in an unknown signed field. A verifier may have a
finite nesting budget, but a revocation it cannot parse must not leave the identity
ACTIVE: either the revocation is applied or verification fails (`fail_closed_allowed`).
"""

from __future__ import annotations

import json

from c2sp_event_identity_check import b64, canonical, payload, unb64
from generate_c2sp_fixtures import OUTPUT, SEEDS, edsign, package_case

TEMPLATE = "authenticated-post-terminal-candidate-is-fatal"
DEPTHS = (0, 1, 8, 32, 63, 64, 65, 128, 256, 2000, 10000, 20000)
# The SDK reports the identity ACTIVE: the parser hits a recursion limit and the
# revocation is dropped as noise. Thresholds depend on stack size.
KNOWN_BUGS = {
    "py": ("json.loads RecursionError is treated as candidate noise (stream_verifier.py)", 2000),
    "ts": ("parseJsonNoDuplicateMembers rethrows a stack-overflow RangeError as malformed JSON (canonical.ts)", 10000),
}


def load_cases():
    template = json.loads(OUTPUT.read_text())["cases"][TEMPLATE]
    issuance, revocation = (json.loads(unb64(e["entry"])) for e in template["entries"][:2])
    cases = []
    for depth in DEPTHS:
        # Spliced as bytes: canonical() is recursive and cannot encode the deepest values.
        nested = b"[" * depth + b"0" + b"]" * depth
        body = dict(payload(revocation), x="NESTED")
        signed = canonical(body).replace(b'"NESTED"', nested)
        entry = dict(body, sigs={"ae": {"kid": "entity-1", "sig": b64(edsign(SEEDS["entity-1"], signed))}})
        raw = canonical(entry).replace(b'"NESTED"', nested)
        assert len(raw) < 65536
        evidence = package_case(template, [(canonical(issuance), "issuance-1", True), (raw, "revocation-nested", True)])
        bugs = {sdk: {"known_bug": why} for sdk, (why, at) in KNOWN_BUGS.items() if depth >= at}
        cases.append({"id": f"nested-extension-depth-{depth}-revocation", "evidence": evidence, "sdk": bugs,
                      "description": f"REVOCATION with an unknown extension nested {depth} deep",
                      "expected": {"valid": True, "appliedEffectIds": ["issuance-1", "revocation-nested"], "identityState": "REVOKED"},
                      "fail_closed_allowed": True})
    return cases

