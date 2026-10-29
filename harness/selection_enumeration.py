"""Every C2SP candidate history of one to three entries over a seven-candidate alphabet (399 cases).

Port of the dnsid-formal `candidate_selection` probe, which found the Go
pre-genesis MIGRATION defect. Evidence reuses the signed logical-v1 fixtures and
is rebuilt in memory (deterministic Ed25519), so no large fixture is committed.
Expectations come from `expect()`, which restates the curated cases in
c2sp-lifecycle-selection.json, not from SDK output.
"""

from __future__ import annotations

import hashlib
import itertools
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from c2sp_event_identity_check import b64, canonical, event_id, payload, unb64
from generate_c2sp_fixtures import OUTPUT, SEEDS, edsign, package_case

TEMPLATE = "unauthenticated-migration-before-genesis-is-ignored"


def _alphabet():
    cases = json.loads(OUTPUT.read_text())["cases"]

    def pick(case, index):
        return json.loads(unb64(cases[case]["entries"][index]["entry"]))

    issuance = pick("byte-identical-complete-entry-is-applied-once", 0)
    rotation = pick("byte-identical-complete-entry-is-applied-once", 2)
    # A second fully signed rotation from the same predecessor, to a different key.
    public = Ed25519PrivateKey.from_private_bytes(bytes([SEEDS["operational-9"]]) * 32).public_key()
    key = {"alg": "EdDSA", "crv": "Ed25519", "kid": "operational-9", "kty": "OKP",
           "x": b64(public.public_bytes(Encoding.Raw, PublicFormat.Raw))}
    fork = dict(rotation, new_ku=key, new_thumb=b64(hashlib.sha256(canonical({k: key[k] for k in ("crv", "kty", "x")})).digest()))
    fork["sigs"] = {role: {"kid": kid, "sig": b64(edsign(SEEDS[kid], canonical(payload(fork))))}
                    for role, kid in (("prev_op", "operational-1"), ("new_op", "operational-9"))}
    # (name, entry, effect ID, kind, authenticated); kinds I/R/V/M.
    alphabet = [
        ("I", issuance, "issuance-1", "I", True),
        ("R", rotation, "rotation-1", "R", True),
        ("FORK", fork, "rotation-fork-key", "R", True),
        ("V", pick("authenticated-post-terminal-candidate-is-fatal", 1), "revocation-1", "V", True),
        ("bad-R", pick("invalid-rotation-countersignature-is-ignored", 1), "rotation-bad-signature", "R", False),
        ("partial-R", pick("missing-rotation-countersignature-is-ignored", 1), "rotation-partial", "R", False),
        ("forged-M", pick(TEMPLATE, 0), "migration-bad-signature", "M", False),
    ]
    genesis = event_id(issuance)
    for name, entry, _, kind, _ in alphabet:
        assert entry["type"] == {"I": "ISSUANCE", "R": "KEY_ROTATION", "V": "REVOCATION", "M": "MIGRATION"}[kind], name
        assert kind in "IM" or entry["prev_event_id"] == genesis, name
    return cases[TEMPLATE], alphabet


def expect(word):
    """C2SP method section 13 selection for one candidate word.

    Duplicate logical events and unauthenticated candidates are ignored; authenticated
    candidates before genesis that are not genesis are ignored. After genesis, an
    authenticated candidate after a terminal event is TERMINAL_STATE, and one that does
    not extend the last applied event is CHAIN_CONTINUITY. Every R/FORK/V here extends
    genesis. A word with no applied event has no lifecycle and is invalid.
    """
    applied, seen, last, dead = [], set(), None, False
    for index, (_, entry, effect, kind, authenticated) in enumerate(word):
        eid = event_id(entry)
        if eid in seen or not authenticated:
            continue
        if last is None:
            if kind != "I":
                continue
        elif dead:
            return {"valid": False, "failingCandidateIndex": index, "errorCategory": "TERMINAL_STATE"}
        elif kind == "I" or entry["prev_event_id"] != last:
            return {"valid": False, "failingCandidateIndex": index, "errorCategory": "CHAIN_CONTINUITY"}
        seen.add(eid)
        last, dead = eid, kind == "V"
        applied.append((index, effect))
    if not applied:
        return {"valid": False}
    out = {"valid": True, "appliedEffectIds": [e for _, e in applied],
           "ignoredCandidateIndexes": [i for i in range(len(word)) if i not in {j for j, _ in applied}]}
    if dead:
        out["identityState"] = "REVOKED"
    return out


def load_cases():
    template, alphabet = _alphabet()
    cases = []
    # The empty word is left out: the Go shim needs at least one entry to anchor a checkpoint.
    for length in range(1, 4):
        for word in itertools.product(alphabet, repeat=length):
            names = [c[0] for c in word]
            case = package_case(template, [(canonical(c[1]), c[2], True) for c in word])
            cases.append({"id": "enum-" + "-".join(names), "description": " ".join(names),
                          "evidence": case, "expected": expect(word)})
    assert len(cases) == 399
    return cases


def _self_check():
    _, a = _alphabet()
    I, R, FORK, V, badR, _, M = a
    assert expect([M, I]) == {"valid": True, "appliedEffectIds": ["issuance-1"], "ignoredCandidateIndexes": [0]}
    assert expect([I, R, FORK])["errorCategory"] == "CHAIN_CONTINUITY"
    assert expect([I, V, R]) == {"valid": False, "failingCandidateIndex": 2, "errorCategory": "TERMINAL_STATE"}
    assert expect([I, V, badR])["identityState"] == "REVOKED"
    assert expect([R, I, I])["ignoredCandidateIndexes"] == [0, 2]
    assert expect([R, badR, M]) == {"valid": False}


if __name__ == "__main__":
    _self_check()
    cases = load_cases()
    print(f"{len(cases)} cases, {sum(c['expected']['valid'] for c in cases)} valid")
