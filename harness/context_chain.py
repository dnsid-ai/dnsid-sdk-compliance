"""Signed method context and chain fields on a REVOCATION (port of dnsid-formal `signed_context`/`signed_chain`).

C2SP method sections 5 and 7: an event whose signed context (method, log_origin,
stream_id, lr) or fqdn does not match the selected stream is noise. Section 13.2:
an authenticated candidate with a broken chain (seq, prev_event_id,
prev_state_hash, prohibited index fields) is fatal; the same
payload under an unauthorized key is noise.
"""

from __future__ import annotations

import json

from c2sp_event_identity_check import b64, canonical, event_id, payload, unb64
from generate_c2sp_fixtures import OUTPUT, SEEDS, edsign, package_case

TEMPLATE = "authenticated-post-terminal-candidate-is-fatal"
DROP = object()


def _encode(body):
    # canonical() takes non-negative integers only; splice other literals as bytes.
    raw = {f"RAW{i}": value for i, (k, value) in enumerate(body.items()) if isinstance(value, bytes)}
    text = canonical({k: (f"RAW{i}" if isinstance(v, bytes) else v) for i, (k, v) in enumerate(body.items())})
    for marker, value in raw.items():
        text = text.replace(json.dumps(marker).encode(), value)
    return text


def _entry(body, seed):
    body = {k: v for k, v in body.items() if v is not DROP}
    sigs = {"ae": {"kid": "entity-1", "sig": b64(edsign(seed, _encode(body)))}}
    return _encode(dict(body, sigs=sigs))


def load_cases():
    template = json.loads(OUTPUT.read_text())["cases"][TEMPLATE]
    issuance, revocation = (json.loads(unb64(e["entry"])) for e in template["entries"][:2])
    base = payload(revocation)
    genesis = event_id(issuance)
    noise = {"valid": True, "appliedEffectIds": ["issuance-1"], "ignoredCandidateIndexes": [1]}
    cases = []

    def add(name, body, expected, seed=SEEDS["entity-1"], effect="revocation-1"):
        evidence = package_case(template, [(canonical(issuance), "issuance-1", True), (_entry(body, seed), effect, True)])
        cases.append({"id": name, "evidence": evidence, "expected": expected})

    add("context-honest-revocation", base, {"valid": True, "appliedEffectIds": ["issuance-1", "revocation-1"],
                                            "ignoredCandidateIndexes": [], "identityState": "REVOKED"})
    other = {"method": "other", "log_origin": "other.example", "stream_id": "other-instance",
             "lr": "c2sp-tlog:public:https://log.example#other-instance", "fqdn": "other.example"}
    for field, value in other.items():
        for variant, replacement in (("other", value), ("missing", DROP), ("wrong-type", True)):
            add(f"context-{field}-{variant}-is-noise", dict(base, **{field: replacement}), noise)
    chain = {
        "no-seq": ("seq", DROP), "seq-zero": ("seq", 0), "seq-gap": ("seq", 2), "seq-negative": ("seq", b"-1"),
        "seq-string": ("seq", "1"), "seq-null": ("seq", None),
        "no-prev-id": ("prev_event_id", DROP), "unknown-prev-id": ("prev_event_id", b64(bytes(32))),
        "empty-prev-id": ("prev_event_id", ""), "prev-id-type": ("prev_event_id", True),
        "no-state": ("prev_state_hash", DROP), "wrong-state": ("prev_state_hash", b64(bytes(32))),
        "empty-state": ("prev_state_hash", ""), "state-type": ("prev_state_hash", True),
        "prev-index": ("prev_index", 0), "prev-leaf-hash": ("prev_leaf_hash", genesis),
        "self-event-id": ("event_id", genesis),
    }
    # Left out: a successor `ts` earlier than its predecessor. Go rejects it, TS and Python
    # apply it, and the method only says "never reorder by ts". Needs a spec decision.
    for name, (field, value) in chain.items():
        body = dict(base, **{field: value})
        add(f"chain-{name}-authenticated-is-fatal", body, {"valid": False})
        # Same kid, wrong key: only the signature check can reject it.
        add(f"chain-{name}-unauthenticated-is-noise", body, noise, seed=SEEDS["other-entity"])
    delegation = {k: base[k] for k in ("v", "kind", "method", "log_origin", "lr", "stream_id", "fqdn", "ts", "seq",
                                       "prev_event_id", "prev_state_hash")}
    delegation.update(type="DELEGATION", delegatee="delegate.example", scope="read", expiry=base["ts"] + 3600)
    add("chain-honest-delegation", delegation, {"valid": True, "appliedEffectIds": ["issuance-1", "delegation-1"],
                                                "ignoredCandidateIndexes": []}, effect="delegation-1")
    return cases
