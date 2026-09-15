#!/usr/bin/env python3
"""Focused corrected c2sp-tlog hash/signature/chain checks; no SDK imports.

This is not a production parser, C2SP proof verifier, bundle verifier, or
migration verifier. Reduction below assumes included, complete, context-bound
fixture entries. Keys are disposable test keys; signatures use real ES256.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
KEYS = [ec.derive_private_key(n, ec.SECP256R1()) for n in (1, 2, 3)]
LR = "c2sp-tlog:public:https://log.example#Q2hWbW5Ta0x5R0JtM3B0dw"


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical(value):
    # ponytail: printable-ASCII/safe-integer fixtures only; use RFC 8785 for general input.
    def check(item):
        if isinstance(item, dict):
            for key, child in item.items():
                check(key)
                check(child)
        elif isinstance(item, list):
            for child in item:
                check(child)
        elif isinstance(item, str):
            assert all(32 <= ord(c) < 127 for c in item)
        else:
            assert type(item) is int and 0 <= item <= 9007199254740991
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(domain, value):
    separator = b"\0" if domain == "event" else b""  # Keep the existing separator-free state hash.
    return b64(hashlib.sha256(f"dnsid-c2sp-{domain}-v1".encode() + separator + canonical(value)).digest())


def payload(entry):
    return {k: v for k, v in entry.items() if k != "sigs"}


def event_id(entry):
    return digest("event", payload(entry))


def leaf(entry):
    return hashlib.sha256(b"\0" + canonical(entry)).digest()


def jwk(key):
    numbers = key.public_key().public_numbers()
    public = {"kty": "EC", "crv": "P-256", "x": b64(numbers.x.to_bytes(32, "big")),
              "y": b64(numbers.y.to_bytes(32, "big"))}
    return dict(public, alg="ES256", kid=thumb(public))


def thumb(public):
    return b64(hashlib.sha256(canonical({k: public[k] for k in ("crv", "kty", "x", "y")})).digest())


PUBLIC = [jwk(key) for key in KEYS]
BY_THUMB = {thumb(public): public for public in PUBLIC}


def sign(body, roles, *, deterministic=False):
    sigs = {}
    for role, key in roles.items():
        der = key.sign(canonical(body), ec.ECDSA(hashes.SHA256(), deterministic_signing=deterministic))
        r, s = utils.decode_dss_signature(der)
        sigs[role] = {"kid": jwk(key)["kid"], "sig": b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}
    return dict(body, sigs=sigs)


def signatures_valid(entry, roles):
    try:
        if set(entry["sigs"]) != set(roles):
            return False
        for role, public in roles.items():
            signature = entry["sigs"][role]
            if set(signature) != {"kid", "sig"} or signature["kid"] != public["kid"]:
                return False
            raw = unb64(signature["sig"])
            if len(raw) != 64:
                return False
            r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
            key = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64(public["x"]), "big"),
                                               int.from_bytes(unb64(public["y"]), "big"), ec.SECP256R1()).public_key()
            key.verify(utils.encode_dss_signature(r, s), canonical(payload(entry)), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


def flipped(entry, *roles):
    result = copy.deepcopy(entry)
    for role in roles:
        raw = unb64(result["sigs"][role]["sig"])
        s = int.from_bytes(raw[32:], "big")
        result["sigs"][role]["sig"] = b64(raw[:32] + (ORDER - s).to_bytes(32, "big"))
    return result


def reduce(entries):
    """Small fixture model of logical selection, not the complete SDK reducer."""
    seen, last, state = {}, None, None
    for entry in entries:
        body, identity = payload(entry), event_id(entry)
        assert body["v"] == 1 and body["method"] == "c2sp-tlog" and body["lr"] == LR
        if identity in seen:
            assert body == seen[identity][0]
            continue
        predecessor = seen.get(body.get("prev_event_id"))
        authority = predecessor[1] if predecessor else state
        kind = body["type"]
        if kind == "ISSUANCE":
            roles = {"ae": BY_THUMB[authority["entity_thumb"]] if authority else body["ek"], "op": body["ku"]}
        elif authority and kind == "KEY_ROTATION":
            roles = {"prev_op": BY_THUMB[authority["operational_thumb"]], "new_op": body["new_ku"]}
        elif authority and kind == "REVOCATION":
            roles = {"ae": BY_THUMB[authority["entity_thumb"]]}
        else:
            continue
        if not signatures_valid(entry, roles):
            continue
        if state and state["status"] != "ACTIVE":
            raise ValueError("TERMINAL_STATE")
        if state and kind == "ISSUANCE":
            raise ValueError("DUPLICATE_ISSUANCE")
        if "event_id" in body or "prev_index" in body or "prev_leaf_hash" in body:
            raise ValueError("CHAIN_CONTINUITY")
        if not state:
            if kind != "ISSUANCE" or body["seq"] != 0 or any(k in body for k in ("prev_event_id", "prev_state_hash")):
                raise ValueError("CHAIN_CONTINUITY")
            state = {"fqdn": body["fqdn"], "status": "ACTIVE", "entity_thumb": thumb(body["ek"]),
                     "operational_thumb": thumb(body["ku"])}
        else:
            if (body.get("prev_event_id") != last or body.get("seq") != seen[last][0]["seq"] + 1
                    or body.get("prev_state_hash") != digest("state", state)):
                raise ValueError("CHAIN_CONTINUITY")
            state = dict(state)
            if kind == "KEY_ROTATION":
                assert body["prev_thumb"] == state["operational_thumb"]
                assert body["new_thumb"] == thumb(body["new_ku"])
                state["operational_thumb"] = body["new_thumb"]
            elif kind == "REVOCATION":
                assert body["reason"] == "keyCompromise"
                state["status"] = "REVOKED"
        seen[identity] = (body, state)
        last = identity
    if not seen:
        raise ValueError("GENESIS_REQUIRED")
    return list(seen), state


def main():
    fixture = Path(__file__).resolve().parents[1] / "docs/sdk-design/conformance/c2sp-event-identity.json"
    for vector in json.loads(fixture.read_text())["vectors"]:
        assert canonical(vector["value"]).decode() == vector["canonical"]
        assert digest(vector["domain"], vector["value"]) == vector["hash"]
    body = {"v": 1, "kind": "dnsid.lifecycle", "method": "c2sp-tlog", "log_origin": "log.example",
            "lr": LR, "stream_id": LR.split("#")[1], "fqdn": "agent.example", "ts": 1788523200}
    issuance_body = dict(body, type="ISSUANCE", seq=0, gi="example", ek=PUBLIC[0], ku=PUBLIC[1])
    issuance = sign(issuance_body, {"ae": KEYS[0], "op": KEYS[1]})
    _, initial = reduce([issuance])
    rotation_body = dict(body, type="KEY_ROTATION", seq=1, ts=body["ts"] + 1,
                         prev_event_id=event_id(issuance), prev_state_hash=digest("state", initial),
                         prev_thumb=thumb(PUBLIC[1]), new_ku=PUBLIC[2], new_thumb=thumb(PUBLIC[2]))
    rotation = sign(rotation_body, {"prev_op": KEYS[1], "new_op": KEYS[2]})
    _, rotated = reduce([issuance, rotation])
    revocation = sign(dict(body, type="REVOCATION", seq=2, ts=body["ts"] + 2,
                           prev_event_id=event_id(rotation), prev_state_hash=digest("state", rotated),
                           reason="keyCompromise"), {"ae": KEYS[0]})
    expected = reduce([issuance, rotation, revocation])
    checks = 2
    for original, roles, position in ((issuance, ("ae", "op"), 0),
                                       (rotation, ("prev_op", "new_op"), 1), (revocation, ("ae",), 2)):
        for changed_roles in [(role,) for role in roles] + [roles]:
            changed = flipped(original, *changed_roles)
            assert event_id(changed) == event_id(original) and leaf(changed) != leaf(original)
            for before in (True, False):
                entries = [issuance, rotation, revocation]
                entries.insert(position if before else position + 1, changed)
                assert reduce(entries) == expected
                checks += 1
    resigned = sign(issuance_body, {"ae": KEYS[0], "op": KEYS[1]})
    assert reduce([resigned, issuance, rotation, revocation, issuance, flipped(revocation, "ae")]) == expected
    checks += 1
    for original, role, prefix in ((issuance, "op", []), (rotation, "new_op", [issuance])):
        for missing in (True, False):
            invalid = copy.deepcopy(original)
            if missing:
                del invalid["sigs"][role]
            else:
                invalid["sigs"][role]["sig"] = b64(bytes(64))
            entries = prefix + [invalid] + ([issuance] if not prefix else []) + [rotation, revocation, invalid]
            assert reduce(entries) == expected
            checks += 1
    negative = [
        ([issuance, sign(dict(issuance_body, ts=body["ts"] + 3), {"ae": KEYS[0], "op": KEYS[1]})], "DUPLICATE_ISSUANCE"),
        ([issuance, sign(dict(issuance_body, extension="different"), {"ae": KEYS[0], "op": KEYS[1]})], "DUPLICATE_ISSUANCE"),
        ([issuance, rotation, sign(dict(rotation_body, ts=body["ts"] + 4), {"prev_op": KEYS[1], "new_op": KEYS[2]})], "CHAIN_CONTINUITY"),
        ([issuance, rotation, revocation, sign(dict(payload(revocation), ts=body["ts"] + 4), {"ae": KEYS[0]})], "TERMINAL_STATE"),
    ]
    for change in ({"prev_event_id": b64(bytes(32))}, {"prev_state_hash": b64(bytes(32))},
                   {"seq": 4}, {"prev_index": 0}, {"prev_leaf_hash": b64(bytes(32))}):
        negative.append(([issuance, sign(dict(rotation_body, **change), {"prev_op": KEYS[1], "new_op": KEYS[2]})], "CHAIN_CONTINUITY"))
    missing_predecessor = {k: v for k, v in rotation_body.items() if k != "prev_event_id"}
    negative.append(([issuance, sign(missing_predecessor, {"prev_op": KEYS[1], "new_op": KEYS[2]})], "CHAIN_CONTINUITY"))
    for entries, error in negative:
        try:
            reduce(entries)
        except ValueError as exc:
            assert str(exc) == error
        else:
            raise AssertionError(f"expected {error}")
        checks += 1
    print(f"C2SP event identity: {checks} focused checks passed (not SDK/proof/bundle/migration conformance).")


if __name__ == "__main__":
    main()
