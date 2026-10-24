#!/usr/bin/env python3
"""Generate corrected, disposable C2SP selection and bundle evidence, without SDK imports.

Requires cryptography >= 43. Historical signed inputs stay byte-for-byte intact.
This deliberately handles only these ASCII fixtures (JCS numbers included), not arbitrary logs.
Run with --check to verify deterministic regeneration of the committed output.
"""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

import yaml
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from c2sp_event_identity_check import (
    KEYS, PUBLIC, ORDER, b64, canonical, digest, event_id, flipped, leaf,
    payload, sign, signatures_valid, thumb, unb64,
)

ROOT = Path(__file__).resolve().parents[1]
SEMANTICS = ROOT / "docs/sdk-design/conformance/c2sp-lifecycle-selection.json"
HISTORICAL = ROOT / "fixtures/c2sp-lifecycle-selection-evidence.json"
OUTPUT = ROOT / "fixtures/c2sp-lifecycle-selection-logical-v1.json"
REVISION = "d5a65d06f76eff4db81e50f8767a600d2ca7fc2a"
SEEDS = {"entity-1": 1, "operational-1": 2, "operational-2": 3, "other-entity": 7, "other-op": 8, "operational-9": 9}
# Rotated accountable-entity keys appear only in ENTITY_KEY_ROTATION evidence.
ENTITY_SEEDS = {**SEEDS, "entity-2": 10, "entity-3": 11}


def edsign(seed, data):
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    signature = key.sign(data)
    key.public_key().verify(signature, data)
    return signature


def tree(leaves):
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b"\1" + tree(leaves[:split]) + tree(leaves[split:])).digest()


def audit_path(leaves, index):
    if len(leaves) == 1:
        return []
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < split:
        return audit_path(leaves[:split], index) + [tree(leaves[split:])]
    return audit_path(leaves[split:], index - split) + [tree(leaves[:split])]


def package_case(template, entries):
    result = copy.deepcopy(template)
    leaves = [hashlib.sha256(b"\0" + raw).digest() for raw, _, _ in entries]
    # Preserve the public test log/witness identities and fixture clock.
    text, signatures = template["checkpoint"].split("\n\n")
    log_line, witness_line = signatures.strip().splitlines()
    log_signature = base64.b64decode(log_line.split()[-1])
    witness_signature = base64.b64decode(witness_line.split()[-1])
    timestamp = witness_signature[4:12]
    checkpoint = f"{text.splitlines()[0]}\n{len(entries)}\n".encode() + base64.b64encode(tree(leaves)) + b"\n"
    cosignature = f"cosignature/v1\ntime {int.from_bytes(timestamp, 'big')}\n".encode() + checkpoint
    signed = checkpoint + b"\n"
    signed += ("— log.example " + base64.b64encode(log_signature[:4] + edsign(4, checkpoint)).decode() + "\n").encode()
    signed += ("— witness.example " + base64.b64encode(witness_signature[:4] + timestamp + edsign(5, cosignature)).decode() + "\n").encode()
    result["checkpoint"] = signed.decode()
    if result.get("checkpointAccepted") is False:
        signature = log_signature[:4] + edsign(4, checkpoint)
        invalid = signature[:-1] + bytes([signature[-1] ^ 1])
        result["checkpoint"] = result["checkpoint"].replace(
            base64.b64encode(signature).decode(), base64.b64encode(invalid).decode()
        )
    result["entries"] = []
    for index, (raw, effect, valid_proof) in enumerate(entries):
        proof = f"c2sp.org/tlog-proof@v1\nindex {index}\n".encode()
        proof += b"".join(base64.b64encode(node) + b"\n" for node in audit_path(leaves, index))
        proof += b"\n" + signed
        if not valid_proof:
            proof = b"invalid fixture inclusion proof"
        result["entries"].append(dict(index=index, entry=b64(raw), proof=b64(proof), effectId=effect, proofValid=valid_proof))
    return result


def ed_public(kid):
    raw = Ed25519PrivateKey.from_private_bytes(bytes([ENTITY_SEEDS[kid]]) * 32).public_key()
    return {"alg": "EdDSA", "crv": "Ed25519", "kid": kid, "kty": "OKP",
            "x": b64(raw.public_bytes(Encoding.Raw, PublicFormat.Raw))}


def ed_thumb(public):
    if public["kty"] == "EC":
        return thumb(public)
    return b64(hashlib.sha256(canonical({k: public[k] for k in ("crv", "kty", "x")})).digest())


def record_jwk(label):
    # "entity-es256" is the disposable P-256 key PUBLIC[0]; other labels are Ed25519 seeds.
    return PUBLIC[0] if label == "entity-es256" else ed_public(label)


def es256_signature(key, data):
    # Low-S, like the other original ES256 signatures; high-S is reserved for malleability cases.
    r, s = utils.decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
    s = min(s, ORDER - s)
    return b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def entity_key_rotation_recipes(issuance, rotation):
    """ENTITY_KEY_ROTATION evidence on the Ed25519 issuance; one disposable key per role."""
    context = {k: issuance[k] for k in ("v", "kind", "method", "log_origin", "lr", "stream_id", "fqdn")}
    e1, e2, e3, o1, o2, o9, spam_e, spam_o = map(ed_public, (
        "entity-1", "entity-2", "entity-3", "operational-1", "operational-2", "operational-9", "other-entity", "other-op"))
    assert issuance["ek"] == e1 and issuance["ku"] == o1 and rotation["prev_event_id"] == event_id(issuance)

    def state(entity, operational, status="ACTIVE"):
        return dict(fqdn=context["fqdn"], status=status, entity_thumb=ed_thumb(entity), operational_thumb=ed_thumb(operational))

    def signed(body, roles):
        # roles: wire role -> (embedded kid, disposable key that actually signs)
        data = canonical(body)
        return dict(body, sigs={role: {"kid": kid, "sig": b64(edsign(ENTITY_SEEDS[signer], data))}
                                for role, (kid, signer) in roles.items()})

    def successor(prev, prev_state, ts, **fields):
        return dict(context, seq=prev["seq"] + 1, prev_event_id=event_id(prev),
                    prev_state_hash=digest("state", prev_state), ts=ts, **fields)

    def ekr(prev, prev_state, ts, new, prev_ae, new_ae, *, prev_thumb=None, new_thumb=None):
        body = successor(prev, prev_state, ts, type="ENTITY_KEY_ROTATION",
                         prev_ek_thumb=prev_thumb or prev_state["entity_thumb"],
                         new_ek=new, new_ek_thumb=new_thumb or ed_thumb(new))
        return signed(body, {role: signer for role, signer in (("prev_ae", prev_ae), ("new_ae", new_ae)) if signer})

    E1, E2, E3 = ("entity-1", "entity-1"), ("entity-2", "entity-2"), ("entity-3", "entity-3")
    s0, s1 = state(e1, o1), state(e2, o1)
    ts = 1782173000
    er12 = ekr(issuance, s0, ts, e2, E1, E2)
    er23 = ekr(er12, s1, ts + 100, e3, E2, E3)
    revocation = lambda signer, offset: signed(successor(er12, s1, ts + offset, type="REVOCATION", reason="keyCompromise"), {"ae": signer})
    retirement = signed(successor(issuance, s0, ts - 50, type="RETIREMENT"), {"ae": E1})
    er_after_op = ekr(rotation, state(e1, o2), ts + 10, e2, E1, E2)
    rotation_after = signed(successor(er_after_op, state(e2, o2), ts + 110, type="KEY_ROTATION", prev_thumb=ed_thumb(o2),
                                      new_ku=o9, new_thumb=ed_thumb(o9)),
                            {"prev_op": ("operational-2", "operational-2"), "new_op": ("operational-9", "operational-9")})
    spam = signed(dict(context, type="ISSUANCE", seq=0, ts=1782172700, gi=issuance["gi"], ek=spam_e, ku=spam_o),
                  {"ae": ("other-entity", "other-entity"), "op": ("other-op", "other-op")})
    spam_rotation = ekr(spam, state(spam_e, spam_o), 1782172750, e2, ("other-entity", "other-entity"), ("entity-2", "other-entity"))
    structural = {
        "thumbprint-mismatch": ekr(issuance, s0, ts, e2, E1, E2, new_thumb=ed_thumb(e3)),
        "private-new-key": ekr(issuance, s0, ts, dict(e2, d=b64(bytes([ENTITY_SEEDS["entity-2"]]) * 32)), E1, E2),
        "new-key-without-kid": ekr(issuance, s0, ts, {k: v for k, v in e2.items() if k != "kid"}, E1, E2),
        "new-key-empty-kid": ekr(issuance, s0, ts, dict(e2, kid=""), E1, E2),
        "new-key-without-alg": ekr(issuance, s0, ts, {k: v for k, v in e2.items() if k != "alg"}, E1, E2),
        "unchanged-thumbprint": ekr(issuance, s0, ts, e1, E1, E1),
        "new-signature-kid-mismatch": ekr(issuance, s0, ts, e2, E1, ("entity-3", "entity-2")),
    }
    single = lambda candidate, event: ([("issuance", issuance), (candidate, event)])
    recipes = {
        "entity-key-rotation-binds-record-to-new-key": single("entity-rotation", er12),
        "entity-key-rotation-rejects-record-with-issuance-key": single("entity-rotation", er12),
        "chained-entity-key-rotations-bind-latest-key": [("issuance", issuance), ("entity-rotation", er12), ("entity-rotation-second", er23)],
        "entity-key-rotation-by-wrong-previous-signer-is-ignored": single(
            "entity-rotation-wrong-previous-signer", ekr(issuance, s0, ts, e2, ("entity-1", "other-entity"), E2)),
        "entity-key-rotation-with-invalid-new-signature-is-ignored": single(
            "entity-rotation-invalid-new-signature", ekr(issuance, s0, ts, e2, E1, ("entity-2", "other-entity"))),
        "entity-key-rotation-without-new-signature-is-ignored": single(
            "entity-rotation-missing-new-signature", ekr(issuance, s0, ts, e2, E1, None)),
        "entity-key-rotation-from-inactive-key-is-fatal": single(
            "entity-rotation-inactive-previous-key", ekr(issuance, s0, ts, e2, E1, E2, prev_thumb=ed_thumb(spam_e))),
        "entity-key-rotation-to-operational-key-is-fatal": single(
            "entity-rotation-to-operational-key", ekr(issuance, s0, ts, o1, E1, ("operational-1", "operational-1"))),
        "revocation-by-rotated-entity-key-is-applied": [
            ("issuance", issuance), ("entity-rotation", er12), ("revocation-by-rotated-entity-key", revocation(E2, 200))],
        "revocation-by-superseded-entity-key-is-ignored": [
            ("issuance", issuance), ("entity-rotation", er12), ("revocation-by-superseded-entity-key", revocation(E1, 210))],
        "operational-and-entity-key-rotations-interleave": [
            ("issuance", issuance), ("rotation-before-entity-rotation", rotation),
            ("entity-rotation-after-operational-rotation", er_after_op), ("rotation-after-entity-rotation", rotation_after)],
        "entity-key-rotation-before-genesis-is-ignored": [("entity-rotation", er12), ("issuance", issuance)],
        "entity-key-rotation-without-genesis-has-no-valid-events": [("entity-rotation", er12)],
        "entity-key-rotation-after-retirement-is-fatal": [
            ("issuance", issuance), ("retirement", retirement),
            ("entity-rotation-after-retirement", ekr(retirement, state(e1, o1, "RETIRED"), ts + 50, e2, E1, E2))],
        "spam-genesis-with-other-entity-key-is-ignored": [("spam-issuance", spam), ("issuance", issuance)],
        "spam-genesis-before-rotated-history-is-ignored": [("spam-issuance", spam), ("issuance", issuance), ("entity-rotation", er12)],
        "spam-genesis-cannot-rotate-to-record-key-without-new-signature": [
            ("spam-issuance", spam), ("spam-entity-rotation-to-record-key", spam_rotation), ("issuance", issuance), ("entity-rotation", er12)],
        "spam-genesis-alone-cannot-rotate-to-record-key": [("spam-issuance", spam), ("spam-entity-rotation-to-record-key", spam_rotation)],
    }
    # A spam genesis whose own authenticated successors contradict each other stays noise.
    spam_revocation = signed(successor(spam, state(spam_e, spam_o), 1782172710, type="REVOCATION", reason="keyCompromise"),
                             {"ae": ("other-entity", "other-entity")})
    spam_retirement = signed(successor(spam_revocation, state(spam_e, spam_o, "REVOKED"), 1782172720, type="RETIREMENT"),
                             {"ae": ("other-entity", "other-entity")})
    recipes["spam-genesis-contradiction-does-not-poison-real-history"] = [
        ("spam-issuance", spam), ("spam-revocation", spam_revocation),
        ("spam-post-terminal-retirement", spam_retirement), ("issuance", issuance)]
    rotation_to_entity = signed(successor(er12, s1, ts + 400, type="KEY_ROTATION", prev_thumb=ed_thumb(o1),
                                          new_ku=e2, new_thumb=ed_thumb(e2)),
                                {"prev_op": ("operational-1", "operational-1"), "new_op": E2})
    recipes["key-rotation-to-rotated-entity-key-is-fatal"] = [
        ("issuance", issuance), ("entity-rotation", er12), ("rotation-to-rotated-entity-key", rotation_to_entity)]
    recipes["entity-key-rotation-with-previous-kid-mismatch-is-ignored"] = single(
        "entity-rotation-previous-kid-mismatch", ekr(issuance, s0, ts, e2, ("entity-2", "entity-1"), E2))
    recipes["entity-key-rotation-by-superseded-key-is-ignored"] = [
        ("issuance", issuance), ("entity-rotation", er12),
        ("entity-rotation-by-superseded-key", ekr(er12, s1, ts + 250, e3, E1, E3, prev_thumb=ed_thumb(e1)))]
    recipes["superseded-entity-key-fork-is-fatal"] = [
        ("issuance", issuance), ("entity-rotation", er12), ("superseded-entity-key-fork", ekr(issuance, s0, ts + 300, e3, E1, E3))]
    es_key = PUBLIC[0]
    es_body = successor(issuance, s0, ts + 500, type="ENTITY_KEY_ROTATION", prev_ek_thumb=ed_thumb(e1),
                        new_ek=es_key, new_ek_thumb=ed_thumb(es_key))
    es_data = canonical(es_body)
    es_rotation = dict(es_body, sigs={"prev_ae": {"kid": "entity-1", "sig": b64(edsign(ENTITY_SEEDS["entity-1"], es_data))},
                                      "new_ae": {"kid": es_key["kid"], "sig": es256_signature(KEYS[0], es_data)}})
    assert signatures_valid(dict(es_rotation, sigs={"new_ae": es_rotation["sigs"]["new_ae"]}), {"new_ae": es_key})
    recipes["entity-key-rotation-to-es256-key-binds-record"] = single("entity-rotation-to-es256-key", es_rotation)
    recipes["retirement-by-rotated-entity-key-is-applied"] = [
        ("issuance", issuance), ("entity-rotation", er12),
        ("retirement-by-rotated-entity-key", signed(successor(er12, s1, ts + 600, type="RETIREMENT"), {"ae": E2}))]
    recipes["ignored-entity-key-rotation-does-not-bind-new-key"] = recipes["entity-key-rotation-by-wrong-previous-signer-is-ignored"]
    # Malformed but fully signed by the active and new keys: fatal, not noise.
    for name in ("thumbprint-mismatch", "new-key-without-alg", "unchanged-thumbprint"):
        recipes[f"authenticated-malformed-entity-key-rotation-{name}-is-fatal"] = single(f"entity-rotation-{name}", structural[name])
    # A private new_ek is never a verification key, so the event cannot authenticate.
    recipes["entity-key-rotation-with-private-new-key-is-ignored"] = single("entity-rotation-private-new-key", structural["private-new-key"])
    # Any private member, not only d, makes new_ek unusable as a verification key.
    recipes["entity-key-rotation-with-stray-private-member-is-ignored"] = single(
        "entity-rotation-stray-private-member", ekr(issuance, s0, ts, dict(e2, p=b64(bytes([1]) * 32)), E1, E2))
    # new_ae must name a non-empty kid(new_ek); otherwise the event cannot authenticate.
    for name in ("new-key-without-kid", "new-key-empty-kid", "new-signature-kid-mismatch"):
        recipes[f"entity-key-rotation-{name}-is-ignored"] = single(f"entity-rotation-{name}", structural[name])
    return recipes


def generate_selection():
    old = json.loads(HISTORICAL.read_bytes())
    historical_semantics = (ROOT / "fixtures/historical/c2sp-lifecycle-selection.json").read_bytes()
    assert hashlib.sha256(historical_semantics).hexdigest() == old["semantic_source_sha256"]
    historical_cases = {case["id"]: case for case in json.loads(historical_semantics)["cases"]}
    semantics = SEMANTICS.read_bytes()
    semantic_suite = json.loads(semantics)
    originals = {}
    for case in old["cases"].values():
        for entry in case["entries"]:
            raw = unb64(entry["entry"])
            originals[b64(hashlib.sha256(b"\0" + raw).digest())] = raw
    corrected = {}

    def correct(raw):
        if raw in corrected:
            return corrected[raw]
        try:
            entry = json.loads(raw)
        except (ValueError, UnicodeError):
            return raw
        body = payload(entry)
        if "prev_leaf_hash" in body:
            predecessor = json.loads(correct(originals[body.pop("prev_leaf_hash")]))
            body["prev_event_id"] = event_id(predecessor)
            del body["prev_index"]
        if body["stream_id"] == body["fqdn"]:
            body["stream_id"] = "other-instance"
            body["lr"] = body["lr"].split("#")[0] + "#other-instance"
        signatures = copy.deepcopy(entry["sigs"])
        for signature in signatures.values():
            if signature["sig"] != "AA":
                signature["sig"] = b64(edsign(SEEDS[signature["kid"]], canonical(body)))
        corrected[raw] = canonical(dict(body, sigs=signatures))
        return corrected[raw]

    templates = {}
    recipes = {}
    for name, case in old["cases"].items():
        candidate_ids = [name.replace("issuance-resigned", "issuance-signed-extension") for name in historical_cases[name]["candidates"]]
        if name == "resigned-event-is-not-byte-identical-deduplication":
            name = "signed-extension-is-a-distinct-genesis"
        templates[name] = case
        entries = [(correct(unb64(item["entry"])), item["proofValid"]) for item in case["entries"]]
        recipes[name] = dict(zip(candidate_ids, entries, strict=True))

    template = templates["byte-identical-complete-entry-is-applied-once"]
    issuance = json.loads(recipes["byte-identical-complete-entry-is-applied-once"]["issuance"][0])
    rotation = json.loads(recipes["byte-identical-complete-entry-is-applied-once"]["rotation"][0])

    def add(name, candidate_ids, items, *, es256=False):
        case = copy.deepcopy(template)
        if es256:
            case["entityJwk"], case["operationalJwk"] = PUBLIC[:2]
        templates[name] = case
        recipes[name] = dict(zip(candidate_ids, [(canonical(e), True) for e in items], strict=True))

    for kind in ("invalid", "missing"):
        partial = copy.deepcopy(rotation)
        if kind == "invalid":
            partial["sigs"]["new_op"]["sig"] = "AA"
        else:
            del partial["sigs"]["new_op"]
        add(f"{kind}-rotation-countersignature-is-ignored", ["issuance", "partial-rotation", "rotation"], [issuance, partial, rotation])
    fork = copy.deepcopy(rotation)
    fork["ts"] += 1
    for signature in fork["sigs"].values():
        signature["sig"] = b64(edsign(SEEDS[signature["kid"]], canonical(payload(fork))))
    add("fully-signed-historical-predecessor-fork-is-fatal", ["issuance", "rotation", "historical-fork"], [issuance, rotation, fork])
    fork["sigs"]["new_op"]["sig"] = "AA"
    add("partial-historical-predecessor-fork-is-ignored", ["issuance", "rotation", "partial-rotation"], [issuance, rotation, fork])
    legacy = old["cases"]["byte-identical-complete-entry-is-applied-once"]["entries"][2]
    add("prohibited-index-chain-is-fatal", ["issuance", "prohibited-index-chain"], [issuance, json.loads(unb64(legacy["entry"]))])

    def resign(entry, seeds=SEEDS):
        for signature in entry["sigs"].values():
            if signature["sig"] != "AA":
                signature["sig"] = b64(edsign(seeds[signature["kid"]], canonical(payload(entry))))
        return entry

    # Only ts/seq are integer-restricted; unknown signed extensions may use any JCS number.
    revocation = json.loads(recipes["authenticated-post-terminal-candidate-is-fatal"]["revocation"][0])
    for label, number in (("fractional", 0.5), ("small-exponent", 1e-7), ("large-exponent", 1e21)):
        extended = resign(dict(copy.deepcopy(revocation), dnsid_test_number=number))
        add(f"revocation-with-{label}-number-extension-is-applied", ["issuance", f"revocation-{label}-number"], [issuance, extended])
    # An unauthenticated MIGRATION must not block a later valid genesis.
    forged = json.loads(recipes["verified-inbound-migration-stitches-prior-history"]["inbound-migration"][0])
    forged["sigs"]["ae"]["sig"] = "AA"
    add("unauthenticated-migration-before-genesis-is-ignored", ["bad-signature-migration", "issuance"], [forged, issuance])
    # Two distinct keys under one non-thumbprint kid. Method section 9: kid is a label and
    # roles select keys, so this genesis is valid.
    shared = copy.deepcopy(issuance)
    shared["ek"]["kid"] = shared["ku"]["kid"] = "shared-kid"
    for role, original in (("ae", "entity-1"), ("op", "operational-1")):
        shared["sigs"][role] = {"kid": "shared-kid", "sig": b64(edsign(SEEDS[original], canonical(payload(shared))))}
    add("shared-kid-label-does-not-select-keys", ["shared-kid-issuance"], [shared])

    for name, items in entity_key_rotation_recipes(issuance, rotation).items():
        add(name, [candidate for candidate, _ in items], [event for _, event in items])

    def low_sign(body, roles):
        entry = sign(body, roles, deterministic=True)
        for role in roles:
            raw = unb64(entry["sigs"][role]["sig"])
            if int.from_bytes(raw[32:], "big") > ORDER // 2:
                entry = flipped(entry, role)
        assert signatures_valid(entry, {role: PUBLIC[KEYS.index(key)] for role, key in roles.items()})
        return entry

    body = payload(issuance)
    body.update(ek=PUBLIC[0], ku=PUBLIC[1])
    issuance = low_sign(body, {"ae": KEYS[0], "op": KEYS[1]})
    duplicate = flipped(issuance, "ae", "op")
    assert signatures_valid(duplicate, {"ae": PUBLIC[0], "op": PUBLIC[1]})
    assert event_id(issuance) == event_id(duplicate) and leaf(issuance) != leaf(duplicate)
    state = dict(fqdn=body["fqdn"], status="ACTIVE", entity_thumb=thumb(PUBLIC[0]), operational_thumb=thumb(PUBLIC[1]))
    body = payload(rotation)
    body.update(prev_event_id=event_id(issuance), prev_state_hash=digest("state", state), prev_thumb=thumb(PUBLIC[1]), new_ku=PUBLIC[2], new_thumb=thumb(PUBLIC[2]))
    rotation = low_sign(body, {"prev_op": KEYS[1], "new_op": KEYS[2]})
    add("es256-signature-only-copy-is-applied-once", ["issuance", "issuance-signature-copy", "rotation"], [issuance, duplicate, rotation], es256=True)
    add("es256-high-s-first-copy-is-applied-once", ["issuance-signature-copy", "issuance", "rotation"], [duplicate, issuance, rotation], es256=True)
    state["operational_thumb"] = thumb(PUBLIC[2])
    body = {k: issuance[k] for k in ("v", "kind", "method", "log_origin", "lr", "stream_id", "fqdn")}
    body.update(type="REVOCATION", ts=rotation["ts"]+1, seq=2, reason="keyCompromise", prev_event_id=event_id(rotation), prev_state_hash=digest("state", state))
    revocation = low_sign(body, {"ae": KEYS[0]})
    add("es256-signature-only-replay-after-terminal-is-ignored", ["issuance", "rotation", "revocation", "rotation-signature-copy"], [issuance, rotation, revocation, flipped(rotation, "prev_op", "new_op")], es256=True)

    assert set(templates) == {case["id"] for case in semantic_suite["cases"]}
    cases = dict.fromkeys(templates)
    for semantic_case in semantic_suite["cases"]:
        name = semantic_case["id"]
        template = copy.deepcopy(templates[name])
        template["domain"] = semantic_suite["domain"]
        for field, default in (("checkpointAccepted", True), ("completeThroughCheckpoint", True), ("priorHistoryVerified", None), ("priorAppliedEffectIds", [])):
            template[field] = semantic_case.get(field, default)
        if "recordEk" in semantic_case:
            # The TXT record's ek; absent means the record still carries the ISSUANCE entity key (entityJwk).
            template["recordEntityJwk"] = record_jwk(semantic_case["recordEk"])
            expected_binding = semantic_case["expected"].get("bilateralBinding")
            if expected_binding:
                assert expected_binding["currentEntityThumbprint"] == ed_thumb(template["recordEntityJwk"]), name
        entries = []
        for candidate_id in semantic_case["candidates"]:
            if candidate_id not in recipes[name]:
                raise ValueError(f"{name}: no evidence recipe for {candidate_id}")
            raw, valid_proof = recipes[name][candidate_id]
            definition = semantic_suite["candidateFixtures"][candidate_id]
            if "type" in definition:
                event = json.loads(raw)
                if event["type"] != definition["type"] or event["fqdn"] != definition["domain"]:
                    raise ValueError(f"{name}: evidence does not match {candidate_id}")
            entries.append((raw, definition["effectId"], valid_proof))
        cases[name] = package_case(template, entries)
    return json.dumps(dict(format=old["format"], method_revision=REVISION,
                           generator="harness/generate_c2sp_fixtures.py; public disposable keys only",
                           semantic_source_sha256=hashlib.sha256(semantics).hexdigest(), cases=cases), indent=2) + "\n"


def generate_bundle():
    vector = json.loads((ROOT / "fixtures/c2sp-stream-bundle-v1.json").read_bytes())
    bundle = json.loads(vector["bundle"])
    issuance, rotation = [json.loads(unb64(item["entry"])) for item in bundle["events"]]
    del rotation["prev_index"], rotation["prev_leaf_hash"]
    rotation["prev_event_id"] = event_id(issuance)
    for signature in rotation["sigs"].values():
        signature["sig"] = b64(edsign(SEEDS[signature["kid"]], canonical(payload(rotation))))
    entries = [canonical(issuance), canonical(rotation)]
    packaged = package_case({"checkpoint": unb64(bundle["checkpoint"]).decode()}, [(entry, "unused", True) for entry in entries])
    bundle["checkpoint"] = b64(packaged["checkpoint"].encode())
    leaves = [leaf(issuance), leaf(rotation)]
    bundle["events"] = [dict(index=i, entry=b64(entry), proof=b64(b"".join(audit_path(leaves, i)))) for i, entry in enumerate(entries)]
    unsigned = {k: v for k, v in bundle.items() if k != "sig"}
    bundle["sig"]["value"] = b64(edsign(6, canonical(unsigned)))
    vector["bundle"] = canonical(bundle).decode()
    vector["unsigned_bundle"] = canonical(unsigned).decode()
    vector["method_revision"] = REVISION
    vector["source"] = "harness/generate_c2sp_fixtures.py; public disposable keys only"
    corpus = json.loads((ROOT / "fixtures/c2sp-generation-v1.json").read_bytes())
    del corpus["events"]["rotation"]["previous_index"]
    corpus["golden_bundle"] = "c2sp-stream-bundle-logical-v1.json"
    corpus["method_revision"] = REVISION
    return {
        ROOT / "fixtures/c2sp-stream-bundle-logical-v1.json": json.dumps(vector, indent=2) + "\n",
        ROOT / "fixtures/c2sp-generation-logical-v1.json": json.dumps(corpus, indent=2) + "\n",
    }


def generate_checkpoints():
    """Signed continuity cases; expectations come from design 11, not SDK output."""
    vector = json.loads(generate_bundle()[ROOT / "fixtures/c2sp-stream-bundle-logical-v1.json"])
    original = json.loads(vector["bundle"])
    entries = [unb64(item["entry"]) for item in original["events"]]
    alternate = json.loads(entries[0])
    alternate["ts"] -= 1
    for signature in alternate["sigs"].values():
        signature["sig"] = b64(edsign(SEEDS[signature["kid"]], canonical(payload(alternate))))

    def history(raw_entries):
        packaged = package_case(
            {"checkpoint": unb64(original["checkpoint"]).decode()},
            [(entry, "unused", True) for entry in raw_entries],
        )
        leaves = [hashlib.sha256(b"\0" + entry).digest() for entry in raw_entries]
        bundle = copy.deepcopy(original)
        bundle["checkpoint"] = b64(packaged["checkpoint"].encode())
        bundle["complete_through_size"] = len(raw_entries)
        bundle["events"] = [dict(index=i, entry=b64(entry), proof=b64(b"".join(audit_path(leaves, i)))) for i, entry in enumerate(raw_entries)]
        bundle["state"].update(event_count=len(raw_entries), last_event_type=json.loads(raw_entries[-1])["type"])
        unsigned = {k: v for k, v in bundle.items() if k != "sig"}
        bundle["sig"]["value"] = b64(edsign(6, canonical(unsigned)))
        proven = [dict(index=item["index"], entry=item["entry"], proof=item["proof"]) for item in packaged["entries"]]
        return dict(checkpoint=packaged["checkpoint"], entries=proven, bundle=canonical(bundle).decode())

    first, grown, other = history(entries[:1]), history(entries), history([canonical(alternate)])
    common = dict(policy=vector["policy"], entityJwk=vector["trust"]["entity_jwk"],
                  bundleVerifierKey=vector["trust"]["bundle_verifier_key"], now=vector["trust"]["now"],
                  lr=original["lr"], domain=original["fqdn"])

    def state(evidence):
        text, signatures = evidence["checkpoint"].split("\n\n")
        origin, size, root = text.splitlines()
        witness = base64.b64decode(signatures.strip().splitlines()[1].split()[-1])
        return dict(origin=origin, treeSize=int(size), rootHash=b64(base64.b64decode(root)),
                    witnessTime=int.from_bytes(witness[4:12], "big"))

    cases = []

    def add(name, trusted, candidate, *, mode="scan", category=None, fault=None, scan=None, proof=None):
        request = dict(common, trusted=trusted, candidate=candidate, mode=mode,
                       scanEntries=candidate["entries"] if scan is None else scan, proof=proof or [])
        if fault:
            request["fault"] = fault
        rejected = bool(category or fault or mode == "missing")
        retained = trusted if rejected else candidate
        expected = dict(ok=not rejected, stored=state(retained) if retained is not None else None)
        if rejected:
            expected["error"] = "CheckpointError"
            expected["transient"] = fault == "proof-fetch"
        if category:
            expected["errorCategory"] = category
        if category in {"LOG_ROLLBACK", "LOG_FORK", "LOG_INCONSISTENT"}:
            old, new = state(trusted), state(candidate)
            expected["diagnostics"] = dict(origin=old["origin"], trustedTreeSize=old["treeSize"],
                                           observedTreeSize=new["treeSize"], trustedRootHash=old["rootHash"],
                                           observedRootHash=new["rootHash"])
        if fault:
            expected["causePreserved"] = True
        if mode == "proof":
            expected["proofRequested"] = True
        if mode == "missing":
            expected["condition"] = "consistency_unavailable"
        cases.append(dict(id="checkpoint-" + name, description=name.replace("-", " "),
                          spec_ref="SDK design 11: Trusted Checkpoint Store Contract; Checkpoint Failure Diagnostics",
                          tags=["required", "security"], op="c2sp_checkpoint_vector",
                          input={"checkpointCase": request}, expect=expected))

    add("first-contact", None, first)
    add("same-checkpoint", first, first)
    add("growth-proof", first, grown, mode="proof", proof=[b64(hashlib.sha256(b"\0" + entries[1]).digest())])
    add("growth-scan", first, grown)
    add("rollback", grown, first, category="LOG_ROLLBACK")
    add("root-conflict", other, first, category="LOG_FORK")
    add("invalid-proof", first, grown, mode="proof", proof=[b64(bytes(32))], category="LOG_INCONSISTENT")
    add("contradictory-prefix", other, grown, category="LOG_INCONSISTENT")
    add("scan-missing-leaf", first, grown, scan=grown["entries"][:1], category="INVALID_EVIDENCE")
    invalid_scan = copy.deepcopy(grown["entries"])
    # Both roots disagree: invalid candidate evidence takes precedence over continuity.
    invalid_scan[0]["entry"] = b64(b"different untrusted leaf")
    add("scan-wrong-root", first, grown, scan=invalid_scan, category="INVALID_EVIDENCE")
    add("missing-consistency", first, grown, mode="missing")
    add("proof-fetch-error", first, grown, mode="proof", fault="proof-fetch")
    add("store-load-error", first, grown, fault="load", category="CHECKPOINT_STORE_ERROR")
    add("store-write-error", first, grown, fault="write", category="CHECKPOINT_STORE_ERROR")
    forged = copy.deepcopy(grown)
    lines = forged["checkpoint"].splitlines()
    name, key, signature = lines[-2].split()
    sig_bytes = bytearray(base64.b64decode(signature))
    sig_bytes[-1] ^= 1
    lines[-2] = f"{name} {key} {base64.b64encode(sig_bytes).decode()}"
    forged["checkpoint"] = "\n".join(lines) + "\n"
    # Keep the entry proof's signed checkpoint consistent with the supplied note.
    for item in forged["entries"]:
        item["proof"] = b64(unb64(item["proof"]).replace(grown["checkpoint"].encode(), forged["checkpoint"].encode()))
    add("invalid-checkpoint-signature", first, forged, category="INVALID_EVIDENCE")
    return {ROOT / "fixtures/c2sp-checkpoint-continuity.yaml":
            "# Generated by harness/generate_c2sp_fixtures.py; disposable test keys only.\n" +
            yaml.safe_dump(dict(suite="c2sp-checkpoint-continuity", cases=cases), sort_keys=False, allow_unicode=True)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = {OUTPUT: generate_selection(), **generate_bundle(), **generate_checkpoints()}
    for path, generated in outputs.items():
        if args.check:
            assert path.read_text() == generated, f"regenerate {path.name}"
        else:
            path.write_text(generated)
    print("Corrected C2SP fixtures are reproducible" if args.check else "Generated corrected C2SP fixtures")
