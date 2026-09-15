#!/usr/bin/env python3
"""Generate corrected, disposable C2SP selection and bundle evidence, without SDK imports.

Requires cryptography >= 43. Historical signed inputs stay byte-for-byte intact.
This deliberately handles only these ASCII/integer fixtures, not arbitrary logs.
Run with --check to verify deterministic regeneration of the committed output.
"""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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


def edsign(seed, data):
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    signature = key.sign(data)
    key.public_key().verify(signature, data)
    return signature


def tree(leaves):
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
    result["entries"] = []
    for index, (raw, effect, valid_proof) in enumerate(entries):
        proof = f"c2sp.org/tlog-proof@v1\nindex {index}\n".encode()
        proof += b"".join(base64.b64encode(node) + b"\n" for node in audit_path(leaves, index))
        proof += b"\n" + signed
        if not valid_proof:
            proof = b"invalid fixture inclusion proof"
        result["entries"].append(dict(index=index, entry=b64(raw), proof=b64(proof), effectId=effect, proofValid=valid_proof))
    return result


def generate_selection():
    old = json.loads(HISTORICAL.read_bytes())
    historical_semantics = ROOT / "fixtures/historical/c2sp-lifecycle-selection.json"
    assert hashlib.sha256(historical_semantics.read_bytes()).hexdigest() == old["semantic_source_sha256"]
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

    cases = {}
    for name, case in old["cases"].items():
        if name == "resigned-event-is-not-byte-identical-deduplication":
            name = "signed-extension-is-a-distinct-genesis"
        entries = []
        for item in case["entries"]:
            raw = correct(unb64(item["entry"]))
            effect = item["effectId"]
            if b'"dnsid_test_variant"' in raw:
                effect = "issuance-extension"
            entries.append((raw, effect, item["proofValid"]))
        cases[name] = package_case(case, entries)

    template = cases["byte-identical-complete-entry-is-applied-once"]
    issuance = json.loads(unb64(template["entries"][0]["entry"]))
    rotation = json.loads(unb64(template["entries"][2]["entry"]))

    def add(name, items, *, es256=False):
        case = copy.deepcopy(template)
        if es256:
            case["entityJwk"], case["operationalJwk"] = PUBLIC[:2]
        cases[name] = package_case(case, [(canonical(e), effect, True) for e, effect in items])

    for kind in ("invalid", "missing"):
        partial = copy.deepcopy(rotation)
        if kind == "invalid":
            partial["sigs"]["new_op"]["sig"] = "AA"
        else:
            del partial["sigs"]["new_op"]
        add(f"{kind}-rotation-countersignature-is-ignored", [(issuance, "issuance-1"), (partial, "rotation-partial"), (rotation, "rotation-1")])
    fork = copy.deepcopy(rotation)
    fork["ts"] += 1
    for signature in fork["sigs"].values():
        signature["sig"] = b64(edsign(SEEDS[signature["kid"]], canonical(payload(fork))))
    add("fully-signed-historical-predecessor-fork-is-fatal", [(issuance, "issuance-1"), (rotation, "rotation-1"), (fork, "rotation-fork")])
    fork["sigs"]["new_op"]["sig"] = "AA"
    add("partial-historical-predecessor-fork-is-ignored", [(issuance, "issuance-1"), (rotation, "rotation-1"), (fork, "rotation-partial")])
    legacy = old["cases"]["byte-identical-complete-entry-is-applied-once"]["entries"][2]
    add("prohibited-index-chain-is-fatal", [(issuance, "issuance-1"), (json.loads(unb64(legacy["entry"])), "rotation-index-chain")])

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
    add("es256-signature-only-copy-is-applied-once", [(issuance, "issuance-1"), (duplicate, "issuance-1"), (rotation, "rotation-1")], es256=True)
    add("es256-high-s-first-copy-is-applied-once", [(duplicate, "issuance-1"), (issuance, "issuance-1"), (rotation, "rotation-1")], es256=True)
    state["operational_thumb"] = thumb(PUBLIC[2])
    body = {k: issuance[k] for k in ("v", "kind", "method", "log_origin", "lr", "stream_id", "fqdn")}
    body.update(type="REVOCATION", ts=rotation["ts"]+1, seq=2, reason="keyCompromise", prev_event_id=event_id(rotation), prev_state_hash=digest("state", state))
    revocation = low_sign(body, {"ae": KEYS[0]})
    add("es256-signature-only-replay-after-terminal-is-ignored", [(issuance, "issuance-1"), (rotation, "rotation-1"), (revocation, "revocation-1"), (flipped(rotation, "prev_op", "new_op"), "rotation-1")], es256=True)

    semantics = SEMANTICS.read_bytes()
    assert set(cases) == {case["id"] for case in json.loads(semantics)["cases"]}
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = {OUTPUT: generate_selection(), **generate_bundle()}
    for path, generated in outputs.items():
        if args.check:
            assert path.read_text() == generated, f"regenerate {path.name}"
        else:
            path.write_text(generated)
    print("Corrected C2SP fixtures are reproducible" if args.check else "Generated corrected C2SP fixtures")
