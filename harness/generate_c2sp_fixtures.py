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
    signed += (f"— {log_line.split()[1]} " + base64.b64encode(log_signature[:4] + edsign(4, checkpoint)).decode() + "\n").encode()
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
    # C2SP section 7: entry bytes must be exactly JCS. A BOM before a validly signed event is encoding noise.
    templates["bom-prefixed-entry-is-ignored"] = copy.deepcopy(template)
    recipes["bom-prefixed-entry-is-ignored"] = {"issuance": (canonical(issuance), True),
                                                "bom-prefixed-revocation": (b"\xef\xbb\xbf" + canonical(revocation), True)}

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


BUNDLE_V2 = ROOT / "fixtures/c2sp-stream-bundle-v2.json"
BUNDLE_V2_REVISION = "972f5f19222e0a55e3ee8f8be28dd087764c144e"
STREAM_HEAD_TYPE = "dnsid-c2sp-stream-head@v1"


def note_key_hash(name, public, alg=1):
    return hashlib.sha256(name.encode() + b"\n" + bytes([alg]) + public).digest()[:4]


def ed_public(seed):
    from cryptography.hazmat.primitives import serialization
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32).public_key()
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sign_note(text, name, seed):
    """Return signed-note bytes for text with one Ed25519 signature line."""
    signature = note_key_hash(name, ed_public(seed)) + edsign(seed, text)
    return text + b"\n" + f"— {name} ".encode() + base64.b64encode(signature) + b"\n"


def statement(lr, size, root, head, expires):
    return (f"{STREAM_HEAD_TYPE}\nlr {lr}\ncheckpoint {size} {base64.b64encode(root).decode()}\n"
            f"head {head}\nexpires {expires}\n").encode()


def noncanonical_b64(value):
    """Set an unused low bit in the final base64 character; lenient decoders accept it."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    data = value.rstrip("=")
    bumped = data[:-1] + alphabet[alphabet.index(data[-1]) | 1]
    assert bumped != data and base64.b64decode(bumped + value[len(data):]) == base64.b64decode(value)
    return bumped + value[len(data):]


def check_spec_statement_vector():
    """Method §20 stream-head statement vector, reproduced from its seed."""
    text = statement("c2sp-tlog:testnet:https://testnet.dnsid.example/log#Q2hWbW5Ta0x5R0JtM3B0dw", 3,
                     base64.b64decode("H3aq5vryyX/jMIrSuLhjl/64vwD/yvpOfXUxGjzC5Ns="),
                     "J-odfRVwktq5YRgXEesz663r5AYJbYgT6qhwmfnyjxQ", 1782432000)
    name = "indexer.testnet.dnsid.example"
    signed = sign_note(text, name, 7)
    assert signed.endswith(b"\n\xe2\x80\x94 indexer.testnet.dnsid.example fV1V63KXqsFYpXw0AAh/oI+Dyrzz2T7V8vxOdWmxdLBBqsZeW8uF20a1qfkJSOgnCXyXaWyegBfmly00wsIFdohXeQQ=\n")
    verifier_key = f"{name}+{note_key_hash(name, ed_public(7)).hex()}+" + base64.b64encode(b"\1" + ed_public(7)).decode()
    assert verifier_key == "indexer.testnet.dnsid.example+7d5d55eb+AepKbGPinFIKvvVQexMuxfmVR3auvr57kkIe6mkURtIs"
    return dict(seed=b64(bytes([7]) * 32), verifier_key=verifier_key, text=text.decode(), signed_note=signed.decode())


def generate_bundle_v2():
    """dnsid-c2sp-stream-bundle@v2 vectors (method §12.1, §20) from the logical-v1 entries."""
    source = json.loads(generate_bundle()[ROOT / "fixtures/c2sp-stream-bundle-logical-v1.json"])
    v1 = json.loads(source["bundle"])
    template = {"checkpoint": unb64(v1["checkpoint"]).decode()}
    issuance, rotation = [unb64(item["entry"]) for item in v1["events"]]
    trust = source["trust"]
    lr, now = v1["lr"], trust["now"]
    witness_time = int.from_bytes(base64.b64decode(template["checkpoint"].splitlines()[-1].split()[-1])[4:12], "big")
    max_expires = witness_time + trust["max_bundle_lifetime_ms"] // 1000
    head = event_id(json.loads(rotation))

    noise = json.loads(rotation)
    signature = bytearray(unb64(noise["sigs"]["new_op"]["sig"]))
    signature[0] ^= 1
    noise["sigs"]["new_op"]["sig"] = b64(bytes(signature))
    fork = json.loads(rotation)
    fork["dnsid_test_variant"] = "fork"
    for item in fork["sigs"].values():
        item["sig"] = b64(edsign(SEEDS[item["kid"]], canonical(payload(fork))))
    noise, fork = canonical(noise), canonical(fork)
    assert event_id(json.loads(fork)) != head and event_id(json.loads(noise)) == head

    def tree_evidence(raw_entries):
        packaged = package_case(template, [(entry, "unused", True) for entry in raw_entries])
        leaves = [hashlib.sha256(b"\0" + entry).digest() for entry in raw_entries]
        events = [dict(index=i, entry=b64(entry), proof=b64(b"".join(audit_path(leaves, i)))) for i, entry in enumerate(raw_entries)]
        return packaged["checkpoint"].encode(), events, tree(leaves)

    def bundle(checkpoint, events, tree_root, tree_size, *, head_note=None, **fields):
        text = statement(fields.get("lr", lr), fields.get("size", tree_size), fields.get("root", tree_root),
                         fields.get("head", head), fields.get("expires", v1["expires"]))
        note = head_note if head_note is not None else sign_note(text, "bundle.example", 6)
        return {"v": 2, "type": "dnsid-c2sp-stream-bundle", "head": b64(note), "checkpoint": b64(checkpoint), "events": events}

    main_checkpoint, main_events, main_root = tree_evidence([issuance, rotation])
    assert main_checkpoint.decode() == template["checkpoint"]
    golden = bundle(main_checkpoint, main_events, main_root, 2)
    golden_text = statement(lr, 2, main_root, head, v1["expires"])

    def variant(**changes):
        result = copy.deepcopy(golden)
        result.update(changes)
        return result

    def with_note(text, name="bundle.example", seed=6):
        return variant(head=b64(sign_note(text, name, seed)))

    def text_edit(old, new):
        edited = golden_text.replace(old.encode(), new.encode(), 1)
        assert edited != golden_text
        return with_note(edited)

    def checkpoint_text(body):
        # Sign arbitrary checkpoint text with the fixture log and witness keys.
        packaged = package_case(template, [(issuance, "unused", True), (rotation, "unused", True)])
        signed = packaged["checkpoint"].encode()
        lines = signed.decode().split("\n\n")[1].strip().splitlines()
        log_prefix = base64.b64decode(lines[0].split()[-1])[:4]
        witness_prefix = base64.b64decode(lines[1].split()[-1])[:12]
        cosigned = f"cosignature/v1\ntime {witness_time}\n".encode() + body
        result = body + b"\n"
        result += f"— {lines[0].split()[1]} ".encode() + base64.b64encode(log_prefix + edsign(4, body)) + b"\n"
        result += b"\xe2\x80\x94 witness.example " + base64.b64encode(witness_prefix + edsign(5, cosigned)) + b"\n"
        return result

    main_body = template["checkpoint"].split("\n\n")[0].encode() + b"\n"
    assert checkpoint_text(main_body) == main_checkpoint
    root_line = base64.b64encode(main_root).decode()
    log_line = main_checkpoint.decode().split("\n\n")[1].splitlines()[0]

    copy_checkpoint, copy_events, copy_root = tree_evidence([issuance, rotation, rotation, noise])
    order_checkpoint, order_events, order_root = tree_evidence([issuance, rotation, issuance])
    fork_checkpoint, fork_events, fork_root = tree_evidence([issuance, rotation, fork])

    def events_edit(position, **fields):
        events = copy.deepcopy(main_events)
        events[position].update(fields)
        return variant(events=events)

    bad_noise_proof = copy.deepcopy([copy_events[0], copy_events[1], copy_events[3]])
    proof = bytearray(unb64(bad_noise_proof[2]["proof"]))
    proof[0] ^= 1
    bad_noise_proof[2]["proof"] = b64(bytes(proof))
    long_lr = lr.split("#")[0] + "#" + "a" * (1025 - len(lr.split("#")[0]) - 1)
    assert len(long_lr) == 1025

    valid = [
        dict(name="reencoded", reason="member order and whitespace do not affect a v2 bundle",
             bundle=json.dumps(dict(reversed(list(golden.items()))), indent=2)),
        dict(name="later-copy", reason="the chosen KEY_ROTATION occurrence is a later identical copy at index 2",
             bundle=canonical(bundle(copy_checkpoint, [copy_events[0], copy_events[2]], copy_root, 4)).decode()),
        dict(name="ignored-noise", reason="an invalid-signature copy with a valid inclusion proof is ignored",
             bundle=canonical(bundle(copy_checkpoint, [copy_events[0], copy_events[1], copy_events[3]], copy_root, 4)).decode()),
    ]
    duplicate = canonical(golden).decode().replace('{"checkpoint"', '{"v":2,"checkpoint"', 1)
    negative = [
        ("head-padded", "padded base64url", variant(head=golden["head"] + "=")),
        ("head-malformed", "malformed base64url", variant(head=golden["head"][:-1] + "!")),
        ("checkpoint-padded", "padded base64url", variant(checkpoint=golden["checkpoint"] + "=")),
        ("entry-padded", "padded base64url", events_edit(0, entry=main_events[0]["entry"] + "=")),
        ("repeated-member", "repeated member", duplicate),
        ("missing-member", "missing member", {k: v for k, v in golden.items() if k != "events"}),
        ("additional-member", "additional member", variant(fqdn=v1["fqdn"])),
        ("version-1-value", "v other than 2", variant(v=1)),
        ("version-1-bundle", "version 1 bundle", source["bundle"]),
        ("wrong-type", "wrong type", variant(type="dnsid-c2sp-stream-index")),
        ("unaccepted-key", "statement signed only by an unaccepted key", with_note(golden_text, "bundle.example", 9)),
        ("log-key", "statement signed only by the log key", with_note(golden_text, "log.example", 4)),
        ("witness-key", "statement signed only by the witness key", with_note(golden_text, "witness.example", 5)),
        ("head-signature-noncanonical", "non-canonical base64 in the statement signature line",
         variant(head=b64(sign_note(golden_text, "bundle.example", 6).replace(
             sign_note(golden_text, "bundle.example", 6).split(b" ")[-1].strip(),
             noncanonical_b64(sign_note(golden_text, "bundle.example", 6).split(b" ")[-1].strip().decode()).encode())))),
        ("statement-extra-line", "additional statement line", with_note(golden_text + b"extra\n")),
        ("statement-missing-line", "missing statement line", text_edit(f"expires {v1['expires']}\n", "")),
        ("statement-reordered", "reordered statement lines", text_edit(f"head {head}\nexpires {v1['expires']}\n", f"expires {v1['expires']}\nhead {head}\n")),
        ("statement-leading-zero", "leading zero", text_edit("checkpoint 2 ", "checkpoint 02 ")),
        ("statement-extra-space", "additional space", text_edit("lr ", "lr  ")),
        ("statement-wrong-type", "unsupported statement type", text_edit(STREAM_HEAD_TYPE, "dnsid-c2sp-stream-head@v2")),
        ("statement-root-noncanonical", "non-canonical statement root hash", text_edit(root_line, noncanonical_b64(root_line))),
        ("statement-lr-too-long", "lr longer than 1024 bytes", bundle(main_checkpoint, main_events, main_root, 2, lr=long_lr)),
        ("statement-lr-mismatch", "statement lr does not match", bundle(main_checkpoint, main_events, main_root, 2, lr=lr.split("#")[0] + "#b3RoZXI")),
        ("statement-size-mismatch", "statement tree size does not match", bundle(main_checkpoint, main_events, main_root, 2, size=3)),
        ("statement-root-mismatch", "statement root hash does not match", bundle(main_checkpoint, main_events, main_root, 2, root=bytes(32))),
        ("omitted-final-event", "replayed head differs from the statement head", variant(events=main_events[:1])),
        ("omitted-middle-event", "omitted ISSUANCE", variant(events=main_events[1:])),
        ("copy-after-successor", "chosen ISSUANCE copy has a greater index than its successor",
         bundle(order_checkpoint, [order_events[1], order_events[2]], order_root, 3)),
        ("entry-mismatch", "entry does not match its proof", events_edit(0, entry=main_events[1]["entry"])),
        ("proof-mismatch", "proof does not match its entry", events_edit(0, proof=main_events[1]["proof"])),
        ("proof-length", "proof length not a multiple of 32", events_edit(0, proof=b64(bytes(31)))),
        ("index-out-of-order", "index out of order", variant(events=[main_events[1], main_events[0]])),
        ("index-duplicate", "duplicate index", events_edit(1, index=0)),
        ("index-beyond-tree", "index not less than the tree size", events_edit(1, index=2)),
        ("ignored-entry-invalid-proof", "invalid proof on an otherwise ignored entry",
         bundle(copy_checkpoint, bad_noise_proof, copy_root, 4)),
        ("authenticated-conflict", "authenticated KEY_ROTATION fork",
         bundle(fork_checkpoint, fork_events, fork_root, 3)),
        ("expired", "statement expired", bundle(main_checkpoint, main_events, main_root, 2, expires=now)),
        ("beyond-lifetime", "expires beyond the maximum bundle lifetime", bundle(main_checkpoint, main_events, main_root, 2, expires=max_expires + 1)),
        ("checkpoint-root-noncanonical", "non-canonical base64 in the checkpoint root hash",
         variant(checkpoint=b64(checkpoint_text(main_body.replace(root_line.encode(), noncanonical_b64(root_line).encode()))))),
        ("checkpoint-size-leading-zero", "leading zero in the checkpoint tree size",
         variant(checkpoint=b64(checkpoint_text(main_body.replace(b"\n2\n", b"\n02\n"))))),
        ("checkpoint-signature-noncanonical", "non-canonical base64 in a checkpoint signature line",
         variant(checkpoint=b64(main_checkpoint.replace(log_line.split()[-1].encode(), noncanonical_b64(log_line.split()[-1]).encode())))),
    ]
    vector = {
        "format": "dnsid-c2sp-stream-bundle@v2",
        "method_revision": BUNDLE_V2_REVISION,
        "source": "harness/generate_c2sp_fixtures.py; public disposable keys only",
        "policy": source["policy"],
        "trust": trust,
        "expected": {**source["expected"], "head_event_id": head},
        "statement": golden_text.decode(),
        "bundle": canonical(golden).decode(),
        "valid_variants": valid,
        "negative_vectors": [dict(name=name, reason=reason, bundle=value if isinstance(value, str) else canonical(value).decode())
                             for name, reason, value in negative],
        "statement_vector": check_spec_statement_vector(),
        "reference_vectors": [
            dict(lr=lr.split("#")[0] + "#" + "a" * (1024 - len(lr.split("#")[0]) - 1), valid=True, reason="lr of exactly 1024 bytes"),
            dict(lr=long_lr, valid=False, reason="lr longer than 1024 bytes"),
        ],
    }
    return {BUNDLE_V2: json.dumps(vector, indent=2, ensure_ascii=False) + "\n"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = {OUTPUT: generate_selection(), **generate_bundle(), **generate_checkpoints(), **generate_bundle_v2()}
    for path, generated in outputs.items():
        if args.check:
            assert path.read_text() == generated, f"regenerate {path.name}"
        else:
            path.write_text(generated)
    print("Corrected C2SP fixtures are reproducible" if args.check else "Generated corrected C2SP fixtures")
