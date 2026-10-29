"""RFC 6962 consistency proofs from every trusted size m to every larger size n (port of dnsid-formal `merkle_consistency`).

Leaf 0 is the signed ISSUANCE; later leaves are non-DNSid entries. For each m < n
the valid proof must advance the trusted checkpoint, and a proof with a node
missing, an extra node, or any node changed must fail with LOG_INCONSISTENT and
keep the trusted state. Proofs are built here, not by an SDK. Expectations follow
the checkpoint cases in generate_c2sp_fixtures.py (SDK design 11).
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json

from c2sp_event_identity_check import b64, canonical, unb64
from generate_c2sp_fixtures import ROOT, audit_path, edsign, generate_bundle, package_case, tree

MAX_SIZE = 17  # covers the 16 -> 17 split; 32 adds ~2,700 cases and finds nothing new on current mains


def subproof(leaves, m, complete=True):
    """RFC 6962 section 2.1.2 SUBPROOF(m, D[n], b)."""
    if m == len(leaves):
        return [] if complete else [tree(leaves)]
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    if m <= k:
        return subproof(leaves[:k], m, complete) + [tree(leaves[k:])]
    return subproof(leaves[k:], m - k, False) + [tree(leaves[:k])]


def load_cases():
    vector = json.loads(generate_bundle()[ROOT / "fixtures/c2sp-stream-bundle-logical-v1.json"])
    original = json.loads(vector["bundle"])
    issuance = unb64(original["events"][0]["entry"])
    raw = [issuance] + [f"non-DNSid fixture leaf {i}".encode() for i in range(1, MAX_SIZE)]
    leaves = [hashlib.sha256(b"\0" + entry).digest() for entry in raw]
    common = dict(policy=vector["policy"], entityJwk=vector["trust"]["entity_jwk"],
                  bundleVerifierKey=vector["trust"]["bundle_verifier_key"], now=vector["trust"]["now"],
                  lr=original["lr"], domain=original["fqdn"])

    def history(size):
        packaged = package_case({"checkpoint": unb64(original["checkpoint"]).decode()},
                                [(entry, "unused", True) for entry in raw[:size]])
        bundle = copy.deepcopy(original)
        bundle["checkpoint"] = b64(packaged["checkpoint"].encode())
        bundle["complete_through_size"] = size
        bundle["events"] = [dict(index=0, entry=b64(issuance), proof=b64(b"".join(audit_path(leaves[:size], 0))))]
        bundle["state"].update(event_count=1, last_event_type="ISSUANCE")
        bundle["sig"]["value"] = b64(edsign(6, canonical({k: v for k, v in bundle.items() if k != "sig"})))
        entries = [dict(index=e["index"], entry=e["entry"], proof=e["proof"]) for e in packaged["entries"]]
        text, signatures = packaged["checkpoint"].split("\n\n")
        origin, tree_size, root = text.splitlines()
        witness = base64.b64decode(signatures.strip().splitlines()[1].split()[-1])
        state = dict(origin=origin, treeSize=int(tree_size), rootHash=b64(base64.b64decode(root)),
                     witnessTime=int.from_bytes(witness[4:12], "big"))
        return dict(checkpoint=packaged["checkpoint"], entries=entries, bundle=canonical(bundle).decode()), state

    histories = [None] + [history(size) for size in range(1, MAX_SIZE + 1)]
    cases = []
    for n in range(2, MAX_SIZE + 1):
        candidate, new = histories[n]
        for m in range(1, n):
            trusted, old = histories[m]
            valid = subproof(leaves[:n], m)
            variants = [("valid", valid), ("missing-node", valid[:-1]), ("extra-node", valid + [bytes(32)])]
            for i in range(len(valid)):
                changed = list(valid)
                changed[i] = bytes([changed[i][0] ^ 1]) + changed[i][1:]
                variants.append((f"changed-node-{i}", changed))
            for name, proof in variants:
                ok = name == "valid"
                expected = dict(ok=ok, stored=new if ok else old, proofRequested=True)
                if not ok:
                    expected.update(error="CheckpointError", transient=False, errorCategory="LOG_INCONSISTENT",
                                    diagnostics=dict(origin=old["origin"], trustedTreeSize=m, observedTreeSize=n,
                                                     trustedRootHash=old["rootHash"], observedRootHash=new["rootHash"]))
                request = dict(common, trusted=trusted, candidate=dict(candidate, entries=candidate["entries"][:1]),
                               mode="proof", scanEntries=candidate["entries"][:1], proof=[b64(node) for node in proof])
                cases.append(dict(id=f"consistency-{m}-to-{n}-{name}", description=f"{name} proof from size {m} to {n}",
                                  spec_ref="RFC 6962 section 2.1.2; SDK design 11: Trusted Checkpoint Store Contract",
                                  op="c2sp_checkpoint_vector", input={"checkpointCase": request}, expect=expected))
    return cases


assert subproof([b"a"] * 3, 3) == [] and len(subproof([bytes(32)] * 7, 3)) == 4
