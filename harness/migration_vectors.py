"""Inbound MIGRATION chains across separate C2SP logs (port of dnsid-formal `migration_composition`/`migration_key_age`).

C2SP method section 15 and SDK design 11 "Destination-Only Migration": the
binding recursively verifies the previous history through `prev_ref`, with cycle
detection and configured depth limits; history before the cutoff is imported
and keeps its key age; later source entries are not part of the migrated history;
migration from REVOKED history is invalid. Each log has its own origin and
policy and a complete local source; prior-log verification is done by the SDK,
not by the shim.
"""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from c2sp_event_identity_check import b64, canonical, event_id, payload, unb64
from generate_c2sp_fixtures import OUTPUT, SEEDS, edsign, package_case

TEMPLATE = "authenticated-post-terminal-candidate-is-fatal"


def _log(template, origin, stream_byte):
    """A log with its own origin, signed by the disposable seed-4 log key."""
    public = Ed25519PrivateKey.from_private_bytes(bytes([4]) * 32).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_hash = hashlib.sha256(origin.encode() + b"\n\x01" + public).digest()[:4]
    witness_line = template["checkpoint"].split("\n\n")[1].strip().splitlines()[1]
    skeleton = f"{origin}\n0\n\n\n— {origin} {base64.b64encode(key_hash + bytes(64)).decode()}\n{witness_line}\n"
    verifier = base64.b64encode(b"\x01" + public).decode()
    policy = f"log {origin}+{key_hash.hex()}+{verifier}\n"
    policy += "".join(line + "\n" for line in template["policy"].splitlines() if not line.startswith("log "))
    stream = b64(bytes([stream_byte]) * 16)
    return {"origin": origin, "lr": f"c2sp-tlog:public:https://{origin}#{stream}", "stream": stream,
            "policy": policy, "skeleton": skeleton}


def _signed(body, roles):
    return dict(body, sigs={role: {"kid": kid, "sig": b64(edsign(SEEDS[kid], canonical(body)))} for role, kid in roles.items()})


def _packaged(log, events):
    case = package_case({"checkpoint": log["skeleton"]}, [(canonical(e), "unused", True) for e in events])
    return {"lr": log["lr"], "policy": log["policy"], "checkpoint": case["checkpoint"],
            "entries": [{"index": e["index"], "entry": e["entry"], "proof": e["proof"]} for e in case["entries"]]}


def load_cases():
    template = json.loads(OUTPUT.read_text())["cases"][TEMPLATE]
    issuance, revocation = (json.loads(unb64(e["entry"])) for e in template["entries"][:2])
    witness = base64.b64decode(template["checkpoint"].split("\n\n")[1].strip().splitlines()[1].split()[-1])
    now = int.from_bytes(witness[4:12], "big")
    first_at = now - 48 * 3600
    a, b, c = (_log(template, f"log-{name}.example", byte) for name, byte in (("a", 0x22), ("b", 0x33), ("c", 0x44)))

    def context(log):
        return {"method": "c2sp-tlog", "log_origin": log["origin"], "lr": log["lr"], "stream_id": log["stream"]}

    genesis = _signed(dict(payload(issuance), **context(a), ts=first_at), {"ae": "entity-1", "op": "operational-1"})
    revoked = _signed(dict(payload(revocation), **context(a), ts=first_at + 60, prev_event_id=event_id(genesis)),
                      {"ae": "entity-1"})

    def migration(source, index, log, ts):
        body = {"v": 1, "kind": "dnsid.lifecycle", "type": "MIGRATION", "fqdn": issuance["fqdn"], "ts": ts, "seq": 0,
                "prev_lr": source["lr"], "new_lr": log["lr"], "prev_ref": f"{source['lr']}@{index}", **context(log)}
        return _signed(body, {"ae": "entity-1"})

    operational = template["operationalJwk"]
    thumb = b64(hashlib.sha256(canonical({k: operational[k] for k in ("crv", "kty", "x")})).digest())
    cases = []

    def add(name, logs, target, expected, max_depth=None):
        request = {"domain": issuance["fqdn"], "entityJwk": template["entityJwk"], "operationalThumbprint": thumb,
                   "logs": [_packaged(log, events) for log, events in logs], "target": target, "maxDepth": max_depth,
                   "at": now, "beforeGenesis": first_at - 1}
        cases.append({"id": "migration-" + name, "description": name.replace("-", " "),
                      "spec_ref": "C2SP tlog method section 15; SDK design 11: Destination-Only Migration",
                      "op": "c2sp_migration_vector", "input": {"migrationCase": request}, "expect": expected})

    def active(count):
        return {"ok": True, "eventCount": count, "keyTimestamp": first_at, "loggedState": "ACTIVE",
                "beforeGenesisRejected": True, "cutoffEventCount": count}

    fail = {"ok": False, "error": "LifecycleError"}
    to_b = migration(a, 0, b, now - 3600)
    to_c = migration(b, 0, c, now - 1800)
    add("source-genesis", [(a, [genesis])], 0, active(1))
    add("one-hop-keeps-key-age", [(a, [genesis]), (b, [to_b])], 1, active(2))
    add("two-hop-keeps-key-age", [(a, [genesis]), (b, [to_b]), (c, [to_c])], 2, active(3))
    add("two-hop-over-depth-limit-fails", [(a, [genesis]), (b, [to_b]), (c, [to_c])], 2, fail, max_depth=1)
    add("source-revocation-after-cutoff-is-not-imported", [(a, [genesis, revoked]), (b, [to_b])], 1, active(2))
    add("from-revoked-history-fails", [(a, [genesis, revoked]), (b, [migration(a, 1, b, now - 3600)])], 1, fail)
    # C2SP section 13.2: an unauthenticated MIGRATION is noise and must not block a later genesis,
    # whether or not its previous log can be resolved (the Go DEV-004 pattern).
    genesis_b = _signed(dict(payload(issuance), **context(b), ts=first_at), {"ae": "entity-1", "op": "operational-1"})
    for label, source in (("resolvable", a), ("unresolvable", c)):
        forged = migration(source, 0, b, now - 3600)
        forged["sigs"]["ae"]["sig"] = "AA"
        add(f"unauthenticated-migration-with-{label}-source-is-ignored", [(a, [genesis]), (b, [forged, genesis_b])], 1,
            {"ok": True, "eventCount": 1, "keyTimestamp": first_at, "loggedState": "ACTIVE"})
    add("cycle-fails", [(b, [migration(c, 0, b, now - 3600)]), (c, [migration(b, 0, c, now - 1800)])], 0, fail)
    return cases
