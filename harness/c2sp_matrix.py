#!/usr/bin/env python3
"""Generate deterministic C2SP entries in every SDK and verify the shared bundle."""

from __future__ import annotations

import base64
import datetime
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "fixtures" / "c2sp-generation-logical-v1.json"


def _sdk_dir(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} is not set")
    return Path(value).resolve()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _private(seed_byte: int) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)


def _raw_jwk(kid: str, private: ed25519.Ed25519PrivateKey) -> dict[str, str]:
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "alg": "EdDSA",
        "crv": "Ed25519",
        "kid": kid,
        "kty": "OKP",
        "x": _b64url(public),
    }


def _python_artifacts(corpus: dict) -> dict:
    from dnsid._crypto import jwk_from_dict
    from dnsid.c2sp_tlog import (
        C2spChain,
        C2spSignerRole,
        C2spVerificationContext,
        canonical_bytes,
        entry_bytes,
        c2sp_event_id,
        prepare_event,
        sign_prepared_event,
        state_hash,
    )
    from dnsid.models import (
        IssuanceEvent,
        KeyRotationEvent,
    )

    class Provider:
        def __init__(self, raw: dict[str, str], private: ed25519.Ed25519PrivateKey):
            self.key = jwk_from_dict(raw)
            self.private = private

        def jwk(self, kid: str):
            if kid != self.key.kid:
                raise ValueError(f"unexpected kid: {kid}")
            return self.key

        def sign_key(self, kid: str, payload: bytes) -> bytes:
            if kid != self.key.kid:
                raise ValueError(f"unexpected kid: {kid}")
            return self.private.sign(payload)

    providers = {}
    for name, spec in corpus["keys"].items():
        private = _private(spec["ed25519_seed_byte"])
        providers[name] = Provider(_raw_jwk(spec["kid"], private), private)

    entity = providers["entity"].key
    initial = providers["operational_initial"].key
    rotated = providers["operational_rotated"].key
    issuance_event = IssuanceEvent(
        domain=corpus["domain"],
        governance_id=corpus["governance_id"],
        timestamp=datetime.datetime.fromtimestamp(
            corpus["events"]["issuance"]["timestamp"], tz=datetime.UTC
        ),
        entity_key=entity,
        operational_key=initial,
    )
    issuance = sign_prepared_event(
        prepare_event(issuance_event, corpus["lr"]),
        C2spSignerRole.ENTITY,
        providers["entity"],
    )
    entity_signed_issuance = _b64url(canonical_bytes(issuance.envelope))
    issuance_context = C2spVerificationContext(
        fqdn=corpus["domain"],
        gi=corpus["governance_id"],
        entity_key=entity,
        operational_key=initial,
    )
    issuance = sign_prepared_event(
        issuance,
        C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE,
        providers["operational_initial"],
        issuance_context,
    )
    issuance_bytes = entry_bytes(issuance, issuance_context)

    chain = C2spChain(
        sequence=1,
        previous_event_id=c2sp_event_id(issuance_bytes),
        previous_state_hash=state_hash(
            {
                "fqdn": corpus["domain"],
                "status": "ACTIVE",
                "entity_thumb": entity.thumbprint(),
                "operational_thumb": initial.thumbprint(),
            }
        ),
    )
    rotation_event = KeyRotationEvent(
        domain=corpus["domain"],
        previous_kid=initial.kid,
        previous_thumbprint=initial.thumbprint(),
        new_kid=rotated.kid,
        new_thumbprint=rotated.thumbprint(),
        new_public_key=rotated,
        timestamp=datetime.datetime.fromtimestamp(
            corpus["events"]["rotation"]["timestamp"], tz=datetime.UTC
        ),
    )
    rotation_context = C2spVerificationContext(previous_operational_key=initial)
    rotation = sign_prepared_event(
        prepare_event(rotation_event, corpus["lr"], chain),
        C2spSignerRole.PREVIOUS_OPERATIONAL,
        providers["operational_initial"],
        rotation_context,
    )
    rotation = sign_prepared_event(
        rotation,
        C2spSignerRole.NEW_OPERATIONAL,
        providers["operational_rotated"],
        rotation_context,
    )
    rotation_bytes = entry_bytes(rotation, rotation_context)
    entries = {
        "issuance": _b64url(issuance_bytes),
        "rotation": _b64url(rotation_bytes),
    }
    return {"entries": entries, "entitySignedIssuance": entity_signed_issuance}


def _run_json(
    command: list[str], *, cwd: Path | None = None, input_value: dict | None = None
) -> dict:
    result = subprocess.run(
        command,
        cwd=cwd,
        input=json.dumps(input_value) if input_value is not None else None,
        text=True,
        capture_output=True,
    )
    if result.returncode:
        raise RuntimeError(
            f"{' '.join(command)} exited {result.returncode}:\n{result.stderr.strip()}"
        )
    return json.loads(result.stdout)


def _assert_entries(name: str, actual: dict[str, str], expected: dict[str, str]) -> None:
    if actual.keys() != expected.keys():
        raise AssertionError(f"{name} generated {sorted(actual)}; expected {sorted(expected)}")
    for event, want in expected.items():
        got = actual[event]
        if got == want:
            continue
        got_bytes = base64.urlsafe_b64decode(got + "==")
        want_bytes = base64.urlsafe_b64decode(want + "==")
        offset = next(
            (i for i, pair in enumerate(zip(got_bytes, want_bytes)) if pair[0] != pair[1]),
            min(len(got_bytes), len(want_bytes)),
        )
        raise AssertionError(
            f"{name} {event} differs at offset {offset} "
            f"(got {len(got_bytes)} bytes, expected {len(want_bytes)})"
        )


def _verify_python(vector: dict, bundle_bytes: bytes | None = None) -> dict:
    from dnsid._crypto import jwk_from_dict
    from dnsid.c2sp_tlog import (
        C2spStreamBundleVerifierOptions,
        parse_signed_note_verifier_key,
        verify_c2sp_stream_bundle,
    )

    trust = vector["trust"]
    verified = verify_c2sp_stream_bundle(
        bundle_bytes if bundle_bytes is not None else vector["bundle"].encode(),
        C2spStreamBundleVerifierOptions(
            policy_bytes=vector["policy"].encode(),
            bundle_keys=[parse_signed_note_verifier_key(trust["bundle_verifier_key"])],
            entity_key=jwk_from_dict(trust["entity_jwk"]),
            checkpoint_freshness_ms=trust["checkpoint_freshness_ms"],
            max_bundle_lifetime_ms=trust["max_bundle_lifetime_ms"],
            max_bundle_bytes=128 * 1024,
            max_events=16,
            now=lambda: trust["now"],
        ),
    )
    return {
        "eventCount": len(verified.events),
        "status": verified.logged_state,
        "activeOperationalThumbprint": verified.active_operational_thumbprint,
        "bundleSignerKid": verified.bundle_signer_kid,
    }


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _mutated_bundle(vector: dict, mutation: dict) -> bytes:
    value = json.loads(vector["bundle"])
    target = value
    parts = mutation["path"].strip("/").split("/")
    for part in parts[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    last = parts[-1]
    if "append" in mutation:
        target[last] += mutation["append"]
    elif isinstance(target, list):
        target[int(last)] = mutation["value"]
    else:
        target[last] = mutation["value"]
    if mutation.get("resign"):
        unsigned = dict(value)
        unsigned.pop("sig")
        private = _private(6)
        value["sig"]["value"] = _b64url(
            private.sign(_canonical_json_bytes(unsigned))
        )
    return _canonical_json_bytes(value)


def _vector_for_entries(vector: dict, entries: dict[str, str]) -> dict:
    bundle = json.loads(vector["bundle"])
    for index, name in enumerate(("issuance", "rotation")):
        bundle["events"][index]["entry"] = entries[name]
    bundle_bytes = _canonical_json_bytes(bundle)
    if bundle_bytes != vector["bundle"].encode():
        raise AssertionError(
            "generated entries differ from the signed checkpoint or bundle signature"
        )
    return {**vector, "bundle": bundle_bytes.decode()}


def _assert_expected_error(sdk: str, mutation: dict, output: str) -> None:
    declared = mutation["error"]
    expected = (declared[sdk] if isinstance(declared, dict) else declared).lower()
    if expected not in output.lower():
        raise AssertionError(
            f"{sdk} rejected mutation {mutation['name']} for the wrong reason: "
            f"expected {expected!r} in {output.strip()!r}"
        )


def _assert_rejected_by_all(vector: dict, golden_path: Path) -> None:
    from dnsid.c2sp_tlog import C2spTlogError

    for mutation in vector["negative_mutations"]:
        bundle_bytes = _mutated_bundle(vector, mutation)
        try:
            _verify_python(vector, bundle_bytes)
        except C2spTlogError as exc:
            _assert_expected_error("py", mutation, str(exc))
        else:
            raise AssertionError(f"py accepted mutation {mutation['name']}")

        mutated = dict(vector)
        mutated["bundle"] = bundle_bytes.decode()
        with tempfile.TemporaryDirectory(prefix="dnsid-c2sp-matrix-") as directory:
            path = Path(directory) / golden_path.name
            path.write_text(json.dumps(mutated))
            checks = {
                "ts": [
                    "node",
                    str(ROOT / "harness" / "c2sp_verify_ts.mjs"),
                    str(path),
                ],
                "go": ["go", "run", "./c2spverify", str(path)],
            }
            for sdk, command in checks.items():
                result = subprocess.run(
                    command,
                    cwd=ROOT / "shims" / "go" if sdk == "go" else None,
                    text=True,
                    capture_output=True,
                )
                if result.returncode == 0:
                    raise AssertionError(f"{sdk} accepted mutation {mutation['name']}")
                _assert_expected_error(
                    sdk, mutation, result.stderr + "\n" + result.stdout
                )


def _verify_writer_matrix(
    generated: dict[str, dict[str, str]], vector: dict, golden_path: Path
) -> None:
    for writer, entries in generated.items():
        writer_vector = _vector_for_entries(vector, entries)
        with tempfile.TemporaryDirectory(prefix="dnsid-c2sp-matrix-") as directory:
            path = Path(directory) / f"{writer}-{golden_path.name}"
            path.write_text(json.dumps(writer_vector))
            results = {
                "py": _verify_python(writer_vector),
                "ts": _run_json(
                    ["node", str(ROOT / "harness" / "c2sp_verify_ts.mjs"), str(path)]
                ),
                "go": _run_json(
                    ["go", "run", "./c2spverify", str(path)],
                    cwd=ROOT / "shims" / "go",
                ),
            }
            for verifier, result in results.items():
                _assert_verified(
                    f"{writer}->{verifier}", result, vector["expected"]
                )


def _assert_verified(name: str, actual: dict, expected: dict) -> None:
    normalized = {
        "eventCount": actual.get("eventCount"),
        "status": actual.get("status"),
        "activeOperationalThumbprint": actual.get("activeOperationalThumbprint"),
        "bundleSignerKid": actual.get("bundleSignerKid"),
    }
    want = {
        "eventCount": expected["event_count"],
        "status": expected["status"],
        "activeOperationalThumbprint": expected["active_operational_thumbprint"],
        "bundleSignerKid": expected["bundle_signer_kid"],
    }
    if normalized != want:
        raise AssertionError(f"{name} verification result {normalized!r}; expected {want!r}")


def _revision(path: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=path,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def main() -> None:
    go_dir = _sdk_dir("DNSID_GO_DIR")
    ts_dir = _sdk_dir("DNSID_TS_DIR")
    py_dir = _sdk_dir("DNSID_PY_DIR")
    sys.path.insert(0, str(py_dir))

    corpus = json.loads(CORPUS.read_text())
    golden_path = CORPUS.parent / corpus["golden_bundle"]
    vector = json.loads(golden_path.read_text())
    bundle = json.loads(vector["bundle"])
    bundle_entries = [item["entry"] for item in bundle["events"]]

    py_artifacts = _python_artifacts(corpus)
    generated = {
        "py": py_artifacts["entries"],
        "ts": _run_json(
            ["node", str(ROOT / "harness" / "c2sp_generate_ts.mjs"), str(CORPUS)]
        )["entries"],
        "go": _run_json(
            ["go", "run", "./c2spgenerate", str(CORPUS), str(golden_path)],
            cwd=ROOT / "shims" / "go",
        )["entries"],
    }
    expected_entries = generated["py"]
    for name, entries in generated.items():
        _assert_entries(name, entries, expected_entries)
    _assert_entries(
        "golden bundle",
        {"issuance": bundle_entries[0], "rotation": bundle_entries[1]},
        {key: expected_entries[key] for key in ("issuance", "rotation")},
    )

    split = _run_json(
        [
            "node",
            str(ROOT / "harness" / "c2sp_generate_ts.mjs"),
            str(CORPUS),
            "--countersign",
        ],
        input_value={"prepared": py_artifacts["entitySignedIssuance"]},
    )
    if split["entry"] != expected_entries["issuance"]:
        raise AssertionError("Python-to-TypeScript split ISSUANCE differs")

    _verify_writer_matrix(generated, vector, golden_path)
    _assert_rejected_by_all(vector, golden_path)

    print(
        "SDK revisions: "
        f"Go {_revision(go_dir)}, TypeScript {_revision(ts_dir)}, Python {_revision(py_dir)}"
    )
    print(
        f"Generation:    Go, TypeScript, and Python produced the same "
        f"{len(expected_entries)} canonical lifecycle entries"
    )
    print(
        "Verification:  every verifier accepted each writer's signed "
        "ISSUANCE -> KEY_ROTATION stream"
    )
    print("Matrix:        3 writers x 3 verifiers = 9 interoperable paths")
    print("Split signing: Python entity signature -> TypeScript countersignature matches")
    print(
        f"Rejections:    all 3 verifiers rejected all "
        f"{len(vector['negative_mutations'])} mutated bundles"
    )


if __name__ == "__main__":
    main()
