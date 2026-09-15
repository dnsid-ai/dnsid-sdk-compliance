#!/usr/bin/env python3
"""Cross-SDK IETF compliance harness for DNSid.

Loads the shared YAML and lifecycle JSON fixtures, runs every case against each
SDK (dnsid-go and dnsid-ts via JSON shims, dnsid-py in-process), and emits a
markdown compliance matrix.

See README.md for the fixture schema and shim protocol.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from semantic_vectors import load_semantic_suites

ROOT = Path(__file__).resolve().parent.parent

# Per-SDK capabilities. A case tagged with a `version` outside an SDK's set is
# not skipped: the harness asserts the SDK *rejects* the record as an
# unsupported version (status REJ). Unsupported versions must fail closed.
CAPABILITIES = {
    "go": {
        "versions": {"dnsid-draft-01", "DNSid1"},
    },
    "ts": {
        "versions": {"dnsid-draft-01", "DNSid1"},
    },
    "py": {
        "versions": {"dnsid-draft-01", "DNSid1"},
    },
}

UNSUPPORTED_VERSION_EXPECT = {"ok": False, "error": "ParseError", "error_contains": "unsupported"}


# --- SDK adapters -----------------------------------------------------------


class SubprocessAdapter:
    """Runs a shim once, feeding all requests as a JSON array on stdin."""

    def __init__(self, name: str, cmd: list[str], env: dict[str, str] | None = None):
        self.name = name
        self.cmd = cmd
        self.env = {**os.environ, **(env or {})}

    def run(self, requests: list[dict]) -> list[dict]:
        proc = subprocess.run(
            self.cmd,
            input=json.dumps(requests),
            capture_output=True,
            text=True,
            env=self.env,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"{self.name} shim failed (exit {proc.returncode}): {proc.stderr.strip()}")
        return json.loads(proc.stdout)


class PyAdapter:
    """Runs dnsid-py in-process (it is installed in the harness venv)."""

    name = "py"

    def run(self, requests: list[dict]) -> list[dict]:
        return [self._handle(r) for r in requests]

    @staticmethod
    def _record_json(rec) -> dict:
        opt = lambda s: s or None
        return {
            "v": rec.v,
            "gi": opt(rec.gi),
            "oi": None,  # dnsid-py has no draft-00 support
            "ek": opt(rec.ek),
            "ku": opt(rec.ku),
            "lr": opt(rec.lr),
            "su": opt(rec.su),
            "sg": opt(rec.sg),
            "fl": opt(rec.fl),
            "ka": opt(rec.ka),
            "cu": opt(rec.cu),
            "unknown": dict(rec.unknown_tags),
        }

    def _handle(self, req: dict) -> dict:
        from dnsid import JWKS
        from dnsid._crypto import jwk_from_dict
        from dnsid._utils import normalize_fqdn
        from dnsid.models import DnsIdTxtRecord

        try:
            op = req["op"]
            if op == "http_signature_base":
                try:
                    from dnsid.http_signatures import _build_signature_base
                    from dnsid.models import HttpRequest, SignatureParams

                    message = HttpRequest(
                        method=req["request"]["method"],
                        url=req["request"]["url"],
                        headers=req["request"]["headers"],
                    )
                    params = SignatureParams.parse_dictionary(req["signature_input"])[req["label"]]
                    return {"ok": True, "value": _build_signature_base(message, params).decode()}
                except Exception as exc:  # noqa: BLE001
                    return {"ok": False, "error": "ConformanceError", "message": str(exc)}
            if op == "lifecycle_vector":
                return self._lifecycle_vector(req)
            if op == "c2sp_lifecycle_vector":
                return self._c2sp_lifecycle_vector(req)
            if op == "c2sp_managed_trust_select":
                return self._c2sp_managed_trust_select(req)
            if op == "sdk_conformance":
                return self._sdk_conformance()
            if op == "create_txt_record":
                return self._create_txt_record(req)
            if op == "agent_status_evaluate":
                return self._agent_status_evaluate(req)
            if op == "normalize_fqdn":
                return {"ok": True, "value": normalize_fqdn(req["name"], agent_fqdn=True)}
            if op == "jwk_thumbprint":
                return {"ok": True, "value": jwk_from_dict(req["jwk"]).thumbprint()}
            if op == "jwk_signature_alg":
                return {"ok": True, "value": jwk_from_dict(req["jwk"]).signature_alg()}
            if op.startswith("jwks_"):
                jwks = JWKS(keys=[jwk_from_dict(key) for key in req["jwks"]["keys"]])
                if op == "jwks_validate":
                    jwks.validate()
                    return {"ok": True}
                if op == "jwks_signing_keys":
                    return {"ok": True, "value": [key.kid for key in jwks.signing_keys()]}
                if op == "jwks_key_by_id":
                    key = jwks.key_by_id(req["kid"])
                    return {"ok": True, "value": key.kid if key else None}
                return {"ok": False, "error": "ShimError", "message": f"unknown op: {op}"}
            rec = DnsIdTxtRecord.parse(req["raw"])
            if op == "parse":
                return {"ok": True, "record": self._record_json(rec)}
            if op == "canonical":
                return {"ok": True, "value": rec.canonical()}
            if op == "roundtrip":
                serialized = rec.serialize()
                try:
                    rec2 = DnsIdTxtRecord.parse(serialized)
                except Exception as e:  # noqa: BLE001
                    return {"ok": False, "error": "RoundTripError", "message": f"reparse failed: {e}"}
                return {"ok": True, "record": self._record_json(rec2), "value": serialized}
            if op == "validate":
                rec.identity_fqdn = req["identity_fqdn"]
                rec.validate()
                return {"ok": True, "record": self._record_json(rec)}
            return {"ok": False, "error": "ShimError", "message": f"unknown op: {op}"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": type(e).__name__, "message": str(e)}

    @staticmethod
    def _c2sp_managed_trust_select(req: dict) -> dict:
        from dnsid.c2sp_tlog import create_dnsid_managed_verification_registry

        try:
            create_dnsid_managed_verification_registry().new_reader(req["lr"])
            return {"ok": True, "trustMode": "trust-profile"}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": "ConformanceError", "message": str(exc)}

    @staticmethod
    def _sdk_conformance() -> dict:
        from dnsid import SDK_CONFORMANCE

        immutable = False
        try:
            SDK_CONFORMANCE.publish_profile = "changed"
        except Exception:  # noqa: BLE001
            try:
                SDK_CONFORMANCE.verification_profiles["changed"] = "changed"
            except Exception:  # noqa: BLE001
                immutable = True
        return {
            "ok": True,
            "publishProfile": SDK_CONFORMANCE.publish_profile,
            "verificationProfiles": dict(SDK_CONFORMANCE.verification_profiles),
            "specificationStatus": SDK_CONFORMANCE.specification_status,
            "logBindings": dict(SDK_CONFORMANCE.log_bindings),
            "knownDeviations": list(SDK_CONFORMANCE.known_deviations),
            "immutable": immutable,
        }

    def _create_txt_record(self, req: dict) -> dict:
        import base64

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from dnsid import DnsidConfig, DnsIdTxtRecord, IdentityConfig, IdentityManager, IdentityManagerDependencies
        from dnsid._crypto import jwk_from_dict

        class KeyProvider:
            def __init__(self, fixture: dict):
                self.fixture = fixture
                self.private = Ed25519PrivateKey.from_private_bytes(
                    base64.urlsafe_b64decode(fixture["seed"] + "==")
                )
                self.public = jwk_from_dict(
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "alg": "EdDSA",
                        "use": "sig",
                        "kid": fixture["kid"],
                        "x": fixture["x"],
                    }
                )
                self.signed_payload = b""
                self.sign_calls = 0

            def signing_key(self):
                return self.public

            def jwk(self, _kid):
                return self.public

            def list_key_ids(self):
                return [self.fixture["kid"]]

            def sign(self, payload):
                self.sign_calls += 1
                self.signed_payload = payload
                return self.private.sign(payload)

        config = req["config"]
        entity = KeyProvider(req["entityKey"]) if req.get("entityKey") else None
        operational = KeyProvider(req["entityKey"] if req.get("sameKey") else req["operationalKey"])
        identity_fields = dict(
            domain=config["domain"],
            governance_id=config["governanceId"],
            log_ref=config["logRef"],
            status_url=config["statusUrl"],
            ek_url=config["ekUrl"],
            ku_url=config["kuUrl"],
            publish_profile=config.get("publishProfile", ""),
            policy_flags=config.get("policyFlags", ""),
            max_key_age=config.get("maxKeyAge", ""),
            capabilities_url=config.get("capabilitiesUrl", ""),
        )
        sdk_config = DnsidConfig(identity=IdentityConfig(**identity_fields))
        manager = IdentityManager(
            sdk_config,
            operational,
            IdentityManagerDependencies(entity_key_provider=entity),
        )
        record = DnsIdTxtRecord.parse(manager.create_txt_record())
        signature = base64.urlsafe_b64decode(record.sg + "==")
        try:
            entity.private.public_key().verify(signature, entity.signed_payload)
            entity_valid = True
        except InvalidSignature:
            entity_valid = False
        try:
            operational.private.public_key().verify(signature, entity.signed_payload)
            operational_valid = True
        except InvalidSignature:
            operational_valid = False
        return {
            "ok": True,
            "record": self._record_json(record),
            "signedPayload": entity.signed_payload.decode(),
            "signatureSource": "entity" if entity.sign_calls == 1 and operational.sign_calls == 0 else "other",
            "signatureVerified": entity_valid and not operational_valid,
        }

    @staticmethod
    def _agent_status_evaluate(req: dict) -> dict:
        from dnsid._https_client import _parse_agent_status_from_dict

        status = _parse_agent_status_from_dict(req["status"])
        status.validate()
        return {
            "ok": True,
            "state": status.state,
            "verificationAccepted": status.state == "ACTIVE",
        }

    @staticmethod
    def _lifecycle_vector(req: dict) -> dict:
        import base64
        import datetime
        import hashlib

        from dnsid._crypto import jwk_from_dict
        from dnsid.exceptions import LifecycleVerificationError
        from dnsid.models import (
            DelegationEvent,
            DomainLog,
            IssuanceEvent,
            KeyRotationEvent,
            MigrationEvent,
            RetirementEvent,
            RevocationEvent,
        )

        keys = {}
        reverse = {}

        def key(ref):
            if not ref:
                return None
            label = ref.removeprefix("jwk:")
            if label not in keys:
                raw = hashlib.sha256(label.encode()).digest()[:32]
                value = jwk_from_dict({"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": label, "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()})
                keys[label] = value
                reverse[value.thumbprint()] = label
            return keys[label]

        def dt(value):
            return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))

        events = []
        for raw in req["events"]:
            common = {"domain": raw["domain"], "timestamp": dt(raw["timestamp"])}
            type_ = raw["type"]
            if type_ == "ISSUANCE":
                event = IssuanceEvent(**common, governance_id=raw["governanceId"], entity_key=key(raw["initialEntityPublicKey"]), operational_key=key(raw["initialOperationalPublicKey"]))
            elif type_ == "KEY_ROTATION":
                previous = key("jwk:" + raw["previousOperationalThumbprint"]) if raw.get("previousOperationalThumbprint") else None
                new_thumb = key("jwk:" + raw["newOperationalThumbprint"]) if raw.get("newOperationalThumbprint") else None
                event = KeyRotationEvent(**common, previous_thumbprint=previous.thumbprint() if previous else "", new_public_key=key(raw.get("newOperationalPublicKey")), new_thumbprint=new_thumb.thumbprint() if new_thumb else "")
            elif type_ == "REVOCATION":
                event = RevocationEvent(**common, reason=raw["reason"])
            elif type_ == "RETIREMENT":
                event = RetirementEvent(**common)
            elif type_ == "MIGRATION":
                event = MigrationEvent(**common, previous_log=raw["previousLog"], new_log=raw["newLog"], final_entry_ref=raw["finalEntryRef"])
            elif type_ == "DELEGATION":
                event = DelegationEvent(**common, delegatee=raw["delegatee"], scope=raw["scope"], expiry=dt(raw["expiry"]))
            else:
                class UnsupportedEvent:
                    pass

                event = UnsupportedEvent()
                event.domain = common["domain"]
                event.timestamp = common["timestamp"]
            events.append(event)
        at = dt(req["at"]) if req.get("at") else datetime.datetime.max.replace(tzinfo=datetime.UTC)
        try:
            snapshot = DomainLog(req["domain"], events).snapshot_at(at)
            return {"ok": True, "identityState": snapshot.historical_state, "activeOperationalThumbprint": reverse.get(snapshot.active_key_thumbprint, snapshot.active_key_thumbprint), "eventCount": len(snapshot.events), "inheritedEventCount": 0, "governanceId": snapshot.governance_id, "keyBoundAt": int(snapshot.key_bound_at.timestamp())}
        except LifecycleVerificationError as exc:
            out = {"ok": False, "error": "LifecycleError", "message": str(exc), "errorCategory": str(exc.category)}
            if exc.failing_event_index is not None:
                out["failingEventIndex"] = exc.failing_event_index
            return out

    @staticmethod
    def _c2sp_lifecycle_vector(req: dict) -> dict:
        import base64

        from dnsid._crypto import jwk_from_dict
        from dnsid.c2sp_tlog import (
            C2spEventContext,
            C2spTlogError,
            IndexedEntry,
            MigrationVerificationResult,
            StreamVerifierOptions,
            parse_c2sp_policy_file,
            parse_c2sp_tlog_lr,
            verify_c2sp_tlog_proof,
            verify_stream_lifecycle,
        )
        from dnsid.models import IssuanceEvent

        if not req["checkpointAccepted"]:
            return {"ok": False, "error": "LifecycleError", "errorCategory": "INVALID_EVIDENCE", "message": "accepted checkpoint failed"}
        if not req["completeThroughCheckpoint"]:
            return {"ok": False, "error": "LifecycleError", "errorCategory": "INCOMPLETE_STREAM", "message": "stream is incomplete"}
        entries = []
        effects = {}
        ignored = []
        policy = parse_c2sp_policy_file(req["policy"])
        for item in req["entries"]:
            data = base64.urlsafe_b64decode(item["entry"] + "==")
            proof = base64.urlsafe_b64decode(item["proof"] + "==").decode()
            try:
                verified_proof = verify_c2sp_tlog_proof(
                    data,
                    proof,
                    policy,
                    origin="log.example",
                    scope="public",
                    now_ms=req["checkpointIntegrationTimeMs"],
                )
            except C2spTlogError:
                ignored.append(item["index"])
                continue
            if verified_proof.index != item["index"]:
                ignored.append(item["index"])
                continue
            entries.append(IndexedEntry(index=item["index"], data=data))
            effects[item["index"]] = item["effectId"]
        entity = jwk_from_dict(req["entityJwk"])
        operational = jwk_from_dict(req["operationalJwk"])
        prior = [IssuanceEvent(domain=req["domain"], governance_id="example", entity_key=entity, operational_key=operational)]

        def migration(_event):
            if req.get("priorHistoryVerified") is not True:
                raise ValueError("prior migration history unavailable")
            return MigrationVerificationResult(entity, operational, prior)

        parsed = parse_c2sp_tlog_lr(req["lr"])
        options = StreamVerifierOptions(
            context=C2spEventContext(scope="public", log_origin="log.example", stream_id=parsed.stream_id, lr=req["lr"]),
            signer_key=entity,
            checkpoint_integration_time_ms=req["checkpointIntegrationTimeMs"],
            verify_migration=migration if req.get("priorHistoryVerified") is not None else None,
        )
        try:
            selected = verify_stream_lifecycle(entries, req["domain"], options)
            applied_indexes = [item.index for item in selected]
            ignored.extend(item["index"] for item in req["entries"] if item["index"] not in applied_indexes and item["index"] not in ignored)
            applied = [effects[index] for index in applied_indexes]
            out = {"ok": True, "appliedEffectIds": applied, "ignoredCandidateIndexes": sorted(ignored)}
            if selected and str(selected[-1].event.event_type) in {"REVOCATION", "RETIREMENT"}:
                out["identityState"] = "REVOKED" if str(selected[-1].event.event_type) == "REVOCATION" else "RETIRED"
            if selected and str(selected[0].event.event_type) == "MIGRATION":
                out["stitchedEffectIds"] = [*req["priorAppliedEffectIds"], *applied]
            return out
        except Exception as exc:  # noqa: BLE001
            category = getattr(exc, "category", None)
            index = getattr(exc, "failing_candidate_index", None)
            out = {"ok": False, "error": "LifecycleError", "message": str(exc), "errorCategory": str(category) if category else "INVALID_MIGRATION"}
            if index is not None:
                out["failingCandidateIndex"] = index
            return out


def build_adapters(only: set[str]) -> dict:
    adapters = {}
    if "go" in only:
        shim = os.environ.get("DNSID_GO_SHIM", str(ROOT / "shims" / "go" / "dnsid-shim"))
        adapters["go"] = SubprocessAdapter("go", [shim])
    if "ts" in only:
        ts_dir = os.environ.get("DNSID_TS_DIR", str(Path.home() / "dnsid-ts"))
        adapters["ts"] = SubprocessAdapter(
            "ts", ["node", str(ROOT / "shims" / "ts" / "shim.mjs")], env={"DNSID_TS_DIR": ts_dir}
        )
    if "py" in only:
        adapters["py"] = PyAdapter()
    return adapters


# --- Fixture loading and expectation resolution ------------------------------


def load_fixtures(fixtures_dir: Path, id_filter: str | None) -> list[dict]:
    suites = []
    seen = set()  # spans all files: case ids key the result matrix globally
    for path in sorted(fixtures_dir.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text())
        cases = [c for c in doc["cases"] if not id_filter or id_filter in c["id"]]
        for c in cases:
            if c["id"] in seen:
                raise ValueError(f"duplicate case id {c['id']} in {path.name}")
            seen.add(c["id"])
        if cases:
            suites.append({"suite": doc["suite"], "path": path.name, "cases": cases})
    return suites


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def resolve_expectation(case: dict, sdk: str) -> tuple[dict, str | None]:
    """Returns (expected, kind) where kind is 'gated', 'override', or None."""
    version = case.get("version")
    if version is not None and version not in CAPABILITIES[sdk]["versions"]:
        return UNSUPPORTED_VERSION_EXPECT, "gated"
    expected = case["expect"]
    override = (case.get("sdk") or {}).get(sdk)
    if override and "expect" in override:
        return deep_merge(expected, override["expect"]), "override"
    return expected, None


# --- Comparison ---------------------------------------------------------------


def compare(expected: dict, actual: dict) -> list[str]:
    problems = []
    if bool(expected.get("ok")) != bool(actual.get("ok")):
        got = actual.get("message") or actual.get("value") or json.dumps(actual.get("record", {}))
        problems.append(f"ok: expected {expected.get('ok')}, got {actual.get('ok')} ({got})")
        return problems
    if expected.get("ok"):
        for key, want in (expected.get("record") or {}).items():
            got = (actual.get("record") or {}).get(key)
            if got != want:
                problems.append(f"record.{key}: expected {want!r}, got {got!r}")
        if "value" in expected and actual.get("value") != expected["value"]:
            problems.append(f"value: expected {expected['value']!r}, got {actual.get('value')!r}")
        for key, want in expected.items():
            if key in {"ok", "record", "value"}:
                continue
            if actual.get(key) != want:
                problems.append(f"{key}: expected {want!r}, got {actual.get(key)!r}")
    else:
        if expected.get("error") and actual.get("error") != expected["error"]:
            problems.append(
                f"error: expected {expected['error']}, got {actual.get('error')} ({actual.get('message')})"
            )
        contains = expected.get("error_contains")
        if contains and contains.lower() not in (actual.get("message") or "").lower():
            problems.append(f"error message missing {contains!r}: got {actual.get('message')!r}")
        for key, want in expected.items():
            if key in {"ok", "error", "error_contains"}:
                continue
            if actual.get(key) != want:
                problems.append(f"{key}: expected {want!r}, got {actual.get(key)!r}")
    return problems


# --- Runner -------------------------------------------------------------------


def sdk_git_sha(path: str) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", path, "rev-parse", "--short", "HEAD"], capture_output=True, text=True
        )
        return out.stdout.strip() or "?"
    except OSError:
        return "?"


def run(args) -> int:
    sdk_names = [s for s in ("go", "ts", "py") if s in args.sdks]
    adapters = build_adapters(set(sdk_names))
    suites = load_fixtures(Path(args.fixtures), args.filter)
    semantic = load_semantic_suites()
    if args.filter:
        semantic = [
            {**suite, "cases": [case for case in suite["cases"] if args.filter in case["id"]]}
            for suite in semantic
        ]
        semantic = [suite for suite in semantic if suite["cases"]]
    suites.extend(semantic)
    all_cases = [c for s in suites for c in s["cases"]]
    if not all_cases:
        print("no cases matched", file=sys.stderr)
        return 2

    requests = [{"op": c["op"], **(c.get("input") or {})} for c in all_cases]
    results = {name: adapters[name].run(requests) for name in sdk_names}
    for name in sdk_names:
        if len(results[name]) != len(requests):
            raise RuntimeError(f"{name} shim returned {len(results[name])} results for {len(requests)} requests")

    # Evaluate
    rows = []  # (suite, case, {sdk: (status, problems, note)})
    idx = 0
    for suite in suites:
        for case in suite["cases"]:
            cells = {}
            for name in sdk_names:
                expected, kind = resolve_expectation(case, name)
                problems = compare(expected, results[name][idx])
                sdk_entry = (case.get("sdk") or {}).get(name) or {}
                known_bug = sdk_entry.get("known_bug") if kind != "gated" else None
                if problems:
                    status = "XFAIL" if known_bug else "FAIL"
                elif known_bug:
                    status = "XPASS"  # marked known_bug but now passes — drop the marker
                elif kind == "gated":
                    status = "REJ"
                else:
                    status = "PASS"
                note = sdk_entry.get("note") if kind == "override" else known_bug
                cells[name] = (status, problems, note, results[name][idx])
            rows.append((suite["suite"], case, cells))
            idx += 1

    report = render_report(sdk_names, suites, rows, args)
    print(report)
    if args.out:
        Path(args.out).write_text(report)
        print(f"\nreport written to {args.out}", file=sys.stderr)

    # XPASS also fails the run: a known_bug marker whose bug is fixed is stale
    # and must be removed, or it would mask a future regression.
    return 1 if any(cells[n][0] in ("FAIL", "XPASS") for _, _, cells in rows for n in sdk_names) else 0


def render_report(sdk_names, suites, rows, args) -> str:
    counts = {n: {"PASS": 0, "REJ": 0, "FAIL": 0, "XFAIL": 0, "XPASS": 0} for n in sdk_names}
    for _, _, cells in rows:
        for n in sdk_names:
            counts[n][cells[n][0]] += 1

    sdk_dirs = {
        "go": os.environ.get("DNSID_GO_DIR", str(Path.home() / "dnsid-go")),
        "ts": os.environ.get("DNSID_TS_DIR", str(Path.home() / "dnsid-ts")),
        "py": os.environ.get("DNSID_PY_DIR", str(Path.home() / "dnsid-py")),
    }

    lines = ["# DNSid Cross-SDK Compliance Report", ""]
    lines.append(f"Run: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    for n in sdk_names:
        lines.append(f"- dnsid-{n}: `{sdk_dirs[n]}` @ `{sdk_git_sha(sdk_dirs[n])}`")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| SDK | Pass | Rejected unsupported | Known bugs | Fail | Total | Compliance |")
    lines.append("|-----|------|----------------------|------------|------|-------|------------|")
    total = len(rows)
    for n in sdk_names:
        c = counts[n]
        passing = c["PASS"] + c["XPASS"]
        compliant = passing + c["REJ"]
        pct = (compliant * 100 / total) if total else 0
        lines.append(
            f"| {n} | {passing} | {c['REJ']} | {c['XFAIL']} | {c['FAIL']} | {total} | "
            f"{compliant}/{total} ({pct:.1f}%) |"
        )
    lines.append("")
    lines.append("`PASS` = matched expected behavior. `REJ` = record version not supported by this SDK;")
    lines.append("the SDK correctly rejected it as unsupported (fail-closed). `XFAIL` = known bug, the")
    lines.append("fixture encodes the spec-correct behavior and the SDK is known not to meet it yet.")
    lines.append("`FAIL` = unexpected mismatch, see details.")
    lines.append("")

    for suite in suites:
        lines.append(f"## Suite: {suite['suite']} ({suite['path']})")
        lines.append("")
        lines.append("| Case | " + " | ".join(sdk_names) + " |")
        lines.append("|------|" + "|".join(["------"] * len(sdk_names)) + "|")
        for s_name, case, cells in rows:
            if s_name != suite["suite"]:
                continue
            marks = []
            for n in sdk_names:
                status = cells[n][0]
                mark = {
                    "PASS": "PASS",
                    "REJ": "REJ",
                    "FAIL": "**FAIL**",
                    "XFAIL": "XFAIL",
                    "XPASS": "**XPASS**",
                }[status]
                if cells[n][2]:  # divergence or known-bug note applied
                    mark += " †"
                marks.append(mark)
            lines.append(f"| `{case['id']}` | " + " | ".join(marks) + " |")
        lines.append("")

    failures = [
        (case, n, cells[n])
        for _, case, cells in rows
        for n in sdk_names
        if cells[n][0] == "FAIL"
    ]
    if failures:
        lines.append("## Failures")
        lines.append("")
        for case, n, (status, problems, _, actual) in failures:
            lines.append(f"### `{case['id']}` — {n}")
            lines.append("")
            lines.append(f"- {case['description']} ({case.get('spec_ref', 'no spec ref')})")
            case_input = case.get("input") or {}
            display_input = case_input.get("raw") or case_input.get("name") or json.dumps(case_input)
            lines.append(f"- input: `{display_input}`")
            for p in problems:
                lines.append(f"- {p}")
            lines.append("")

    known_bugs = [
        (case, n, cells[n])
        for _, case, cells in rows
        for n in sdk_names
        if cells[n][0] in ("XFAIL", "XPASS")
    ]
    if known_bugs:
        lines.append("## Known bugs (XFAIL)")
        lines.append("")
        lines.append("The fixture encodes the spec-correct behavior; these SDKs are known not to meet it yet.")
        lines.append("")
        for case, n, (status, problems, note, _) in known_bugs:
            suffix = " — **now passes, remove the known_bug marker**" if status == "XPASS" else ""
            lines.append(f"- `{case['id']}` ({n}): {note}{suffix}")
            for p in problems:
                lines.append(f"  - {p}")
        lines.append("")

    divergences = [
        (case, n, cells[n][2])
        for _, case, cells in rows
        for n in sdk_names
        if cells[n][2] and cells[n][0] in ("PASS", "FAIL")
    ]
    if divergences:
        lines.append("## Documented divergences (†)")
        lines.append("")
        lines.append("Cases where a per-SDK expectation override was applied:")
        lines.append("")
        for case, n, note in divergences:
            lines.append(f"- `{case['id']}` ({n}): {note}")
        lines.append("")

    lines.append("## Suite summary")
    lines.append("")
    lines.append("Compliance counts `PASS` plus fail-closed `REJ`; known bugs and failures are shown separately.")
    lines.append("")
    lines.append("| Suite | " + " | ".join(sdk_names) + " |")
    lines.append("|-------|" + "|".join(["-------"] * len(sdk_names)) + "|")
    for suite in suites:
        suite_rows = [(case, cells) for s_name, case, cells in rows if s_name == suite["suite"]]
        total = len(suite_rows)
        cells_out = []
        for n in sdk_names:
            c = {"PASS": 0, "REJ": 0, "FAIL": 0, "XFAIL": 0, "XPASS": 0}
            for _, cells in suite_rows:
                c[cells[n][0]] += 1
            compliant = c["PASS"] + c["XPASS"] + c["REJ"]
            pct = (compliant * 100 / total) if total else 0
            details = []
            if c["FAIL"]:
                details.append(f"{c['FAIL']} fail")
            if c["XFAIL"]:
                details.append(f"{c['XFAIL']} known")
            suffix = f"; {', '.join(details)}" if details else ""
            cells_out.append(f"{compliant}/{total} ({pct:.1f}%){suffix}")
        lines.append(f"| {suite['suite']} | " + " | ".join(cells_out) + " |")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description="DNSid cross-SDK compliance harness")
    p.add_argument("--sdks", default="go,ts,py", help="comma-separated subset of go,ts,py")
    p.add_argument("--fixtures", default=str(ROOT / "fixtures"))
    p.add_argument("--filter", help="only run cases whose id contains this substring")
    p.add_argument("--out", help="write the markdown report to this file")
    args = p.parse_args()
    args.sdks = set(args.sdks.split(","))
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
