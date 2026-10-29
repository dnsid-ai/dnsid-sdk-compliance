"""Load lifecycle semantics and checked-in C2SP protocol evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import context_chain
import nested_revocation
import selection_enumeration


ROOT = Path(__file__).resolve().parents[1]
CONFORMANCE_DIR = ROOT / "docs" / "sdk-design" / "conformance"
EVIDENCE = ROOT / "fixtures" / "c2sp-lifecycle-selection-logical-v1.json"


def load_semantic_suites() -> list[dict]:
    http_signatures = json.loads((CONFORMANCE_DIR / "http-message-signatures.json").read_text())
    lifecycle = json.loads((CONFORMANCE_DIR / "lifecycle-transitions.json").read_text())
    selection_path = CONFORMANCE_DIR / "c2sp-lifecycle-selection.json"
    selection_bytes = selection_path.read_bytes()
    selection = json.loads(selection_bytes)
    managed = json.loads((CONFORMANCE_DIR / "c2sp-managed-trust-selection.json").read_text())
    evidence_suite = json.loads(EVIDENCE.read_text())
    source_sha256 = hashlib.sha256(selection_bytes).hexdigest()
    if evidence_suite.get("semantic_source_sha256") != source_sha256:
        raise ValueError("C2SP selection evidence is stale for its semantic source")
    evidence = evidence_suite["cases"]
    expected_ids = {case["id"] for case in selection["cases"]}
    if evidence.keys() != expected_ids:
        raise ValueError("C2SP selection evidence does not match the semantic cases")
    lifecycle_cases = [
        {
            "id": case["id"],
            "description": case["id"],
            "spec_ref": "SDK design 06 lifecycle reducer",
            "op": "lifecycle_vector",
            "input": {
                "domain": lifecycle["domain"],
                "operation": case["operation"],
                "at": case.get("at"),
                "events": [
                    lifecycle["eventFixtures"][name] for name in case["events"]
                ],
            },
            "expect": _expect(case["expected"]),
        }
        for case in lifecycle["cases"]
    ]
    http_signature_cases = []
    for case in http_signatures["cases"]:
        expected = (
            {"ok": False, "error": "ConformanceError"}
            if "expectedError" in case
            else {"ok": True, "value": case["expectedBase"]}
        )
        sdk = {
            name: {"known_bug": reason}
            for name, reason in case.get("knownBugs", {}).items()
        }
        http_signature_cases.append(
            {
                "id": case["id"],
                "description": case["description"],
                "spec_ref": case["specRef"],
                "op": "http_signature_base",
                "input": {
                    "request": case["request"],
                    "signature_input": case["signatureInput"],
                    "label": case["label"],
                },
                "expect": expected,
                "sdk": sdk,
            }
        )
    suites = [
        {
            "suite": "http-message-signatures",
            "path": "docs/sdk-design/conformance/http-message-signatures.json",
            "cases": http_signature_cases,
        },
        {
            "suite": "lifecycle-transitions",
            "path": "docs/sdk-design/conformance/lifecycle-transitions.json",
            "cases": lifecycle_cases,
        },
        {
            "suite": "c2sp-lifecycle-selection",
            "path": "docs/sdk-design/conformance/c2sp-lifecycle-selection.json",
            "cases": [
                {
                    "id": case["id"],
                    "description": case["id"],
                    "spec_ref": "C2SP tlog method d5a65d06f76eff4db81e50f8767a600d2ca7fc2a: logical identity, chain metadata, and stream completeness",
                    "op": "c2sp_lifecycle_vector",
                    "input": evidence[case["id"]],
                    "expect": _expect(case["expected"]),
                    "sdk": {name: {"known_bug": reason} for name, reason in case.get("knownBugs", {}).items()},
                }
                for case in selection["cases"]
            ],
        },
        _generated("c2sp-selection-enumeration", selection_enumeration, "C2SP tlog method section 13: candidate selection"),
        _generated("c2sp-nested-revocation", nested_revocation, "C2SP tlog method sections 5, 7-8: unknown signed fields"),
        _generated("c2sp-context-chain", context_chain, "C2SP tlog method sections 5, 7, 13.2: signed context and chain"),
        {
            "suite": "c2sp-managed-trust-selection",
            "path": "docs/sdk-design/conformance/c2sp-managed-trust-selection.json",
            "cases": [
                {
                    "id": case["id"],
                    "description": case["id"],
                    "spec_ref": "C2SP tlog managed trust selection",
                    "op": "c2sp_managed_trust_select",
                    "input": {"lr": case["lr"]},
                    "expect": (
                        {"ok": True, "trustMode": case["expected"]["trustMode"]}
                        if case["expected"]["accepted"]
                        else {"ok": False, "error": "ConformanceError"}
                    ),
                }
                for case in managed["cases"]
            ],
        },
    ]
    loaded = {Path(suite["path"]).name for suite in suites if suite["path"].startswith("docs/")}
    # Hash primitives run separately in c2sp_event_identity_check.py, not SDK adapters.
    loaded.add("c2sp-event-identity.json")
    # WBA signing/verification cases are loaded by wba_vectors.py.
    loaded.add("web-bot-auth.json")
    # Negotiated response cases are loaded by negotiated_vectors.py.
    loaded.add("negotiated-response-signatures.json")
    available = {path.name for path in CONFORMANCE_DIR.glob("*.json")}
    if loaded != available:
        raise ValueError(f"unhandled conformance vectors: {sorted(available - loaded)}")
    return suites


def _generated(suite: str, module, spec_ref: str) -> dict:
    """Signed lifecycle cases built in memory by a harness module."""
    return {
        "suite": suite,
        "path": f"harness/{module.__name__}.py",
        "cases": [
            {"id": case["id"], "description": case.get("description", case["id"]), "spec_ref": spec_ref,
             "op": "c2sp_lifecycle_vector", "input": case["evidence"], "expect": _expect(case["expected"]),
             **{key: case[key] for key in ("sdk", "fail_closed_allowed") if key in case}}
            for case in module.load_cases()
        ],
    }


def _expect(value: dict) -> dict:
    out = dict(value)
    out["ok"] = out.pop("valid")
    if not out["ok"]:
        out["error"] = "LifecycleError"
    return out
