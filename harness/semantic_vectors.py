"""Load lifecycle semantics and checked-in C2SP protocol evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFORMANCE_DIR = ROOT / "docs" / "sdk-design" / "conformance"
EVIDENCE = ROOT / "fixtures" / "c2sp-lifecycle-selection-logical-v1.json"
# Per-SDK XFAIL markers for lifecycle and selection vectors; kept out of the
# language-neutral conformance JSON so SDK status never changes its hashes.
KNOWN_BUGS = Path(__file__).resolve().parent / "semantic_known_bugs.json"


def load_known_bugs(case_ids: set[str], path: Path = KNOWN_BUGS) -> dict[str, dict]:
    """Return {case_id: {sdk: {"known_bug": reason}}}; unknown or repeated IDs fail."""
    markers: dict[str, dict] = {}
    for sdk, groups in json.loads(path.read_text()).items():
        if sdk not in {"go", "ts", "py"}:
            raise ValueError(f"unknown SDK in {path.name}: {sdk}")
        for group in groups:
            reason = group["reason"]
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError(f"{path.name}: {sdk} marker needs a reason")
            for case_id in group["cases"]:
                if case_id not in case_ids:
                    raise ValueError(f"{path.name}: unknown case {case_id}")
                if sdk in markers.setdefault(case_id, {}):
                    raise ValueError(f"{path.name}: repeated {sdk} marker for {case_id}")
                markers[case_id][sdk] = {"known_bug": reason}
    return markers


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
    known_bugs = load_known_bugs(
        {case["id"] for case in lifecycle["cases"]} | expected_ids
    )
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
            "sdk": known_bugs.get(case["id"], {}),
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
                    "sdk": known_bugs.get(case["id"], {}),
                }
                for case in selection["cases"]
            ],
        },
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
    loaded = {Path(suite["path"]).name for suite in suites}
    # Hash primitives run separately in c2sp_event_identity_check.py, not SDK adapters.
    loaded.add("c2sp-event-identity.json")
    # WBA signing/verification cases are loaded by wba_vectors.py.
    loaded.add("web-bot-auth.json")
    available = {path.name for path in CONFORMANCE_DIR.glob("*.json")}
    if loaded != available:
        raise ValueError(f"unhandled conformance vectors: {sorted(available - loaded)}")
    return suites


def _expect(value: dict) -> dict:
    out = dict(value)
    out["ok"] = out.pop("valid")
    if not out["ok"]:
        out["error"] = "LifecycleError"
    return out
