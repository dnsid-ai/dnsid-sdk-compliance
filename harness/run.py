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
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml

from py_adapter import PyAdapter
from semantic_vectors import load_semantic_suites
from negotiated_vectors import CAPABILITY as NEGOTIATED_CAPABILITY
from negotiated_vectors import check_prepare_output, check_sign_output, load_negotiated_suite
from wba_vectors import check_signed_output, load_wba_suite

ROOT = Path(__file__).resolve().parent.parent

# Per-SDK capabilities. A case tagged with a `version` outside an SDK's set is
# not skipped: the harness asserts the SDK *rejects* the record as an
# unsupported version (status REJ). Unsupported versions must fail closed.
CAPABILITIES = {
    "go": {
        "directory_cache": False,
        "versions": {"dnsid-draft-01", "DNSid1"},
    },
    "ts": {
        "directory_cache": False,
        "versions": {"dnsid-draft-01", "DNSid1"},
    },
    "py": {
        "directory_cache": False,
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
        # Keep stream crashes visible per case without losing the full report.
        if self.name == "ts" and len(requests) > 1:
            native = [i for i, req in enumerate(requests) if req["op"] == "wba_verify_request"]
            if native:
                ordinary = [i for i, req in enumerate(requests) if req["op"] != "wba_verify_request"]
                results = [None] * len(requests)
                if ordinary:
                    for i, result in zip(ordinary, self.run([requests[i] for i in ordinary])):
                        results[i] = result
                for i in native:
                    try:
                        results[i] = self.run([requests[i]])[0]
                    except (RuntimeError, ValueError, IndexError) as exc:
                        results[i] = {"ok": False, "error": "AdapterError", "message": str(exc)}
                return results
        proc = subprocess.run(
            self.cmd,
            input=json.dumps(requests),
            capture_output=True,
            text=True,
            env=self.env,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"{self.name} shim failed (exit {proc.returncode}): {proc.stderr.strip()}")
        results = json.loads(proc.stdout)
        if not isinstance(results, list) or len(results) != len(requests) or any(
            not isinstance(result, dict) for result in results
        ):
            raise RuntimeError(f"{self.name} shim returned malformed results")
        if self.name == "go":
            from wba_adapters import verify_go

            indices = [i for i, result in enumerate(results) if requests[i]["op"] == "wba_verify_request" and result.get("error") == "NativeAdapterRequired"]
            if indices:
                native = verify_go([requests[i] for i in indices])
                for i, result in zip(indices, native):
                    results[i] = result
        return results


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
    if "uncachedExpect" in case and not CAPABILITIES[sdk]["directory_cache"]:
        return case["uncachedExpect"], "uncached"
    override = (case.get("sdk") or {}).get(sdk)
    if override and "expect" in override:
        return deep_merge(expected, override["expect"]), "override"
    return expected, None


# --- Comparison ---------------------------------------------------------------


def compare(expected: dict, actual: dict) -> list[str]:
    problems = []
    if type(actual.get("ok")) is not bool:
        return ["SDK result lacks an explicit boolean ok field"]
    if actual.get("error") in {"AdapterError", "ShimError"}:
        return [f"adapter failure: {actual.get('message')}"]
    if expected.get("ok") is False and not expected.get("error"):
        return ["rejection expectation must name an error class"]
    if bool(expected.get("ok")) != bool(actual.get("ok")):
        got = actual.get("message") or actual.get("value") or json.dumps(actual.get("record", {}))
        problems.append(f"ok: expected {expected.get('ok')}, got {actual.get('ok')} ({got})")
        return problems
    if expected.get("ok"):
        if "publishProfile" in expected:
            deviations = actual.get("knownDeviations")
            if not isinstance(deviations, list) or any(
                not isinstance(item, str) or not item.strip() for item in deviations
            ):
                problems.append("knownDeviations: expected a list of non-empty strings")
        for key, want in (expected.get("record") or {}).items():
            got = (actual.get("record") or {}).get(key)
            if got != want:
                problems.append(f"record.{key}: expected {want!r}, got {got!r}")
    else:
        if expected.get("error") and actual.get("error") != expected["error"]:
            problems.append(
                f"error: expected {expected['error']}, got {actual.get('error')} ({actual.get('message')})"
            )
        contains = expected.get("error_contains")
        if contains and contains.lower() not in (actual.get("message") or "").lower():
            problems.append(f"error message missing {contains!r}: got {actual.get('message')!r}")
    special = {"ok", "record"} if expected.get("ok") else {"ok", "error", "error_contains"}
    for key, want in expected.items():
        if key not in special and actual.get(key) != want:
            problems.append(f"{key}: expected {want!r}, got {actual.get(key)!r}")
    return problems


def evaluate_result(case: dict, sdk: str, actual: dict) -> tuple:
    expected, kind = resolve_expectation(case, sdk)
    if case["op"] == "wba_verify_request" and actual == {
        "ok": False, "error": "CapabilityMissing", "capability": "wba_request_verification",
        "message": "SDK has signing/directory serving only",
    }:
        return ("MISSING", [], actual["message"], actual)
    if actual.get("error") == "CapabilityMissing" and actual.get("capability") in {NEGOTIATED_CAPABILITY, "c2sp_migration_recursion"}:
        return ("MISSING", [], actual.get("message"), actual)
    problems = compare(expected, actual)
    # A finite parser budget may reject evidence; it must not ignore it.
    if case.get("fail_closed_allowed") and actual.get("ok") is False and actual.get("error") == "LifecycleError":
        problems = []
    if case["op"] == "c2sp_checkpoint_vector":
        # Taxonomy gaps must not hide acceptance, state changes, or lost injected causes.
        invariants = {key: value for key, value in expected.items()
                      if key in {"ok", "error", "stored", "causePreserved", "proofRequested"}}
        if actual.get("error") in {"AdapterError", "ShimError"} or compare(invariants, actual):
            return ("FAIL", problems or ["checkpoint adapter failed"], None, actual)
    sdk_entry = (case.get("sdk") or {}).get(sdk) or {}
    known_bug = sdk_entry.get("known_bug") if kind != "gated" else None
    if problems:
        status = "XFAIL" if known_bug and actual.get("error") not in {"AdapterError", "ShimError"} else "FAIL"
    elif known_bug:
        status = "XPASS"
    elif kind == "gated":
        status = "REJ"
    else:
        status = "PASS"
    note = sdk_entry.get("note") if kind == "override" else known_bug
    if kind == "uncached":
        note = "Directory caching is not implemented; two fresh discoveries are required instead."
    return (status, problems, note, actual)


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
    semantic = [*load_semantic_suites(), load_wba_suite(), load_negotiated_suite()]
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

    ids = [case["id"] for case in all_cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case ids across fixture suites")
    requests = [{"op": c["op"], **(c.get("input") or {})} for c in all_cases]
    started = int(time.time())
    results = {name: adapters[name].run(requests) for name in sdk_names}
    finished = int(time.time())
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
                actual = results[name][idx]
                if case["op"] == "wba_sign":
                    actual = check_signed_output(case["input"], actual, started, finished)
                elif case["op"] == "negotiated_response_sign":
                    actual = check_sign_output(case["input"], actual, started, finished)
                elif case["op"] == "negotiated_response_prepare":
                    actual = check_prepare_output(case["input"], actual)
                cells[name] = evaluate_result(case, name, actual)
            rows.append((suite["suite"], case, cells))
            idx += 1

    report = render_report(sdk_names, suites, rows)
    print(report)
    if args.out:
        Path(args.out).write_text(report)
        print(f"\nreport written to {args.out}", file=sys.stderr)

    # XPASS also fails the run: a known_bug marker whose bug is fixed is stale
    # and must be removed, or it would mask a future regression.
    return 1 if any(cells[n][0] in ("FAIL", "XPASS") for _, _, cells in rows for n in sdk_names) else 0


def render_report(sdk_names, suites, rows) -> str:
    suite_rows = {suite["suite"]: [] for suite in suites}
    for suite, case, cells in rows:
        suite_rows[suite].append((case, cells))
    counts = {n: Counter(cells[n][0] for _, _, cells in rows) for n in sdk_names}
    details = [(case, n, cells[n]) for _, case, cells in rows for n in sdk_names]

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
    lines.append("| SDK | Pass | Rejected unsupported | Known bugs | Fail | Total | Compliance | Missing |")
    lines.append("|-----|------|----------------------|------------|------|-------|------------|---------|")
    total = len(rows)
    for n in sdk_names:
        c = counts[n]
        passing = c["PASS"] + c["XPASS"]
        compliant = passing + c["REJ"]
        pct = (compliant * 100 / total) if total else 0
        lines.append(
            f"| {n} | {passing} | {c['REJ']} | {c['XFAIL']} | {c['FAIL']} | {total} | "
            f"{compliant}/{total} ({pct:.1f}%) | {c['MISSING']} |"
        )
    lines.append("")
    lines.append("`PASS` = matched expected behavior. `REJ` = record version not supported by this SDK;")
    lines.append("the SDK correctly rejected it as unsupported (fail-closed). `XFAIL` = known bug, the")
    lines.append("fixture encodes the spec-correct behavior and the SDK is known not to meet it yet.")
    lines.append("`FAIL` = unexpected mismatch, see details. `MISSING` = no integrated WBA verifier,")
    lines.append("negotiated response API or built-in recursive migration verification;")
    lines.append("the case did not execute and is not compliant. Missing capabilities do not fail the run.")
    lines.append("")

    for suite in suites:
        lines.append(f"## Suite: {suite['suite']} ({suite['path']})")
        lines.append("")
        lines.append("| Case | " + " | ".join(sdk_names) + " |")
        lines.append("|------|" + "|".join(["------"] * len(sdk_names)) + "|")
        for case, cells in suite_rows[suite["suite"]]:
            marks = []
            for n in sdk_names:
                status = cells[n][0]
                mark = f"**{status}**" if status in {"FAIL", "XPASS"} else status
                if cells[n][2] and status != "MISSING":  # divergence or known-bug note applied
                    mark += " †"
                marks.append(mark)
            lines.append(f"| `{case['id']}` | " + " | ".join(marks) + " |")
        lines.append("")

    failures = [(case, n, result) for case, n, result in details if result[0] == "FAIL"]
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

    if any(c["MISSING"] for c in counts.values()):
        lines.extend(["## Missing capabilities", "", "WBA request/directory verification is not shipped in the tested signing-only bindings.",
                      "Negotiated response vectors report MISSING for SDKs without the negotiated response APIs.",
                      "Migration-chain vectors report MISSING for SDKs whose reader cannot verify prior logs itself.",
                      "Positive and negative verifier vectors remain unexecuted. Integrate native verifier adapters",
                      "when each SDK ships verification; these results are not end-to-end WBA conformance.", ""])

    known_bugs = [(case, n, result) for case, n, result in details if result[0] in {"XFAIL", "XPASS"}]
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

    divergences = [(case, n, result[2]) for case, n, result in details
                   if result[2] and result[0] in {"PASS", "FAIL"}]
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
        cases = suite_rows[suite["suite"]]
        total = len(cases)
        cells_out = []
        for n in sdk_names:
            c = Counter(cells[n][0] for _, cells in cases)
            compliant = c["PASS"] + c["XPASS"] + c["REJ"]
            pct = (compliant * 100 / total) if total else 0
            details = []
            if c["FAIL"]:
                details.append(f"{c['FAIL']} fail")
            if c["XFAIL"]:
                details.append(f"{c['XFAIL']} known")
            if c["MISSING"]:
                details.append(f"{c['MISSING']} missing")
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
