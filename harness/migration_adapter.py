"""Run MIGRATION chains through Python's C2SP readers; prior logs are resolved by migration_reader_factory."""

import base64
import datetime


def verify_python(case: dict) -> dict:
    from dnsid._crypto import jwk_from_dict
    from dnsid.c2sp_tlog import (
        C2spMigrationVerificationLimits, C2spResourceFetchGuarantees, C2spTlogError, C2spTlogReader,
        C2spTlogReaderOptions, IndexedEntry, StreamEvidence, parse_c2sp_policy_file, parse_checkpoint,
    )
    from dnsid.exceptions import DNSidError

    entity = jwk_from_dict(case["entityJwk"])
    logs = {log["lr"]: log for log in case["logs"]}
    domain = case["domain"]

    def reader(lr, limits=None):
        log = logs[lr]

        class Source:
            def security_guarantees(self):
                # Fixture-only source performs no network I/O.
                return C2spResourceFetchGuarantees(True, True, True, True, True)

            def load_stream(self, _reference, _domain):
                return StreamEvidence(
                    checkpoint=parse_checkpoint(log["checkpoint"]), checkpoint_bytes=log["checkpoint"].encode(),
                    complete=True, completeness_mode="full-scan",
                    entries=[IndexedEntry(index=e["index"], data=base64.urlsafe_b64decode(e["entry"] + "=="))
                             for e in log["entries"]],
                )

        extra = {"migration_limits": limits} if limits else {}
        # The fixture clock is in the past; freshness is not under test here.
        return C2spTlogReader(lr, C2spTlogReaderOptions(
            policy=parse_c2sp_policy_file(log["policy"]), source=Source(), entity_key=entity,
            checkpoint_freshness_ms=10**13, migration_reader_factory=reader, **extra,
        ))

    def at(seconds):
        return datetime.datetime.fromtimestamp(seconds, tz=datetime.UTC)

    lr = case["logs"][case["target"]]["lr"]
    limits = C2spMigrationVerificationLimits(max_depth=case["maxDepth"]) if case.get("maxDepth") else None
    target = reader(lr, limits)
    errors = (C2spTlogError, DNSidError)
    try:
        events = target.rebuild_history(domain)
    except errors as exc:
        return {"ok": False, "error": "LifecycleError", "message": str(exc)}
    out = {"ok": True, "eventCount": len(events)}
    try:
        out["keyTimestamp"] = int(target.key_timestamp(domain, case["operationalThumbprint"]).timestamp())
    except errors as exc:
        out["keyTimestamp"] = f"error: {exc}"
    try:
        out["loggedState"] = str(target.verify_non_revocation(domain, at(case["at"])).logged_state)
    except errors as exc:
        out["loggedState"] = f"error: {exc}"
    try:
        target.verify_non_revocation(domain, at(case["beforeGenesis"]))
        out["beforeGenesisRejected"] = False
    except errors:
        out["beforeGenesisRejected"] = True
    try:
        cutoff = target.rebuild_history_through(
            domain, f"{lr}@0", entity, max_depth=8, max_events=10_000, max_response_bytes=8 << 20,
            seen_log_references=frozenset(),
        )
        out["cutoffEventCount"] = len(cutoff.events)
    except errors as exc:
        out["cutoffEventCount"] = f"error: {exc}"
    return out
