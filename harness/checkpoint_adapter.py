"""Run signed checkpoint sequences through Python's public C2SP verifiers."""

import base64


def verify_python(case: dict) -> dict:
    if case.get("mode") not in {"scan", "proof", "missing"} or case.get("fault") not in {None, "load", "write", "proof-fetch"}:
        return {"ok": False, "error": "AdapterError", "message": "unknown checkpoint mode/fault"}

    from dnsid._crypto import jwk_from_dict
    from dnsid.exceptions import VerificationError
    from dnsid.c2sp_tlog import (
        C2spTlogReader, C2spTlogReaderOptions, C2spStreamBundleVerifierOptions,
        parse_c2sp_policy_file, parse_c2sp_tlog_lr, parse_signed_note_verifier_key, verify_c2sp_stream_bundle,
    )
    from dnsid.c2sp_tlog.checkpoint import parse_checkpoint
    from dnsid.c2sp_tlog.checkpoint_store import InMemoryCheckpointStore
    from dnsid.c2sp_tlog.errors import (
        C2spCheckpointConsistencyError, C2spCheckpointStoreError, C2spTlogError,
        C2spTlogTransportError,
    )
    # shortcut: missing-evidence subtype is private, use a public classifier when supplied.
    from dnsid.c2sp_tlog.stream_bundle import _MissingC2spConsistencyEvidenceError
    from dnsid.c2sp_tlog.stream_source import IndexedEntry, StreamEvidence
    from dnsid.c2sp_tlog.resource_fetcher import C2spResourceFetchGuarantees

    def decode(value):
        return base64.urlsafe_b64decode(value + "==")

    def encode(value):
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    fault = None
    sentinel = OSError("injected checkpoint dependency failure")
    proof_requests = 0

    class Store(InMemoryCheckpointStore):
        def verify_and_advance(self, candidate, verify):
            def checked(current):
                if fault == "load":
                    raise C2spCheckpointStoreError("injected load failure") from sentinel
                verify(current)
                if fault == "write":
                    raise C2spCheckpointStoreError("injected write failure") from sentinel
            super().verify_and_advance(candidate, checked)

    store = Store()

    class ProofSource:
        def fetch_consistency_proof(self, reference, from_size, to_size):
            nonlocal proof_requests
            proof_requests += 1
            if fault == "proof-fetch":
                raise C2spTlogTransportError("injected fetch failure", transient=True, cause=sentinel)
            return [decode(node) for node in case["proof"]]

    def verify(evidence, mode="scan", scan=None):
        if mode in {"proof", "missing"}:
            verify_c2sp_stream_bundle(evidence["bundle"].encode(), C2spStreamBundleVerifierOptions(
                policy_bytes=case["policy"].encode(),
                bundle_keys=[parse_signed_note_verifier_key(case["bundleVerifierKey"])],
                entity_key=jwk_from_dict(case["entityJwk"]),
                checkpoint_freshness_ms=120_000, max_bundle_lifetime_ms=300_000,
                max_bundle_bytes=128 * 1024, max_events=16, now=lambda: case["now"],
                checkpoint_store=store, consistency_source=ProofSource() if mode == "proof" else None,
            ))
            return

        class Source:
            def security_guarantees(self):
                # Fixture-only source performs no network I/O.
                return C2spResourceFetchGuarantees(True, True, True, True, True)

            def load_stream(self, reference, fqdn):
                return StreamEvidence(
                    checkpoint=parse_checkpoint(evidence["checkpoint"]),
                    checkpoint_bytes=evidence["checkpoint"].encode(), complete=True,
                    entries=[IndexedEntry(index=item["index"], data=decode(item["entry"]))
                             for item in (evidence["entries"] if scan is None else scan)],
                    completeness_mode="full-scan",
                )

        C2spTlogReader(case["lr"], C2spTlogReaderOptions(
            policy=parse_c2sp_policy_file(case["policy"]), source=Source(),
            entity_key=jwk_from_dict(case["entityJwk"]), checkpoint_store=store,
        )).rebuild_history(case["domain"])

    try:
        if case["trusted"] is not None:
            verify(case["trusted"])
    except Exception as exc:
        return {"ok": False, "error": "AdapterError", "message": f"trusted seed failed: {exc}"}

    fault = case.get("fault")
    result = {"ok": True}
    try:
        verify(case["candidate"], case["mode"], case["scanEntries"])
    except Exception as exc:
        chain = []
        current = exc
        while current is not None and all(current is not seen for seen in chain):
            chain.append(current)
            current = current.__cause__
        recognized = isinstance(exc, (C2spTlogError, VerificationError))
        result = dict(ok=False, error="CheckpointError" if recognized else "AdapterError", message=str(exc))
        result["errorCategory"] = (getattr(exc, "category", None) or "INVALID_EVIDENCE") if recognized else None
        result["transient"] = bool(getattr(exc, "transient", False)) if recognized else None
        result["causePreserved"] = any(item is sentinel for item in chain)
        for item in chain:
            if isinstance(item, _MissingC2spConsistencyEvidenceError):
                result["condition"] = "consistency_unavailable"
            if isinstance(item, C2spCheckpointConsistencyError):
                result["diagnostics"] = dict(
                    origin=item.origin, trustedTreeSize=item.trusted_tree_size,
                    observedTreeSize=item.observed_tree_size,
                    trustedRootHash=encode(item.trusted_root_hash),
                    observedRootHash=encode(item.observed_root_hash),
                )
    # Read the native store without the injected failure; never infer state from the verdict.
    stored = store.get(parse_c2sp_tlog_lr(case["lr"]).origin)
    result["stored"] = None if stored is None else dict(
        origin=stored.origin, treeSize=stored.tree_size, rootHash=encode(stored.root_hash),
        witnessTime=int(stored.witness_time.timestamp()),
    )
    result["proofRequests"] = proof_requests
    result["proofRequested"] = proof_requests > 0
    return result
