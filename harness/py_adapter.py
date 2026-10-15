"""In-process dnsid-py adapter and disposable fixture signing keys."""

from __future__ import annotations


class FixtureKeyProvider:
    def __init__(self, fixture: dict):
        import base64

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from dnsid._crypto import jwk_from_dict

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
        self.next_provider = None

    def signing_key(self):
        return self.public

    def jwk(self, _kid):
        return self.public

    def list_key_ids(self):
        return [self.fixture["kid"]]

    def sign(self, payload):
        if self.next_provider is not None:
            next_key = self.next_provider
            self.fixture, self.private, self.public = next_key.fixture, next_key.private, next_key.public
            self.next_provider = None
        self.sign_calls += 1
        self.signed_payload = payload
        return self.private.sign(payload)


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
            if op in {"wba_sign", "wba_verify_request"}:
                return self._wba(req)
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
            if op == "c2sp_checkpoint_vector":
                from checkpoint_adapter import verify_python

                return verify_python(req["checkpointCase"])
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
    def _wba(req: dict) -> dict:
        import base64

        import dnsid
        from dnsid import wba_signer as wba
        from dnsid.models import HttpRequest

        if req["op"] == "wba_verify_request":
            if hasattr(dnsid, "WBAHttpVerifier"):
                from wba_adapters import verify_python

                return verify_python(req)
            return {"ok": False, "error": "CapabilityMissing", "capability": "wba_request_verification", "message": "SDK has signing/directory serving only"}
        key = FixtureKeyProvider(req["key"])
        if req.get("signingKeyChange"):
            key.next_provider = FixtureKeyProvider(req["signingKeyChange"])
        config = req.get("webBotAuth", {})
        agent = config.get("signatureAgent", {})
        cfg = wba.WebBotAuthConfig(
            signature_agent_uri=agent.get("uri", ""),
            signature_agent_type=agent.get("type", "directory"),
            include_signature_agent=config.get("includeSignatureAgent", True),
            signature_ttl=config.get("signatureTTL", 60),
            directory_signature_ttl=config.get("directorySignatureTTL", 300),
        )
        raw = req["request"]
        body = base64.b64decode(raw["bodyBase64"], validate=True) if raw.get("bodyBase64") is not None else None
        message = HttpRequest(method=raw["method"], url=raw["url"], headers=dict(raw["headers"]), body=body)
        if req["operation"] == "directory":
            result = wba.serve_http_message_signatures_directory(message, key, cfg)
            output = {"status": result.status, "headers": result.headers, "bodyBase64": base64.b64encode(result.body).decode()}
        else:
            opts = req.get("options", {})
            signer = wba.WBAHttpSigner(key, req["domain"], config=cfg, ku_url=req.get("localKu", ""))
            mutation = req.get("configMutation", {})
            if "includeSignatureAgent" in mutation:
                cfg.include_signature_agent = mutation["includeSignatureAgent"]
            if "signatureAgent" in mutation:
                cfg.signature_agent_uri = mutation["signatureAgent"]["uri"]
            result = signer.sign(message, options=wba.WebBotAuthSigningOptions(
                additional_components=opts.get("additionalComponents", []),
                signature_agent=opts.get("signatureAgent"),
                ttl=opts.get("ttl"),
            ))
            output = {"headers": {name.lower(): value for name, value in result.headers.items()}, "bodyBase64": base64.b64encode(result.body).decode() if result.body is not None else None}
        return {"ok": True, "message": output}

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
        from dnsid import DnsidConfig, DnsIdTxtRecord, IdentityConfig, IdentityManager, IdentityManagerDependencies

        config = req["config"]
        entity = FixtureKeyProvider(req["entityKey"]) if req.get("entityKey") else None
        operational = FixtureKeyProvider(req["entityKey"] if req.get("sameKey") else req["operationalKey"])
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
