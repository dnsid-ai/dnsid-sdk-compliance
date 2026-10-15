"""Native WBA fixture adapters; only SDK verification errors count as rejection."""

from __future__ import annotations

import base64
import json
import os
import ssl
import subprocess
import tempfile
import threading
from contextlib import ExitStack
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TLS_FIXTURES = ROOT / "shims/testdata"


def verify_python(req: dict) -> dict:
    import httpcore
    from dnsid import JWKS, WBAHttpVerifier, WebBotAuthVerificationOptions
    from dnsid._crypto import jwk_from_dict
    from dnsid.enums import DNSSECState, VerificationCode
    from dnsid.exceptions import ArgumentError, VerificationError
    from dnsid.models import (
        AgentStatus,
        DnsIdTxtRecord,
        HttpRequest,
        TLSCertificate,
        TransportConfig,
        VerifiedDomain,
    )
    from dnsid.safe_transport import make_ssrf_safe_transport
    from dnsid.wba_signer import WebBotAuthConfig

    scenario = req["verification"]
    domain = scenario["signerDomain"]
    clock = scenario["now"]
    discoveries = 0
    phase = 0
    seen = set()
    public = {"kty": "OKP", "crv": "Ed25519", "x": req["key"]["x"]}

    class Resolver:
        def verify_domain(self, signer, peer_cert=None):
            # Identity evidence is injected at the public resolver boundary.
            if not scenario["dnsidExists"]:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID, "fixture DNSid record absent"
                )
            if not scenario["acceptanceAllowed"] and phase:
                raise VerificationError(
                    VerificationCode.COUNTERPARTY_NOT_ACCEPTED,
                    "fixture acceptance denied",
                )
            if scenario["requiresMtls"] and peer_cert is None:
                raise VerificationError(
                    VerificationCode.TLS_ERROR, "fixture current mTLS peer missing"
                )
            now = datetime.fromtimestamp(clock, timezone.utc)
            keys = scenario["currentKu"] if phase else [public]
            keys = [
                jwk_from_dict({"alg": "EdDSA", "kid": "fixture-ku", **key})
                for key in keys
            ]
            return VerifiedDomain(
                domain=signer,
                record=DnsIdTxtRecord(v="dnsid-draft-01"),
                jwks=JWKS(keys=keys),
                signing_key=jwk_from_dict(public),
                tls_cert=TLSCertificate(),
                registry_status=AgentStatus("ACTIVE", now),
                verified_at=now,
                dns_ttl=scenario.get("dnsTTL", 300),
                key_bound_at=now,
                last_status_check_at=now,
                dnssec_state=DNSSECState.UNKNOWN,
                log_reader=None,
            )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal clock, discoveries
            discoveries += 1
            clock = scenario["finishedAt"]
            if scenario.get("directoryTimeout"):
                self.connection.settimeout(2)
                self.connection.recv(1)
                return
            if scenario["redirects"]:
                self.send_response(302)
                self.send_header("Location", scenario["redirects"][0]["url"])
                self.end_headers()
                return
            message = req["directory"]
            self.send_response(scenario.get("directoryStatus", message["status"]))
            for name, value in message["headers"].items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(base64.b64decode(message["bodyBase64"], validate=True))

        def log_message(self, *_args):
            pass

    def resolve(*_args):
        if discoveries and scenario["redirects"]:
            return scenario["redirects"][0]["resolvedAddresses"]
        return scenario["resolvedAddresses"]

    original_connect = httpcore.SyncBackend.connect_tcp

    def dial(
        backend, _host, _port, timeout=None, local_address=None, socket_options=None
    ):
        # The SDK checks the fixture DNS answers before this physical dial.
        return original_connect(
            backend, *server.server_address, timeout, local_address, socket_options
        )

    def replay(signer, keyid, nonce, retain_until):
        if not scenario["replayStoreAvailable"]:
            raise OSError("fixture replay store unavailable")
        identity = (signer, keyid, nonce)
        if identity in seen:
            return False
        seen.add(identity)
        return True

    def message():
        raw = req["request"]
        body = (
            base64.b64decode(raw["bodyBase64"], validate=True)
            if raw.get("bodyBase64") is not None
            else None
        )
        return HttpRequest(
            method=raw["method"],
            url=raw["url"],
            headers=dict(raw["headers"]),
            body=body,
        )

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(TLS_FIXTURES / "wba-cert.pem", TLS_FIXTURES / "wba-key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    )
    thread.start()
    try:
        with ExitStack() as stack:
            stack.enter_context(
                patch("dnsid.safe_transport._resolve_addresses", side_effect=resolve)
            )
            stack.enter_context(patch("httpcore.SyncBackend.connect_tcp", new=dial))
            stack.enter_context(
                patch(
                    "dnsid.wba_verifier._now",
                    side_effect=lambda: datetime.fromtimestamp(clock, timezone.utc),
                )
            )
            config = TransportConfig(
                ca_bundle_path=str(TLS_FIXTURES / "wba-cert.pem")
                if scenario["directoryTlsValid"]
                else ""
            )
            transport = stack.enter_context(make_ssrf_safe_transport(config))
            profile_config = WebBotAuthConfig(clock_skew=scenario["clockSkew"])
            verifier = WBAHttpVerifier(
                Resolver(), config=profile_config, transport=transport
            )
            if hasattr(verifier, "close"):
                stack.callback(verifier.close)
            opts = WebBotAuthVerificationOptions(
                signer_domain=domain,
                discovery_uri=scenario["trustedDiscoveryUri"],
                required_components=scenario.get("requiredComponents", []),
                timeout=scenario.get("timeoutMs", 30000) / 1000,
                replay_policy=replay if scenario["replayEnabled"] else None,
            )
            for name, value in scenario.get("configMutation", {}).items():
                if name != "clockSkew":
                    raise ValueError(f"unknown configuration mutation: {name}")
                profile_config.clock_skew = value
            if scenario["cacheHit"] or scenario["nonceSeen"]:
                try:
                    verifier.verify_web_bot_auth_signed_request(message(), opts)
                except Exception as exc:  # noqa: BLE001 - setup failure is not a verification rejection.
                    return {
                        "ok": False,
                        "error": "AdapterError",
                        "message": f"warm-up failed: {exc}",
                    }
            phase = 1
            clock = scenario["now"]
            verified = verifier.verify_web_bot_auth_signed_request(message(), opts)
            return {
                "ok": True,
                "signerDomain": verified.domain,
                "discoveryRequests": discoveries,
            }
    except VerificationError as exc:
        return {
            "ok": False,
            "error": "ConformanceError",
            "nativeError": type(exc).__name__,
            "code": exc.code.name,
            "transient": exc.transient,
            "message": str(exc),
            "discoveryRequests": discoveries,
        }
    except ArgumentError as exc:
        return {
            "ok": False,
            "error": "ArgumentError",
            "message": str(exc),
            "discoveryRequests": discoveries,
        }
    except Exception as exc:  # noqa: BLE001 - unexpected SDK errors must remain visible.
        return {
            "ok": False,
            "error": "AdapterError",
            "message": f"{type(exc).__name__}: {exc}",
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def verify_go(requests: list[dict]) -> list[dict]:
    """Run an overlay test bridge without modifying the SDK checkout."""
    sdk_dir = Path(os.environ.get("DNSID_GO_DIR", Path.home() / "dnsid-go")).resolve()
    with tempfile.TemporaryDirectory(prefix="dnsid-wba-go-") as directory:
        work = Path(directory)
        input_path, output_path = work / "input.json", work / "output.json"
        input_path.write_text(json.dumps(requests))
        overlay = work / "overlay.json"
        overlay.write_text(
            json.dumps(
                {
                    "Replace": {
                        str(sdk_dir / "webbotauth/compliance_adapter_test.go"): str(
                            ROOT / "shims/go/testdata/wba_adapter_test.go"
                        ),
                    }
                }
            )
        )
        proc = subprocess.run(
            [
                "go",
                "test",
                f"-overlay={overlay}",
                "./webbotauth",
                "-run",
                "^TestComplianceWBAAdapter$",
                "-count=1",
            ],
            cwd=sdk_dir,
            capture_output=True,
            text=True,
            check=False,
            env={
                **os.environ,
                "DNSID_WBA_INPUT": str(input_path),
                "DNSID_WBA_OUTPUT": str(output_path),
                "DNSID_WBA_TLS": str(TLS_FIXTURES),
            },
        )
        if proc.returncode != 0 or not output_path.exists():
            error = {
                "ok": False,
                "error": "AdapterError",
                "message": (proc.stdout + proc.stderr).strip(),
            }
            return [dict(error) for _ in requests]
        results = json.loads(output_path.read_text())
        if len(results) != len(requests):
            raise RuntimeError("Go WBA bridge returned the wrong number of results")
        return results
