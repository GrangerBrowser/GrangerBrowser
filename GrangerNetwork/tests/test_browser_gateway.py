from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from granger_network.browser_gateway import (
    PROTOCOL_VERSION,
    _LocalDemo,
    _load_browser_peer_identity,
    handle_request,
    parse_request,
)
from granger_network.client import GrangerClient, GrangerResponse
from granger_network.errors import (
    DescriptorError,
    IdentityVerificationError,
    ProtocolError,
    RendezvousError,
    ReplayError,
)
from granger_network.resolver import LocalResolver
from granger_network.wan_config import load_or_create_identity


def request_document(**changes: object) -> bytes:
    document: dict[str, object] = {
        "body": "",
        "headers": {"accept": "text/css", "cookie": "session=allowed"},
        "method": "GET",
        "name": "test.granger",
        "path": "/style.css?theme=dark",
        "requestId": "a" * 32,
        "type": "fetch",
        "version": PROTOCOL_VERSION,
    }
    document.update(changes)
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


class BrowserGatewayTests(unittest.TestCase):
    def test_gateway_distinguishes_negative_network_evidence(self):
        from granger_network.browser_gateway import _error_code
        from granger_network.errors import (
            IntroductionOfflineError, NetworkUnavailableError, OverlayRoutingError,
            RecordQuorumError, ResolutionError,
        )
        for error, code in (
            (RecordQuorumError("missing replicas"), "QUORUM_UNAVAILABLE"),
            (NetworkUnavailableError("first contact failed"), "NETWORK_UNAVAILABLE"),
            (IntroductionOfflineError("no live registrations"), "INTRO_UNAVAILABLE"),
            (OverlayRoutingError("route budget exhausted"), "NO_ROUTE"),
            (ResolutionError("unknown local alias"), "SERVICE_NOT_FOUND"),
        ):
            with self.subTest(code=code):
                self.assertEqual(_error_code(error), code)

    def test_browser_relay_identity_is_persistent_and_separate_from_client_seed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="granger-browser-identities-") as temporary:
            state = Path(temporary)
            client_identity = load_or_create_identity(state / "client-identity.json")
            first = _load_browser_peer_identity(state)
            second = _load_browser_peer_identity(state)

        self.assertEqual(first.public_key_bytes, second.public_key_bytes)
        self.assertNotEqual(first.public_key_bytes, client_identity.public_key_bytes)

    def test_local_demo_uses_identity_bound_encrypted_service_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            demo = _LocalDemo(Path(temporary) / "registry")
            demo.start()
            try:
                alias = GrangerClient(demo.resolver).fetch("test.granger")
                canonical = GrangerClient(demo.resolver).fetch(demo.descriptor.canonical_name)
            finally:
                demo.stop()
        self.assertEqual(alias.canonical_service, demo.descriptor.canonical_name)
        self.assertEqual(canonical.canonical_service, demo.descriptor.canonical_name)
        self.assertIn(b"test.granger works", alias.body)

    def test_request_parser_accepts_only_bounded_granger_fetches(self) -> None:
        request = parse_request(request_document())
        self.assertEqual(request["name"], "test.granger")
        self.assertEqual(request["path"], "/style.css?theme=dark")
        self.assertEqual(
            request["headers"], {"accept": "text/css", "cookie": "session=allowed"}
        )

        for changes in (
            {"name": "example.com"},
            {"name": "nested.test.granger"},
            {"method": "TRACE"},
            {"method": "POST", "body": "***"},
            {"method": "GET", "body": base64.b64encode(b"unexpected").decode("ascii")},
            {"path": "//example.com/escape"},
            {"path": "/bad\npath"},
            {"requestId": "invalid"},
            {"version": 1},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                parse_request(request_document(**changes))

    def test_gateway_returns_body_without_exposing_unapproved_headers(self) -> None:
        response = GrangerResponse(
            status=200,
            reason="OK",
            headers={"content-type": "text/css", "cache-control": "no-store"},
            body=b"body { color: white; }",
            canonical_service=f"{'b' * 52}.granger",
        )
        with tempfile.TemporaryDirectory() as temporary:
            resolver = LocalResolver(Path(temporary))
            with patch("granger_network.browser_gateway.GrangerClient.fetch", return_value=response) as fetch:
                result = handle_request(resolver, 2.0, request_document())
        self.assertTrue(result["ok"])
        self.assertEqual(result["dnsRequests"], 0)
        self.assertEqual(base64.b64decode(result["body"]), response.body)
        self.assertEqual(
            result["headers"],
            [["content-type", "text/css"], ["cache-control", "no-store"]],
        )
        fetch.assert_called_once_with(
            "test.granger",
            "/style.css?theme=dark",
            method="GET",
            headers={"accept": "text/css", "cookie": "session=allowed"},
        )

    def test_gateway_preserves_repeated_response_header_fields(self) -> None:
        response = GrangerResponse(
            200,
            "OK",
            {"set-cookie": "second=two; Path=/"},
            b"",
            f"{'d' * 52}.granger",
            (
                ("set-cookie", "first=one; Path=/; HttpOnly"),
                ("set-cookie", "second=two; Path=/"),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            resolver = LocalResolver(Path(temporary))
            with patch("granger_network.browser_gateway.GrangerClient.fetch", return_value=response):
                result = handle_request(resolver, 2.0, request_document())
        self.assertEqual(
            result["headers"],
            [
                ["set-cookie", "first=one; Path=/; HttpOnly"],
                ["set-cookie", "second=two; Path=/"],
            ],
        )

    def test_post_body_is_forwarded_only_to_a_body_capable_gateway(self) -> None:
        response = GrangerResponse(
            201,
            "Created",
            {"content-type": "text/plain"},
            b"stored",
            f"{'c' * 52}.granger",
        )

        class BodyGateway:
            def __init__(self) -> None:
                self.calls: list[tuple] = []

            def fetch_gateway(self, *args):
                self.calls.append(args)
                return response

        gateway = BodyGateway()
        body = b"GRANGER_TEST_MESSAGE_123"
        result = handle_request(
            gateway,
            2.0,
            request_document(
                method="POST",
                path="/message",
                body=base64.b64encode(body).decode("ascii"),
                headers={"content-type": "text/plain", "cookie": "session=allowed"},
            ),
        )
        self.assertTrue(result["ok"])
        self.assertEqual(
            gateway.calls,
            [
                (
                    "test.granger",
                    "/message",
                    "POST",
                    {"content-type": "text/plain", "cookie": "session=allowed"},
                    body,
                )
            ],
        )

    def test_unknown_service_fails_closed_with_safe_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = handle_request(
                LocalResolver(Path(temporary)),
                1.0,
                request_document(name="missing.granger"),
            )
        self.assertEqual(
            result,
            {
                "code": "SERVICE_NOT_FOUND",
                "dnsRequests": 0,
                "ok": False,
                "requestId": "a" * 32,
                "type": "response",
                "version": PROTOCOL_VERSION,
            },
        )

    def test_sensitive_failures_are_reduced_to_safe_browser_codes(self) -> None:
        cases = (
            (DescriptorError("private descriptor detail"), "IDENTITY_VERIFICATION_FAILED"),
            (IdentityVerificationError("private key mismatch detail"), "IDENTITY_VERIFICATION_FAILED"),
            (ReplayError("private session detail"), "REPLAY_REJECTED"),
            (RendezvousError("relay credential detail"), "NETWORK_UNAVAILABLE"),
            (ProtocolError("encrypted frame detail"), "CONNECTION_FAILED"),
            (OSError("local path detail"), "NETWORK_UNAVAILABLE"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            resolver = LocalResolver(Path(temporary))
            for error, expected in cases:
                with self.subTest(error=type(error).__name__), patch(
                    "granger_network.browser_gateway.GrangerClient.fetch",
                    side_effect=error,
                ):
                    result = handle_request(resolver, 1.0, request_document())
                self.assertEqual(result["code"], expected)
                self.assertNotIn(str(error), json.dumps(result))


if __name__ == "__main__":
    unittest.main()
