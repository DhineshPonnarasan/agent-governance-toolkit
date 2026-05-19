# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for CedarlingBackend.

No real cedarling_python installation required — tests mock the module.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from cedarling_agentmesh import CedarlingBackend

# =============================================================================
# Protocol surface
# =============================================================================


class TestProtocol:
    def test_name(self):
        assert CedarlingBackend().name == "cedarling"

    def test_evaluate_returns_backend_decision(self):
        b = CedarlingBackend()
        d = b.evaluate({"tool_name": "read", "agent_id": "a1"})
        assert hasattr(d, "allowed")
        assert hasattr(d, "backend")
        assert d.backend == "cedarling"

    def test_denied_safely_when_no_runtime(self):
        b = CedarlingBackend(mode="auto")
        d = b.evaluate({"tool_name": "read", "agent_id": "a1"})
        assert d.allowed is False
        assert d.error is not None

    def test_timing_populated(self):
        b = CedarlingBackend()
        d = b.evaluate({"tool_name": "read", "agent_id": "a1"})
        assert d.evaluation_ms >= 0


# =============================================================================
# Request normalization
# =============================================================================


class TestRequestMapping:
    """Verify AGT context → Cedar request mapping via HTTP round-trip capture."""

    def _capture_http(self, b: CedarlingBackend, context: dict) -> dict:
        """Evaluate via HTTP mode; return the decoded Cedar request payload."""
        captured: dict = {}

        def _fake_urlopen(request, timeout):
            captured["payload"] = json.loads(request.data.decode("utf-8"))
            return _http_resp(True)

        with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
            b.evaluate(context)

        return captured.get("payload", {})

    def test_tool_name_to_pascal_case(self):
        b = CedarlingBackend(cedarling_url="http://x", mode="http")
        payload = self._capture_http(b, {"tool_name": "read_data", "agent_id": "a1"})
        assert '"ReadData"' in payload["action"]

    def test_single_word_tool(self):
        b = CedarlingBackend(cedarling_url="http://x", mode="http")
        payload = self._capture_http(b, {"tool_name": "query", "agent_id": "a"})
        assert '"Query"' in payload["action"]

    def test_agent_id_becomes_principal(self):
        b = CedarlingBackend(cedarling_url="http://x", mode="http")
        payload = self._capture_http(b, {"tool_name": "call", "agent_id": "agent-42"})
        assert payload["principal"]["id"] == "agent-42"

    def test_resource_mapped(self):
        b = CedarlingBackend(cedarling_url="http://x", mode="http")
        payload = self._capture_http(
            b, {"tool_name": "r", "agent_id": "a", "resource": "db-1"}
        )
        assert payload["resource"]["id"] == "db-1"

    def test_extra_keys_go_to_context(self):
        b = CedarlingBackend(cedarling_url="http://x", mode="http")
        payload = self._capture_http(
            b, {"tool_name": "read", "agent_id": "a", "env": "prod"}
        )
        assert payload["context"]["env"] == "prod"

    def test_defaults_for_missing_keys(self):
        b = CedarlingBackend(cedarling_url="http://x", mode="http")
        payload = self._capture_http(b, {})
        assert payload["principal"]["id"] == "anonymous"
        assert payload["resource"]["id"] == "default"

    def test_custom_namespace(self):
        b = CedarlingBackend(cedarling_url="http://x", mode="http", action_namespace="MyNS")
        payload = self._capture_http(b, {"tool_name": "act", "agent_id": "a"})
        assert payload["action"].startswith("MyNS::")

    def test_custom_entity_types(self):
        b = CedarlingBackend(
            cedarling_url="http://x",
            mode="http",
            principal_entity_type="User",
            resource_entity_type="File",
        )
        payload = self._capture_http(b, {"tool_name": "r", "agent_id": "u1"})
        assert payload["principal"]["type"] == "User"
        assert payload["resource"]["type"] == "File"


# =============================================================================
# Python binding mode
# =============================================================================


def _make_cedarling_python(allowed: bool) -> MagicMock:
    """Minimal cedarling_python mock."""
    mod = MagicMock()
    result = MagicMock()
    result.is_allowed.return_value = allowed
    result.workload = None
    mod.Cedarling.return_value.authorize.return_value = result
    mod.AuthorizeError = Exception
    return mod


class TestPythonMode:
    def test_allow(self):
        mod = _make_cedarling_python(allowed=True)
        with patch.dict("sys.modules", {"cedarling_python": mod}):
            b = CedarlingBackend(mode="python")
            d = b.evaluate({"tool_name": "read_data", "agent_id": "a1"})
        assert d.allowed is True
        assert d.backend == "cedarling"
        assert "(python)" in d.reason

    def test_deny(self):
        mod = _make_cedarling_python(allowed=False)
        with patch.dict("sys.modules", {"cedarling_python": mod}):
            b = CedarlingBackend(mode="python")
            d = b.evaluate({"tool_name": "write", "agent_id": "a1"})
        assert d.allowed is False
        assert "denied" in d.reason

    def test_timing_nonzero_path(self):
        mod = _make_cedarling_python(allowed=True)
        with patch.dict("sys.modules", {"cedarling_python": mod}):
            b = CedarlingBackend(mode="python")
            d = b.evaluate({"tool_name": "q", "agent_id": "a"})
        assert d.evaluation_ms >= 0

    def test_python_available_cached(self):
        """Once _python_available is set, evaluate must not re-probe."""
        b = CedarlingBackend(mode="auto")
        b._python_available = False  # pre-set; no cedarling_url → safe denial
        import builtins

        original = builtins.__import__
        calls: list[str] = []

        def tracking_import(name, *args, **kwargs):
            if name == "cedarling_python":
                calls.append(name)
            return original(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=tracking_import):
            b.evaluate({"tool_name": "x", "agent_id": "a"})

        assert "cedarling_python" not in calls

    def test_missing_package_returns_denial(self):
        """ImportError from missing cedarling_python is caught; returns denial."""
        with patch.dict("sys.modules", {"cedarling_python": None}):
            b = CedarlingBackend(mode="python")
            d = b.evaluate({"tool_name": "read", "agent_id": "a"})
        assert d.allowed is False


# =============================================================================
# HTTP mode
# =============================================================================


def _http_resp(allowed: bool, request_id: str = "req-1") -> MagicMock:
    body = json.dumps({"allowed": allowed, "request_id": request_id}).encode()
    resp = MagicMock()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    resp.read.return_value = body
    return resp


class TestHTTPMode:
    def test_allow(self):
        with patch("urllib.request.urlopen", return_value=_http_resp(True)):
            b = CedarlingBackend(cedarling_url="http://cedarling.internal:8080", mode="http")
            d = b.evaluate({"tool_name": "read", "agent_id": "a"})
        assert d.allowed is True
        assert "(http)" in d.reason

    def test_deny(self):
        with patch("urllib.request.urlopen", return_value=_http_resp(False)):
            b = CedarlingBackend(cedarling_url="http://cedarling.internal:8080", mode="http")
            d = b.evaluate({"tool_name": "write", "agent_id": "a"})
        assert d.allowed is False

    def test_request_id_in_raw_result(self):
        with patch("urllib.request.urlopen", return_value=_http_resp(True, "abc-123")):
            b = CedarlingBackend(cedarling_url="http://x", mode="http")
            d = b.evaluate({"tool_name": "read", "agent_id": "a"})
        assert d.raw_result["request_id"] == "abc-123"

    def test_no_url_returns_denial(self):
        b = CedarlingBackend(mode="http")
        d = b.evaluate({"tool_name": "read", "agent_id": "a"})
        assert d.allowed is False
        assert d.error is not None

    def test_bad_scheme_returns_denial(self):
        b = CedarlingBackend(cedarling_url="ftp://bad.example.com", mode="http")
        d = b.evaluate({"tool_name": "read", "agent_id": "a"})
        assert d.allowed is False
        assert d.error is not None
        assert "Unsupported scheme" in d.error

    def test_http_error_returns_denial(self):
        import urllib.error

        err = urllib.error.HTTPError(
            url="http://x",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=MagicMock(read=lambda: b"denied"),
        )
        with patch("urllib.request.urlopen", side_effect=err):
            b = CedarlingBackend(cedarling_url="http://x", mode="http")
            d = b.evaluate({"tool_name": "read", "agent_id": "a"})
        assert d.allowed is False
        assert "403" in d.reason

    def test_timeout_returns_denial(self):
        with patch("urllib.request.urlopen", side_effect=TimeoutError()):
            b = CedarlingBackend(cedarling_url="http://x", mode="http")
            d = b.evaluate({"tool_name": "read", "agent_id": "a"})
        assert d.allowed is False
        assert "timeout" in (d.error or "").lower() or "timed out" in d.reason.lower()


# =============================================================================
# Auto mode routing
# =============================================================================


class TestAutoMode:
    def test_uses_python_when_available(self):
        mod = _make_cedarling_python(allowed=True)
        with patch.dict("sys.modules", {"cedarling_python": mod}):
            b = CedarlingBackend(mode="auto")
            d = b.evaluate({"tool_name": "read", "agent_id": "a"})
        assert "(python)" in d.reason

    def test_falls_back_to_http_when_python_absent(self):
        with patch.dict("sys.modules", {"cedarling_python": None}):
            with patch("urllib.request.urlopen", return_value=_http_resp(True)):
                b = CedarlingBackend(
                    cedarling_url="http://cedarling.internal:8080", mode="auto"
                )
                d = b.evaluate({"tool_name": "read", "agent_id": "a"})
        assert "(http)" in d.reason

    def test_safe_denial_when_nothing_configured(self):
        with patch.dict("sys.modules", {"cedarling_python": None}):
            b = CedarlingBackend(mode="auto")
            d = b.evaluate({"tool_name": "read", "agent_id": "a"})
        assert d.allowed is False
