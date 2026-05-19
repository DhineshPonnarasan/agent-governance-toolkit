# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""CedarlingBackend — Cedarling policy adapter for AGT.

Implements the ExternalPolicyBackend protocol (name + evaluate) so that
Cedarling authorization decisions flow seamlessly into AGT's PolicyEvaluator
pipeline without modifying AGT core.

``cedarling_python`` is optional. The backend falls back to HTTP when the
bindings are absent, and fails safe with a denial when neither is configured.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from agent_os.policies import BackendDecision

logger = logging.getLogger(__name__)


def _tool_to_cedar_action(tool_name: str) -> str:
    """Convert a snake_case tool name to PascalCase for Cedar action naming.

    Examples::

        "read_data"    -> "ReadData"
        "send_message" -> "SendMessage"
        "query"        -> "Query"
    """
    return "".join(part.capitalize() for part in tool_name.split("_"))


class CedarlingBackend:
    """AGT policy backend that delegates decisions to Cedarling.

    Implements the ``ExternalPolicyBackend`` protocol — exposes ``name`` and
    ``evaluate(context) -> BackendDecision`` — so it can be registered with
    ``PolicyEvaluator.add_backend()`` without any changes to AGT core.

    Modes:
        ``"auto"``   — cedarling_python if installed, else HTTP if url set,
                       else safe denial.
        ``"python"`` — cedarling_python bindings only (ImportError if absent).
        ``"http"``   — HTTP service only (requires ``cedarling_url``).
    """

    def __init__(
        self,
        bootstrap_config: Optional[dict[str, Any]] = None,
        application_name: str = "agent-governance-toolkit",
        tokens: Optional[dict[str, str]] = None,
        principal_entity_type: str = "Agent",
        resource_entity_type: str = "Resource",
        action_namespace: str = "Action",
        cedarling_url: Optional[str] = None,
        mode: Literal["auto", "python", "http"] = "auto",
        timeout_seconds: float = 5.0,
    ) -> None:
        cfg: dict[str, Any] = dict(bootstrap_config) if bootstrap_config else {}
        cfg.setdefault("application_name", application_name)
        self._bootstrap_config = cfg
        self._tokens = tokens or {}
        self._principal_entity_type = principal_entity_type
        self._resource_entity_type = resource_entity_type
        self._action_namespace = action_namespace
        self._cedarling_url = cedarling_url.rstrip("/") if cedarling_url else None
        self._mode = mode
        self._timeout = timeout_seconds
        self._python_available: Optional[bool] = None  # lazily resolved

    @property
    def name(self) -> str:
        return "cedarling"

    def evaluate(self, context: dict[str, Any]) -> BackendDecision:
        """Evaluate *context* and return a normalized ``BackendDecision``."""
        start = datetime.now(timezone.utc)
        try:
            # Detect cedarling_python availability once, then cache.
            if self._python_available is None:
                try:
                    import cedarling_python  # noqa: F401

                    self._python_available = True
                except ImportError:
                    self._python_available = False

            use_python = self._mode == "python" or (
                self._mode == "auto" and self._python_available
            )
            use_http = self._mode == "http" or (
                self._mode == "auto" and not use_python and self._cedarling_url is not None
            )

            if use_python:
                result = self._evaluate_python(context)
            elif use_http:
                result = self._evaluate_http(context)
            else:
                msg = (
                    "No Cedarling runtime available. "
                    "Install cedarling_python or set cedarling_url."
                )
                logger.warning(msg)
                result = self._deny(
                    msg,
                    "cedarling_python not installed and cedarling_url not configured",
                )

            result.evaluation_ms = (
                datetime.now(timezone.utc) - start
            ).total_seconds() * 1000
            return result

        except Exception as exc:
            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            logger.error("Cedarling evaluation failed: %s", exc)
            return BackendDecision(
                allowed=False,
                action="deny",
                reason=f"Cedarling evaluation error: {exc}",
                backend="cedarling",
                evaluation_ms=elapsed,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _deny(self, reason: str, error: str) -> BackendDecision:
        return BackendDecision(
            allowed=False,
            action="deny",
            reason=reason,
            backend="cedarling",
            error=error,
        )

    def _build_request(self, context: dict[str, Any]) -> dict[str, Any]:
        """Map AGT context keys to a Cedarling authorization request."""
        agent_id = str(context.get("agent_id", "anonymous"))
        tool_name = str(context.get("tool_name", "unknown"))
        resource_id = str(context.get("resource", "default"))
        action = _tool_to_cedar_action(tool_name)
        extra = {
            k: v
            for k, v in context.items()
            if k not in ("agent_id", "tool_name", "resource")
        }
        return {
            "principal": {"type": self._principal_entity_type, "id": agent_id},
            "action": f'{self._action_namespace}::"{action}"',
            "resource": {"type": self._resource_entity_type, "id": resource_id},
            "context": extra,
        }

    def _evaluate_python(self, context: dict[str, Any]) -> BackendDecision:
        """Delegate to cedarling_python bindings."""
        try:
            import cedarling_python
        except ImportError as exc:
            raise ImportError(
                "cedarling_python is not installed. "
                "Run `pip install cedarling_python` to use Python-binding mode."
            ) from exc

        req = self._build_request(context)
        bootstrap = cedarling_python.BootstrapConfig(**self._bootstrap_config)
        engine = cedarling_python.Cedarling(bootstrap)
        resource = cedarling_python.ResourceData(
            resource_type=req["resource"]["type"],
            id=req["resource"]["id"],
            payload=req["context"],
        )
        request = cedarling_python.Request(
            tokens=self._tokens,
            action=req["action"],
            resource=resource,
            context=req["context"],
        )
        try:
            result = engine.authorize(request)
        except cedarling_python.AuthorizeError as exc:
            return BackendDecision(
                allowed=False,
                action="deny",
                reason=f"Cedarling authorization error: {exc}",
                backend="cedarling",
                error=str(exc),
                raw_result={"request_id": getattr(exc, "request_id", None)},
            )

        allowed = result.is_allowed()
        diagnostics: Optional[dict[str, Any]] = None
        if hasattr(result, "workload") and result.workload is not None:
            diagnostics = {"workload": str(result.workload)}

        return BackendDecision(
            allowed=allowed,
            action="allow" if allowed else "deny",
            reason=f"Cedarling: {'allowed' if allowed else 'denied'} (python)",
            backend="cedarling",
            raw_result={
                "request_id": getattr(result, "request_id", None),
                "diagnostics": diagnostics,
            },
        )

    def _evaluate_http(self, context: dict[str, Any]) -> BackendDecision:
        """Delegate to a Cedarling HTTP service (/cedarling/authorize)."""
        import urllib.error
        import urllib.parse
        import urllib.request

        if not self._cedarling_url:
            return self._deny(
                "Cedarling HTTP mode requires cedarling_url",
                "cedarling_url not configured",
            )

        parsed = urllib.parse.urlparse(self._cedarling_url)
        if parsed.scheme not in ("http", "https"):
            return self._deny(
                f"Invalid cedarling_url: unsupported scheme {parsed.scheme!r}",
                f"Unsupported scheme: {parsed.scheme!r}",
            )

        req = self._build_request(context)
        payload = json.dumps({"tokens": self._tokens, **req}).encode("utf-8")
        url = f"{self._cedarling_url}/cedarling/authorize"
        http_req = urllib.request.Request(  # noqa: S310
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(http_req, timeout=self._timeout) as resp:  # noqa: S310
                body: dict[str, Any] = json.loads(
                    resp.read().decode("utf-8", errors="replace")
                )
                allowed = bool(body.get("allowed", False))
                return BackendDecision(
                    allowed=allowed,
                    action="allow" if allowed else "deny",
                    reason=f"Cedarling: {'allowed' if allowed else 'denied'} (http)",
                    backend="cedarling",
                    raw_result={
                        "request_id": body.get("request_id"),
                        "diagnostics": body.get("diagnostics"),
                        "body": body,
                    },
                )
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            return self._deny(
                f"Cedarling HTTP error {exc.code}: {body_text[:200]}",
                f"HTTP {exc.code}",
            )
        except TimeoutError:
            return self._deny("Cedarling HTTP request timed out", "timeout")
        except Exception as exc:
            return self._deny(f"Cedarling HTTP connection error: {exc}", str(exc))
