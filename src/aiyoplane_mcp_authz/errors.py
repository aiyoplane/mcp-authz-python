"""Typed errors for aiyoplane-mcp-authz.

Every failure mode in the authorization composition raises one of these,
never a generic Exception. This lets integrators handle specific failure
modes distinctly.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class AiyoAuthzError(Exception):
    """Base class for all aiyoplane-mcp-authz errors."""

    code: Optional[str] = None

    def __init__(
        self,
        message: str,
        *,
        code: Optional[str] = None,
        cause: Optional[BaseException] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code
        self.__cause__ = cause
        self.details: Dict[str, Any] = details or {}


class AiyoDenied(AiyoAuthzError):
    """The RDP returned a DENY verdict; the gated tool must not be invoked.

    The Composition Boundary (the wrapping MCP server handler) catches this
    exception and surfaces a structured MCP error to the agent.

    .reason_code and .reason_detail (via `details`) carry the Policy's
    reason for the denial.
    """

    code = "DENIED"


class AiyoUnreachable(AiyoAuthzError):
    """Aiyo's hosted RDP could not be reached.

    Default behavior: raised to the Composition Boundary, which fails closed
    (treats as DENY). Integrators who want fail-open behavior under specific
    conditions MUST implement that explicitly at the Composition Boundary
    with an audit trail.
    """

    code = "UNREACHABLE"


class ReceiptMismatchError(AiyoAuthzError):
    """A receipt was issued but did not match the intent it was supposed to attest to."""

    code = "RECEIPT_MISMATCH"


class ToolConfigError(AiyoAuthzError):
    """A tool was declared as `aiyo_gated: True` but is missing required config."""

    code = "TOOL_CONFIG"
