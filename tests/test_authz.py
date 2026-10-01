"""Tests for aiyoplane-mcp-authz.

Covers LocalRdp policy evaluation (allow/deny/escalate/silence-is-denial/
amount-gating), end-to-end receipt round-trip through aiyoplane-verify (the
second-independent-implementation check this port exists to carry), and the
AiyoAuthz middleware surface (decorator + direct-call forms, sync + async
handlers, denial raises AiyoDenied, ungated passthrough, ToolConfigError on
missing tool_config).
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

import pytest

from aiyoplane_mcp_authz import (
    AiyoAuthz,
    AiyoDenied,
    LocalRdp,
    ToolConfigError,
    create_aiyo_mcp_authz,
    create_local_rdp,
)
from aiyoplane_mcp_authz.rdp import Intent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


POLICY = {
    "rules": [
        {
            "action_type": "deploy",
            "action_target": "production",
            "effect": "allow",
            "reason_code": "POLICY_ALLOW",
            "reason_detail": "Production deploy allowed by policy.",
        },
        {
            "action_type": "deploy",
            "action_target": "staging",
            "effect": "allow",
        },
        {
            "action_type": "payment",
            "amount_max": 1000,
            "effect": "allow",
        },
        {
            "action_type": "payment",
            "amount_min": 10001,
            "effect": "deny",
            "reason_code": "POLICY_DENY",
            "reason_detail": "Payment exceeds hard cap.",
        },
        {
            "action_type": "refund",
            "effect": "escalate",
            "reason_code": "POLICY_ESCALATE",
            "reason_detail": "Refunds require human approval.",
        },
    ]
}


TOOL_CONFIG = {
    "deploy_to_production": {
        "aiyo_gated": True,
        "action": {"type": "deploy", "target": "production"},
    },
    "deploy_to_staging": {
        "aiyo_gated": True,
        "action": {"type": "deploy", "target": "staging"},
    },
    "process_payment": {
        "aiyo_gated": True,
        "action": {"type": "payment"},
    },
    "refund_order": {
        "aiyo_gated": True,
        "action": {"type": "refund"},
    },
    "search_docs": {"aiyo_gated": False},
    "misconfigured_tool": {
        "aiyo_gated": True,
        # action.type intentionally missing to exercise ToolConfigError
    },
}


def make_rdp() -> LocalRdp:
    return create_local_rdp(POLICY)


def make_authz() -> AiyoAuthz:
    return create_aiyo_mcp_authz(rdp=make_rdp(), tool_config=TOOL_CONFIG)


def make_intent(
    *,
    action_type: str,
    action_target: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
    intent_id: str = "int_test00000001",
) -> Intent:
    return Intent(
        intent_id=intent_id,
        action_type=action_type,
        action_target=action_target,
        actor={"actor_type": "agent", "actor_id": "test_agent"},
        parameters=parameters or {},
        merchant_id="mrch_local_demo",
    )


# ---------------------------------------------------------------------------
# LocalRdp policy evaluation
# ---------------------------------------------------------------------------


def test_local_rdp_allows_matching_intent():
    rdp = make_rdp()
    result = rdp.evaluate(make_intent(action_type="deploy", action_target="production"))
    assert result.verdict == "allow"
    assert result.receipt is not None
    assert result.receipt.startswith("v1.")
    assert result.reason_code == "POLICY_ALLOW"
    assert result.intent_id == "int_test00000001"


def test_local_rdp_silence_is_denial():
    """No rule matches action_type=unknown → POLICY_SILENT_ON_ACTION_TYPE deny."""
    rdp = make_rdp()
    result = rdp.evaluate(make_intent(action_type="purge_db"))
    assert result.verdict == "deny"
    assert result.reason_code == "POLICY_SILENT_ON_ACTION_TYPE"
    assert result.receipt is None


def test_local_rdp_amount_gating_allow():
    rdp = make_rdp()
    result = rdp.evaluate(make_intent(action_type="payment", parameters={"amount": 500}))
    assert result.verdict == "allow"
    assert result.receipt is not None


def test_local_rdp_amount_gating_deny_over_max():
    rdp = make_rdp()
    result = rdp.evaluate(make_intent(action_type="payment", parameters={"amount": 10500}))
    assert result.verdict == "deny"
    assert result.reason_code == "POLICY_DENY"
    assert result.receipt is None


def test_local_rdp_escalate():
    rdp = make_rdp()
    result = rdp.evaluate(make_intent(action_type="refund"))
    assert result.verdict == "escalate"
    assert result.reason_code == "POLICY_ESCALATE"
    assert result.receipt is None


# ---------------------------------------------------------------------------
# Receipt round-trips through aiyoplane-verify
# This is the "second independent implementation of AEAP" check.
# ---------------------------------------------------------------------------


def test_local_rdp_receipt_round_trips_through_aiyoplane_verify():
    """A receipt issued by LocalRdp is accepted by aiyoplane-verify when
    given the matching HMAC secret. This is the integration test that proves
    the Python port composes correctly with the Python verifier.
    """
    from aiyoplane_verify import verify as verify_receipt

    rdp = make_rdp()
    result = rdp.evaluate(make_intent(action_type="deploy", action_target="production"))
    assert result.verdict == "allow"
    assert result.receipt is not None

    verified = verify_receipt(result.receipt, hmac_secret=rdp.hmac_secret)
    assert verified["valid"] is True
    assert verified["claims"]["iid"] == "int_test00000001"
    assert verified["claims"]["mid"] == "mrch_local_demo"


# ---------------------------------------------------------------------------
# AiyoAuthz middleware - decorator and direct-call forms
# ---------------------------------------------------------------------------


def test_authz_wrap_decorator_form_allows():
    """@authz.wrap decorator wraps a sync handler and invokes it on ALLOW."""
    authz = make_authz()
    calls = []  # type: list

    @authz.wrap("deploy_to_production")
    def deploy(args, ctx):
        calls.append({"args": args, "receipt": ctx.receipt, "verdict": ctx.verdict})
        return "deployed"

    result = deploy({"region": "us-east-1"}, None)
    assert result == "deployed"
    assert len(calls) == 1
    assert calls[0]["verdict"] == "allow"
    assert calls[0]["receipt"].startswith("v1.")


def test_authz_wrap_direct_form_allows():
    """authz.wrap(name, fn) direct-call form (non-decorator)."""
    authz = make_authz()
    calls = []  # type: list

    def deploy(args, ctx):
        calls.append(ctx.verdict)
        return "ok"

    wrapped = authz.wrap("deploy_to_staging", deploy)
    assert wrapped({"region": "us-west-2"}, None) == "ok"
    assert calls == ["allow"]


def test_authz_wrap_denied_raises_aiyodenied():
    """A tool whose intent matches a DENY rule raises AiyoDenied and does
    not invoke the handler."""
    authz = make_authz()
    invoked = False

    @authz.wrap("process_payment")
    def process_payment(args, ctx):
        nonlocal invoked
        invoked = True
        return "paid"

    with pytest.raises(AiyoDenied) as excinfo:
        process_payment({"amount": 50000}, None)
    assert invoked is False
    assert excinfo.value.details.get("reason_code") == "POLICY_DENY"


def test_authz_wrap_escalate_raises_aiyodenied():
    """ESCALATE verdict also halts invocation and raises AiyoDenied with
    code=ESCALATE so the Composition Boundary can route to human approval."""
    authz = make_authz()
    invoked = False

    @authz.wrap("refund_order")
    def refund(args, ctx):
        nonlocal invoked
        invoked = True
        return "refunded"

    with pytest.raises(AiyoDenied) as excinfo:
        refund({"order_id": "ord_123"}, None)
    assert invoked is False
    assert excinfo.value.code == "ESCALATE"


def test_authz_ungated_tool_passthrough():
    """A tool marked `aiyo_gated: False` is invoked without consulting the RDP."""
    authz = make_authz()
    captured = []  # type: list

    @authz.wrap("search_docs")
    def search(args, ctx):
        captured.append(ctx.verdict)
        return "results"

    result = search({"query": "aeap"}, None)
    assert result == "results"
    assert captured == ["allow"]  # synthetic ALLOW context for passthrough


def test_authz_tool_config_error_on_unregistered_tool():
    """Wrapping a tool with no tool_config entry raises ToolConfigError."""
    authz = make_authz()
    with pytest.raises(ToolConfigError):

        @authz.wrap("unregistered_tool")
        def _handler(args, ctx):  # pragma: no cover
            return None


def test_authz_tool_config_error_on_missing_action_type():
    """A gated tool with no action.type declaration raises ToolConfigError."""
    authz = make_authz()
    with pytest.raises(ToolConfigError):

        @authz.wrap("misconfigured_tool")
        def _handler(args, ctx):  # pragma: no cover
            return None


# ---------------------------------------------------------------------------
# Async handler path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authz_wrap_async_handler_allowed():
    """An async handler wrapped by @authz.wrap is awaited and receives the
    verified receipt in its ctx."""
    authz = make_authz()
    calls = []  # type: list

    @authz.wrap("deploy_to_production")
    async def deploy(args, ctx):
        await asyncio.sleep(0)  # yield to prove the coroutine path runs
        calls.append({"receipt": ctx.receipt, "verdict": ctx.verdict})
        return "deployed-async"

    result = await deploy({"region": "us-east-1"}, None)
    assert result == "deployed-async"
    assert calls[0]["verdict"] == "allow"
    assert calls[0]["receipt"].startswith("v1.")


@pytest.mark.asyncio
async def test_authz_wrap_async_handler_denied():
    """Async handler path also enforces DENY by raising AiyoDenied."""
    authz = make_authz()

    @authz.wrap("process_payment")
    async def process_payment(args, ctx):  # pragma: no cover
        return "paid"

    with pytest.raises(AiyoDenied):
        await process_payment({"amount": 99999}, None)
