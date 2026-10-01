"""The AiyoAuthz middleware - the composition point above an MCP tool call.

Usage pattern:

    from aiyoplane_mcp_authz import create_aiyo_mcp_authz, create_local_rdp

    authz = create_aiyo_mcp_authz(
        rdp=create_local_rdp(policy=policy),
        tool_config={
            "deploy_to_production": {
                "aiyo_gated": True,
                "action": {"type": "deploy", "target": "production"},
            },
            "search_docs": {"aiyo_gated": False},
        },
    )

    @authz.wrap("deploy_to_production")
    async def deploy(args, ctx):
        # Runs only if the RDP returned ALLOW. ctx.receipt is the verified receipt.
        return await actually_deploy(args)

Register `deploy` with your MCP server the usual way. The MCP protocol between
agent and server is unchanged; the agent never learns that Aiyo is in the loop.
"""

from __future__ import annotations

import asyncio
import inspect
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional, Union

from aiyoplane_verify import verify as verify_receipt_v2
from aiyoplane_verify.errors import AiyoVerifyError

from aiyoplane_mcp_authz.errors import AiyoDenied, AiyoUnreachable, ReceiptMismatchError, ToolConfigError
from aiyoplane_mcp_authz.rdp import Intent, LocalRdp, RdpProvider, RdpResult


@dataclass
class ToolCallContext:
    """Context handed to the gated tool handler on ALLOW.

    Contains the verified Execution Receipt and the intent attribution so the
    handler can audit its own invocations and attach the receipt to downstream
    artifacts for cross-system lineage.
    """

    receipt: str
    intent_id: str
    verdict: str
    reason_code: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


Handler = Callable[[Dict[str, Any], ToolCallContext], Union[Any, Awaitable[Any]]]


class AiyoAuthz:
    """Middleware that composes Aiyo's RDP above an MCP server's tool-call boundary."""

    def __init__(
        self,
        *,
        rdp: RdpProvider,
        tool_config: Dict[str, Dict[str, Any]],
        merchant_id: str = "mrch_local_demo",
        close_lineage: bool = True,
    ) -> None:
        self._rdp = rdp
        self._tool_config = tool_config
        self._merchant_id = merchant_id
        self._close_lineage = close_lineage

    def wrap(self, tool_name: str, handler: Optional[Handler] = None):
        """Wrap a tool handler with the authorization composition.

        Can be used as a direct function call:

            wrapped = authz.wrap("deploy_to_production", my_handler)

        Or as a decorator:

            @authz.wrap("deploy_to_production")
            async def deploy(args, ctx):
                ...
        """
        if handler is not None:
            return self._wrap_impl(tool_name, handler)

        def decorator(fn: Handler) -> Handler:
            return self._wrap_impl(tool_name, fn)

        return decorator

    def _wrap_impl(self, tool_name: str, handler: Handler) -> Handler:
        config = self._tool_config.get(tool_name)
        if config is None:
            raise ToolConfigError(f'No tool_config entry for "{tool_name}"')
        gated = bool(config.get("aiyo_gated", False))

        is_coroutine_handler = inspect.iscoroutinefunction(handler)

        if not gated:
            # Ungated tool: pass through with an empty context.
            if is_coroutine_handler:
                async def ungated_async_handler(args: Dict[str, Any], ctx: Optional[ToolCallContext] = None):
                    _ = ctx
                    return await handler(args, ToolCallContext(receipt="", intent_id="", verdict="allow"))
                return ungated_async_handler

            def ungated_sync_handler(args: Dict[str, Any], ctx: Optional[ToolCallContext] = None):
                _ = ctx
                return handler(args, ToolCallContext(receipt="", intent_id="", verdict="allow"))
            return ungated_sync_handler

        action_config = config.get("action") or {}
        action_type = action_config.get("type")
        action_target = action_config.get("target")
        if action_type is None:
            raise ToolConfigError(
                f'Tool "{tool_name}" is aiyo_gated but has no action.type declared'
            )

        async def gated_async_handler(args: Dict[str, Any], ctx: Optional[ToolCallContext] = None):
            _ = ctx  # unused; we build our own
            intent = self._build_intent(tool_name, args, action_type, action_target)
            result = await self._evaluate_async(intent)
            await self._enforce_verdict(result, intent)
            # ALLOW path
            invocation_ctx = ToolCallContext(
                receipt=result.receipt or "",
                intent_id=intent.intent_id,
                verdict=result.verdict,
                reason_code=result.reason_code,
            )
            try:
                outcome_value = await handler(args, invocation_ctx) if is_coroutine_handler else handler(args, invocation_ctx)
            except Exception as exc:
                if self._close_lineage:
                    await self._close_lineage_async(intent.intent_id, {"error": str(exc)})
                raise
            if self._close_lineage:
                await self._close_lineage_async(intent.intent_id, {"ok": True})
            return outcome_value

        def gated_sync_handler(args: Dict[str, Any], ctx: Optional[ToolCallContext] = None):
            _ = ctx
            intent = self._build_intent(tool_name, args, action_type, action_target)
            result = self._rdp.evaluate(intent)
            self._enforce_verdict_sync(result, intent)
            invocation_ctx = ToolCallContext(
                receipt=result.receipt or "",
                intent_id=intent.intent_id,
                verdict=result.verdict,
                reason_code=result.reason_code,
            )
            try:
                outcome_value = handler(args, invocation_ctx)
            except Exception as exc:
                if self._close_lineage:
                    self._close_lineage_sync(intent.intent_id, {"error": str(exc)})
                raise
            if self._close_lineage:
                self._close_lineage_sync(intent.intent_id, {"ok": True})
            return outcome_value

        return gated_async_handler if is_coroutine_handler else gated_sync_handler

    # ---- Intent construction ----

    def _build_intent(
        self,
        tool_name: str,
        args: Dict[str, Any],
        action_type: str,
        action_target: Optional[str],
    ) -> Intent:
        intent_id = f"int_{secrets.token_hex(8)}"
        actor = {
            "actor_type": "agent",
            "actor_id": args.get("_aiyo_agent_id", "unknown_agent"),
            "tool_name": tool_name,
        }
        return Intent(
            intent_id=intent_id,
            action_type=action_type,
            action_target=action_target,
            actor=actor,
            parameters={k: v for k, v in args.items() if not k.startswith("_aiyo_")},
            merchant_id=self._merchant_id,
            context_id=args.get("_aiyo_context_id"),
        )

    # ---- Evaluation + enforcement (sync + async paths) ----

    async def _evaluate_async(self, intent: Intent) -> RdpResult:
        # Run blocking evaluate() on a worker thread so the async handler path
        # doesn't block the event loop.
        return await asyncio.to_thread(self._rdp.evaluate, intent)

    async def _enforce_verdict(self, result: RdpResult, intent: Intent) -> None:
        if result.verdict == "allow":
            self._verify_receipt(result, intent)
            return
        if result.verdict == "escalate":
            # Escalation is first-class but the Composition Boundary must hold.
            raise AiyoDenied(
                "Tool invocation requires escalation.",
                code="ESCALATE",
                details={
                    "verdict": result.verdict,
                    "reason_code": result.reason_code,
                    "reason_detail": result.reason_detail,
                },
            )
        raise AiyoDenied(
            result.reason_detail or "Tool invocation denied by policy.",
            details={
                "verdict": result.verdict,
                "reason_code": result.reason_code,
            },
        )

    def _enforce_verdict_sync(self, result: RdpResult, intent: Intent) -> None:
        if result.verdict == "allow":
            self._verify_receipt(result, intent)
            return
        if result.verdict == "escalate":
            raise AiyoDenied(
                "Tool invocation requires escalation.",
                code="ESCALATE",
                details={
                    "verdict": result.verdict,
                    "reason_code": result.reason_code,
                    "reason_detail": result.reason_detail,
                },
            )
        raise AiyoDenied(
            result.reason_detail or "Tool invocation denied by policy.",
            details={
                "verdict": result.verdict,
                "reason_code": result.reason_code,
            },
        )

    def _verify_receipt(self, result: RdpResult, intent: Intent) -> None:
        """Verify the receipt locally before invoking the handler."""
        receipt = result.receipt
        if not receipt:
            raise ReceiptMismatchError(
                "RDP returned ALLOW but no receipt was issued.",
                details={"intent_id": intent.intent_id},
            )
        # Local RDP uses v1 HMAC; HostedRdp returns v2 Ed25519.
        if isinstance(self._rdp, LocalRdp):
            try:
                verified = verify_receipt_v2(receipt, hmac_secret=self._rdp.hmac_secret)
            except AiyoVerifyError as exc:
                raise ReceiptMismatchError(
                    f"LocalRdp receipt failed verification: {exc}",
                    cause=exc,
                    details={"intent_id": intent.intent_id},
                ) from exc
        else:
            try:
                verified = verify_receipt_v2(receipt)
            except AiyoVerifyError as exc:
                raise ReceiptMismatchError(
                    f"Hosted RDP receipt failed verification: {exc}",
                    cause=exc,
                    details={"intent_id": intent.intent_id},
                ) from exc

        if verified["claims"].get("iid") != intent.intent_id:
            raise ReceiptMismatchError(
                "Receipt iid claim does not match intent_id.",
                details={
                    "intent_id": intent.intent_id,
                    "receipt_iid": verified["claims"].get("iid"),
                },
            )

    # ---- Lineage closure ----

    async def _close_lineage_async(self, intent_id: str, outcome: Dict[str, Any]) -> None:
        try:
            await asyncio.to_thread(self._rdp.close, intent_id, outcome)
        except Exception:  # noqa: BLE001 - fire-and-forget
            pass

    def _close_lineage_sync(self, intent_id: str, outcome: Dict[str, Any]) -> None:
        try:
            self._rdp.close(intent_id, outcome)
        except Exception:  # noqa: BLE001 - fire-and-forget
            pass


def create_aiyo_mcp_authz(
    *,
    rdp: RdpProvider,
    tool_config: Dict[str, Dict[str, Any]],
    merchant_id: str = "mrch_local_demo",
    close_lineage: bool = True,
) -> AiyoAuthz:
    """Factory for the AiyoAuthz middleware."""
    return AiyoAuthz(
        rdp=rdp,
        tool_config=tool_config,
        merchant_id=merchant_id,
        close_lineage=close_lineage,
    )
