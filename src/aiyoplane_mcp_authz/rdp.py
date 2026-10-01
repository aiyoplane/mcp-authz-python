"""Runtime Decision Point providers.

Two providers are shipped:
  - LocalRdp: in-process RDP that evaluates a small JSON policy against the
    intent and issues v1 HMAC-signed receipts. Zero credentials, zero network.
    For demos and local development.
  - HostedRdp: calls Aiyo's hosted RDP over HTTPS and returns the result.
    For production use.

Both providers implement the same abstract RdpProvider interface, so the
AiyoAuthz middleware is agnostic about which one is in use.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from secrets import token_bytes
from typing import Any, Callable, Dict, Optional
from urllib.error import HTTPError, URLError

from aiyoplane_mcp_authz.errors import AiyoUnreachable


# -----------------------------------------------------------------------------
# Public types
# -----------------------------------------------------------------------------


@dataclass
class Intent:
    """A structured representation of a proposed consequential action."""

    intent_id: str
    action_type: str
    action_target: Optional[str]
    actor: Dict[str, Any]
    parameters: Dict[str, Any]
    merchant_id: str
    context_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "iid": self.intent_id,
            "action_type": self.action_type,
            "actor": self.actor,
            "parameters": self.parameters,
            "mid": self.merchant_id,
        }
        if self.action_target is not None:
            d["action_target"] = self.action_target
        if self.context_id is not None:
            d["cid"] = self.context_id
        return d


@dataclass
class RdpResult:
    """The RDP's response to an intent evaluation."""

    verdict: str  # "allow" | "escalate" | "deny"
    receipt: Optional[str] = None  # Present on allow (and optionally on escalate/deny)
    reason_code: Optional[str] = None
    reason_detail: Optional[str] = None
    intent_id: Optional[str] = None


class RdpProvider(ABC):
    """Abstract interface for RDP providers."""

    @abstractmethod
    def evaluate(self, intent: Intent) -> RdpResult:
        """Evaluate an intent and return the Verdict + receipt (where applicable)."""

    @abstractmethod
    def close(self, intent_id: str, outcome: Dict[str, Any]) -> None:
        """Close the execution lineage with the eventual outcome.

        Fire-and-forget: implementations SHOULD NOT raise on close failure.
        """


# -----------------------------------------------------------------------------
# Local RDP (in-process; demo / local-dev only)
# -----------------------------------------------------------------------------


class LocalRdp(RdpProvider):
    """In-process RDP for demos and local development.

    Evaluates a small JSON policy against the intent and issues v1 HMAC-signed
    receipts. Not for production. For production, use HostedRdp.
    """

    def __init__(
        self,
        policy: Dict[str, Any],
        *,
        hmac_secret: Optional[str] = None,
        merchant_id: str = "mrch_local_demo",
        receipt_ttl_seconds: int = 300,
    ) -> None:
        self._policy = policy
        self._hmac_secret = hmac_secret or token_bytes(32).hex()
        self._merchant_id = merchant_id
        self._receipt_ttl_seconds = receipt_ttl_seconds

    @property
    def hmac_secret(self) -> str:
        """Expose the HMAC secret so the verifier can re-check locally in demos."""
        return self._hmac_secret

    def evaluate(self, intent: Intent) -> RdpResult:
        policy_rules = self._policy.get("rules", [])
        if not isinstance(policy_rules, list):
            return RdpResult(
                verdict="deny",
                reason_code="POLICY_INDETERMINATE",
                reason_detail="Policy has no rules array.",
                intent_id=intent.intent_id,
            )

        for rule in policy_rules:
            if not isinstance(rule, dict):
                continue
            if self._rule_matches(rule, intent):
                effect = rule.get("effect", "deny")
                reason_code = rule.get("reason_code")
                reason_detail = rule.get("reason_detail")
                if effect == "allow":
                    receipt = self._issue_receipt(intent)
                    return RdpResult(
                        verdict="allow",
                        receipt=receipt,
                        reason_code=reason_code or "POLICY_ALLOW",
                        reason_detail=reason_detail,
                        intent_id=intent.intent_id,
                    )
                if effect == "escalate":
                    return RdpResult(
                        verdict="escalate",
                        reason_code=reason_code or "POLICY_ESCALATE",
                        reason_detail=reason_detail,
                        intent_id=intent.intent_id,
                    )
                return RdpResult(
                    verdict="deny",
                    reason_code=reason_code or "POLICY_DENY",
                    reason_detail=reason_detail,
                    intent_id=intent.intent_id,
                )

        # No rule matched; silence is denial per the AEAP fail-closed invariant.
        return RdpResult(
            verdict="deny",
            reason_code="POLICY_SILENT_ON_ACTION_TYPE",
            reason_detail=f"Policy has no rule matching action_type={intent.action_type}",
            intent_id=intent.intent_id,
        )

    def close(self, intent_id: str, outcome: Dict[str, Any]) -> None:
        # Local RDP has no backend to notify; close is a no-op.
        del intent_id, outcome

    # ---- Rule-match helpers ----

    def _rule_matches(self, rule: Dict[str, Any], intent: Intent) -> bool:
        action_type_match = rule.get("action_type")
        if action_type_match is not None and action_type_match != intent.action_type:
            return False

        target_match = rule.get("action_target")
        if target_match is not None and target_match != intent.action_target:
            return False

        amount_max = rule.get("amount_max")
        if amount_max is not None:
            amount = intent.parameters.get("amount")
            if not isinstance(amount, (int, float)) or amount > amount_max:
                return False

        amount_min = rule.get("amount_min")
        if amount_min is not None:
            amount = intent.parameters.get("amount")
            if not isinstance(amount, (int, float)) or amount < amount_min:
                return False

        return True

    def _issue_receipt(self, intent: Intent) -> str:
        now_s = int(time.time())
        claims = {
            "iid": intent.intent_id,
            "mid": self._merchant_id,
            "iat": now_s,
            "exp": now_s + self._receipt_ttl_seconds,
        }
        if intent.context_id is not None:
            claims["cid"] = intent.context_id

        payload_json = json.dumps(claims, separators=(",", ":"), sort_keys=True)
        payload_b64 = _base64url_encode(payload_json.encode("utf-8"))
        signed_bytes = payload_b64.encode("utf-8")
        signature = hmac.new(
            self._hmac_secret.encode("utf-8"),
            signed_bytes,
            hashlib.sha256,
        ).digest()
        sig_b64 = _base64url_encode(signature)
        return f"v1.{payload_b64}.{sig_b64}"


# -----------------------------------------------------------------------------
# Hosted RDP (calls Aiyo API; production use)
# -----------------------------------------------------------------------------


class HostedRdp(RdpProvider):
    """RDP provider that calls Aiyo's hosted RDP over HTTPS.

    Default API endpoint is https://api.aiyoplane.com; override with api_base_url.
    Requires an API key (contact Aiyo for provisioning in production).
    """

    def __init__(
        self,
        *,
        api_key: str,
        api_base_url: str = "https://api.aiyoplane.com",
        timeout_seconds: float = 10.0,
    ) -> None:
        if not isinstance(api_key, str) or not api_key:
            raise ValueError("HostedRdp requires a non-empty api_key")
        self._api_key = api_key
        self._api_base = api_base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds

    def evaluate(self, intent: Intent) -> RdpResult:
        body = json.dumps(intent.to_dict()).encode("utf-8")
        req = urllib.request.Request(
            f"{self._api_base}/v1/rdp/evaluate",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout_seconds) as response:
                response_body = response.read()
        except HTTPError as exc:
            raise AiyoUnreachable(
                f"RDP evaluate returned HTTP {exc.code}",
                cause=exc,
            ) from exc
        except URLError as exc:
            raise AiyoUnreachable(
                f"Could not reach Aiyo RDP: {exc.reason}",
                cause=exc,
            ) from exc

        try:
            data = json.loads(response_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise AiyoUnreachable(
                "RDP response was not valid JSON",
                cause=exc,
            ) from exc

        return RdpResult(
            verdict=str(data.get("verdict", "deny")),
            receipt=data.get("receipt"),
            reason_code=data.get("reason_code"),
            reason_detail=data.get("reason_detail"),
            intent_id=data.get("intent_id") or intent.intent_id,
        )

    def close(self, intent_id: str, outcome: Dict[str, Any]) -> None:
        # Fire-and-forget: swallow all errors so lineage closure never surfaces
        # to the agent as a tool-call failure.
        body = json.dumps({"iid": intent_id, "outcome": outcome}).encode("utf-8")
        req = urllib.request.Request(
            f"{self._api_base}/v1/rdp/close",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
        )
        try:
            urllib.request.urlopen(req, timeout=self._timeout_seconds)
        except Exception:  # noqa: BLE001 - intentionally swallow
            pass


# -----------------------------------------------------------------------------
# Factory helpers
# -----------------------------------------------------------------------------


def create_local_rdp(policy: Dict[str, Any], **kwargs: Any) -> LocalRdp:
    """Factory for the LocalRdp provider."""
    return LocalRdp(policy, **kwargs)


def create_hosted_rdp(*, api_key: str, **kwargs: Any) -> HostedRdp:
    """Factory for the HostedRdp provider."""
    return HostedRdp(api_key=api_key, **kwargs)


# -----------------------------------------------------------------------------
# base64url helpers (shared with receipt-signing)
# -----------------------------------------------------------------------------


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
