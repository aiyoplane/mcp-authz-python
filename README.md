# aiyoplane-mcp-authz

**Reference implementation of how Aiyo's Runtime Decision Point composes above an MCP server.**

Permission to invoke a tool is not authorization for the consequential action that invocation will cause. This package demonstrates the right shape of the answer: a middleware that intercepts every gated MCP `tools/call` request, delegates the authorization decision to Aiyo's Runtime Decision Point, verifies the returned execution receipt locally, and invokes the underlying tool handler only on ALLOW.

Python port of the Node reference implementation at [`@aiyoplane/mcp-authz`](https://github.com/aiyoplane/mcp-authz). Same composition pattern, same semantics. Apache 2.0 licensed.

Aiyoplane, Inc. · [aiyoplane.com](https://aiyoplane.com)

---

## Install

```sh
pip install aiyoplane-mcp-authz
```

Requires Python 3.9+. Depends on `aiyoplane-verify` (installed automatically) for receipt verification.

---

## Quick start

Load a merchant-authored policy, create a `LocalRdp` (in-process; demo / local-dev), wrap the gated tool handlers, and expose them via your MCP server:

```python
from aiyoplane_mcp_authz import create_aiyo_mcp_authz, create_local_rdp
import json

policy = json.loads(open("policy.example.json").read())

authz = create_aiyo_mcp_authz(
    rdp=create_local_rdp(policy, merchant_id="mrch_demo"),
    merchant_id="mrch_demo",
    tool_config={
        "deploy_to_production": {
            "aiyo_gated": True,
            "action": {"type": "deploy", "target": "production"},
        },
        "charge_customer": {
            "aiyo_gated": True,
            "action": {"type": "payment"},
        },
        "search_docs": {"aiyo_gated": False},
    },
)

@authz.wrap("deploy_to_production")
def deploy(args, ctx):
    # Runs only if the RDP returned ALLOW.
    # ctx.receipt is the verified Execution Receipt.
    return actually_deploy(args)
```

Register `deploy` with your MCP server the usual way. The MCP protocol between the agent and your server is unchanged; the agent never learns that Aiyo is in the loop.

Run the full demo:

```sh
pip install -e ".[dev]"
python examples/demo.py
```

The demo exercises ALLOW, ESCALATE equivalents, and BLOCK paths against a sample policy.

---

## What it does

- **Intercepts every gated MCP tool call** at the exact composition point the AEAP invariants specify.
- **Delegates the authorization decision to an RDP provider** — either `LocalRdp` (in-process, zero credentials, evaluates a small JSON policy) or `HostedRdp` (composes above Aiyo's production RDP over HTTPS).
- **Verifies the returned execution receipt locally** using the sister `aiyoplane-verify` package before the handler runs. No round-trip at the moment of execution.
- **On ALLOW**, invokes the underlying handler with the verified receipt on the invocation context.
- **On DENY**, raises a typed `AiyoDenied` exception the MCP server catches and surfaces to the agent as a structured MCP error.
- **On ESCALATE**, raises `AiyoDenied` with `code="ESCALATE"` so the Composition Boundary can route to the merchant's human-in-the-loop surface.
- **On any tamper, mismatch, expiry, or transport failure**, fails closed. The tool never runs.
- **After the handler completes (or raises), closes execution lineage** as a fire-and-forget call. Close failures never surface to the agent.

## What it isn't

- Not an MCP server. Bring your own — the official [`modelcontextprotocol/python-sdk`](https://github.com/modelcontextprotocol/python-sdk), a framework, or your own implementation.
- Not a replacement for Aiyo's HTTP API. The HostedRdp provider calls it.
- Not an MCP authorization standard. It's a composition example.
- Not stateful. Every gated tool call is a fresh authorization decision. There's no session cache to invalidate, no policy snapshot to drift.
- Not economic logic. Pricing, billing, and settlement live server-side on Aiyo.

---

## Example policy

The demo policy (`examples/policy.example.json`) is deliberately minimal — enough to show the ALLOW / BLOCK paths across both payment and non-payment action types:

```json
{
  "version": "policy_demo_v1",
  "rules": [
    {"action_type": "deploy", "action_target": "staging", "effect": "allow"},
    {"action_type": "deploy", "action_target": "production", "effect": "deny"},
    {"action_type": "payment", "amount_max": 100, "effect": "allow"},
    {"action_type": "payment", "amount_min": 101, "effect": "deny"}
  ]
}
```

Production policies are richer; the `LocalRdp` is a legible substitute for the demo path. Production deployments use `HostedRdp` against Aiyo's production policy service.

---

## Typed errors

Every failure in the composition raises one of these typed exceptions:

```python
from aiyoplane_mcp_authz import (
    AiyoDenied,            # RDP returned deny or escalate
    AiyoUnreachable,       # Hosted RDP could not be reached
    ReceiptMismatchError,  # Receipt did not match the intent
    ToolConfigError,       # Tool declared aiyo_gated but missing action config
)
```

Handle them explicitly in the MCP server's tool-call outer error handler:

```python
try:
    result = tool_handler(args, None)
except AiyoDenied as exc:
    # Surface a structured MCP error to the agent.
    raise McpError(exc.code or "DENIED", str(exc))
except AiyoUnreachable:
    # Treat as fail-closed by default. If the merchant wants fail-open behavior
    # under specific conditions, implement that explicitly here with an audit trail.
    raise McpError("AIYO_UNREACHABLE", "Aiyo RDP temporarily unavailable")
```

---

## Why this composition point

The two invariants any RDP composition above a tool-invocation protocol must satisfy:

1. **One authorization decision per consequential action.** Not one per session, not one per workflow, not one aggregated across multiple actions.
2. **The decision must occur strictly between intent and execution.** Not before the intent is knowable; not after the action has already run.

The MCP tool-call boundary is the one composition point that satisfies both invariants in the MCP protocol. See the [Aiyo × MCP blog post](https://aiyoplane.com/blog/aiyo-mcp-authz) for the full architectural argument.

---

## About Aiyo

Aiyo is the settlement-verified Economic Execution Authorization plane for autonomous systems. Its Runtime Decision Point verifies that settlement actually occurred on a real rail, evaluates merchant policy, and issues a portable authorization artifact that unlocks the action a payment — or any qualifying condition — was supposed to enable. **Verify First. Execute Second.**

[aiyoplane.com](https://aiyoplane.com)

---

## License

Apache License 2.0 © 2026 Aiyoplane, Inc. — see `LICENSE` and `NOTICE`.
