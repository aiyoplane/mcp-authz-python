"""Self-contained demo of aiyoplane-mcp-authz.

Shows the composition pattern end-to-end:
  1. A merchant-authored policy (JSON) is loaded
  2. A LocalRdp is created from the policy
  3. AiyoAuthz wraps two gated tool handlers (a payment and a deploy)
  4. Each tool is invoked; the RDP evaluates and the handler runs only on ALLOW
  5. The receipt returned on ALLOW is verified before the handler is reached

Run with: python examples/demo.py
"""

from __future__ import annotations

import json
from pathlib import Path

from aiyoplane_mcp_authz import (
    AiyoDenied,
    create_aiyo_mcp_authz,
    create_local_rdp,
)


def main() -> None:
    policy = json.loads((Path(__file__).parent / "policy.example.json").read_text())

    rdp = create_local_rdp(policy, merchant_id="mrch_demo")

    authz = create_aiyo_mcp_authz(
        rdp=rdp,
        merchant_id="mrch_demo",
        tool_config={
            "deploy_to_production": {
                "aiyo_gated": True,
                "action": {"type": "deploy", "target": "production"},
            },
            "deploy_to_staging": {
                "aiyo_gated": True,
                "action": {"type": "deploy", "target": "staging"},
            },
            "charge_customer": {
                "aiyo_gated": True,
                "action": {"type": "payment"},
            },
            "search_docs": {"aiyo_gated": False},
        },
    )

    @authz.wrap("deploy_to_staging")
    def deploy_to_staging(args, ctx):
        print(f"✓ Deploying to staging: {args}")
        print(f"  (receipt: {ctx.receipt[:40]}…)")
        return {"status": "deployed", "env": "staging"}

    @authz.wrap("deploy_to_production")
    def deploy_to_production(args, ctx):
        print(f"✓ Deploying to production: {args}")
        print(f"  (receipt: {ctx.receipt[:40]}…)")
        return {"status": "deployed", "env": "production"}

    @authz.wrap("charge_customer")
    def charge_customer(args, ctx):
        print(f"✓ Charging customer: ${args.get('amount')}")
        print(f"  (receipt: {ctx.receipt[:40]}…)")
        return {"status": "charged", "amount": args.get("amount")}

    print("\n--- Case 1: deploy to staging (should ALLOW) ---")
    try:
        deploy_to_staging({"artifact_sha": "a3f21e"}, None)
    except AiyoDenied as exc:
        print(f"✗ Denied: {exc} (code={exc.code})")

    print("\n--- Case 2: deploy to production (demo policy BLOCKS) ---")
    try:
        deploy_to_production({"artifact_sha": "a3f21e"}, None)
    except AiyoDenied as exc:
        print(f"✗ Denied: {exc} (code={exc.code})")

    print("\n--- Case 3: $50 charge (ALLOW) ---")
    try:
        charge_customer({"amount": 50}, None)
    except AiyoDenied as exc:
        print(f"✗ Denied: {exc} (code={exc.code})")

    print("\n--- Case 4: $500 charge (BLOCK; exceeds policy threshold) ---")
    try:
        charge_customer({"amount": 500}, None)
    except AiyoDenied as exc:
        print(f"✗ Denied: {exc} (code={exc.code})")


if __name__ == "__main__":
    main()
