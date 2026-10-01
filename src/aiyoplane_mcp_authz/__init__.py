"""aiyoplane-mcp-authz.

Reference implementation of how Aiyo's Runtime Decision Point composes above
an MCP server. Governs consequential tool invocations at the protocol boundary.

Aiyoplane, Inc. - Apache 2.0 licensed.
https://aiyoplane.com
"""

from aiyoplane_mcp_authz.authz import AiyoAuthz, create_aiyo_mcp_authz
from aiyoplane_mcp_authz.errors import (
    AiyoAuthzError,
    AiyoDenied,
    AiyoUnreachable,
    ReceiptMismatchError,
    ToolConfigError,
)
from aiyoplane_mcp_authz.rdp import (
    HostedRdp,
    LocalRdp,
    RdpProvider,
    create_hosted_rdp,
    create_local_rdp,
)

__version__ = "1.0.1"

__all__ = [
    "AiyoAuthz",
    "create_aiyo_mcp_authz",
    "LocalRdp",
    "HostedRdp",
    "RdpProvider",
    "create_local_rdp",
    "create_hosted_rdp",
    "AiyoAuthzError",
    "AiyoDenied",
    "AiyoUnreachable",
    "ReceiptMismatchError",
    "ToolConfigError",
    "__version__",
]
