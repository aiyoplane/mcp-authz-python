# Changelog — `aiyoplane-mcp-authz` (Python)

All notable changes to this package are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.1] — 2026-10 (packaging polish and LICENSE)

### Changed
- Ships the full Apache 2.0 LICENSE text with the source distribution (previously a stub pointing at the sister package).
- Removed internal setup instructions from the source distribution. The sdist and wheel now ship only end-user artifacts.
- Dependency floor bumped to `aiyoplane-verify>=1.0.2` to track the paired clean release.
- `pyproject.toml` and `__init__.__version__` bumped to `1.0.1`.

### Compatibility
- No API changes. Drop-in replacement for 1.0.0.

### Protocol Conformance
- Continues to implement the Runtime Decision Point composition pattern defined in [AEAP](https://aiyoplane.com/trust) §2.

---

## Yanked Versions

- `1.0.0` — Superseded by 1.0.1 (full Apache 2.0 LICENSE text and packaging polish).

---

## [1.0.0] — 2026-10 (initial Python port)

### Added
- Initial Python port of `@aiyoplane/mcp-authz` v1.0.0.
- `AiyoAuthz.wrap()` supporting both direct-call and decorator usage:
  - Direct: `authz.wrap("deploy_to_production", fn)`
  - Decorator: `@authz.wrap("deploy_to_production")`
- `RdpProvider` abstract base class with two concrete implementations:
  - `LocalRdp` — in-process policy evaluation with v1 HMAC-SHA256 receipt issuance. For development and single-process deployments.
  - `HostedRdp` — HTTP client against the hosted Aiyo RDP at `api.aiyoplane.com/v1/rdp/evaluate`. For production composition where policy, evidence, and receipts are managed centrally.
- Sync and async handler support via `asyncio.to_thread` for blocking HTTP calls.
- Typed error hierarchy: `AiyoDenied`, `AiyoUnreachable`, `ReceiptMismatchError`, `ToolConfigError`.
- `Intent` and `RdpResult` dataclasses mirroring the Node implementation.
- `examples/policy.example.json` with deploy-authorization and payment-authorization rules.
- `examples/demo.py` exercising four composition cases.
- `py.typed` marker (PEP 561) so downstream type checkers can read the package's inline annotations.

### Notes on Protocol Conformance

This package is an implementation of the Runtime Decision Point composition pattern defined in [AEAP](https://aiyoplane.com/trust) §2 (Composition Boundary invariants). It is **not** a reference specification — the specification is AEAP. Any behavior that differs between this package and AEAP is a bug in this package, not a feature.

The package shares no vendored code with `@aiyoplane/mcp-authz` (Node). The two implementations independently derive behavior from the AEAP spec. That mutual independence is what makes AEAP an implementable protocol rather than a reference-library-with-wrappers.

---

## Known Future Work

Items identified but not shipped. Documented here so they don't drift out of memory.

### Async-native `RdpProvider` interface (deferred to v1.1 or v2.0)

**Current behavior (v1.0.0).** When a wrapped async handler is called, the synchronous `HostedRdp.evaluate(...)` HTTP call is dispatched to a thread via `asyncio.to_thread` so it doesn't block the event loop. This is a compatibility choice: it means a single `RdpProvider` abstraction works for both sync and async handler paths without introducing an async-provider interface.

**Why this is correct for v1.0.** First production reference implementation. Simplicity and correctness over premature optimization. The `to_thread` dispatch is predictable, debuggable, and matches how most Python HTTP libraries get used from async code in 2026.

**Why this will need to change eventually.** If RDP evaluation becomes high-frequency — specifically, inside agent runtimes that fire dozens to hundreds of composition-boundary checks per minute — unconditionally dispatching every synchronous hosted RDP call into a thread will exert back-pressure on the thread pool and incur per-call context-switch overhead that a native async HTTP path (e.g. `httpx.AsyncClient`) would avoid.

**Target shape of the fix.** Introduce a parallel async interface on `RdpProvider`:

```python
class RdpProvider(ABC):
    @abstractmethod
    def evaluate(self, intent: Intent) -> RdpResult: ...

    async def evaluate_async(self, intent: Intent) -> RdpResult:
        # Default: dispatch sync evaluate to a thread. Native async
        # providers (e.g. HttpxAsyncHostedRdp) override this.
        return await asyncio.to_thread(self.evaluate, intent)
```

`AiyoAuthz.wrap()` detects whether the wrapped handler is a coroutine function and calls `evaluate_async` on the provider in that path. Existing providers get the default thread-dispatched behavior unchanged. New async-native providers override `evaluate_async` and avoid the thread hop.

**When to actually ship this.** When there's a concrete workload showing the thread-dispatch overhead is non-trivial. Shipping before then is premature optimization. This note exists so the decision isn't rediscovered from scratch when the workload arrives.

**Why this note matters.** "Future refinement" items that live only in Slack vanish. This note lives in the package itself, so anyone opening the source — including a future Aiyo engineer or an external contributor — sees it next to the code it's about.

---

## Links

- **Package home:** https://pypi.org/project/aiyoplane-mcp-authz/
- **Source:** https://github.com/aiyoplane/aiyoplane-mcp-authz
- **AEAP specification:** https://aiyoplane.com/trust (links to the current draft)
- **Node sibling:** https://www.npmjs.com/package/@aiyoplane/mcp-authz
