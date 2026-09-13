# Installed Finalization Launcher Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the installed `auto-code-launcher` entrypoint compose and serve one protected finalization or receipt request from inherited launcher-owned capabilities.

**Architecture:** A canonical, signed bootstrap envelope is read only from fixed inherited descriptors. It validates file identity, access mode, ownership, schema, and all capability bindings before creating the state/index, bridge, Git, artifact, and signing-key dependencies consumed by `FinalizationLauncher`. The launcher then creates the existing one-use IPC listener and gives the child only finalization capability descriptors.

**Tech Stack:** Python 3.12, Pydantic 2, cryptography Ed25519, Unix file descriptors/sockets, pytest.

**Spec:** `docs/superpowers/specs/2026-09-13-finalization-launcher-boundary-design.md`

## Global Constraints

- Installed launcher input is protected inherited FDs only; argv contains only operation identifiers and may never supply paths, callbacks, keys, bridge state, or capabilities.
- Validate all descriptor identity, regular/read-only mode, owner, canonical JSON shape, signatures, and cross-bindings before constructing operational dependencies.
- The child receives only finalization IPC descriptor/trust/binding FDs, not bootstrap FDs or launcher-owned capabilities.
- Serve exactly one request and remove descriptors and Unix listener paths on every outcome.
- Missing, malformed, replaced, expired, mismatched, or unauthenticated bootstrap data fails closed with the fixed launcher error.
- Browser E2E is not required because the change is deterministic launcher IPC and local capability composition.

### Task 1: Protected Bootstrap Contract

**Files:**
- Modify: `src/auto_code/launcher.py`
- Test: `tests/test_finalization_launcher.py`

**Interfaces:**
- Produces: `load_protected_bootstrap() -> _LauncherRuntime` from fixed inherited descriptors.
- Produces: `main(argv: Sequence[str] | None = None) -> int`, accepting only `finalize --run --expected-revision --expected-hash` and `receipt --run --expected-revision --expected-hash --request-id`.

- [ ] **Step 1: Write failing installed-console subprocess tests**

```python
def test_installed_launcher_composes_finalize_from_protected_bootstrap(...):
    result = run_installed_launcher_with_fake_capabilities("finalize", generation)
    assert result.returncode == 0

def test_installed_launcher_rejects_replaced_or_malformed_bootstrap(...):
    result = run_installed_launcher_with_replaced_bootstrap(...)
    assert result.returncode == 2
    assert result.stderr == "auto-code-launcher: protected runtime unavailable\n"
```

- [ ] **Step 2: Run the focused bootstrap tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_finalization_launcher.py -q -k 'installed_launcher'`

Expected: FAIL because the installed entrypoint always returns the protected-runtime error.

- [ ] **Step 3: Implement the minimal canonical bootstrap loader and dispatch**

```python
def main(argv: Sequence[str] | None = None) -> int:
    try:
        runtime = load_protected_bootstrap()
        command = parse_identifier_only_command(argv)
        return FinalizationLauncher(runtime).serve_ticket_process(*command)
    except (BootstrapError, FinalizationLauncherError, OSError, ValueError):
        print("auto-code-launcher: protected runtime unavailable", file=sys.stderr)
        return 2
```

Use a signed envelope descriptor plus protected capability descriptors for the state root, index binding, bridge, Git, and private key. Reject every inconsistent descriptor before `FinalizationLauncher` is instantiated.

- [ ] **Step 4: Run the focused bootstrap tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_finalization_launcher.py -q -k 'installed_launcher'`

Expected: PASS.

### Task 2: Receipt Routing And Delivery Evidence

**Files:**
- Modify: `src/launcher_finalization.py`
- Modify: `tests/test_finalization_launcher.py`
- Modify: `.superpowers/sdd/2026-09-05-04-ralph-and-finalization/task-3-report.md`

**Interfaces:**
- Produces: launcher-owned receipt routing for `FinalizationRequest(operation="receipt", ...)` without ticket-provided receipt content.
- Produces: a committed bootstrap implementation and test coverage.

- [ ] **Step 1: Write a failing receipt-route subprocess test**

```python
def test_installed_launcher_routes_receipt_with_only_identifiers(...):
    result = run_installed_launcher_with_fake_capabilities("receipt", generation, request_id)
    assert result.returncode == 0
```

- [ ] **Step 2: Run the receipt regression to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_finalization_launcher.py -q -k 'receipt.*installed_launcher'`

Expected: FAIL because the launcher receipt handler is unavailable.

- [ ] **Step 3: Compose receipt handling from the trusted launcher bridge**

```python
def _handle_receipt(self, generation: StateGeneration, request: FinalizationRequest) -> StepResult:
    self._require_request(generation, request)
    return self._finalizer_for(generation).accept_trusted_receipt(request.request_id)
```

The actual method name must match the existing trusted `LinearGateway`/finalizer receipt reconciliation API; the IPC client remains identifier-only.

- [ ] **Step 4: Verify focused and complete suites**

Run: `.venv/bin/python -m pytest tests/test_finalization_launcher.py tests/test_finalization_service.py tests/test_finalizer.py tests/test_cli.py -q && .venv/bin/python -m pytest -q && .venv/bin/python -m compileall -q src tests && git diff --check`

Expected: all commands exit `0`.

- [ ] **Step 5: Record evidence and commit**

Append exact commands/results and the minimal-bootstrap interface ruling to the ignored Task 3 report. Commit intended source/test files with:

```bash
git add src/auto_code/launcher.py src/launcher_finalization.py tests/test_finalization_launcher.py docs/superpowers/plans/2026-09-13-installed-finalization-launcher-bootstrap.md
git commit -m "feat: bootstrap installed finalization launcher"
```

## Plan Self-Review

- Spec coverage: Task 1 covers launcher-only FD input, capability validation, child FD isolation, one-use serving, and fail-closed bootstrap; Task 2 covers receipt routing and required deterministic verification.
- Placeholder scan: the only deferred API spelling is explicitly constrained to the existing trusted receipt API and will be resolved from source before implementation.
- Type consistency: Task 1 constructs the existing `_LauncherRuntime` consumed by `FinalizationLauncher`; Task 2 changes only its existing receipt handler.
