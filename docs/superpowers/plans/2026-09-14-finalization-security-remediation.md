# Finalization Security Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close verified finalization isolation, bridge recovery, and protected Git execution gaps.

**Architecture:** The launcher kills every unverified prepared child, requires signed child-observed procfs denial, completes bridge failures durably, and composes a protected Git executor into `GitGuard`. Each boundary is verified with a fail-closed regression.

**Tech Stack:** Python 3.12, Unix sockets, Ed25519, `SCM_RIGHTS`, pytest.

**Spec:** `docs/superpowers/specs/2026-09-14-finalization-remediation-design.md`

## Global Constraints

- Missing, malformed, or unauthorized sandbox evidence kills and reaps the prepared child before failure is reported.
- A failed kill and failed reap are both surfaced to the caller.
- Evidence must prove denied access to the launcher bootstrap FD before finalization capability transfer.
- Bridge timeout or handler failure persists a signed terminal error response.
- Git commands execute only through launcher-owned protected capability; ticket children receive no Git credential or executor descriptor.

---

### Task 1: Clean Up Invalid Prepared Children

**Files:**
- Modify: `src/auto_code/process.py`, `src/launcher_finalization.py`
- Test: `tests/test_process.py`, `tests/test_finalization_launcher.py`

**Interfaces:**
- Produces `PreparedChildCleanupError(ExceptionGroup)` containing failed kill/reap exceptions.

- [ ] **Step 1: Write failing cleanup regressions**

```python
def test_invalid_preparation_evidence_kills_and_reaps_returned_child(...):
    with pytest.raises(ProcessConfigurationError):
        sandbox.prepare_finalization_child(argv)
    assert calls == ["kill_finalization_child", "wait_finalization_child"]
```

- [ ] **Step 2: Verify RED**

Run: `.venv/bin/python -m pytest tests/test_process.py tests/test_finalization_launcher.py -k 'invalid_preparation and cleanup' -q`

Expected: FAIL because invalid preparation closes only the transport.

- [ ] **Step 3: Implement independent kill/reap before close**

```python
try:
    verify_preparation(response)
except Exception:
    cleanup_errors = cleanup_prepared_child(transport, child_id)
    raise ProcessConfigurationError("Finalization child evidence is invalid") from cleanup_errors
```

Call both cleanup operations when a syntactically valid child ID was received; retain both failures in an `ExceptionGroup`.

- [ ] **Step 4: Verify GREEN and commit**

Run: `.venv/bin/python -m pytest tests/test_process.py tests/test_finalization_launcher.py -q`

```bash
git add src/auto_code/process.py src/launcher_finalization.py tests/test_process.py tests/test_finalization_launcher.py
git commit -m "fix: reap children with invalid isolation evidence"
```

### Task 2: Prove Procfs Bootstrap Denial

**Files:**
- Modify: `src/auto_code/process.py`, `src/launcher_finalization.py`
- Test: `tests/test_process.py`, `tests/test_finalization_launcher.py`

**Interfaces:**
- Extends `SandboxChildEvidence` with `bootstrap_fd_access: Literal["denied"]`.

- [ ] **Step 1: Write failing signed-probe regressions**

```python
def test_launcher_rejects_signed_evidence_when_bootstrap_fd_access_is_not_denied(...):
    with pytest.raises(ProcessConfigurationError):
        sandbox.prepare_finalization_child(argv)

def test_isolated_child_probe_cannot_open_parent_bootstrap_fd(...):
    assert evidence.bootstrap_fd_access == "denied"
```

- [ ] **Step 2: Verify RED**

Run: `.venv/bin/python -m pytest tests/test_process.py tests/test_finalization_launcher.py -k 'bootstrap_fd_access or procfs_probe' -q`

Expected: FAIL because the signed payload has no probe result.

- [ ] **Step 3: Bind fixed probe result to evidence**

```python
if evidence.bootstrap_fd_access != "denied":
    raise ValueError
verify_signature(evidence, sandbox_identity)
```

The sandbox runs a fixed child probe for `/proc/$PPID/fd/8`; only its signed `denied` result is accepted before FDs 4-6 transfer.

- [ ] **Step 4: Verify GREEN and commit**

Run: `.venv/bin/python -m pytest tests/test_process.py tests/test_finalization_launcher.py -q`

```bash
git add src/auto_code/process.py src/launcher_finalization.py tests/test_process.py tests/test_finalization_launcher.py
git commit -m "feat: verify finalization procfs isolation"
```

### Task 3: Complete Bridge Failures Durably

**Files:**
- Modify: `src/auto_code/launcher.py`, `src/auto_code/finalization_service.py`
- Test: `tests/test_finalization_service.py`, `tests/test_launcher.py`

**Interfaces:**
- `_ProtectedBridgeClient.call(..., deadline: float) -> McpToolResult`.
- `FinalizationService.dispatch(...) -> FinalizationResponse` returns a signed error response for timeout/handler failure.

- [ ] **Step 1: Write failing deadline and replay regressions**

```python
def test_handler_failure_completes_nonce_with_replayable_signed_error(...):
    first = service.dispatch(request)
    assert service.dispatch(request) == first
    assert first.error is not None
```

- [ ] **Step 2: Verify RED**

Run: `.venv/bin/python -m pytest tests/test_finalization_service.py tests/test_launcher.py -k 'bridge and timeout or handler_failure' -q`

Expected: FAIL because the nonce remains `consumed`.

- [ ] **Step 3: Apply total deadline and terminal-error persistence**

```python
try:
    result = handler(request)
    response = response_for(result=result, error=None)
except Exception as error:
    response = response_for(result=None, error=str(error))
persist_completed(descriptor, response)
```

Set socket timeout from the remaining deadline before send and read; persist the signed response in both branches.

- [ ] **Step 4: Verify GREEN and commit**

Run: `.venv/bin/python -m pytest tests/test_finalization_service.py tests/test_launcher.py -q`

```bash
git add src/auto_code/launcher.py src/auto_code/finalization_service.py tests/test_finalization_service.py tests/test_launcher.py
git commit -m "fix: complete failed bridge requests durably"
```

### Task 4: Compose Protected Git Execution

**Files:**
- Modify: `src/auto_code/launcher.py`, `src/auto_code/git.py`
- Test: `tests/test_launcher.py`, `tests/test_git.py`, `tests/test_finalization_launcher.py`

**Interfaces:**
- `ProcessGitExecutor(bridge: TrustedLinearBridge, policy: ProtectedGitPolicy)` supplied as `GitGuard(..., executor=executor)`.

- [ ] **Step 1: Write failing launcher composition regression**

```python
def test_protected_bootstrap_finalization_uses_process_git_executor(...):
    runtime = load_protected_bootstrap()
    assert isinstance(runtime.git_guard.executor, ProcessGitExecutor)
```

- [ ] **Step 2: Verify RED**

Run: `.venv/bin/python -m pytest tests/test_launcher.py tests/test_git.py tests/test_finalization_launcher.py -k 'protected_bootstrap and git_executor' -q`

Expected: FAIL because `GitGuard.executor` is `None`.

- [ ] **Step 3: Compose protected executor from bootstrap policy**

```python
executor = ProcessGitExecutor(
    bridge=trusted_bridge,
    repository_root=repository_root,
    protected_paths=tuple(git["protected_paths"]),
)
git_guard = GitGuard(repository_root, executor=executor, ...)
```

Use only bootstrap-verified descriptors and policy. Test a valid finalization through a fake executor without starting Git.

- [ ] **Step 4: Verify GREEN and commit**

Run: `.venv/bin/python -m pytest tests/test_launcher.py tests/test_git.py tests/test_finalization_launcher.py -q`

```bash
git add src/auto_code/launcher.py src/auto_code/git.py tests/test_launcher.py tests/test_git.py tests/test_finalization_launcher.py
git commit -m "feat: compose protected finalization git executor"
```

### Task 5: Whole-Branch Security Regression

**Files:**
- Test: `tests/test_process.py`, `tests/test_finalization_service.py`, `tests/test_launcher.py`, `tests/test_git.py`, `tests/test_finalization_launcher.py`

- [ ] **Step 1: Run complete verification**

Run: `.venv/bin/python -m pytest -q && .venv/bin/python -m compileall -q src tests && git diff --check`

Expected: all commands exit 0.

- [ ] **Step 2: Record evidence and request independent review**

Record exact output in the SDD report, generate review package from the plan base through `HEAD`, and request a read-only final security review.
