# Finalization Process Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Isolate ticket children from launcher bootstrap authority and make installed finalization Git/bridge handling operational and recoverable.

**Architecture:** The launcher retains all bootstrap FDs in a privileged process and delegates ticket startup to the existing launcher sandbox under a procfs-isolated boundary. It builds `GitGuard` with a protected executor, bounds bridge I/O, and completes consumed nonce records with a signed error on bridge failure.

**Tech Stack:** Python 3.12, Unix process namespaces/procfs, Unix sockets, Ed25519, pytest.

**Spec:** `docs/superpowers/specs/2026-09-13-finalization-process-isolation-design.md`

## Global Constraints

- Ticket children receive only finalization descriptor, trust, and binding FDs.
- Bootstrap FDs, private key, state root, bridge transport, and Git executor stay launcher-owned.
- Missing process isolation, malformed capability, bridge timeout, or receipt mismatch fails closed before another effect.
- Browser E2E is not required.

---

### Task 1: Isolate Ticket Process Authority

**Files:**
- Modify: `src/auto_code/launcher.py`, `src/launcher_finalization.py`, `src/auto_code/process.py`
- Test: `tests/test_finalization_launcher.py`, `tests/test_process.py`

**Interfaces:**
- Produces `LauncherSocketSandbox.start_finalization_child(...) -> ProcessHandle` that applies PID/procfs isolation before passing FDs 4-6.

- [ ] **Step 1: Write failing procfs isolation regression**

```python
def test_ticket_child_cannot_open_launcher_key_fd(...):
    result = run_isolated_ticket("/proc/$PPID/fd/8")
    assert result.returncode != 0
```

- [ ] **Step 2: Verify RED**

Run: `.venv/bin/python -m pytest tests/test_finalization_launcher.py -k 'procfs or ticket_child' -q`

Expected: FAIL because the child can access its parent's bootstrap FD.

- [ ] **Step 3: Implement isolated child startup**

```python
handle = sandbox.start_finalization_child(
    ticket_argv,
    capability_fds=(descriptor_fd, trust_fd, binding_fd),
    isolate_procfs=True,
)
```

Require a verified launcher sandbox capability. Refuse to spawn if it cannot establish the configured procfs/PID isolation; only map the three capability FDs into child slots 4-6.

- [ ] **Step 4: Verify GREEN**

Run: `.venv/bin/python -m pytest tests/test_finalization_launcher.py tests/test_process.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/auto_code/launcher.py src/launcher_finalization.py src/auto_code/process.py tests/test_finalization_launcher.py tests/test_process.py
git commit -m "fix: isolate finalization ticket process"
```

### Task 2: Compose Protected Git Execution

**Files:**
- Modify: `src/auto_code/launcher.py`, `src/auto_code/git.py`
- Test: `tests/test_finalization_launcher.py`, `tests/test_git.py`

**Interfaces:**
- Produces `GitGuard(..., executor=ProcessGitExecutor(...))` from the protected bootstrap sandbox/executor descriptor.

- [ ] **Step 1: Write a failing real-finalization composition test**

```python
def test_installed_launcher_reaches_protected_git_executor(...):
    result = run_valid_launcher_finalization(fake_executor)
    assert fake_executor.commands == [("git", "status", "--porcelain=v1")]
```

- [ ] **Step 2: Verify RED**

Run: `.venv/bin/python -m pytest tests/test_finalization_launcher.py -k protected_git_executor -q`

Expected: FAIL because bootstrap creates GitGuard without an executor.

- [ ] **Step 3: Build the executor from the bootstrap capability**

```python
executor = ProcessGitExecutor(sandbox=bootstrap.git_sandbox, policy=bootstrap.git_policy)
git_guard = GitGuard(repository_root, executor=executor, ...)
```

Validate the executor identity, repository binding, command policy, and sandbox descriptor before composition.

- [ ] **Step 4: Verify GREEN**

Run: `.venv/bin/python -m pytest tests/test_finalization_launcher.py tests/test_git.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/auto_code/launcher.py src/auto_code/git.py tests/test_finalization_launcher.py tests/test_git.py
git commit -m "fix: compose protected finalization git executor"
```

### Task 3: Bound Bridge I/O And Complete Consumed Nonces

**Files:**
- Modify: `src/auto_code/launcher.py`, `src/auto_code/finalization_service.py`
- Test: `tests/test_finalization_launcher.py`, `tests/test_finalization_service.py`

**Interfaces:**
- Produces `ProtectedBridgeClient.call(..., deadline: _Deadline) -> McpToolResult`.
- Produces durable signed `FinalizationResponse(error=...)` for a consumed nonce whose bridge I/O times out or has an invalid frame.

- [ ] **Step 1: Write failing bridge timeout and replay tests**

```python
def test_bridge_timeout_completes_consumed_nonce_once(...):
    first = invoke_stalled_bridge_capability()
    replay = invoke_same_capability()
    assert replay == first
    assert bridge.calls == 1
```

- [ ] **Step 2: Verify RED**

Run: `.venv/bin/python -m pytest tests/test_finalization_service.py tests/test_finalization_launcher.py -k 'bridge_timeout or consumed_nonce' -q`

Expected: FAIL because the nonce remains consumed without a response.

- [ ] **Step 3: Implement deadline and terminal-error completion**

```python
try:
    result = handler(request, deadline)
except (TimeoutError, BridgeFrameError):
    response = self._response(request, result=None, error="bridge unavailable")
    self._complete_nonce(request.nonce, response)
    return response
```

Use one monotonic deadline across bridge send/read. Store and sign the error response under the nonce lock; replay returns it without rerunning handlers.

- [ ] **Step 4: Verify GREEN**

Run: `.venv/bin/python -m pytest tests/test_finalization_service.py tests/test_finalization_launcher.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/auto_code/launcher.py src/auto_code/finalization_service.py tests/test_finalization_launcher.py tests/test_finalization_service.py
git commit -m "fix: recover finalization bridge timeouts"
```

### Task 4: Integration Verification And Review

**Files:**
- Modify: `tests/test_finalization_launcher.py`, `tests/test_finalization_service.py`
- Modify: `.superpowers/sdd/2026-09-05-04-ralph-and-finalization/task-3-report.md` (ignored evidence only)

- [ ] **Step 1: Add complete isolated-launcher scenario**

```python
def test_installed_launcher_finalizes_with_isolated_child_and_protected_git(...):
    result = run_launcher_finalization(...)
    assert result.returncode == 0
```

- [ ] **Step 2: Run complete verification**

Run: `.venv/bin/python -m pytest -q && .venv/bin/python -m compileall -q src tests && git diff --check`

Expected: all commands exit 0.

- [ ] **Step 3: Record evidence and request independent review**

Append exact command outputs and process-isolation rationale to the Task 3 report. Generate a whole-branch review package and request a read-only security review.

- [ ] **Step 4: Commit regression coverage**

```bash
git add tests/test_finalization_launcher.py tests/test_finalization_service.py
git commit -m "test: cover isolated finalization launcher"
```
