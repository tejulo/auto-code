# Verified Finalization Sandbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify sandbox PID/procfs isolation before a ticket child receives finalization capabilities.

**Architecture:** The authenticated launcher sandbox starts a child without capability FDs, returns signed child namespace/FD evidence, then receives FDs 4-6 over `SCM_RIGHTS` only after verification. The launcher verifies the evidence against its bootstrap-pinned sandbox key and kills the child on any mismatch.

**Tech Stack:** Python 3.12, Unix sockets, `SCM_RIGHTS`, `SO_PEERCRED`, Ed25519, pytest.

**Spec:** `docs/superpowers/specs/2026-09-13-finalization-process-isolation-design.md`

## Global Constraints

- Bootstrap FDs and key material never enter the child namespace.
- Signed evidence proves both namespace identity and child FD table.
- Capability transfer occurs only after evidence verification.
- Any authentication/evidence/transfer failure kills the child before use.

---

### Task 1: Authenticated Sandbox Evidence

**Files:**
- Modify: `src/auto_code/process.py`, `src/auto_code/launcher.py`
- Test: `tests/test_process.py`

**Interfaces:**
- Produces `SandboxChildEvidence(pid: int, pid_namespace_inode: int, mount_namespace_inode: int, fd_numbers: tuple[int, ...], signature: str)`.

- [ ] **Step 1: Write failing evidence-verification tests**

```python
def test_sandbox_rejects_unsigned_or_wrong_peer_evidence(...):
    with pytest.raises(ProcessConfigurationError):
        sandbox.prepare_finalization_child(...)
```

- [ ] **Step 2: Verify RED**

Run: `.venv/bin/python -m pytest tests/test_process.py -k 'sandbox and evidence' -q`

Expected: FAIL because the protocol only accepts a boolean attestation.

- [ ] **Step 3: Implement authenticated prepare phase**

```python
evidence = sandbox.prepare_finalization_child(ticket_argv)
verify_peer_credentials(connection)
verify_signature(evidence, bootstrap.sandbox_public_key)
require(evidence.fd_numbers == ())
```

Use pinned socket identity plus `SO_PEERCRED`; verify Ed25519 signature over canonical evidence before accepting it.

- [ ] **Step 4: Verify GREEN and commit**

Run: `.venv/bin/python -m pytest tests/test_process.py -q`

```bash
git add src/auto_code/process.py src/auto_code/launcher.py tests/test_process.py
git commit -m "feat: verify finalization sandbox evidence"
```

### Task 2: Verified Capability Transfer

**Files:**
- Modify: `src/auto_code/process.py`, `src/launcher_finalization.py`
- Test: `tests/test_finalization_launcher.py`, `tests/test_process.py`

**Interfaces:**
- Produces `SandboxChildHandle.transfer_finalization_fds((fd4, fd5, fd6)) -> SandboxChildEvidence`.

- [ ] **Step 1: Write failing child-boundary test**

```python
def test_child_cannot_read_parent_key_and_receives_only_456(...):
    evidence = start_verified_child(...)
    assert evidence.fd_numbers == (0, 1, 2, 4, 5, 6)
    assert child_probe("/proc/$PPID/fd/8") == "denied"
```

- [ ] **Step 2: Verify RED**

Run: `.venv/bin/python -m pytest tests/test_finalization_launcher.py -k 'procfs or only_456' -q`

Expected: FAIL because FDs are sent before verified isolation.

- [ ] **Step 3: Implement two-phase `SCM_RIGHTS` transfer**

```python
handle = sandbox.prepare_finalization_child(ticket_argv)
verify_pre_transfer_evidence(handle.evidence)
post = handle.transfer_finalization_fds((descriptor_fd, trust_fd, binding_fd))
verify_post_transfer_evidence(post, required_fds=(4, 5, 6))
```

Kill the child if pre/post evidence differs or transfer fails. Start `serve_once` only after post-transfer validation.

- [ ] **Step 4: Verify GREEN and commit**

Run: `.venv/bin/python -m pytest tests/test_finalization_launcher.py tests/test_process.py -q`

```bash
git add src/auto_code/process.py src/launcher_finalization.py tests/test_finalization_launcher.py tests/test_process.py
git commit -m "fix: transfer finalization capability after isolation"
```

### Task 3: Integrated Security Verification

**Files:**
- Modify: `tests/test_finalization_launcher.py`, `tests/test_process.py`
- Modify: `.superpowers/sdd/2026-09-05-04-ralph-and-finalization/task-3-report.md` (ignored evidence only)

- [ ] **Step 1: Add end-to-end signed-evidence regression**

```python
def test_installed_launcher_refuses_forged_evidence_before_capability(...):
    assert run_forged_sandbox().returncode == 2
```

- [ ] **Step 2: Run verification**

Run: `.venv/bin/python -m pytest -q && .venv/bin/python -m compileall -q src tests && git diff --check`

Expected: all commands exit 0.

- [ ] **Step 3: Commit and independent review**

```bash
git add tests/test_finalization_launcher.py tests/test_process.py
git commit -m "test: cover verified finalization sandbox"
```

Append exact verification evidence, generate a review package, and request a read-only security review.
