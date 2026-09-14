# Task 3 Finalization Fix Wave Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finalize only an approved, freshly reconciled ticket through a launcher-owned capability boundary.

**Architecture:** The installed CLI validates a signed, expiring launcher descriptor and sends only fixed identifiers over authenticated local IPC. The launcher owns the existing `Finalizer`, bridge, Git guard, Active Run Index, and retry-state transitions; the finalizer persists all evidence needed to resume safely.

**Tech Stack:** Python 3.12, Pydantic contracts, Unix domain sockets, existing state CAS and trusted MCP bridge.

**Spec:** User-approved Task 3 composition request, 2026-09-12.

## Global Constraints

- No repository-provided factories, callbacks, signing keys, or capability objects.
- Descriptor binds operation, run, expected generation/hash, expiry, and nonce; malformed, expired, mismatched, replayed, or unauthenticated requests fail closed.
- Every behavioral change is test-first with observed RED and GREEN evidence.
- No real provider, Linear, browser, commit, or push effects in tests.

---

### Task 1: Launcher Capability Descriptor and IPC

**Files:**
- Create: `src/auto_code/finalization_service.py`
- Modify: `src/auto_code/cli.py`
- Test: `tests/test_finalization_service.py`, `tests/test_cli.py`

- [ ] Write failing tests for forged, expired, operation/run/CAS mismatch, replay, and a valid identifier-only request.
- [ ] Run the focused tests and observe authentication failures before implementation.
- [ ] Implement signed fixed-FD descriptor parsing and authenticated single-use local IPC request/response validation.
- [ ] Re-run focused tests and confirm they pass.

### Task 2: Safe Finalizer Reconciliation

**Files:**
- Modify: `src/auto_code/finalizer.py`, `src/auto_code/git.py`, `src/auto_code/contracts.py`, `src/auto_code/state.py`, `src/auto_code/mcp_bridge.py`, `src/auto_code/linear.py`
- Test: `tests/test_finalizer.py`, `tests/test_git.py`, `tests/test_linear.py`, `tests/test_state.py`

- [ ] Write focused regressions for ticket state/revision receipts, post-projection remote drift, manifest-bound commit reconciliation, exact index release, and persisted retry eligibility.
- [ ] Run the focused regressions and observe the unsafe behavior.
- [ ] Implement the smallest bridge, Git, index, and retry-state changes that make each regression pass.
- [ ] Re-run the focused tests and confirm they pass.

### Task 3: Verification and Evidence

**Files:**
- Modify: `.superpowers/sdd/2026-09-05-04-ralph-and-finalization/task-3-report.md`

- [ ] Run the finalizer/git/linear/supervisor/state/cli tests, full suite, `compileall`, and `git diff --check`.
- [ ] Append exact RED/GREEN and verification evidence to the Task 3 report.
- [ ] Commit the complete Task 3 fix wave without the ignored report.
