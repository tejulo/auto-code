# Launcher Sandbox Daemon Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a root-owned systemd sandbox daemon that proves finalization children cannot read launcher bootstrap FDs before capability transfer.

**Architecture:** A Python daemon owns the configured Unix socket, authenticates the launcher with `SO_PEERCRED`, signs canonical child evidence, and owns child lifecycle. It creates finalization children in new PID/mount namespaces with isolated procfs, runs a fixed probe before transferring FDs 4-6, and fails closed.

**Tech Stack:** Python 3.12, Linux namespaces/procfs, Unix sockets, `SCM_RIGHTS`, `SO_PEERCRED`, Ed25519, systemd, pytest.

**Spec:** `docs/superpowers/specs/2026-09-14-launcher-sandbox-daemon-design.md`

## Global Constraints

- Run daemon setup as root; run every child under configured unprivileged UID/GID.
- Accept only the versioned launcher-sandbox protocol over the configured Unix socket.
- Require configured peer UID/GID, bounded frames, configured sandbox identity, and exact request schemas.
- The fixed probe attempts `/proc/$PPID/fd/8`; no caller-controlled argv/output supplies its result.
- Transfer only exactly three FDs to targets 4, 5, and 6 after signed `bootstrap_fd_access: "denied"` evidence.
- Kill and reap owned children on any invalid state, timeout, disconnect, or cleanup request.
- The canonical `auto-code-sandbox-child-evidence/v1` payload and current `LauncherSocketSandbox` client contract remain compatible.
- Privileged integration tests are mandatory on the Ubuntu VM; mocks do not prove isolation.

---

### Task 1: Daemon Configuration And Signed Evidence

**Files:**
- Create: `src/auto_code/launcher_sandbox_daemon.py`
- Modify: `pyproject.toml`
- Test: `tests/test_launcher_sandbox_daemon.py`

**Interfaces:**
- Produces `SandboxDaemonConfig` with socket, identity, key, launcher UID/GID, child UID/GID, executable roots, and positive timeout.
- Produces `load_sandbox_daemon_config(path: Path) -> SandboxDaemonConfig` and `sandbox_daemon_entrypoint() -> None`.

- [ ] **Step 1: Write failing configuration/signature tests**

```python
def test_config_rejects_relative_socket_and_insecure_key(tmp_path: Path) -> None:
    with pytest.raises(SandboxProtocolError):
        load_sandbox_daemon_config(tmp_path / "bad.json")

def test_evidence_signature_matches_launcher_payload(daemon) -> None:
    evidence = daemon.sign_child_evidence(child_id, challenge, pid, 7, 8, (), "denied")
    public_key.verify(bytes.fromhex(evidence.signature), _sandbox_child_evidence_payload(evidence, "launcher"))
```

- [ ] **Step 2: Verify RED**

Run: `.venv/bin/python -m pytest tests/test_launcher_sandbox_daemon.py -k 'config or signature' -q`

Expected: FAIL because no daemon module exists.

- [ ] **Step 3: Implement strict loader and signing**

```python
@dataclass(frozen=True, slots=True)
class SandboxDaemonConfig:
    socket_path: Path
    identity: str
    signing_key_path: Path
    launcher_uid: int
    launcher_gid: int
    child_uid: int
    child_gid: int
    protocol_timeout: float
```

Reject nonabsolute/symlink paths, non-root `0600` keys, nonpositive timeout, and root child identity. Load Ed25519 key and sign the existing canonical payload. Register `auto-code-launcher-sandbox` console script.

- [ ] **Step 4: Verify GREEN and commit**

Run: `.venv/bin/python -m pytest tests/test_launcher_sandbox_daemon.py -k 'config or signature' -q`

```bash
git add pyproject.toml src/auto_code/launcher_sandbox_daemon.py tests/test_launcher_sandbox_daemon.py
```

### Task 2: Authenticated Socket Dispatcher

**Files:**
- Modify: `src/auto_code/launcher_sandbox_daemon.py`
- Test: `tests/test_launcher_sandbox_daemon.py`

**Interfaces:**
- Produces `LauncherSandboxDaemon.serve_forever()` and `handle_connection(connection: socket.socket)`.

- [ ] **Step 1: Write failing peer/schema tests**

```python
def test_daemon_rejects_wrong_peer_before_dispatch(daemon) -> None:
    with pytest.raises(SandboxProtocolError, match="peer"):
        daemon.handle_connection(FakeConnection(peer_credentials=(1, 65534, 65534)))

def test_unknown_operation_creates_no_child(daemon) -> None:
    daemon.handle_connection(FakeConnection(request={"schema_version": "v1", "operation": "shell"}))
    assert daemon.children == {}
```

- [ ] **Step 2: Verify RED**

Run: `.venv/bin/python -m pytest tests/test_launcher_sandbox_daemon.py -k 'peer or operation' -q`

Expected: FAIL because no listener exists.

- [ ] **Step 3: Implement listener and dispatcher**

```python
def handle_connection(self, connection: socket.socket) -> None:
    if _peer_credentials(connection)[1:] != (self.config.launcher_uid, self.config.launcher_gid):
        raise SandboxProtocolError("launcher sandbox peer is invalid")
    request, fds = _receive_one_json_frame(connection, maximum=1_048_576)
    _send_json_frame(connection, self._dispatch(request, fds))
```

Bind socket with restricted permissions, reject replaced socket/insecure frame, validate `schema_version` and identity, and close all unclaimed received FDs. Permit only existing run/effect/sign/archive and finalization lifecycle operation names.

- [ ] **Step 4: Verify GREEN and commit**

Run: `.venv/bin/python -m pytest tests/test_launcher_sandbox_daemon.py -k 'peer or operation' -q`

```bash
git add src/auto_code/launcher_sandbox_daemon.py tests/test_launcher_sandbox_daemon.py
```

### Task 3: Namespace Child And Fixed Procfs Probe

**Files:**
- Modify: `src/auto_code/launcher_sandbox_daemon.py`
- Test: `tests/test_launcher_sandbox_daemon.py`
- Test: `tests/test_process.py`

**Interfaces:**
- Consumes `prepare_finalization_child` with argv/challenge/isolate_procfs.
- Produces signed child evidence with empty FDs and `bootstrap_fd_access == "denied"`.

- [ ] **Step 1: Write privileged failing probe test**

```python
@pytest.mark.skipif(os.geteuid() != 0, reason="requires namespaces")
def test_real_child_cannot_open_parent_bootstrap_fd(running_daemon) -> None:
    child = LauncherSocketSandbox(running_daemon.socket, "launcher", running_daemon.public_key).prepare_finalization_child(argv)
    assert child.evidence.bootstrap_fd_access == "denied"
    assert child.evidence.fd_numbers == ()
```

Also assert a successful/indeterminate probe kills and reaps its child.

- [ ] **Step 2: Verify RED**

Run: `sudo .venv/bin/python -m pytest tests/test_launcher_sandbox_daemon.py tests/test_process.py -k procfs -q`

Expected: FAIL because child namespace setup does not exist.

- [ ] **Step 3: Implement child preparation**

```python
def _prepare_finalization_child(self, request):
    child = self._fork_pid_and_mount_namespaces(request["argv"])
    if child.fixed_probe("/proc/$PPID/fd/8") != "denied":
        self._kill_and_reap(child)
        raise SandboxProtocolError("bootstrap fd probe failed")
    return self._signed_preparation(child, request["challenge"])
```

Create PID/mount namespaces, mount fresh procfs, close nonstandard FDs, drop child UID/GID, run fixed open attempt before ticket code, record namespace inodes/pid, retain pidfd where available, and sign evidence with the existing canonical encoder.

- [ ] **Step 4: Verify GREEN and commit**

Run: `sudo .venv/bin/python -m pytest tests/test_launcher_sandbox_daemon.py tests/test_process.py -k procfs -q`

```bash
git add src/auto_code/launcher_sandbox_daemon.py tests/test_launcher_sandbox_daemon.py tests/test_process.py
```

### Task 4: Capability Transfer And Child Lifecycle

**Files:**
- Modify: `src/auto_code/launcher_sandbox_daemon.py`
- Test: `tests/test_launcher_sandbox_daemon.py`
- Test: `tests/test_finalization_launcher.py`

**Interfaces:**
- Consumes `transfer_finalization_fds` with verified child/challenge, targets `[4, 5, 6]`, exactly three FDs.
- Produces signed post-transfer evidence and compatible poll/wait/terminate/kill responses.

- [ ] **Step 1: Write failing transfer/disconnect tests**

```python
def test_transfer_requires_verified_denial(running_daemon) -> None:
    with pytest.raises(ProcessConfigurationError):
        running_daemon.transfer(unverified_child, (fd4, fd5, fd6))

def test_disconnect_kills_and_reaps_prepared_child(running_daemon) -> None:
    child = running_daemon.prepare(argv)
    running_daemon.disconnect()
    assert running_daemon.was_reaped(child.child_id)
```

- [ ] **Step 2: Verify RED**

Run: `sudo .venv/bin/python -m pytest tests/test_launcher_sandbox_daemon.py tests/test_finalization_launcher.py -k 'transfer or disconnect' -q`

Expected: FAIL because preparation state and descriptor transfer are absent.

- [ ] **Step 3: Implement exact transfer/lifecycle**

```python
if not child.probe_denied or request["capability_fd_targets"] != [4, 5, 6] or len(fds) != 3:
    self._kill_and_reap(child)
    raise SandboxProtocolError("finalization capability transfer is invalid")
child.install_capabilities(fds, targets=(4, 5, 6))
```

Reject duplicates, challenge mismatch, extra FDs, and foreign children. On disconnect/timeout independently kill and reap each owned child. Make kill/wait idempotent and preserve terminal output.

- [ ] **Step 4: Verify GREEN and commit**

Run: `sudo .venv/bin/python -m pytest tests/test_launcher_sandbox_daemon.py tests/test_finalization_launcher.py -k 'transfer or disconnect' -q`

```bash
git add src/auto_code/launcher_sandbox_daemon.py tests/test_launcher_sandbox_daemon.py tests/test_finalization_launcher.py
```

### Task 5: Existing Protected Process Operations

**Files:**
- Modify: `src/auto_code/launcher_sandbox_daemon.py`
- Test: `tests/test_launcher_sandbox_daemon.py`
- Test: `tests/test_process.py`

**Interfaces:**
- Produces protocol-compatible responses for `run`, `invoke_effect`, `observe_effect`, `sign_activation`, and `run_python_archive`.

- [ ] **Step 1: Write failing compatibility tests**

```python
def test_daemon_runs_only_descriptor_backed_executable(running_daemon) -> None:
    result = ProcessRunner(executables, LauncherSocketSandbox(...)).run(argv, cwd, 3, sink, env, policy)
    assert result.returncode == 0

def test_daemon_rejects_run_without_received_executable_fd(running_daemon) -> None:
    assert running_daemon.request(run_request, descriptors=()).error == "invalid descriptors"
```

- [ ] **Step 2: Verify RED**

Run: `sudo .venv/bin/python -m pytest tests/test_launcher_sandbox_daemon.py tests/test_process.py -k 'descriptor or archive or effect' -q`

Expected: FAIL because only lifecycle operations are served.

- [ ] **Step 3: Implement existing protocol operations**

Dispatch only existing operations and preserve the response schemas in `src/auto_code/process.py`. Execute transferred executables via `/proc/self/fd/<n>` only after exact descriptor count, timeout, environment, cwd, roots, controlled HOME, and no-download policy validation. Never accept an executable filesystem path as a substitute for transferred FDs.

- [ ] **Step 4: Verify GREEN and commit**

Run: `sudo .venv/bin/python -m pytest tests/test_launcher_sandbox_daemon.py tests/test_process.py -k 'descriptor or archive or effect' -q`

```bash
git add src/auto_code/launcher_sandbox_daemon.py tests/test_launcher_sandbox_daemon.py tests/test_process.py
```

### Task 6: Package And Deploy systemd Service

**Files:**
- Create: `deploy/systemd/auto-code-launcher-sandbox.service`
- Create: `deploy/auto-code/launcher-sandbox.json.example`
- Create: `docs/launcher-sandbox-deployment.md`
- Test: `tests/test_launcher_sandbox_deployment.py`

**Interfaces:**
- Produces an installed service running `auto-code-launcher-sandbox --config /etc/auto-code/launcher-sandbox.json`.

- [ ] **Step 1: Write failing unit/config artifact test**

```python
def test_unit_creates_runtime_directory_and_uses_root_only_config() -> None:
    unit = Path("deploy/systemd/auto-code-launcher-sandbox.service").read_text()
    assert "RuntimeDirectory=auto-code" in unit
    assert "--config /etc/auto-code/launcher-sandbox.json" in unit
```

- [ ] **Step 2: Verify RED**

Run: `.venv/bin/python -m pytest tests/test_launcher_sandbox_deployment.py -q`

Expected: FAIL because deployment artifacts do not exist.

- [ ] **Step 3: Add deployment artifacts and runbook**

Use `User=root`, `RuntimeDirectory=auto-code`, `PrivateNetwork=true`, and the daemon CLI. Document root `0600` config/key installation, `systemctl daemon-reload`, enable/start/status, restricted socket metadata, public-key rotation, and privileged probe verification.

- [ ] **Step 4: Verify GREEN and VM gate**

Run: `.venv/bin/python -m pytest tests/test_launcher_sandbox_deployment.py -q && sudo .venv/bin/python -m pytest tests/test_launcher_sandbox_daemon.py tests/test_process.py tests/test_finalization_launcher.py -q`

Expected: PASS with real procfs-denial evidence.

- [ ] **Step 5: Commit**

```bash
git add deploy/systemd deploy/auto-code docs/launcher-sandbox-deployment.md tests/test_launcher_sandbox_deployment.py
```

### Task 7: Whole-Branch Security Verification

**Files:**
- Test: `tests/test_launcher_sandbox_daemon.py`
- Test: `tests/test_launcher_sandbox_deployment.py`
- Test: `tests/test_process.py`
- Test: `tests/test_finalization_launcher.py`

- [ ] **Step 1: Run all verification**

Run: `.venv/bin/python -m pytest -q && sudo .venv/bin/python -m pytest tests/test_launcher_sandbox_daemon.py tests/test_launcher_sandbox_deployment.py tests/test_process.py tests/test_finalization_launcher.py -q && .venv/bin/python -m compileall -q src tests && git diff --check`

Expected: every command passes; privileged tests are not skipped on the Ubuntu VM.

- [ ] **Step 2: Verify installed service**

Run: `sudo systemctl restart auto-code-launcher-sandbox && sudo systemctl is-active --quiet auto-code-launcher-sandbox && stat -c '%F %a %U %G' /run/auto-code/launcher-sandbox.sock`

Expected: active service and restricted Unix socket.

- [ ] **Step 3: Record evidence and request final review**

Record exact test output, systemd status, socket metadata, public-key hash, and signed real probe evidence. Generate a review package and request read-only security review that rejects mocked evidence as a deployment substitute.
