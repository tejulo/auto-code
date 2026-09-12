# Programmer Tools And Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Safely expose bounded Programmer repository tools, execute every configured verification command, and bind product/build/review inputs into immutable manifests.

**Architecture:** `RepoToolPolicy` owns descriptor-relative repository access and `ProgrammerTools` only adapts it to the existing CrewAI tool boundary. `VerificationRunner` delegates configured checks to the existing sandboxed `ProcessRunner`, while `manifests.py` builds immutable Product Change, Build Identity, and Review Manifest bindings from trusted inputs.

**Tech Stack:** Python 3.12, Pydantic 2, pytest, CrewAI tools, existing `ProcessRunner`, `GitGuard`, and Project Policy contracts.

**Spec:** `docs/superpowers/specs/2026-09-11-task-5-programmer-tools-verification-design.md`

## Global Constraints

- Do not execute or mutate Git state, create commits, use worktrees, or run Git commands.
- Tests use temporary paths plus injected fake process/evidence/Git-input capabilities; never use network, browser, Linear, credentials, state-root, or real product subprocesses.
- File tools accept only bounded relative paths, use descriptor-relative no-follow traversal, and deny protected, state, secret, Git, symlink, non-regular, and escaping paths.
- New untracked product files are authorized only when they are inside Project Policy `writable_roots`; protected and commit-excluded paths remain denied.
- The Programmer receives exactly `read_repo`, `write_repo`, `search_repo`, and `run_authorized`; model input cannot supply argv, environment, or working directory.
- Verification runs every `verification.commands` entry in order even if an earlier check fails, times out, or cannot start. An empty list requires `allow_empty=true`.
- Build and review manifests use canonical hashes and reject missing or mismatched inputs. Browser execution is not implemented by this change.

---

## File Structure

- `src/auto_code/contracts.py`: immutable product-file/change and verification result contracts used by all later tasks.
- `src/auto_code/programmer_tools.py`: descriptor-relative read/write/search policy and four CrewAI Programmer tools.
- `src/auto_code/verification.py`: non-short-circuit configured verification adapter.
- `src/auto_code/manifests.py`: trusted Git input normalization plus Build Identity and Review Manifest factories.
- `src/auto_code/tool_broker.py`: injects the exact four Programmer tools only for `Stage.PROGRAMMER`.
- `src/auto_code/crew.py`: validates Programmer context against task manifests and limits tool names to the registered set.
- `tests/test_programmer_tools.py`, `tests/test_verification.py`, `tests/test_manifests.py`: deterministic behavior and safety regressions.
- `tests/test_contracts.py`, `tests/test_prompt_boundaries.py`: contract and broker integration coverage.

### Task 1: Immutable Product And Verification Contracts

**Files:**
- Modify: `src/auto_code/contracts.py`
- Modify: `tests/test_contracts.py`

**Interfaces:**
- Produces: `ProductChangeFile(path, status, old_path, old_mode, mode, old_object_id, object_id, binary, untracked)`.
- Produces: `ProductChangeManifest(baseline_sha, files)` with unique paths and canonical `content_hash`.
- Produces: `VerificationCheck(command_id, command_hash, returncode, failure_kind, stdout_evidence, stderr_evidence)` and `VerificationResult(build_identity_hash, checks, passed, empty_authorized)`.
- Consumes: existing `CommandResult`, `BuildIdentity`, `EvidenceRef`, `OutputContract`, `hash_json`, and existing SHA/path validators.

- [ ] **Step 1: Write failing contract tests**

```python
def test_product_change_manifest_binds_modes_renames_objects_and_untracked_entries() -> None:
    manifest = ProductChangeManifest.from_files(
        "a" * 40,
        (
            ProductChangeFile(
                path="new.py", status="R100", old_path="old.py",
                old_mode="100644", mode="100755", old_object_id="b" * 40,
                object_id="c" * 40, binary=False, untracked=False,
            ),
            ProductChangeFile(
                path="generated/data.bin", status="A", old_path=None,
                old_mode="000000", mode="100644", old_object_id=None,
                object_id="d" * 40, binary=True, untracked=True,
            ),
        ),
    )
    assert manifest.content_hash == hash_json(manifest.model_dump(mode="json", exclude={"content_hash"}))
    with pytest.raises(ValidationError, match="unique"):
        manifest.model_copy(update={"files": (manifest.files[0], manifest.files[0])})


def test_verification_result_requires_exact_build_hash_and_complete_command_evidence() -> None:
    build = build_identity()
    check = VerificationCheck(
        command_id="pytest", command_hash=sha("pytest"), returncode=0,
        failure_kind=None, stdout_evidence=evidence_ref(), stderr_evidence=evidence_ref(),
    )
    result = VerificationResult(
        build_identity_hash=hash_json(build.model_dump(mode="json")),
        checks=(check,), passed=True, empty_authorized=False,
    )
    assert result.checks == (check,)
    with pytest.raises(ValidationError, match="empty"):
        VerificationResult(build_identity_hash=result.build_identity_hash, checks=(), passed=True, empty_authorized=False)
```

- [ ] **Step 2: Run contract tests to verify RED**

Run: `.venv/bin/python -m pytest tests/test_contracts.py -q -k 'product_change_manifest or verification_result'`

Expected: collection fails because the product and verification contract classes do not exist.

- [ ] **Step 3: Add the minimal frozen contracts**

```python
class ProductChangeManifest(OutputContract):
    baseline_sha: _GIT_SHA
    files: tuple[ProductChangeFile, ...] = Field(min_length=1, max_length=512)
    content_hash: Sha256

    @model_validator(mode="after")
    def validate_hash_and_paths(self) -> Self:
        if len({entry.path for entry in self.files}) != len(self.files):
            raise ValueError("Product manifest paths must be unique")
        payload = self.model_dump(mode="json", round_trip=True, exclude={"content_hash"})
        if self.content_hash.lower() != hash_json(payload):
            raise ValueError("Product manifest hash does not match content")
        return self


class VerificationResult(OutputContract):
    build_identity_hash: Sha256
    checks: tuple[VerificationCheck, ...] = Field(max_length=128)
    passed: bool
    empty_authorized: bool

    @model_validator(mode="after")
    def validate_checks(self) -> Self:
        if not self.checks and not self.empty_authorized:
            raise ValueError("Empty verification result is not authorized")
        if self.passed != all(check.returncode == 0 for check in self.checks):
            raise ValueError("Verification pass state does not match checks")
        return self
```

Define `VerificationCheck` as an `OutputContract` with a bounded command identifier, canonical command hash, integer return code, optional bounded failure kind, and mandatory stdout/stderr `EvidenceRef` values. Define path, mode, status, object-ID, rename, and untracked consistency validators beside the product model. Add `ProductChangeManifest.from_files(baseline_sha, files)` to reconstruct an unchecked temporary object when calculating `content_hash`, following the established `TicketSnapshot.from_snapshot` pattern, so callers cannot choose the hash.

- [ ] **Step 4: Run contract tests to verify GREEN**

Run: `.venv/bin/python -m pytest tests/test_contracts.py -q -k 'product_change_manifest or verification_result or build_identity'`

Expected: PASS.

### Task 2: Descriptor-Relative Programmer Tools

**Files:**
- Create: `src/auto_code/programmer_tools.py`
- Create: `tests/test_programmer_tools.py`
- Modify: `src/auto_code/tool_broker.py`
- Modify: `src/auto_code/crew.py`
- Modify: `tests/test_prompt_boundaries.py`

**Interfaces:**
- Produces: `RepoToolPolicy(root: Path, writable_roots: tuple[str, ...], protected_paths: tuple[str, ...])`.
- Produces: `SearchMatch(relative_path: str, line_number: int, text: str)`, `ProtectedPathError`, and `RepoToolPolicy.open_read(relative: str) -> BinaryIO`, `.atomic_write(relative: str, content: bytes) -> None`, and `.search(relative: str, query: str) -> tuple[SearchMatch, ...]`.
- Produces: `ProgrammerTools(policy, config, process, evidence_sink, sandbox_policy, environment, executable, timeout).for_manifest(manifest) -> tuple[BaseTool, ...]`.
- Consumes: `ProjectConfig`, `ProcessRunner`, existing `ToolManifest`, `ToolBroker`, and `MAX_NATIVE_TOOL_CALLS`.

- [ ] **Step 1: Write failing containment and tool-registration tests**

```python
def test_repo_policy_rejects_escape_protected_symlink_and_non_regular_paths(repo: Path) -> None:
    state = repo.parent / "launcher-state"
    state.mkdir()
    (state / "current.json").write_text("secret", encoding="ascii")
    (repo / "link").symlink_to(state / "current.json")
    (repo / "fifo").mkfifo()
    policy = RepoToolPolicy(repo, writable_roots=("src",), protected_paths=(".env", ".auto-code", ".git"))
    for path in ("../launcher-state/current.json", ".env", "link", "fifo"):
        with pytest.raises(ProtectedPathError):
            policy.open_read(path)


def test_programmer_tools_expose_only_fixed_tools_and_configured_indexes(harness) -> None:
    tools = harness.programmer_tools.for_manifest(ToolManifest())
    assert tuple(tool.name for tool in tools) == ("read_repo", "write_repo", "search_repo", "run_authorized")
    assert tuple(tool.name for tool in harness.tool_broker.for_stage(Stage.PROGRAMMER, ToolManifest())) == (
        "read_repo", "write_repo", "search_repo", "run_authorized",
    )
    tools[3]._run(index=0)
    assert harness.process.argvs == [harness.config.verification.commands[0]]
```

- [ ] **Step 2: Run tool tests to verify RED**

Run: `.venv/bin/python -m pytest tests/test_programmer_tools.py tests/test_prompt_boundaries.py -q -k 'repo_policy or programmer_tools'`

Expected: collection fails because `auto_code.programmer_tools` does not exist.

- [ ] **Step 3: Implement no-follow repository access and fixed CrewAI tools**

```python
def open_read(self, relative: str) -> BinaryIO:
    parts = self._validated_parts(relative, require_writable=False)
    parent_fd = self._walk_parent(parts[:-1])
    try:
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ProtectedPathError("Repository path is not a regular file")
    return os.fdopen(fd, "rb")


def run_configured(self, index: int) -> CommandResult:
    if isinstance(index, bool) or index not in range(len(self._config.verification.commands)):
        raise ToolAccessDenied("Command index is not authorized")
    return self._process.run(
        self._config.verification.commands[index], self._root, self._timeout,
        self._evidence_sink, self._environment, self._sandbox_policy,
    )
```

Validate every segment before opening, reject sensitive path components and paths outside `writable_roots` for writes, and walk only real directories with `O_DIRECTORY | O_NOFOLLOW`. Implement atomic writes with a unique temporary sibling, `fsync`, `os.replace`, and parent `fsync`, cleaning the temporary entry on every exception. Cap reads/search output and make search results sorted by relative path then line number. Define `SearchMatch` as a frozen dataclass containing the bounded relative path, positive line number, and capped line text. Implement four narrowly typed `BaseTool` subclasses with the exact expected names, `ToolFailurePolicy.RAISE`, and the existing maximum native call count. `ToolBroker` validates the returned names and limits, while `ProgrammerTools` obtains roots and configured command indexes exclusively from its pinned `ProjectConfig`.

- [ ] **Step 4: Run tool and prompt-boundary tests to verify GREEN**

Run: `.venv/bin/python -m pytest tests/test_programmer_tools.py tests/test_prompt_boundaries.py -q`

Expected: PASS.

### Task 3: Full Non-Short-Circuit Verification

**Files:**
- Create: `src/auto_code/verification.py`
- Create: `tests/test_verification.py`

**Interfaces:**
- Produces: `EmptyVerificationPolicyError`, `VerificationEvidenceError`, and `VerificationRunner(config, process, evidence_sink, sandbox_policy, environment, cwd, timeout).run_all(build: BuildIdentity) -> VerificationResult`.
- Consumes: Task 1 `VerificationCheck`/`VerificationResult`, `ProjectConfig.verification`, `ProcessRunner`, and `BuildIdentity`.

- [ ] **Step 1: Write failing verification tests**

```python
def test_run_all_keeps_running_after_exit_timeout_and_spawn_failure(harness) -> None:
    harness.process.results = (failed_result(), timeout_result(), spawn_result(), passed_result())
    result = harness.runner.run_all(harness.build)
    assert [check.returncode for check in result.checks] == [1, 124, 127, 0]
    assert harness.process.argvs == list(harness.config.verification.commands)
    assert result.passed is False


def test_empty_verification_requires_explicit_policy_authorization(harness) -> None:
    harness.config = config_with_commands((), allow_empty=False)
    with pytest.raises(EmptyVerificationPolicyError):
        harness.runner.run_all(harness.build)
    harness.config = config_with_commands((), allow_empty=True)
    result = harness.runner.run_all(harness.build)
    assert result.checks == ()
    assert result.empty_authorized is True


def test_verification_result_binds_the_exact_build_identity(harness) -> None:
    result = harness.runner.run_all(harness.build)
    assert result.build_identity_hash == hash_json(harness.build.model_dump(mode="json", round_trip=True))
```

- [ ] **Step 2: Run verification tests to verify RED**

Run: `.venv/bin/python -m pytest tests/test_verification.py -q`

Expected: collection fails because `auto_code.verification` does not exist.

- [ ] **Step 3: Implement ordered verification execution**

```python
def run_all(self, build: BuildIdentity) -> VerificationResult:
    commands = self._config.verification.commands
    if not commands and not self._config.verification.allow_empty:
        raise EmptyVerificationPolicyError("Verification commands are required")
    checks: list[VerificationCheck] = []
    for index, argv in enumerate(commands):
        result = self._process.run(
            argv, self._cwd, self._timeout, self._evidence_sink,
            self._environment, self._sandbox_policy,
        )
        if result.stdout_path is None or result.stderr_path is None:
            raise VerificationEvidenceError("Verification command has no immutable evidence")
        checks.append(VerificationCheck(
            command_id=f"check-{index + 1}", command_hash=hash_json(argv),
            returncode=result.returncode,
            failure_kind=None if result.failure_kind is None else result.failure_kind.value,
            stdout_evidence=result.stdout_path, stderr_evidence=result.stderr_path,
        ))
    return VerificationResult(
        build_identity_hash=hash_json(build.model_dump(mode="json", round_trip=True)),
        checks=tuple(checks),
        passed=all(check.returncode == 0 for check in checks),
        empty_authorized=not checks,
    )
```

Validate constructor dependencies and do not call `mutation_commands`. Let `ProcessRunner` return timeout/spawn/exit evidence; do not call `require_success` and do not catch/fabricate command results. Before creating each `VerificationCheck`, reject a result without both immutable evidence references. Reject a non-`BuildIdentity` input before executing any command.

- [ ] **Step 4: Run verification tests to verify GREEN**

Run: `.venv/bin/python -m pytest tests/test_verification.py tests/test_contracts.py -q -k 'verification or build_identity'`

Expected: PASS.

### Task 4: Product, Build, And Review Manifest Factories

**Files:**
- Create: `src/auto_code/manifests.py`
- Create: `tests/test_manifests.py`
- Modify: `src/auto_code/crew.py`
- Modify: `tests/test_crew.py`

**Interfaces:**
- Produces: `ManifestBindingError`, `ProductChangeManifestBuilder(config).build(inputs: GitManifestInputs) -> ProductChangeManifest`.
- Produces: `BuildIdentityFactory.create(baseline_sha, product_manifest, policy, commands, runtime_hash) -> BuildIdentity`.
- Produces: `ReviewManifestBuilder.create(requirements, outline, artifact_hashes, definitions, status, product_manifest, policy, build, verification, browser) -> ReviewManifest`.
- Consumes: Task 1 contracts, `GitManifestInputs`, `ProjectConfig`, `RequirementsPackage`, `ChangeOutline`, Task Definition/Status manifests, `VerificationResult`, `BrowserResult`, and existing `ReviewManifest`.

- [ ] **Step 1: Write failing factory and drift tests**

```python
def test_product_builder_allows_only_untracked_paths_under_writable_roots(inputs, policy) -> None:
    product = ProductChangeManifestBuilder(policy).build(inputs.with_untracked("generated/result.json"))
    assert product.files[-1].untracked is True
    with pytest.raises(UnauthorizedUntrackedPathError):
        ProductChangeManifestBuilder(policy).build(inputs.with_untracked("notes.txt"))


def test_build_identity_binds_every_product_policy_command_and_runtime_input(inputs, policy) -> None:
    product = ProductChangeManifestBuilder(policy).build(inputs)
    build = BuildIdentityFactory.create(inputs.baseline_sha, product, policy, policy.verification.commands, sha("runtime"))
    assert build.product_manifest_hash == product.content_hash
    assert build.project_policy_hash == policy.policy_hash
    assert tuple(build.command_hashes.values()) == tuple(hash_json(command) for command in policy.verification.commands)


def test_review_manifest_rejects_stale_product_build_or_verification_binding(review_inputs) -> None:
    manifest = ReviewManifestBuilder.create(**review_inputs)
    assert manifest.product_manifest_hash == review_inputs["product_manifest"].content_hash
    with pytest.raises(ManifestBindingError):
        ReviewManifestBuilder.create(**{**review_inputs, "verification": stale_verification_result()})
```

- [ ] **Step 2: Run manifest tests to verify RED**

Run: `.venv/bin/python -m pytest tests/test_manifests.py tests/test_crew.py -q -k 'product_builder or build_identity or review_manifest'`

Expected: collection fails because `auto_code.manifests` does not exist.

- [ ] **Step 3: Implement trusted normalization and hash binding**

```python
class ProductChangeManifestBuilder:
    def build(self, inputs: GitManifestInputs) -> ProductChangeManifest:
        files = tuple(self._product_file(entry) for entry in inputs.files)
        return ProductChangeManifest.from_files(inputs.baseline_sha, files)

    def _product_file(self, entry: GitManifestFile) -> ProductChangeFile:
        if entry.untracked and not any(_under(entry.path, root) for root in self._config.writable_roots):
            raise UnauthorizedUntrackedPathError("Untracked path is outside Project Policy writable roots")
        if _overlaps_policy(entry.path, self._config.protected_paths + self._config.commit_excluded_paths):
            raise ManifestBindingError("Product manifest contains a denied path")
        return ProductChangeFile(
            path=entry.path, status=entry.status, old_path=entry.old_path,
            old_mode=entry.old_mode, mode=entry.new_mode,
            old_object_id=entry.old_object_id, object_id=entry.object_id,
            binary=entry.binary, untracked=entry.untracked,
        )


class BuildIdentityFactory:
    @staticmethod
    def create(baseline_sha: str, product: ProductChangeManifest, policy: ProjectConfig,
               commands: tuple[tuple[str, ...], ...], runtime_hash: str) -> BuildIdentity:
        if baseline_sha.lower() != product.baseline_sha.lower():
            raise ManifestBindingError("Build baseline does not match product manifest")
        if commands != policy.verification.commands:
            raise ManifestBindingError("Build commands do not match Project Policy")
        return BuildIdentity(
            baseline_sha=baseline_sha, product_manifest_hash=product.content_hash,
            project_policy_hash=policy.policy_hash,
            command_hashes={f"check-{index + 1}": hash_json(argv) for index, argv in enumerate(commands)},
            runtime_hash=runtime_hash,
        )
```

Implement `ReviewManifestBuilder` so it derives all hashes from the provided objects and confirms: the status definition hash matches definitions; build baseline/product/policy hashes match their inputs; verification build hash matches build; and Browser Result build hash matches build. Require every four visible OpenSpec artifact hashes and add the resulting `ReviewManifest` hash to `UnitContext` only after the object is built. Do not add browser execution; consume its existing contract only.

- [ ] **Step 4: Run manifest and crew tests to verify GREEN**

Run: `.venv/bin/python -m pytest tests/test_manifests.py tests/test_crew.py tests/test_contracts.py -q`

Expected: PASS.

- [ ] **Step 5: Run final non-browser regression and bytecode compilation**

Run: `.venv/bin/python -m pytest tests/test_programmer_tools.py tests/test_verification.py tests/test_manifests.py tests/test_git.py tests/test_linear.py tests/test_openspec.py tests/test_crew.py tests/test_prompt_boundaries.py -q && .venv/bin/python -m compileall -q src tests`

Expected: PASS and exit code `0`.
