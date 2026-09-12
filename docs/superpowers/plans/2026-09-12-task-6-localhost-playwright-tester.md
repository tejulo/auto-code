# Localhost Playwright Tester Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute declared Browser E2E scenarios against only a configured localhost app and return hash-bound browser results or classified failures.

**Architecture:** `LocalPlaywrightTools` maps a fixed operation schema to the policy-approved Playwright CLI prefix and is the sole Tester tool. `BrowserRunner` owns application lifecycle, Tester execution, context validation, and exhaustive cleanup using injected trusted boundaries.

**Tech Stack:** Python 3.12, Pydantic 2, pytest, CrewAI tools, existing `ManagedProcessRunner`, `ProcessRunner`, `ToolBroker`, and browser contracts.

**Spec:** `docs/superpowers/specs/2026-09-12-task-6-localhost-playwright-tester-design.md`

## Global Constraints

- Do not execute or mutate Git state, create commits/worktrees, use network, or start a real browser/application in tests.
- Allow only localhost HTTP policy URLs and only `open`, `goto`, `snapshot`, `click`, `fill`, `type`, `press`, `screenshot`, and `close`.
- Playwright command prefix, session name, cwd, environment, executable, and URL origin are trusted inputs; no model argument selects them.
- Missing required localhost policy is an Ambiguity failure; scenario mismatch is a Product Defect owned by Programmer; lifecycle/CLI/evidence/cleanup faults are Orchestration Defects.
- `BrowserResult` always validates against the exact Browser E2E Decision and Build Identity. Optional decisions skip without process/tool activity.
- Always attempt Playwright-session close and owned process stop/reap after startup, preserving cleanup errors as evidence.

---

## File Structure

- `src/auto_code/browser.py`: restricted Playwright tool adapter, browser lifecycle runner, and browser-specific failures.
- `src/auto_code/tool_broker.py`: injects `LocalPlaywrightTools` only for `Stage.TESTER` using the existing exact-tool validation.
- `src/auto_code/crew.py`: accepts the browser runner's Tester context without granting additional tools.
- `tests/test_browser.py`: fake-backed safety, lifecycle, cleanup, result, and routing tests.
- `tests/test_prompt_boundaries.py`: exact Tester tool registration regression.

### Task 1: Localhost-Only Playwright Tool Boundary

**Files:**
- Create: `src/auto_code/browser.py`
- Create: `tests/test_browser.py`
- Modify: `src/auto_code/tool_broker.py`
- Modify: `tests/test_prompt_boundaries.py`

**Interfaces:**
- Produces: `PlaywrightOperation` Pydantic input schema and `LocalPlaywrightTools(config, process, evidence_sink, sandbox_policy, environment, cwd, run_id).for_manifest(manifest) -> tuple[BaseTool, ...]`.
- Produces: `PlaywrightAccessError` and one CrewAI tool named `playwright`.
- Consumes: `BrowserPolicy`, `ProcessRunner`, `ToolManifest`, and `MAX_NATIVE_TOOL_CALLS`.

- [ ] **Step 1: Write failing boundary tests**

```python
def test_playwright_tool_uses_only_policy_prefix_session_and_local_url(harness) -> None:
    tool = harness.tools.for_manifest(ToolManifest())[0]
    tool._run(operation="goto", url="http://localhost:4173/page")
    assert harness.process.argvs == [
        (*harness.config.browser.playwright_command_prefix, "goto", "--session", "run-run_1", "http://localhost:4173/page"),
    ]


@pytest.mark.parametrize("operation,url", (("install", None), ("goto", "https://example.test"), ("goto", "http://localhost:4173/?x=1")))
def test_playwright_tool_rejects_unapproved_operation_or_url(harness, operation, url) -> None:
    with pytest.raises(PlaywrightAccessError):
        harness.tools.invoke(operation=operation, url=url)
    assert harness.process.argvs == []
```

- [ ] **Step 2: Run focused tests to verify RED**

Run: `.venv/bin/python -m pytest tests/test_browser.py -q -k 'playwright_tool'`

Expected: collection fails because `auto_code.browser` does not exist.

- [ ] **Step 3: Implement the fixed operation adapter**

```python
def _run_operation(self, operation: str, url: str | None = None, target: str | None = None, value: str | None = None) -> str:
    request = PlaywrightOperation(operation=operation, url=url, target=target, value=value)
    if request.operation not in self._policy.allowed_operations:
        raise PlaywrightAccessError("Playwright operation is not authorized")
    if request.url is not None and not _is_policy_local_url(request.url, self._policy.base_url):
        raise PlaywrightAccessError("Playwright URL is not authorized")
    argv = (*self._policy.playwright_command_prefix, request.operation, "--session", self._session_name, *request.arguments())
    return self._process.run(argv, self._cwd, self._timeout, self._evidence_sink, self._environment, self._sandbox_policy).require_success().stdout_text
```

Define the input schema so each operation accepts only its required bounded fields. Derive `_session_name` from validated `run_id`; never expose it in the schema. Require policy URL equality of scheme, hostname, and port, without credentials/query/fragment. Create one `BaseTool` named `playwright` with `ToolFailurePolicy.RAISE` and the existing call limit. Let `ToolBroker` retain its exact Stage.TESTER tool-name check; only add construction/wiring required to inject this adapter.

- [ ] **Step 4: Run tool boundary tests to verify GREEN**

Run: `.venv/bin/python -m pytest tests/test_browser.py tests/test_prompt_boundaries.py -q -k 'playwright or tester'`

Expected: PASS.

### Task 2: Browser Lifecycle, Results, And Cleanup

**Files:**
- Modify: `src/auto_code/browser.py`
- Modify: `src/auto_code/crew.py`
- Modify: `tests/test_browser.py`
- Modify: `tests/test_router.py`

**Interfaces:**
- Produces: `BrowserRunner(config, process_runner, playwright_tools, crew_runner, evidence_sink, sandbox_policy, environment, cwd).run(decision, build, run_id, ticket_id) -> BrowserResult | FailureRecord`.
- Consumes: Task 1 adapter, `ManagedProcessRunner`, `BrowserE2EDecision`, `BuildIdentity`, `CrewRunner`, `BrowserResult`, and `FailureRecord`.

- [ ] **Step 1: Write failing lifecycle and routing tests**

```python
def test_optional_browser_decision_skips_without_starting_app(browser_harness) -> None:
    result = browser_harness.runner.run(optional_decision(), browser_harness.build, "run-1", "ENG-1")
    assert result.status == "skipped"
    assert browser_harness.managed.starts == []
    assert browser_harness.crew.calls == []


def test_required_missing_local_policy_returns_browser_ambiguity(browser_harness) -> None:
    result = browser_harness.runner.run(required_decision(), browser_harness.build, "run-1", "ENG-1")
    assert result.failure_class is FailureClass.AMBIGUITY
    assert result.failure_source is FailureSource.BROWSER


def test_scenario_failure_routes_to_programmer_and_cleanup_failure_requires_repair(browser_harness, active_state) -> None:
    failure = browser_harness.run_with_failed_scenario()
    assert route_failure(active_state, failure).next_stage is Stage.PROGRAMMER
    cleanup_failure = browser_harness.run_with_close_failure()
    assert route_failure(active_state, cleanup_failure).disposition is RunDisposition.REPAIR_REQUIRED
```

- [ ] **Step 2: Run lifecycle tests to verify RED**

Run: `.venv/bin/python -m pytest tests/test_browser.py tests/test_router.py -q -k 'optional_browser or missing_local or scenario_failure'`

Expected: FAIL because `BrowserRunner` does not exist.

- [ ] **Step 3: Implement lifecycle and classified failures**

```python
def run(self, decision: BrowserE2EDecision, build: BuildIdentity, run_id: str, ticket_id: str) -> BrowserResult | FailureRecord:
    if not decision.required:
        return BrowserResult.model_validate(self._skipped_payload(decision, build), context=self._context(decision, build))
    if self._config.browser.start_command is None or self._config.browser.base_url is None:
        return self._ambiguity_failure()
    process = None
    primary: BrowserResult | FailureRecord | None = None
    try:
        process = self._managed.start(self._config.browser.start_command, self._cwd, self._timeout, self._evidence_sink,
                                      self._environment, self._sandbox_policy, readiness=self._ready)
        primary = self._tester_result(decision, build, run_id)
    except Exception:
        primary = self._orchestration_failure()
    finally:
        cleanup = self._cleanup(run_id, process)
    return self._combine(primary, cleanup)
```

`_tester_result` calls `CrewRunner.run(Stage.TESTER, UnitContext(...))` with the exact decision/build/run ID and validates a `BrowserResult` with context. Convert an `InvalidUnitOutput`, invalid type, missing evidence, startup/readiness/CLI failure, or cleanup error to browser-sourced Orchestration failure. Convert a valid failed scenario result to a Product failure with `FindingKind.SCENARIO_MISMATCH` and owner `Stage.PROGRAMMER`. Cleanup always tries CLI close then `process.stop_and_reap`; collect both exceptions without masking prior evidence. Update `crew.py` only to construct this existing Tester context with the sole `playwright` tool; do not broaden `_ALLOWED_TOOL_NAMES`.

- [ ] **Step 4: Run lifecycle and router tests to verify GREEN**

Run: `.venv/bin/python -m pytest tests/test_browser.py tests/test_router.py tests/test_crew.py -q`

Expected: PASS.

- [ ] **Step 5: Run final browser regression and compile**

Run: `.venv/bin/python -m pytest tests/test_browser.py tests/test_verification.py tests/test_programmer_tools.py tests/test_openspec.py tests/test_git.py tests/test_linear.py tests/test_router.py tests/test_crew.py -q && .venv/bin/python -m compileall -q src tests`

Expected: PASS and exit code `0`.

## Task 2 Report

- Added Tester scenario description and expected-result prompt coverage; browser results now replace model-supplied evidence with the current run's evidence-sink references.
- Browser lifecycle cleanup is in `finally`, covers `BaseException` and exposed partial startup resources, and records cleanup command evidence where the sink provides it.
- Added run-ID adapter binding, injected skipped-result evidence, and focused lifecycle/evidence regressions.
- Required final regression and `compileall` command was not executed because this fix wave explicitly prohibits process execution.
- Round 2: skipped results now require an injected capability to mint and verify evidence against the current run ID; the two-run replay regression rejects a reference minted for another run.
- Round 2: `CrewRunner` validates that the real `playwright` tool returned by `ToolBroker` owns the exact BrowserRunner adapter and session before model creation; the real-broker mismatch regression rejects the other-run adapter without Tester activity.
- Focused evidence command `.venv/bin/python -m pytest tests/test_browser.py tests/test_crew.py -q` was not executed because this fix wave explicitly prohibits process execution.
- Round 3: changed the real-broker integration regression so its distinct `LocalPlaywrightTools` adapter uses the same `run-1` binding as BrowserRunner; rejection now proves object-identity validation rather than a run-ID mismatch. `.venv/bin/python -m pytest tests/test_browser.py tests/test_crew.py -q`: `37 passed in 11.75s`.
