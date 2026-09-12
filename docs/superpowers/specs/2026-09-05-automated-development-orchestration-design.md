# Automated Development Orchestration Design

**Date:** 2026-09-05
**Status:** Approved design
**Repository model:** The automation is invoked for the current repository but executes from a separate immutable installation or worktree.

## Objective

Build a resumable automation that selects eligible work from Linear, plans it with OpenSpec, implements and verifies it through five CrewAI roles, and finalizes it through Git and Linear only after independent approval. The design prioritizes, in order, token optimization, simplicity, and compactness.

## Scope

The system must:

- Use a Python virtual environment rooted at `.venv`.
- Use CrewAI for the Analyst, Architect, Programmer, Tester, and Reviewer roles.
- Allow every role to select any model offered by OpenCode Go or Ollama Pro/Cloud that is present in the live catalog and a tested Model Compatibility Profile, through root `.env` values.
- Use OpenCode and the `opencode-ralph-loop` plugin as the outer continuation and repair mechanism.
- Query Linear through MCP before the first CrewAI call.
- Select one unblocked ticket by assignee and milestone, set it to `In Progress`, create a ticket branch, and work in that branch.
- Persist validated progress so failed work resumes from the earliest pending or invalidated unit.
- Distinguish product defects from orchestration defects.
- Stop after a configurable attempt budget, defaulting to three, for human review.
- Commit, push, and set Linear to `Done` only after every required verification passes.

The system will not:

- Invent missing ticket requirements.
- Let CrewAI own global routing, Linear state, Git finalization, or retry budgets.
- Archive an OpenSpec change automatically.
- Deploy the product or merge the branch.
- Hide a failed artifact by changing its upstream requirements.
- Treat a completion phrase as sufficient evidence of success.

## Terminology

Canonical domain terms are defined in the repository root `CONTEXT.md`. In particular, a Crew Iteration is not the same as a Ralph continuation, and a Product Defect is not an Orchestration Defect.

## Options Considered

### 1. Deterministic Python supervisor with unit CrewAI executions

A small supervisor owns state and routing. It invokes one CrewAI role for one bounded unit, validates the output, and checkpoints it. Ralph wraps complete supervisor passes and asks OpenCode to continue or repair when necessary.

Benefits:

- Minimum repeated context and token usage.
- Explicit, testable transitions and idempotent effects.
- Precise resumption at an Artifact Unit.
- Clear separation between automation repair and product correction.

Cost:

- Requires a small amount of purpose-built state-machine code.

### 2. CrewAI Flow as the complete orchestrator

CrewAI Flow can hold structured state and route through listeners. This reduces custom routing code but places critical recovery behavior closer to model-driven execution, makes external repair harder to isolate, and weakens control over exact invalidation boundaries.

### 3. OpenCode prompts as the complete orchestrator

OpenCode could invoke stage-specific CrewAI commands directly and infer progress from files. This is initially compact but spreads state across prompts, conversations, and artifacts. It is harder to test, resume safely, and protect already valid work.

## Decision

Use option 1. Deterministic orchestration costs little code and avoids the larger cost of repeated LLM context, ambiguous retries, and unsafe side effects. CrewAI performs cognitive work; ordinary code owns control flow.

The supervisor and CrewAI automation execute from a separate immutable installation or worktree. The target repository remains the ticket workspace. Automation Repair occurs in an isolated repair workspace; if a path is simultaneously part of the ticket change and the repair, the run enters Human Review rather than merging the concerns.

## Architecture

### Compatibility Baseline

Version one pins Python `3.12`, CrewAI `1.15.20`, OpenSpec `1.12.0`, Node `>=20.19.0`, agent-oriented `@playwright/cli` `0.1.19` with its exact `playwright`/`playwright-core` dependency `1.63.0-alpha-2026-08-31`, and a content-addressed state-aware Ralph fork based on `opencode-ralph-loop` `1.0.10`. Preflight rejects mismatched versions. Dependency upgrades require their contract suites to pass and a new versioned compatibility baseline.

A minimal trusted launcher installed outside the target repository resolves and verifies the Active Run's Runner Identity before every command. A separately pinned Repair Runner Identity and OS-protected repair launcher alone may validate, build, and atomically activate a repaired runner. The active runner can emit only a hash-bound repair request. Neither launcher executes mutable `latest` content.

### OpenCode Entry Command

The entry command accepts:

- Linear assignee.
- Linear milestone.
- `max_attempts`, default `3` and required to be a positive integer.

It first calls the local preparation probe, which acquires the repository lock and consults ActiveRunIndex. A matching Active Run resumes before any Candidate query. Only an `INPUT_REQUIRED` probe result authorizes OpenCode to ask the launcher-owned Linear bridge for a trusted PreparationInput. The selector validates its bridge attestation, captures the immutable Ticket Snapshot, requests the Linear mutation, and records its Trusted MCP Receipt before Git preparation and Ralph begin.

### Ralph Loop

Use a minimal content-addressed fork of `charfeng1/opencode-ralph-loop` 1.0.10. Its native state file remains advisory and is ignored by Git, but completion and cancellation hooks read the authoritative Active Run through the trusted launcher.

The plugin's iteration counter measures idle continuations, not business attempts, and its state is advisory only. The supervisor's persisted Crew Iteration count and immutable `run_id` are authoritative. Each launch/relaunch computes Ralph's safety cap as `max(10, 3 * authorized_iteration_limit + 2)`, including consumed Human Authorization grants and leaving room for MCP/repair turns. At Human Review the supervisor emits a report and the state-aware hook cancels Ralph before the plugin can silently exhaust its own cap.

The upstream plugin's permissive text match is disabled. The fork stops continuation only after validating persisted `DONE`, or cancels after validating Human Review/abandonment. It never depends on a model relaying tool stdout or a textual promise. Contract tests pin the fork's upstream base, content hash, event ordering, run/session binding, and state reconciliation.

### Deterministic Supervisor

The Python supervisor owns:

- `RunStateStore`: atomic checkpoints and input/output hashes.
- `ActiveRunIndex`: repository-identity lookup that resumes or blocks before Candidate Ticket selection.
- `StageRouter`: next-unit calculation and downstream invalidation.
- `LinearGateway`: deterministic selection plus typed MCP action requests and trusted bridge-receipt validation.
- `GitGuard`: branch, cleanliness, protected-file, and commit checks.
- `CrewRunner`: one ephemeral agent/task execution per unit.
- `ModelFactory`: role URI validation and protocol-specific clients.
- `ArtifactValidator`: Pydantic and OpenSpec validation.
- `VerificationRunner`: configured product checks and browser setup.
- `Finalizer`: idempotent commit, push, and Linear completion.

The supervisor contains no LLM-based routing. It accepts only typed results and applies fixed transition rules. It persists a Run Disposition separately from failure cause and Failure Source. It does not call Linear over an undocumented Python API: it persists typed pending requests before returning them. OpenCode invokes only the launcher-owned Linear MCP bridge, which records Trusted MCP Receipts directly under the Authoritative State Root. Model-authored receipt files are never accepted.

### CrewAI Units

CrewAI runs one ephemeral agent and one task for each unit. Memory, delegation, and verbose transcript propagation are disabled. A unit receives only its contract and allowlisted dependencies. It returns a typed envelope plus artifact content or references.

### State and Evidence

Authoritative run data lives outside the target repository in a launcher-owned root that product, verification, browser, and model tool subprocesses cannot mount or read:

```text
<state-root>/runs/<run-id>/
  current.json
  generations/
  ticket-snapshot.json
  evidence/
  repairs/
```

Run state is stored as checksummed immutable JSON generations plus an atomically replaced compare-and-swap current pointer. A per-run interprocess lock covers pointer re-read, expected revision/hash comparison, exclusive generation creation, fsync, and pointer replacement; exactly one concurrent writer can succeed. Each generation records a monotonic revision, random immutable run ID, canonical physical repository identity, Preparation Transaction phase, Run Disposition, Runner Identity, contract/input/output hashes, validation receipts, current stage, Crew Iteration count, finalization substeps, complete failure history, Human Authorizations, and Effect Ledger. Transition validation rejects immutable-field changes and any non-prefix mutation of append-only collections. The store rejects a generation whose embedded run ID differs from its path. The ticket branch is optional until branch creation succeeds. Secrets and full provider responses are prohibited.

Ticket and artifact identifiers are validated before becoming path components. State replacement fsyncs both the new file and containing directory where supported. Unreferenced temporary generations may be discarded. A missing or corrupt generation referenced by `current.json` enters Human Review unless a transaction journal proves the pointer never committed; the system never rewinds Effect Ledger history automatically.

Version one accepts only OpenSpec's local `spec-driven` schema. Store-backed/external artifact roots, custom schemas, and `skip_specs` are rejected in preflight. The supervisor creates the lowercase kebab-case change idempotently and verifies that any existing change belongs to the same ticket and Active Run.

The Change Outline is a typed run-local JSON Artifact Unit. Every OpenSpec Artifact Unit is represented by a manifest of one or more `{relative_path, content_hash}` files, allowing `specs/**/*.md` to contain multiple capability specs. Files remain in paths returned by the installed OpenSpec CLI.

## Preflight and Ticket Selection

The Preparation Transaction persists these phases: `SELECTED`, `IN_PROGRESS_REQUESTED`, `IN_PROGRESS_CONFIRMED`, `BRANCH_CREATED`, `READY`, and `COMPENSATION_REQUIRED`. Every phase reconciles the intended effect with observable state before issuing another command or MCP request.

Under lock, the first local `prepare --repository` probe either finds an Active Run or writes a durable short-lived preparation reservation. It returns `RESUME`, `BLOCKED`, or the reservation's out-of-band `INPUT_REQUIRED` challenge. Only then does OpenCode invoke a bridge query by challenge/request ID. The launcher-owned bridge writes a versioned PreparationInput under Authoritative State Root with complete pages, page hashes, positive `max_crew_iterations`, bridge/tool-call identity and signature, but never the challenge itself. Model-authored preparation files are rejected. One locked `activate_reservation` operation owns a journal containing reservation/index CAS bindings, challenge hash, trusted input hash, selected outcome, chosen run ID, initial generation hash, and transaction phase. It validates provenance, eligibility, and budget, durably records `NO_CANDIDATE` or creates the initial generation, and then replaces the reservation with ActiveRunRecord. Identical replay returns the recorded run or no-candidate result; a mismatched replay fails. No-candidate performs no Linear, Git, Active Run, or ticket-work effect, while reservation bookkeeping remains durable. Subsequent mutations require run ID, expected state revision/hash, request ID, and Trusted MCP Receipt.

Preflight performs read-only checks before mutation. OpenCode is the MCP transport, while the Python selector owns filtering and ordering:

1. Confirm `.venv`, required Python packages, OpenSpec CLI, Playwright CLI when configured, Git remote, and project configuration.
2. Confirm a clean worktree. Existing unrelated modifications cause Human Review rather than being stashed or discarded.
3. Ask OpenCode to resolve assignee and milestone through Linear MCP and return the raw typed response.
4. Ask OpenCode to query tickets and blocker relationships through Linear MCP.
5. Normalize the MCP response; exclude completed, canceled, and started tickets as well as tickets with Active Blockers; and reject ambiguous identities.
6. Sort candidates by Linear priority, creation time ascending, and canonical ticket ID.
7. Select the first Candidate Ticket and write the immutable, versioned Ticket Snapshot before any mutation. It contains title, description, explicit criteria, comments, labels, relationships, subtickets, sanitized attachment metadata, capture time, workspace/team IDs, pagination completeness, source references, and content hash. URL userinfo/query/fragment data and secret-like values are removed before model visibility; safely redacted attachment text may be included, but arbitrary binaries are not fetched. Hash-addressed references preserve sanitized raw MCP pages outside the Analyst prompt.
8. Validate all five model URIs and required capabilities before consuming an attempt.

Under the repository lock, preflight derives `RepositoryIdentity` from the real path and filesystem identity of `git rev-parse --git-common-dir`, so aliases and linked worktrees share one identity and one launcher-owned index/lock namespace. A matching Active Run resumes its started Resumable Ticket, including when under Human Review; it blocks new selection until `DONE` or authenticated human `abandon`. Candidate selection occurs only when no Active Run exists. Version one supports one automation instance per physical repository. Linear is re-fetched immediately before mutation; cross-machine exclusion is explicitly not guaranteed and an observed race enters Human Review.

After read-only validation:

1. Resolve the team's unique configured or unambiguous `started` and `completed` workflow-state IDs. Multiple states of a required type without configuration cause Human Review.
2. Record the ticket's original state ID and update timestamp.
3. Emit a compare-before-update request for the resolved `started` state, have OpenCode execute it through Linear MCP, and validate its receipt.
4. Fetch the remote default branch.
5. Create `<ticket-id>-<slug>` from `origin/<default-branch>` and switch to it.

If branch preparation fails after the Linear mutation, phase becomes `COMPENSATION_REQUIRED`. Preflight re-reads Linear and emits a compare-before-update request restoring the original state only if no intervening actor changed the ticket; otherwise it enters Human Review. Successful restoration persists both receipts, `compensated=true`, and Human Review; it neither deletes a partial branch/worktree nor releases ActiveRunIndex. After operator correction, authenticated `resume` atomically changes phase from compensated `COMPENSATION_REQUIRED` back to `SELECTED`, preserves all prior effect history, revalidates Linear at the original state, and repeats start/branch reconciliation. Authenticated `abandon` releases instead. An existing branch is reusable only when branch name, ticket ID, base SHA, repository identity, and checkpoint lineage match the Active Run.

## Execution Graph

The normal graph is:

```text
Analyst
  -> Architect:outline
  -> Architect:proposal
  -> Architect:specs
  -> Architect:design
  -> Architect:tasks
  -> Programmer
  -> VerificationRunner
  -> Tester
  -> Reviewer
```

Reviewer processing has no intermediate durable state. Approval persists the validated result/checkpoint, `iteration_open=false`, and finalization eligibility in one CAS generation. Rejection persists validated result evidence, failure history, `iteration_open=false`, routing/invalidation, and next stage in one CAS generation. A crash can expose neither finalization with an open iteration nor an unrouted rejection. Finalizer is a deterministic lifecycle component, not a stage or Artifact Unit, and advances without consuming Crew Iterations.

OpenSpec dependencies are authoritative: `proposal` precedes `specs` and `design`; `tasks` requires both `specs` and `design`. Although `specs` and `design` become available from the proposal independently, they run sequentially to keep execution and recovery simple.

Artifact validation is phased. Each unit is staged as immutable versions, validated, bound by CheckpointAuthority, and only then published to visible paths. Full-change validation runs only after proposal, specs, design, and tasks are structurally complete and before Programmer starts. Each task line has a unique explicit numeric ID such as `1.2`; parsing freezes ID and text into Task Definition Manifest. Programmer output names completed task IDs and repeats input definition/status hashes. The supervisor deterministically produces a separate Task Status Manifest bound to the definition hash, only for known IDs and only from unchecked to checked. Any definition change invalidates the tasks Artifact Unit and status; any unchecked task blocks review/finalization.

Every unit becomes an Approved Artifact Unit and is reusable only after the private checkpoint authority records:

- Pydantic and stage-specific invariant results.
- Contract version/hash and all named input hashes.
- An immutable content-addressed output hash.
- Validator identity/version and validation-receipt hash.
- Each evidence item's relative path, SHA-256, media type, and creator.
- Relevant OpenSpec CLI validation.

Artifacts are written as immutable versions, validated, and bound by a checkpoint before any convenience path is updated. If an input changes, invalidation removes the affected checkpoint and all descendant output references, including Task Status, Product Change Manifest, Build Identity, verification/browser results, Review Manifest/result, and finalization eligibility. Execution routing always receives expected contract and input hashes; status-only inspection reports unknown freshness when those expectations are unavailable.

## Role Contracts

Persisted role IDs are `analyst`, `architect`, `programmer`, `tester`, and `reviewer`. The descriptive CrewAI `role` titles below remain part of the prompts and are not identifiers.

### Analyst

**Role:** Requirements Analyst

**Goal:** Obtain the real Linear ticket and convert it into requirements that are clear, verifiable, and faithful to existing information.

**Behavior:** Analyze objective, scope, requirements, acceptance criteria, restrictions, dependencies, and ambiguities. Do not choose architecture, program, modify Linear, or invent requirements.

**Input:** Ticket Snapshot only.

**Output:** `RequirementsPackage` containing traceable requirement IDs, explicit scope, acceptance criteria, constraints, dependencies, and ambiguity severity. A blocking ambiguity or substantive Requirements defect routes directly to Human Review. Only an Invalid Unit Output from the correctly functioning schema validator can rerun Analyst automatically against the unchanged snapshot.

**Permissions:** Read-only task context; no Linear, Git, shell, or file-write tools.

### Architect

**Role:** Software Architect

**Goal:** Plan an OpenSpec change and produce each artifact as a strict, verifiable unit coherent with its selected context.

**Behavior:** Produce a Change Outline first and then exactly one requested proposal, specs, design, or tasks unit per invocation. Each invocation is independent and receives only its contract and bounded dependencies. Never alter requirements to conceal an earlier failure. Explicitly decide whether Browser E2E is required and explain why.

**Input:** Requirements Package, current OpenSpec instructions, Change Outline, only dependencies required by the requested unit, and the latest typed Architect finding when correcting an invalidated artifact.

**Output:** One typed Artifact Unit. The supervisor, not the agent, materializes and validates it.

**Permissions:** A hash-checking read-only tool limited to explicitly authorized repository and artifact paths; no Linear or Git mutation.

### Programmer

**Role:** Senior Software Developer

**Goal:** Implement the proposal, specs, design, and tasks faithfully while correcting the root cause evidenced by the latest failed attempt.

**Behavior:** Treat specs as the functional contract, design as the technical contract, and Task Definition Manifest as the immutable checklist. Implement only work supported by OpenSpec and update only the separate Task Status Manifest. Prefer compact, simple, readable code.

**Input:** Requirements Package, approved OpenSpec artifacts, current task status, relevant repository context, and only the latest failure evidence when retrying.

**Output:** Product changes, completed task IDs, input Task Definition/Status hashes, command evidence, and a typed implementation summary. The supervisor, not Programmer tools, validates and persists the resulting Task Status Manifest.

**Permissions:** Bounded repository read/write/search and Project Policy commands. Reads and writes to secrets, `.git`, run-state internals, and paths outside authorized roots are denied. Reads/searches are size- and result-limited and reject symlink escapes. No Linear mutation, push, final commit, OpenSpec archive, or run-state editing.

### Tester

**Role:** Browser QA Tester

**Goal:** Validate browser scenarios with Playwright CLI when OpenSpec says Browser E2E is required.

**Behavior:** Never modify product code or invent results. Test real behavior on localhost. Return `skipped` with the Architect's reason when Browser E2E is not required.

**Input:** Browser E2E Decision, configured localhost URL/start command, and Build Identity. The decision is the sole source of browser scenarios.

**Output:** `passed`, `failed`, or `skipped`, always with the exact Browser E2E Decision hash, Build Identity hash, scenario-level evidence, and observed results.

**Permissions:** Playwright CLI and evidence writes under the run directory only.

### Reviewer

**Role:** Quality Reviewer

**Goal:** Independently decide whether the change is ready for finalization.

**Behavior:** Check requirements, scenarios, design, tasks, verification evidence, Tester result, and diff. Never archive OpenSpec or modify Linear.

**Input:** Validated artifact references and hashes, implementation diff, verification results, and Tester result. It receives a fresh context with no prior conversational history.

**Output:** A typed `ReviewResult` with `approved`, `failure_class`, `failure_source`, `owner_stage`, `blocking_findings`, cited requirement/artifact IDs, evidence, and `next_action`.

**Permissions:** Hash-checking read-only tools limited to the explicit review manifest. Independent Review does not require a different model unless Project Policy enables that constraint.

The Reviewer reports; `StageRouter` decides and validates the transition.

## Model Configuration

The root `.env` contains secrets and role selections:

```dotenv
ANALYST_MODEL=opencode-go/<model-id>
ARCHITECT_MODEL=opencode-go/<model-id>
PROGRAMMER_MODEL=ollama-cloud/<model-id>
TESTER_MODEL=opencode-go/<model-id>
REVIEWER_MODEL=opencode-go/<model-id>

OPENCODE_API_KEY=
OLLAMA_API_KEY=
AUTO_CODE_MAX_ATTEMPTS=3
```

`.env.example` contains placeholders and illustrative URI shapes, never keys or rigid model defaults. Every role selection is mandatory.

`ModelFactory` resolves:

- `opencode-go/<model-id>` against `https://opencode.ai/zen/go/v1/models`.
- `ollama-cloud/<model-id>` against the authenticated Ollama Cloud catalog.

OpenCode Go currently exposes different models through OpenAI Chat Completions, OpenAI Responses, or Anthropic Messages endpoints. A CrewAI `BaseLLM` adapter normalizes message, structured-output, and tool-call behavior while preserving the required `x-opencode-session` header. Ollama Cloud uses `https://ollama.com` with `OLLAMA_API_KEY` Bearer authentication.

The live catalog is queried and cached during preflight. Protocol and capability claims come from a versioned Model Compatibility Profile, not from catalog fields the providers do not publish. Selection requires the intersection of the live catalog and compatibility profile; an optional bounded smoke probe can verify a deployment without becoming part of the normal token budget.

Role capability profiles are:

- Analyst: text and structured output.
- Architect: text, structured output, and bounded read-only tool calling.
- Programmer: text, structured output, and bounded tool calling.
- Tester: text, structured output, and Playwright tool calling.
- Reviewer: text, structured output, and bounded read-only tool calling.

Normalized tool calls preserve provider correlation IDs and support multiple calls and correctly correlated results. Unknown tools, malformed arguments, or malformed provider responses become Orchestration Defects. `Retry-After` accepts delta-seconds or HTTP-date, has a Project Policy total-wait cap, and always retries the identical serialized request.

## Token Policy

Token reduction has priority over implementation cleverness:

- No shared agent memory or delegation.
- No full conversation replay between units.
- Artifact paths and hashes replace repeated artifact bodies where the provider can access bounded files.
- Each prompt includes only the contract and direct dependencies.
- Only validated results are cached.
- Structured envelopes are concise; prose belongs in required artifacts, not wrappers.
- CrewAI generative retry is disabled. Transport retry uses bounded backoff and reuses the same payload.
- Analyst and Architect are not rerun for a Product Defect unless their own validated input or output is explicitly invalidated.
- The model catalog is dynamic, allowing operators to balance quality and quota per role without code changes.

## Failure and Resume Rules

Failure classification is total and orthogonal:

| FailureClass | Meaning | Permitted handling |
| --- | --- | --- |
| `PRODUCT` | Implementation differs from approved requirements/artifacts | Programmer, or cited Architect unit when independently validated |
| `INVALID_OUTPUT` | A model result fails a correctly functioning unit schema or artifact validator | Close iteration; retry the same unit in the next iteration |
| `ORCHESTRATION` | Automation code, provider transport, tool, harness, validator execution, or transition failed | Automation Repair |
| `AMBIGUITY` | Safe action or requirement cannot be determined | Human Review |
| `BUDGET_EXHAUSTED` | Authorized Crew Iterations are consumed | Human Review |

`FailureSource` records `PREFLIGHT`, `TRANSPORT`, `ARTIFACT`, `VERIFICATION`, `BROWSER`, `REVIEW`, `FINALIZATION`, or `SUPERVISOR`. `StageRouter` implements a total table over class, source, finding kind, and owner. An unlisted combination converts once to terminal `ORCHESTRATION + SUPERVISOR + INVALID_ROUTING` Human Review and never recursively routes. Reviewer attribution to Architect requires cited artifact IDs and evidence. Reviewer attribution to Analyst always becomes Human Review. Budget exhaustion uses source `SUPERVISOR`.

### Preflight or ambiguity

No Crew Iteration is consumed. Preserve diagnostics and enter Human Review.

### Transient transport failure

Retry the same request with bounded backoff and `Retry-After` support. Do not regenerate the prompt. On exhaustion, classify it as an Orchestration Defect.

### Orchestration Defect

OpenCode must:

1. Read the structured failure and relevant automation diff.
2. Write a repair plan in the isolated repair workspace containing root cause, bounded files, intended change, and regression proof; the active runner can emit only a hash-bound RepairRequest.
3. Modify only the CrewAI automation implicated by that plan, outside the ticket workspace.
4. Run the complete automation regression suite.
5. The OS-protected repair launcher independently verifies workspace baseline/diff and RepairRequest, executes the pinned Repair Runner Identity, builds a content-addressed immutable release, and atomically activates its Runner Identity through a registry compare against expected old identity and activation history.
6. Revalidate checkpoints against the new contract versions, invalidating only those whose bindings changed.
7. Terminate the old OpenCode/Ralph process and restart through the trusted launcher with the new Runner Identity before any next CrewAI execution.

A failed repair does not authorize product changes. Previous Validated Checkpoints remain intact unless their contract or inputs changed. If repair and ticket ownership overlap on any path, enter Human Review.

### Product Defect

Invalidate Programmer and every downstream result. Preserve Analyst and Architect outputs. The next Crew Iteration begins at Programmer with the latest evidence, then reruns all configured verifications, Tester when required, and Reviewer.

### Invalid Unit Output and Architect failure

A model-generated result from any cognitive stage that fails its correctly functioning schema/artifact validator is `INVALID_OUTPUT`, not an Orchestration Defect. It closes the iteration and retries that same unit in the next Crew Iteration. Preserve valid prior units and invalidate descendants: invalid `design` keeps outline, proposal, and specs; invalid Programmer/Tester/Reviewer output resumes that same stage with bounded invalid-output evidence. A validator crash, wrong contract, or adapter defect remains an Orchestration Defect and requires Automation Repair.

### Upstream defect

When a typed finding identifies a substantive requirements defect, enter Human Review. An Analyst Invalid Unit Output may rerun Analyst. When a finding identifies an Architect defect, provide that cited finding as bounded correction input and invalidate only the affected Artifact Unit and graph descendants. The system may not silently rewrite requirements to make implementation pass.

### Exhausted budget

One Crew Iteration starts once, immediately before its first cognitive unit, and closes on a classified failure or valid Reviewer result. Preflight, MCP waits, transport retries, Automation Repair, and finalization never increment it. After `max_crew_iterations`, preserve the branch, artifacts, run state, and evidence; leave Linear in its resolved started state; do not create the final commit or push; and emit a Human Review report with the first unresolved stage, complete failure history, last hashed evidence, reconciliation state, and resume command.

Human continuation is unavailable to the active Ralph/OpenCode command. `authorization challenge` creates an immutable one-time challenge by state CAS. An operator signs canonical UTF-8 JSON with Ed25519 and domain `auto-code-human-authorization/v1`; the envelope contains `key_id`, action, run ID, challenge, actor, reason, additional positive budget when resuming, issue time, expiry, and signature. `resume` or `abandon` validates the launcher-owned public key and atomically consumes the challenge/appends authorization by CAS. Authorized iteration capacity is the original `max_crew_iterations` plus consumed valid resume grants; the original budget/history never changes. Identical signed replay is idempotent and conflicting replay is rejected.

## Verification

Non-secret Project Policy lives in versioned `auto-code.yaml`. Its initial content hash is pinned by launcher-owned configuration before an Active Run and cannot change during that run. Authorization public keys, Active Run Index/registry locations, Repair Runner Identity, and launcher configuration never come from the target repository. Project Policy includes:

- Remote and default-branch overrides when discovery is insufficient.
- Verification commands in deterministic order.
- `verification.allow_empty`, default `false`; when true the exception is recorded for Independent Review.
- Localhost start command and base URL.
- Synchronous command, managed-process, readiness, and total transport timeouts.
- A Playwright command prefix and argument allowlist.
- Separate protected, evidence-readable, and commit-excluded paths.
- Separate read-only verification commands and explicitly authorized mutation commands.
- A minimal environment allowlist for every subprocess.
- An optional requirement that Reviewer and Programmer use different models.

`ProcessRunner` handles finite commands and converts timeout/spawn/signal failures into evidence-bearing results. `ManagedProcessRunner` separately owns long-lived application process groups, readiness, termination escalation, and reaping. Both require an explicit deny-by-default environment, an empty controlled `HOME`, absolute hash-verified executables, disabled dynamic package downloads, bounded/redacted evidence, and an OS sandbox that does not mount the Authoritative State Root or secret files. Policy declares the minimum writable target/build/cache paths for each command.

The Architect's Browser E2E Decision is mandatory and is the sole source of scenarios. If E2E is required but start command or localhost URL is absent, execution enters Human Review rather than guessing. Tester uses the pinned `playwright-cli` agent interface against the real local service through a run-bound named session. The wrapper permits only `open`, `goto`, `snapshot`, `click`, `fill`, `type`, `press`, `screenshot`, and `close`, constrains navigation to configured localhost, directs output through the evidence broker, and always closes/kills its owned session. Dynamic install and arbitrary-code commands are denied. An observed scenario mismatch is a Product Defect; CLI, port, process, or harness failure is an Orchestration Defect.

Every verification and Browser Result is bound to a Build Identity containing baseline commit, exact product-change manifest/hash, Project Policy hash, command hashes, and relevant runtime identity. After every product correction, `VerificationRunner` executes the full configured suite, not only the previously failing test. This is the primary guarantee that a correction does not break previously working behavior.

An empty verification command list is invalid unless Project Policy explicitly sets `verification.allow_empty: true`. Without that authorization preflight enters Human Review; with it, Reviewer receives the exception as a mandatory review input.

Independent Review receives a Review Manifest bound to baseline SHA; exact paths, content hashes, file modes, renames, binaries, and authorized untracked files; Requirements and OpenSpec manifests; immutable tasks; Project Policy; Build Identity; and verification/browser evidence hashes. Reviewer approval is necessary but not sufficient. The supervisor also confirms all required checks, completed OpenSpec tasks, Browser E2E status, current branch, and manifest hashes.

## Finalization

Finalization begins only when:

- Reviewer returns a valid approval.
- All mandatory project verification commands pass.
- Tester is `passed` or validly `skipped`.
- OpenSpec tasks are complete and validation passes.
- The worktree, baseline, and current product-change manifest match the approved Review Manifest.
- No secret or run-local file is staged.

The idempotent sequence is:

1. Re-read Linear and the remote default branch. Normative ticket-content changes or remote-base advancement cause Human Review; the run never rebases or merges automatically.
2. Stage exactly the files, modes, renames, binaries, and authorized untracked entries in the approved Review Manifest.
3. Create or reconcile one ticket commit using the repository's commit convention, and verify its tree equals the approved manifest.
4. Push or reconcile the branch with upstream tracking.
5. Emit a compare-before-update request for the resolved completed state, have OpenCode execute it through Linear MCP, and validate its receipt.
6. Persist finalization evidence and return `DONE`; the state-aware Ralph hook independently verifies it through the trusted launcher.

Every intended branch, commit, push, or Linear action appends immutable events sharing an effect ID. Event sequence is globally monotonic and unique within a run; legal per-effect order is one `INTENTION`, zero or more `INVOCATION`/`OBSERVATION` pairs, then one terminal `RECONCILIATION`. Counts and waits are derived, never updated in place. Before retry, Finalizer queries local refs, commit tree/trailers, remote refs, or current Linear state. A compatible completed Linear state is accepted; an incompatible human state or divergent Git state enters Human Review. Finalization retries are bounded, then enter Human Review without consuming a Crew Iteration. A pending MCP request with request/effect/hash bindings is persisted by CAS before `MCP_ACTION`; the trusted bridge receipt is consumed exactly once by CAS, identical replay is idempotent, and conflicting replay is rejected. ActiveRunIndex release requires repository ID, exact run ID, expected index revision/hash, and terminal run-generation hash. Preparation under lock reconciles a terminal indexed run and performs that bound release if a crash occurred after durable `DONE`. OpenSpec remains unarchived.

## Proposed Source Layout

```text
pyproject.toml
.env.example
auto-code.example.yaml
runner/
  opencode.json
  commands/
    auto-code.md
  plugins/
    ralph-loop/
src/auto_code/
  cli.py
  supervisor.py
  state.py
  contracts.py
  models.py
  linear.py
  git.py
  openspec.py
  verification.py
  finalizer.py
  config/
    agents.yaml
    tasks.yaml
tests/
```

Development uses `.venv`, but production commands execute an absolute, hash-verified virtualenv and OpenCode binary from the immutable runner installation. The launcher sets an isolated OpenCode config directory, disables target/global project config discovery, and applies deny-by-default OpenCode permissions allowing only the trusted launcher and required Linear MCP bridge. Target-local Ralph state is advisory and Git-ignored; authoritative state never lives in the target repository.

## Test Strategy

### Unit tests

- Candidate Ticket ordering and Active Blocker filtering.
- State transitions, downstream invalidation, and contract/hash changes.
- Crew Iteration accounting independent of Ralph continuation count.
- Interprocess CAS races, interrupted writes, and refusal to rewind a referenced corrupt generation.
- Branch naming and same-ticket branch reuse.
- Secret redaction and protected path checks.
- Idempotent commit, push, and Linear finalization.

### Contract tests

- OpenCode Go Chat Completions, Responses, and Anthropic Messages adapters.
- Ollama Cloud authentication, catalog, and responses.
- CrewAI structured outputs and tool calls.
- Linear MCP query/mutation requests and Trusted MCP Receipt provenance through the launcher-owned bridge.
- OpenSpec instructions, artifact paths, and validation results.
- Ralph fork source/content pin, state-derived completion, cancellation, restart, and spoof resistance.

### Integration tests

Use temporary Git repositories and fakes for external systems. Inject interruption before and after every external effect and verify reconciliation before any retry. Required scenarios are:

- Success with Browser E2E skipped.
- Success with required Browser E2E.
- Reviewer detects a Product Defect; only Programmer and downstream stages rerun.
- Architect fails on one Artifact Unit; earlier units remain valid.
- Orchestration Defect triggers planned automation-only repair.
- Attempt budget reaches Human Review with Linear still `In Progress`.
- Push succeeds and Linear completion fails; retry does not create another commit.
- A correction passes the complete regression suite.
- No Candidate Ticket causes no Linear, Git, Active Run, or ticket-work effects and replays its durable preparation outcome.
- Started Resumable Ticket continues only its matching Active Run.
- Equal-priority/equal-time candidates use canonical ID as tie-breaker.
- Linear start succeeds and branch creation fails, with safe compensation and human-change refusal.
- Concurrent CAS, corrupt referenced state, orphan temporary file, stale lock, and mismatched run/session are rejected safely.
- Multi-file specs and illegal tasks rewrites are handled correctly.
- Empty verification policy, browser infrastructure failure, and stale Build Identity route correctly.
- Normative ticket change or remote-base advancement before finalization enters Human Review.
- Arbitrary model text, including the upstream completion token, cannot stop Ralph; persisted validated Done stops it without a token.
- Human Authorization adds derived budget without rewriting history and is CAS/replay safe.
- A forged MCP receipt, hostile target OpenCode config, inherited secret, state-root access, mutable trust root, active-runner self-activation, or premodified repair workspace is rejected.
- A repaired runner terminates the old OpenCode/Ralph process and restarts through the trusted launcher before ticket work resumes.

Real provider smoke tests are opt-in so normal tests do not consume subscription quotas.

## Acceptance Criteria

- Before the first CrewAI call, exactly one eligible Linear ticket is selected deterministically, moved to `In Progress`, and associated with a new ticket branch.
- Every role uses the model URI configured for it in root `.env`.
- Any live-catalog OpenCode Go or Ollama Cloud model can be selected when a tested Model Compatibility Profile satisfies the role's declared capabilities.
- Every completed unit has a Validated Checkpoint and is not repeated while its contract and inputs remain unchanged.
- OpenSpec is pinned to the local `spec-driven` schema and supports multi-file specs manifests without external stores.
- A Reviewer-reported Product Defect resumes at Programmer and reruns all downstream verification.
- An Architect Invalid Unit Output resumes at the failed Artifact Unit; an automation/validator malfunction requires Automation Repair.
- An Orchestration Defect is planned and repaired in CrewAI automation without unauthorized product changes.
- No correction bypasses the complete configured regression suite.
- The default budget permits three Crew Iterations, after which unresolved work enters Human Review without commit, push, or Linear `Done`.
- Successful work has one observable ticket commit and remote result before being marked `Done`; interrupted finalization reconciles each effect and resumes idempotently.
- Ralph stops only after its trusted hook validates persisted `DONE`; no completion-token command exists.

## Delivery Decomposition

Implementation should be planned as four independently testable increments:

1. Contracts, state machine, checkpointing, and fake integrations.
2. ModelFactory plus OpenCode Go/Ollama Cloud adapters and CrewAI role units.
3. Linear/Git/OpenSpec preflight, Programmer tools, verification, and Playwright Tester.
4. Ralph/OpenCode repair loop, idempotent finalization, and end-to-end failure injection.

This ordering proves recovery semantics before connecting destructive external effects.

## Risks and Mitigations

- **Provider catalogs and protocols change:** intersect live availability with versioned Model Compatibility Profiles, pin adapter contract tests, and fail preflight clearly.
- **A listed model performs tool calls poorly:** validate declared capability before assignment and keep role choices independent.
- **Ralph semantics differ from Crew Iterations and upstream tag matching is permissive:** disable text matching in the pinned fork, keep plugin state advisory, and stop only from authoritative persisted state.
- **Linear mutation succeeds while Git preparation fails:** record original state and compensate.
- **Agent output claims success without evidence:** require independent validators and `HEAD`-bound hashes.
- **Ticket text contains prompt injection:** treat Ticket Snapshot content as untrusted data inside fixed role contracts and expose least-privilege tools.
- **Repair damages valid automation behavior:** only the separately trusted Repair Runner may build/activate a replacement; restart the old OpenCode/Ralph process before another CrewAI call.

## Verified External Assumptions

- CrewAI 1.15.20 supports custom `BaseLLM` implementations, per-agent LLM instances, Pydantic structured outputs, and stateful flows. This design uses the first three but keeps global routing outside CrewAI.
- OpenSpec 1.12.0 requires Node >=20.19.0; its default spec-driven graph is `proposal -> specs/design -> tasks`, and specs may contain multiple files.
- `@playwright/cli` 0.1.19 exposes the `playwright-cli` binary and agent-oriented commands such as named-session `open`, `goto`, `snapshot`, element-ref interactions, `screenshot`, and `close`.
- OpenCode Go publishes a model catalog and direct endpoints using three protocol families; external coding agents must identify sessions with `x-opencode-session`.
- Ollama Cloud supports authenticated remote API access through `https://ollama.com` and `OLLAMA_API_KEY`.
- `charfeng1/opencode-ralph-loop` 1.0.10 persists advisory project-local state, continues on idle events, and matches the completion token anywhere in the latest assistant message; the supervisor must not rely on it for validation or budget accounting.

References:

- https://docs.crewai.com/
- https://github.com/fission-ai/openspec
- https://github.com/microsoft/playwright-cli
- https://opencode.ai/docs/go/
- https://docs.ollama.com/cloud
- https://github.com/charfeng1/opencode-ralph-loop
