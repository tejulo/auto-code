# Automated Development Orchestration

This context coordinates a ticket from selection through verified delivery while preserving explicit evidence, bounded agent responsibilities, and resumable progress.

## Work Selection

**Candidate Ticket**:
A Linear ticket in an unstarted state, assigned to the requested user, belonging to the requested milestone, and having no Active Blockers. When several qualify, they are ordered by priority, creation date, and canonical ticket identifier.
_Avoid_: Task, issue, work item

**Resumable Ticket**:
A Linear ticket in a started state that has an Active Run bound to the same ticket and repository. It resumes that run instead of competing in Candidate Ticket selection.
_Avoid_: Candidate Ticket, started candidate

**Active Blocker**:
A blocking Linear relationship whose ticket has not reached a completed or canceled state. A Candidate Ticket cannot have an Active Blocker.
_Avoid_: Dependency, impediment

**Ticket Snapshot**:
The immutable, normalized, source-referenced Linear information captured before agent work begins, including all safely accessible content that may constrain the ticket. It is the sole requirements source supplied to the Analyst.
_Avoid_: Ticket copy, issue dump

**Preparation Transaction**:
The durable, reconciled progression from ticket selection through Linear start confirmation and ticket-branch creation. It is complete only when the Active Run is ready for its first Crew Iteration.
_Avoid_: Setup, preflight script

## Planning

**Requirements Package**:
The Analyst's traceable statement of objective, scope, requirements, acceptance criteria, constraints, dependencies, and ambiguities derived from the Ticket Snapshot.
_Avoid_: Analysis, brief

**Change Outline**:
The Architect's manifest of the OpenSpec artifacts required for a change and the bounded context needed by each artifact.
_Avoid_: Plan, draft

**Artifact Unit**:
One independently produced and validated planning result: Change Outline, proposal, specs, design, or tasks. It may contain multiple files but has one manifest and validation boundary.
_Avoid_: Document step, architect output

**Task Definition Manifest**:
The immutable identifiers and text of the implementation tasks approved as part of the tasks Artifact Unit.
_Avoid_: Checklist state, completed tasks

**Task Status Manifest**:
The current completion state of each entry in a Task Definition Manifest. It may change only through validated unchecked-to-checked transitions.
_Avoid_: Tasks artifact, rewritten checklist

**Approved Artifact Unit**:
An Artifact Unit whose current inputs, output, contract, and validation evidence are bound by a Validated Checkpoint. Approval does not imply a separate human sign-off.
_Avoid_: Generated artifact, human-approved artifact

**Browser E2E Decision**:
The Architect's explicit, reasoned declaration that browser validation is either required or not required for the change.
_Avoid_: E2E flag, test hint

## Execution

**Crew Iteration**:
One budgeted pass from the earliest pending or invalidated cognitive unit through Reviewer approval or a classified failure. Preflight, external-action waits, transport retries, Automation Repair, and finalization are outside a Crew Iteration.
_Avoid_: Ralph iteration, retry, run

**Active Run**:
The durable orchestration record currently authorized to process one ticket in one physical repository. It remains active through Human Review until it is done or explicitly abandoned; version one permits only one Active Run per physical repository.
_Avoid_: Session, Ralph loop, process

**Validated Checkpoint**:
A durable record created by the checkpoint authority that binds a unit's contract, inputs, immutable output, validator, and hashed evidence. Only a Validated Checkpoint whose bindings still match is eligible for reuse.
_Avoid_: Cache, progress file, save point

**Product Defect**:
A mismatch between implementation and the approved Requirements Package or OpenSpec artifacts. Its correction resumes with Programmer and does not require new analysis or architecture unless an upstream artifact is explicitly invalidated.
_Avoid_: Crew failure, agent failure

**Orchestration Defect**:
A failure in automation code, a contract definition, model adapter, tool integration, validator execution, or state transition rather than in ticket implementation or an ordinary model-generated Invalid Unit Output.
_Avoid_: Product bug, coding defect

**Invalid Unit Output**:
A model-generated cognitive-unit result that fails its correctly functioning schema or artifact validator. It closes the current Crew Iteration and retries the same unit without authorizing Automation Repair.
_Avoid_: Orchestration Defect, Product Defect

**Failure Source**:
The stage or boundary where a failure was observed, independently of whether its cause is a Product Defect, Orchestration Defect, ambiguity, or exhausted budget.
_Avoid_: Failure class, owner

**Run Disposition**:
The durable lifecycle condition of an Active Run, such as active, waiting for an external action, awaiting repair, under Human Review, done, or abandoned.
_Avoid_: Failure, step result, status message

**Human Review**:
The paused state entered for unresolved requirements, unsafe or ambiguous conditions, or an exhausted Crew Iteration budget. Existing branch, artifacts, and checkpoints are preserved.
_Avoid_: Failed, aborted

**Reconciled Effect**:
An external change whose observed result is compared with its intended result before any retry. It provides an idempotent outcome without claiming that the underlying command or API was invoked exactly once.
_Avoid_: Exactly-once effect, blind retry

**Effect Ledger**:
The append-only history of immutable intention, invocation, observation, and reconciliation events for external changes in an Active Run.
_Avoid_: Command log, retry list

**Authoritative State Root**:
The launcher-owned storage outside the target repository that contains Active Runs, generations, evidence, pending requests, and the Active Run Index and is not mounted into product subprocesses.
_Avoid_: .auto-code directory, project state

**Trusted MCP Receipt**:
A receipt created by the launcher-owned MCP bridge, not by model-authored text, that binds an allowlisted request and observed result to bridge identity and tool-call correlation.
_Avoid_: Tool output copy, caller-written receipt

**Model Compatibility Profile**:
A versioned statement of the protocol and tested capabilities of a provider model that is also present in the provider's live catalog.
_Avoid_: Model catalog entry, assumed capability

**Build Identity**:
The immutable binding between repository baseline, product changes, Project Policy, and verification inputs for one implementation state.
_Avoid_: HEAD, build number, commit hash

**Project Policy**:
The operator-controlled, versioned constraints that authorize repository commands, protected paths, browser startup, timeouts, and verification behavior.
_Avoid_: Agent configuration, ticket instructions

**Independent Review**:
A fresh, memoryless, read-only Reviewer execution over explicitly authorized, hash-checked inputs. It need not use a different model unless Project Policy requires it.
_Avoid_: Second opinion, different model

**Review Manifest**:
The exact, hash-bound product change, planning artifacts, policy, and verification evidence submitted for Independent Review and authorized for finalization.
_Avoid_: Diff, changed files, review context

**Human Authorization**:
An immutable, authenticated decision created outside the Active Run that permits resume with stated reason/additional Crew Iteration budget or explicit abandonment.
_Avoid_: Retry, resume flag, approval

**Runner Identity**:
The immutable, content-addressed orchestration release authorized to execute an Active Run.
_Avoid_: Environment, checkout, latest version

**Repair Runner Identity**:
The separately trusted, immutable release authorized to validate, build, and activate an Automation Repair without executing ticket work.
_Avoid_: Runner Identity, repair script

**Automation Repair**:
A correction to the orchestration system performed outside the ticket change and validated independently before ticket processing resumes.
_Avoid_: Product correction, ticket fix

## Roles

**Analyst**:
The role that converts the Ticket Snapshot into a Requirements Package without designing, programming, inventing requirements, or changing Linear.
_Avoid_: Business analyst, analyst agent

**Architect**:
The role that creates the Change Outline and each OpenSpec Artifact Unit independently, including the Browser E2E Decision.
_Avoid_: Arquitect, architecture agent

**Programmer**:
The role that implements the approved OpenSpec change and addresses evidence from the latest Product Defect.
_Avoid_: Programer, developer agent

**Tester**:
The role that validates required browser scenarios against the real localhost application through Playwright CLI, or reports a justified skip when Browser E2E is not required.
_Avoid_: QA agent, test agent

**Reviewer**:
The independent role that determines readiness from requirements, scenarios, design, tasks, verification evidence, browser results, and the implementation diff.
_Avoid_: Approver, code reviewer
