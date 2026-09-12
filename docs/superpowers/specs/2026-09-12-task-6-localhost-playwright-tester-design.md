# Localhost Playwright Tester Design

## Purpose

Add a bounded browser-validation subsystem that executes declared Browser E2E
scenarios only against a policy-configured local application and returns
hash-bound browser evidence for review.

## Scope

In scope:

- Sandboxed lifecycle management for the configured local application.
- A `BrowserRunner` that coordinates app readiness, Tester execution, cleanup,
  and failure classification.
- A localhost-only `LocalPlaywrightTools` adapter exposing exactly one
  `playwright` tool to `Stage.TESTER`.
- Deterministic tests using injected process, Crew, Playwright, and evidence
  fakes.

Out of scope:

- Browser access outside localhost, external networking, browser installation,
  arbitrary shell/code operations, finalization, and Git effects.
- Real process or browser execution in tests.

## Architecture

`BrowserRunner` in `browser.py` owns the full local-browser lifecycle. It
receives the pinned `ProjectConfig`, `ManagedProcessRunner`, a Tester
`CrewRunner`, a `LocalPlaywrightTools` adapter, evidence sink, and trusted
sandbox dependencies. It returns a skipped `BrowserResult` without process
or tool activity when Browser E2E is not required.

When Browser E2E is required, a missing paired `start_command` and `base_url`
configuration returns an Ambiguity failure sourced at Browser. A configured
run starts only the policy's argument-array start command under
`ManagedProcessRunner`, waits for readiness at the policy's local HTTP URL,
then builds Tester context from the exact Browser E2E Decision and Build
Identity. The Tester receives only the injected `playwright` tool from
`ToolBroker`.

`LocalPlaywrightTools` translates a fixed operation schema into calls to the
absolute, hash-verified Playwright CLI prefix. It permits only `open`, `goto`,
`snapshot`, `click`, `fill`, `type`, `press`, `screenshot`, and `close` from
the Project Policy. Every URL must remain the configured localhost origin.
It derives one session name from the trusted run ID and cannot accept a model
supplied executable, command prefix, session ID, arbitrary argument, install
operation, script, environment, or destination.

## Result And Failure Flow

1. An optional Browser E2E Decision returns a skipped `BrowserResult` with
   exact decision/build hashes and its declared reason, without starting an
   application or Playwright session.
2. A required decision with no localhost policy returns an ambiguity failure.
3. A configured required decision starts the app, checks readiness, invokes
   the Tester, and validates its `BrowserResult` using decision/build context.
   The scenario observation IDs must exactly equal the decision's scenario
   IDs.
4. A failed declared browser scenario is a Product Defect owned by Programmer.
   Startup, readiness, CLI, evidence, protocol, or cleanup failure is an
   Orchestration Defect requiring Automation Repair.
5. Every post-start path attempts to close the owned Playwright session and
   stop/reap the owned process. Cleanup attempts all actions even after one
   failure. Cleanup failure produces an Orchestration Defect and preserves the
   primary outcome as evidence.

## Safety Rules

- Accept only Project Policy `http://localhost`, `127.0.0.1`, or `::1` URLs;
  reject credentials, query/fragment drift, foreign hostnames, and scheme
  changes.
- Invoke only the policy start command and Playwright prefix as argument
  arrays through injected trusted process boundaries.
- Persist browser outputs only through the evidence capability; no product
  subprocess receives the Authoritative State Root or secrets.
- Give the Tester exactly one `playwright` tool with the existing finite
  native-call limit. All other roles retain their existing tool boundaries.

## Testing

Tests cover skipped decisions, missing policy ambiguity, valid app/session
lifecycle, localhost and operation rejection, exact decision/build/scenario
binding, product scenario mismatch routing, orchestration faults, and
best-effort cleanup. Fakes record argv, session ownership, evidence, and
cleanup ordering. The final regression runs browser, verification, programmer
tools, OpenSpec, Git, and Linear tests plus bytecode compilation without real
browser or network activity.
