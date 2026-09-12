# Task 3b Compatibility And Catalog Preflight Design

## Purpose

Task 3b supplies the launcher-owned compatibility, policy, runtime, and live
model-catalog proof that Task 3c must obtain before it can activate a
preparation run or request any Linear or Git effect. It turns the existing
structural `RunState` compatibility hash/reference fields into a typed,
hash-bound preflight result without adding coordinator or CLI behavior.

## Scope

- Expand the protected runtime descriptor with non-secret project, policy, and
  runner bindings.
- Add a typed, root-owned `CompatibilityReceipt` and a receipt authority that
  persists and reloads canonical compatibility evidence safely.
- Add a launcher-composed version and runner-package verifier for the approved
  compatibility baseline.
- Add an injected, authenticated live catalog preflight service that resolves
  every selected role model against the immutable compatibility profile bundle.
- Add deterministic offline tests and an opt-in provider-smoke marker.

## Non-Goals

- Do not add `PrepareCoordinator`, `prepare` CLI modes, Active Run activation,
  ticket selection, Linear actions, Git actions, or browser sessions. Task 3c
  owns those effects.
- Do not add catalog I/O to `ModelFactory`, `ModelCatalog`,
  `ModelCompatibilityRegistry`, or `ModelTransport`.
- Do not put provider credentials, signing keys, executable paths/hashes, cache
  roots, endpoints, or launcher services in Project Policy, run state, CLI
  arguments, or the protected JSON descriptor.
- Do not use a stale/offline catalog fallback for a new preflight.

## Existing Constraints

- The compatibility baseline is Python `3.12.x`, CrewAI `1.15.20`, OpenSpec
  `1.12.0`, Node `>=20.19.0`, Ralph based on `opencode-ralph-loop` `1.0.10`,
  and, only when browser policy is configured, `@playwright/cli` `0.1.19` with
  exact `playwright` and `playwright-core`
  `1.63.0-alpha-2026-08-31`.
- `ProjectConfig.policy_hash` is canonical and must match the descriptor before
  preflight. Task 3c will require it to match the initial state binding and on
  every later advance.
- `RunState` already requires `compatibility_receipt_hash` and
  `compatibility_receipt_ref` for a fully preparation-bound initial state; the
  reference hash must equal the stored receipt hash.
- `ModelFactory` remains a pure injected-catalog consumer. The compatibility
  registry remains the tested-profile intersection boundary.
- Errors are fixed and secret-free. A Task 3b failure produces no Active Run,
  state generation, Linear request, or Git effect; Task 3c maps it to Human
  Review.

## Runtime Descriptor And Launcher Composition

`TrustedRuntimeConfig` accepts exactly these non-secret descriptor fields:

- `state_root`: absolute Authoritative State Root.
- `project_root`: absolute canonical target repository root.
- `project_policy_path`: absolute policy path below `project_root`.
- `project_policy_hash`: canonical SHA-256 expected after strict policy load.
- `runner_identity`: typed runner provenance already approved by the launcher.

The descriptor remains FD-3-only, regular-file-only, read-only, ASCII JSON,
bounded, duplicate-key-free, and does not accept arbitrary extras. It does not
construct or serialize capabilities. The launcher separately composes a
`CompatibilityRuntime` capability containing verified executable observations,
runner package manifests, a profile bundle, a catalog client factory, opaque
provider credential source, evidence writer, and any bounded clock/cache
implementation.

`CompatibilityRuntime` is injected directly into Task 3b services. Its
capabilities are not reconstructed from descriptor strings or target-repository
metadata. The launcher validates all supplied paths, executable identities,
runner identity, and credentials before composition.

## Receipt And Evidence

`CompatibilityReceipt` is a frozen contract with a schema version, receipt ID,
issuance time, launcher identity, runner identity/content hash, Project Policy
hash, selected-role-model hash, compatibility-profile bundle hash, catalog
receipt hashes, browser-preflight status, and typed component observations.
Each observation contains a fixed component name, expected constraint, observed
safe version/identity, and zero or more non-secret evidence hashes. The receipt
content hash is the runtime identity for later `BuildIdentity.runtime_hash`.

`CompatibilityReceiptAuthority` owns canonical JSON evidence only below
`trusted-launcher/compatibility/<canonical-uuid>.json` under the Authoritative
State Root. It writes once, returns an `EvidenceRef` with creator
`trusted-launcher` and the receipt content hash, and reloads only a path/hash/
shape/launcher/runner-identity matching receipt. It exposes fixed failures and
never accepts a caller-authored path or receipt payload as proof.

`CompatibilityPreflightResult` returns the frozen receipt, its evidence
reference, provider-keyed `ModelCatalog` mapping, and resolved role metadata.
Task 3c consumes this object to construct the complete initial `RunState`; it
does not recompute or accept a receipt supplied by CLI input.

## Version And Runner Verification

`PreflightVersionVerifier` receives only launcher-composed runtime capabilities
and returns a successful `CompatibilityPreflightResult` or a typed,
secret-free preflight rejection.

- Python checks the executing, launcher-pinned interpreter is `3.12.x` and
  records its full observed version and verified identity.
- CrewAI reads installed distribution metadata from that interpreter and
  requires exact `1.15.20`; its observation binds the immutable runner
  dependency-lock identity.
- OpenSpec and Node use hash-verified absolute executables through the existing
  trusted command/evidence boundary; they require exact `1.12.0` and final
  SemVer `>=20.19.0`, respectively.
- The runner package manifest proves the local OpenSpec schema, the Ralph
  upstream base/version, source/dependency/content/contract hashes, and, when
  configured, the exact Playwright CLI/core package tree. A banner alone is
  insufficient for package-tree assertions.
- Browser preflight is `not_configured` only when both browser start command
  and base URL are absent under the existing paired-policy rule. Otherwise all
  Playwright assertions are mandatory.

No dynamic install, `npx`, `PATH` discovery, mutable `latest` tag, or target
repository package manifest is accepted as runner evidence.

## Live Catalog Preflight

`LiveCatalogPreflight` is a preflight-only launcher-composed service. It accepts
selected `RoleModelConfig.models`, an opaque `ProviderCredentialSource`, a
`ModelCompatibilityRegistry` with a deterministic profile-bundle hash, fixed
provider clients/endpoints, and non-secret policy limits.

For every selected provider it:

1. Obtains required opaque credentials from the launcher source. Ollama
   credentials are mandatory when any role selects Ollama. OpenCode Go uses a
   launcher-supplied credential when available but has no caller-controlled
   fallback.
2. Fetches the provider catalog once per preflight under fixed endpoint,
   timeout, response-size, and retry bounds.
3. Sanitizes and validates model identifiers into the existing immutable
   `ModelCatalog`; raw responses and credentials are discarded.
4. Resolves every selected role against the tested profile registry and role
   capability requirements.
5. Records provider, fixed endpoint identity, credential-scope fingerprint,
   fetched/expiry timestamps, sanitized model-set hash, profile bundle hash,
   and response/evidence hash in non-secret catalog evidence.

The cache is private to the launcher service and keyed by provider, endpoint,
credential scope, runner identity, and profile bundle. It may deduplicate a
fresh response only within the same preflight operation. Every new preflight
performs a live fetch; an expired entry or a failed new fetch never becomes a
stale/offline fallback. A profile mismatch rejects preflight.

`ModelCompatibilityRegistry` gains a deterministic profile-bundle content hash
derived from all canonical profiles. `ModelFactory` continues receiving only
the resolved injected catalog mapping and performs no catalog I/O.

## Project Policy

Project Policy gains only non-secret preflight controls: catalog timeout,
maximum response bytes, retry budget, and cache validity bound. They are typed,
positive/bounded values included in `policy_hash`. Provider endpoints,
credentials, executable identities, runner manifests, and state/evidence roots
remain launcher-owned and forbidden in policy.

The preflight loads policy only through the descriptor-bound path, rejects a
path outside the descriptor-bound project root, and requires the reloaded
canonical hash to equal `TrustedRuntimeConfig.project_policy_hash`. Task 3c
will repeat this drift check before its effects and compare against the run's
immutable policy hash.

## Failure Ordering

1. Validate descriptor and load descriptor-bound policy/hash.
2. Verify runner/interpreter/package baseline and browser conditionality.
3. Fetch and resolve live catalogs/profile bundle.
4. Persist the compatibility receipt through its authority and return the
   typed result.

Any failure stops at that step. It does not persist a partial receipt, reserve
or activate a run, emit an MCP request, invoke Linear, or run Git. Error text
contains a fixed category only; it never includes credentials, raw provider
responses, arbitrary command output, paths outside permitted identities, or
untrusted model values.

## Testing

Tests are offline and use deterministic fake launcher capabilities. They cover:

- protected descriptor exact shape, path containment, policy hash match, and
  policy drift rejection;
- every version/package/runner-manifest baseline mismatch, with no receipt
  publication;
- browser conditional not-configured and configured exact-package paths;
- receipt canonical write/load, tampered path/hash/identity/shape rejection,
  and no secret serialization or exception leak;
- one catalog fetch per selected provider, credential requirements, malformed
  or oversized responses, all-role profile/capability resolution, cache-key
  isolation, expiry rejection, and no stale fallback;
- unchanged pure `ModelFactory` construction with injected catalog mappings;
- an opt-in `provider_smoke` marker that uses launcher credentials, asserts only
  contract shape, and is excluded from default offline pytest runs.

Each implementation task follows TDD and receives independent review. Final
verification runs focused compatibility/config/catalog tests, the full suite,
and Python compilation.
