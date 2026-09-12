# Programmer Tools And Verification Design

## Purpose

Add the bounded execution layer that lets the Programmer inspect and change
only authorized product files, run only configured commands, verify the full
project suite, and create immutable product, build, and review bindings.

## Scope

In scope:

- Descriptor-relative, no-follow repository reads and atomic writes.
- Bounded Programmer read, write, search, and configured-command tools.
- Ordered, non-short-circuit project verification.
- Immutable Product Change Manifest, Build Identity, and Review Manifest
  construction.
- Registering exactly the approved Programmer tools with `ToolBroker` and
  carrying their required context through `crew.py`.

Out of scope:

- Browser execution, Playwright, tester tools, finalization, or Linear effects.
- Git mutation or new Git plumbing collection. `GitGuard` remains the source
  of already-collected manifest inputs.
- Real processes, network access, credentials, or launcher/state-root access
  in tests.

## Architecture

The implementation has four focused adapters.

`RepoToolPolicy` in `programmer_tools.py` owns filesystem authorization. It
opens the repository root once, validates relative paths, and walks each path
with descriptor-relative `openat` operations using `O_NOFOLLOW`. It permits
only regular files beneath declared writable roots, denies protected paths and
state/secret/Git paths, and never follows symlinks. Reads have byte limits;
search has deterministic result and byte limits. Writes create a temporary
regular file beside the target, fsync it, atomically replace the target, and
fsync the parent directory. No API resolves a path before opening it.

`ProgrammerTools` is the CrewAI-facing adapter. It exposes exactly
`read_repo`, `write_repo`, `search_repo`, and `run_authorized`. The first
three delegate to `RepoToolPolicy`. `run_authorized` accepts only a numeric
index into the configured Project Policy command lists and delegates to the
injected `ProcessRunner`; it cannot accept argv, shell syntax, environment,
or an alternate working directory from the model. Every tool has the existing
finite native-call bound and no tools are exposed to Verification.

`VerificationRunner` in `verification.py` receives a pinned `ProjectConfig`,
an injected `ProcessRunner`, evidence sink, sandbox policy, and fixed runtime
context. It rejects an empty verification list unless `allow_empty` is true.
It runs every `verification.commands` entry in configured order despite prior
nonzero exits, timeouts, or spawn failures. Its immutable result contains each
command result/evidence, the exact `BuildIdentity` hash, the aggregate pass
state, and whether an empty suite was explicitly authorized. Mutation commands
remain distinct from ordinary verification commands and are not run here.

`manifests.py` composes immutable hash-bound inputs. `ProductChangeManifestBuilder`
normalizes `GitGuard.collect_manifest_inputs` into paths, modes, Git object
hashes, renames, binary entries, and untracked files. An untracked path is
accepted only if it is under a `writable_roots` entry in the pinned Project
Policy; all protected and excluded paths remain rejected. `BuildIdentityFactory`
binds the baseline SHA, complete Product Change Manifest hash, Project Policy
hash, configured-command hashes, and verified runtime hash. `ReviewManifestBuilder`
binds the exact requirements, every visible OpenSpec artifact, immutable task
definitions/status, product manifest, policy, build identity, verification
result, and browser result. Its callers must supply all hashes explicitly;
missing, stale, or mismatched inputs fail construction.

## Data Flow

1. The supervisor receives Git manifest inputs for a known baseline and uses
   `ProductChangeManifestBuilder` with the pinned Project Policy.
2. `BuildIdentityFactory` creates a Build Identity from that product manifest,
   policy, configured commands, and compatibility-verified runtime identity.
3. The Programmer receives the exact tool set from `ToolBroker`; tool calls
   remain inside the repository and policy boundary.
4. After an implementation result, `VerificationRunner` executes every
   configured check and returns hash-bound evidence.
5. `ReviewManifestBuilder` captures the exact product/build/verification state
   together with all approved planning inputs for independent review.
6. Any product content, mode, rename, authorized-untracked set, policy,
   command, runtime, artifact, task, or evidence drift changes a bound hash;
   that state cannot be reviewed or finalized as the prior manifest.

## Errors And Safety Rules

- Reject absolute paths, traversal, empty segments, protected paths, sensitive
  path parts, symlinks, non-regular files, and accesses outside authorized
  roots before reading or writing.
- Reject oversized reads and searches plus invalid command indexes before a
  model-visible tool effect.
- Treat command failures as recorded verification evidence, not as a reason to
  skip later configured commands. Configuration and input-binding failures
  reject verification before execution.
- Treat a mismatched baseline, policy, product input, build hash, task hash,
  evidence hash, or untracked authorization as manifest construction failure.
- Use injected process, evidence, sandbox, and Git-input capabilities. The
  adapters do not access the Authoritative State Root, invoke Git, use network
  services, or run browser workflows.

## Testing

Tests will use temporary repository trees and injected fake process/Git input
capabilities. They will prove no traversal or symlink escape, protected-path
access, non-regular file access, oversized data exposure, arbitrary command
execution, or write atomicity failure is accepted. Verification tests will
prove every command runs after failures and that Build Identity binding and
empty-suite authorization are enforced. Manifest tests will cover modes,
renames, binary objects, authorized and unauthorized untracked paths, and
input-hash drift. The final non-browser regression covers Programmer tools,
verification, Git, Linear, and OpenSpec, then `compileall`.
