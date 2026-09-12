# Task 3b Compatibility And Catalog Preflight Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a launcher-owned, offline-testable compatibility and live-model-catalog preflight that publishes one hash-bound receipt before Task 3c can activate a run or request any external effect.

**Architecture:** Keep the protected FD-3 descriptor limited to five non-secret bindings, then load and hash-check Project Policy before any runtime observation. Put pure profile hashing and the injected live-catalog boundary upstream of `ModelFactory`; put durable receipt contracts in the existing contract module and root-owned persistence/version orchestration in a new compatibility module. Every capability that can observe executables, credentials, provider responses, time, or authoritative storage is injected by the launcher and never reconstructed from policy, state, CLI arguments, or the descriptor.

**Tech Stack:** Python 3.12, Pydantic 2, PyYAML, `httpx`-agnostic injected provider clients, existing canonical JSON/hash/state helpers, pytest.

**Spec:** `docs/superpowers/specs/2026-09-07-task-3b-compatibility-catalog-preflight-design.md`

## Global Constraints

- Preserve the current unborn Git repository: do not run Git commands, create commits, create branches/worktrees, stash, reset, checkout, push, or alter staging.
- `TrustedRuntimeConfig` accepts exactly `state_root`, `project_root`, `project_policy_path`, `project_policy_hash`, and `runner_identity`; all are non-secret and descriptor JSON remains FD-3-only, ASCII, bounded, duplicate-key-free, regular-file-only, read-only, and extra-key-free.
- `state_root`, `project_root`, and `project_policy_path` are absolute; `project_policy_path` is strictly below `project_root`; reloaded `ProjectConfig.policy_hash` must match the descriptor before any runtime probe or catalog call.
- Project Policy gains only bounded non-secret controls for catalog timeout, response bytes, retry budget, and cache validity. Endpoints, credentials, executable identities/hashes, package manifests, cache roots, and evidence roots remain launcher-owned.
- Enforce Python `3.12.x`, CrewAI `1.15.20`, OpenSpec `1.12.0`, final Node SemVer `>=20.19.0`, and Ralph upstream `opencode-ralph-loop` `1.0.10`. When browser policy is configured, also enforce `@playwright/cli` `0.1.19`, `playwright` `1.63.0-alpha-2026-08-31`, and `playwright-core` `1.63.0-alpha-2026-08-31`.
- Browser status is `not_configured` only when both `BrowserPolicy.start_command` and `BrowserPolicy.base_url` are absent; the existing paired-policy validation remains authoritative.
- Keep `ModelFactory`, `ModelCatalog`, `ModelCompatibilityRegistry`, and `ModelTransport` free of catalog I/O. `ModelFactory` continues to consume only injected provider-keyed `ModelCatalog` instances.
- A new preflight always performs live catalog fetches. A cache may deduplicate only within one explicit preflight operation and must be keyed by operation, provider, endpoint identity, credential scope fingerprint, runner identity, and profile-bundle hash. Never use stale/offline results after a failed new fetch.
- Persist only canonical, non-secret evidence below `trusted-launcher/compatibility/<canonical-uuid>.json` under the Authoritative State Root. Never persist raw provider responses, credentials, arbitrary command output, executable paths, or partial receipts.
- Fail with fixed category text only. A Task 3b failure must publish no receipt and must not create an Active Run/state generation, emit MCP/Linear requests, invoke Git, or start browser activity.
- All default tests are deterministic and offline. `provider_smoke` is explicitly opt-in and uses only an externally launcher-composed test harness.
- Submit each completed implementation task, its exact changed files, and its focused test output to a fresh independent reviewer before starting the next task.

---

## File Structure

- Modify `src/auto_code/cli.py`: expand and strictly parse the protected descriptor into `TrustedRuntimeConfig` without adding a CLI command.
- Modify `src/auto_code/project_config.py`: add the bounded, non-secret `CatalogPreflightPolicy` section to `ProjectConfig`.
- Modify `auto-code.example.yaml`: provide safe default preflight limits required by the new strict policy shape.
- Modify `src/auto_code/model_compatibility.py`: expose an order-independent `profile_bundle_hash` for the immutable tested profile set.
- Create `src/auto_code/catalog_preflight.py`: define injected credential/client/cache protocols and resolve selected roles into sanitized catalogs, model metadata, and non-secret catalog evidence.
- Modify `src/auto_code/contracts.py`: add frozen compatibility receipt, component observation, catalog observation, and browser-status contracts with canonical content hashes.
- Create `src/auto_code/compatibility.py`: load descriptor-bound policy, validate the version/package baseline through injected trusted probes, own receipt persistence/reload, and compose `CompatibilityPreflightResult`.
- Modify `pyproject.toml`: register the `provider_smoke` marker without adding a default network dependency.
- Create `tests/conftest.py`: deselect `provider_smoke` tests unless the explicit `--provider-smoke` option is provided.
- Create `tests/test_catalog_preflight.py`: deterministic fakes covering catalog fetch, cache, credential, sanitization, profile, and pure-factory boundaries.
- Create `tests/test_compatibility.py`: deterministic launcher capability fakes covering receipts, policy binding, baseline/version/package checks, browser conditionality, and no-publication failures.
- Create `tests/test_provider_smoke.py`: opt-in contract-shape smoke entrypoint supplied by an external launcher-owned harness.
- Modify `tests/test_cli.py`, `tests/test_project_config.py`, and `tests/test_model_catalog.py`: cover the exact descriptor/policy/profile-hash changes while retaining current behavior tests.

### Task 1: Bind Descriptor And Project Policy

**Files:**
- Modify: `src/auto_code/cli.py:17-84`
- Modify: `src/auto_code/project_config.py:273-328`
- Modify: `auto-code.example.yaml:15-21`
- Modify: `tests/test_cli.py:18-23,272-465`
- Modify: `tests/test_project_config.py:21-80`

**Interfaces:**
- Consumes: `RunnerIdentity` from `auto_code.contracts` and `ProjectConfig.policy_hash` from `auto_code.project_config`.
- Produces: `TrustedRuntimeConfig(state_root: Path, project_root: Path, project_policy_path: Path, project_policy_hash: str, runner_identity: RunnerIdentity)` and `CatalogPreflightPolicy` for later policy binding and catalog calls.

- [ ] **Step 1: Write failing descriptor and policy tests**

  Add one reusable valid runner identity fixture and a descriptor payload helper. Require all five descriptor keys, reject a policy path outside the project root, reject an extra key, and assert a policy load includes bounded preflight values:

  ```python
  def runtime_payload(tmp_path: Path) -> dict[str, object]:
      project_root = tmp_path / "project"
      project_root.mkdir()
      policy_path = project_root / "auto-code.yaml"
      return {
          "state_root": str(tmp_path / "state"),
          "project_root": str(project_root),
          "project_policy_path": str(policy_path),
          "project_policy_hash": "0" * 64,
          "runner_identity": runner_identity().model_dump(mode="json"),
      }


  def test_runtime_descriptor_rejects_policy_outside_project_root(tmp_path: Path) -> None:
      payload = runtime_payload(tmp_path)
      payload["project_policy_path"] = str(tmp_path / "outside.yaml")

      with pytest.raises(ValueError, match="project policy path"):
          TrustedRuntimeConfig.from_descriptor(payload)


  def test_policy_hash_changes_when_catalog_preflight_limits_change(tmp_path: Path) -> None:
      data = policy_data()
      data["preflight"] = {
          "catalog_timeout_seconds": 30,
          "max_catalog_response_bytes": 1_048_576,
          "catalog_retry_budget": 2,
          "catalog_cache_validity_seconds": 300,
      }
      first = ProjectConfig.load(write_policy(tmp_path, data, "first.yaml"))
      data["preflight"]["catalog_retry_budget"] = 1  # type: ignore[index]
      second = ProjectConfig.load(write_policy(tmp_path, data, "second.yaml"))

      assert first.policy_hash != second.policy_hash
  ```

- [ ] **Step 2: Run the focused tests and confirm the pre-change failure**

  Run: `.venv/bin/python -m pytest tests/test_cli.py tests/test_project_config.py -q`

  Expected: FAIL because `TrustedRuntimeConfig.from_descriptor` and the required `preflight` policy section do not exist yet.

- [ ] **Step 3: Implement exact descriptor and policy contracts**

  In `project_config.py`, add the frozen strict policy model and make it required on `ProjectConfig`:

  ```python
  class CatalogPreflightPolicy(_PolicyModel):
      catalog_timeout_seconds: int = Field(ge=1, le=300)
      max_catalog_response_bytes: int = Field(ge=1_024, le=8_388_608)
      catalog_retry_budget: int = Field(ge=0, le=3)
      catalog_cache_validity_seconds: int = Field(ge=1, le=3_600)


  class ProjectConfig(_PolicyModel):
      git: GitPolicy
      verification: VerificationPolicy
      browser: BrowserPolicy
      process: ProcessPolicy
      transport: TransportPolicy
      preflight: CatalogPreflightPolicy
      finalization: FinalizationPolicy
      # Keep every existing field unchanged below this point.
  ```

  In `cli.py`, validate paths without resolving caller-controlled symlinks, parse only the exact descriptor shape, and use Pydantic's existing `RunnerIdentity` parser:

  ```python
  @dataclass(frozen=True)
  class TrustedRuntimeConfig:
      state_root: Path
      project_root: Path
      project_policy_path: Path
      project_policy_hash: str
      runner_identity: RunnerIdentity

      @classmethod
      def from_descriptor(cls, value: object) -> "TrustedRuntimeConfig":
          if not isinstance(value, dict) or set(value) != {
              "state_root", "project_root", "project_policy_path", "project_policy_hash", "runner_identity",
          }:
              raise ValueError("runtime descriptor shape is invalid")
          return cls(
              state_root=Path(value["state_root"]),
              project_root=Path(value["project_root"]),
              project_policy_path=Path(value["project_policy_path"]),
              project_policy_hash=value["project_policy_hash"],
              runner_identity=RunnerIdentity.model_validate(value["runner_identity"]),
          )
  ```

  `__post_init__` must reject non-absolute roots, `..` path components, a policy path equal to or outside the project root, malformed SHA-256 text, and a non-`RunnerIdentity` value. Update FD-3 loading to call `from_descriptor`; update the example policy and all `policy_data()` fixtures with the four safe values above. Do not change `status` behavior or add CLI arguments.

- [ ] **Step 4: Run descriptor and policy regressions**

  Run: `.venv/bin/python -m pytest tests/test_cli.py tests/test_project_config.py -q`

  Expected: PASS, including read-only FD handling, duplicate-key rejection, exact five-key parsing, path containment, and canonical policy-hash coverage.

- [ ] **Step 5: Record the task evidence without Git activity**

  Run: `.venv/bin/python -m compileall -q src tests`

  Expected: exit `0`. Do not run `git add` or `git commit` in this unborn repository.

### Task 2: Hash Profiles And Resolve Live Catalogs

**Files:**
- Modify: `src/auto_code/model_compatibility.py:32-63`
- Modify: `src/auto_code/contracts.py:146-162`
- Create: `src/auto_code/catalog_preflight.py`
- Create: `tests/test_catalog_preflight.py`
- Modify: `tests/test_model_catalog.py:36-54`
- Modify: `tests/test_models.py:453-480`

**Interfaces:**
- Consumes: `CatalogPreflightPolicy`, `RunnerIdentity`, `RoleName`, `ModelRef`, `ModelCatalog`, `ModelCompatibilityRegistry`, and `RoleCapabilityMatrix.required_for_role`.
- Produces: `ModelCompatibilityRegistry.profile_bundle_hash`, `CatalogObservation`, `CatalogPreflightResult`, and `LiveCatalogPreflight.resolve(role_models, policy, operation_id)`.
- Later tasks rely on: `CatalogPreflightResult.catalogs`, `.resolved_models`, and `.catalog_observations` to build the final compatibility receipt.

- [ ] **Step 1: Write failing deterministic catalog tests**

  Define fakes in `tests/test_catalog_preflight.py` with a call counter and opaque credential sentinels. Cover one fetch for each selected provider, all role resolution, profile bundle ordering, malformed IDs, mandatory Ollama credentials, optional OpenCode Go credentials, cache isolation, expiry, and no stale fallback:

  ```python
  def test_preflight_fetches_each_selected_provider_once_and_resolves_every_role() -> None:
      client = RecordingCatalogClient("opencode-go", ["analyst", "architect", "programmer", "tester", "reviewer"])
      result = LiveCatalogPreflight(
          clients={"opencode-go": client},
          credentials=FakeCredentials(opencode=object()),
          profiles=profiles_for_opencode_roles(),
          runner_identity=runner_identity(),
          cache=InMemoryCatalogCache(),
          now=fixed_now,
      ).resolve(all_opencode_roles(), preflight_policy(), operation_id="operation-a")

      assert client.calls == 1
      assert set(result.catalogs) == {"opencode-go"}
      assert set(result.resolved_models) == set(RoleName)
      assert result.catalog_observations["opencode-go"].model_set_hash == hash_json(sorted(client.model_ids))


  def test_new_operation_does_not_use_a_stale_catalog_after_fetch_failure() -> None:
      cache = InMemoryCatalogCache()
      service = catalog_service(cache=cache, client=RecordingCatalogClient("opencode-go", ["analyst"]))
      service.resolve(one_role_per_model(), preflight_policy(), operation_id="operation-a")
      service.clients["opencode-go"].failure = RuntimeError("credential=secret-value")

      with pytest.raises(CatalogPreflightError, match="catalog preflight failed"):
          service.resolve(one_role_per_model(), preflight_policy(), operation_id="operation-b")
  ```

  Add a factory regression that constructs `ModelFactory` with the returned static catalog mapping while a fake catalog client would fail if called; assert the client call count does not change during construction.

- [ ] **Step 2: Run the catalog and current pure-model tests to confirm failure**

  Run: `.venv/bin/python -m pytest tests/test_model_catalog.py tests/test_models.py tests/test_catalog_preflight.py -q`

  Expected: FAIL because `profile_bundle_hash`, `LiveCatalogPreflight`, and the injected catalog contracts do not exist.

- [ ] **Step 3: Implement pure bundle hashing and the launcher-injected catalog boundary**

  Make the registry hash order-independent by serializing every profile to a stable list sorted by `(provider, model_id)`:

  ```python
  @property
  def profile_bundle_hash(self) -> str:
      profiles = [
          {
              "provider": profile.provider,
              "model_id": profile.model_id,
              "protocol": profile.protocol,
              "capabilities": sorted(profile.capabilities),
              "context_limit": profile.context_limit,
              "version": profile.version,
          }
          for _, profile in sorted(self._profiles.items())
      ]
      return hash_json({"schema_version": "v1", "profiles": profiles})
  ```

  In `catalog_preflight.py`, create these public types and keep credentials opaque:

  ```python
  class ProviderCredentialSource(Protocol):
      def require(self, provider: str) -> object: ...
      def optional(self, provider: str) -> object | None: ...
      def credential_scope_hash(self, provider: str, credential: object | None) -> str: ...


  class CatalogPreflightError(RuntimeError):
      pass


  @dataclass(frozen=True)
  class CatalogFetch:
      model_ids: tuple[object, ...]
      response_evidence_hash: str
      fetched_at: datetime
      response_bytes: int


  class ProviderCatalogClient(Protocol):
      provider: str
      endpoint_identity: str

      def fetch(
          self,
          credential: object | None,
          *,
          timeout_seconds: int,
          max_response_bytes: int,
          retry_budget: int,
      ) -> CatalogFetch: ...


  @dataclass(frozen=True)
  class CatalogCacheKey:
      operation_id: str
      provider: str
      endpoint_identity: str
      credential_scope_hash: str
      runner_content_hash: str
      profile_bundle_hash: str


  class CatalogPreflightCache(Protocol):
      def get(self, key: CatalogCacheKey, *, now: datetime) -> CatalogFetch | None: ...
      def put(self, key: CatalogCacheKey, fetch: CatalogFetch, *, expires_at: datetime) -> None: ...


  @dataclass(frozen=True)
  class CatalogPreflightResult:
      catalogs: Mapping[str, ModelCatalog]
      resolved_models: Mapping[RoleName, ModelMetadata]
      catalog_observations: Mapping[str, CatalogObservation]


  class LiveCatalogPreflight:
      def __init__(
          self,
          *,
          clients: Mapping[str, ProviderCatalogClient],
          credentials: ProviderCredentialSource,
          profiles: ModelCompatibilityRegistry,
          runner_identity: RunnerIdentity,
          cache: CatalogPreflightCache,
          now: Callable[[], datetime],
      ) -> None: ...

      def resolve(
          self,
          role_models: Mapping[RoleName, ModelRef],
          policy: CatalogPreflightPolicy,
          *,
          operation_id: str,
      ) -> CatalogPreflightResult: ...
  ```

  Define the frozen `CatalogObservation` contract in `contracts.py` before importing it into the new module:

  ```python
  class CatalogObservation(ContractModel):
      provider: str
      endpoint_identity: str
      credential_scope_hash: Sha256
      fetched_at: datetime
      expires_at: datetime
      model_set_hash: Sha256
      profile_bundle_hash: Sha256
      response_evidence_hash: Sha256

      @property
      def content_hash(self) -> str:
          return hash_json(self.model_dump(mode="json", round_trip=True))
  ```

  Validate the provider against `SUPPORTED_PROVIDERS`, use fixed safe endpoint identities, require timezone-aware `fetched_at < expires_at`, and reject unsafe identifiers or non-SHA-256 values. Before cache lookup, `LiveCatalogPreflight` must obtain the opaque credential and its `credential_scope_hash()` from the launcher source; that hash is the `CatalogCacheKey` input and the value persisted in `CatalogObservation`, never a provider-supplied value. Freeze all `CatalogPreflightResult` mappings with `MappingProxyType` in `__post_init__`. `LiveCatalogPreflight.resolve()` must derive the distinct selected providers from all roles, demand a credential for `ollama-cloud`, accept only a launcher-supplied optional credential for `opencode-go`, call each provider once per `operation_id`, reject a `CatalogFetch` whose response byte count, evidence hash, or timestamp are invalid, feed untrusted IDs into `ModelCatalog`, resolve every role with `RoleCapabilityMatrix.required_for_role`, and convert every client/parser/profile failure to `CatalogPreflightError("catalog preflight failed")` without chaining an untrusted message.

  Use a private `CatalogCacheKey` containing `operation_id`, provider, endpoint identity, credential scope fingerprint, `runner_identity.content_hash`, and `profiles.profile_bundle_hash`. An entry is eligible only for the same operation and only while `now < expires_at`; an expired entry triggers a live fetch, and any failure on that fetch rejects rather than reading older data. Keep raw response data and opaque credential objects out of result dataclasses, exceptions, reprs, and persistent evidence.

- [ ] **Step 4: Run catalog regressions**

  Run: `.venv/bin/python -m pytest tests/test_model_catalog.py tests/test_models.py tests/test_catalog_preflight.py -q`

  Expected: PASS. The test suite must prove profile hash stability/mutation detection, cache-key isolation, expired-entry rejection, response-size/malformed-ID rejection, secret-free exception text, one fetch per selected provider, and no catalog I/O from `ModelFactory`.

- [ ] **Step 5: Record the task evidence without Git activity**

  Run: `.venv/bin/python -m compileall -q src tests`

  Expected: exit `0`. Do not run Git commands.

### Task 3: Define And Persist Compatibility Receipts

**Files:**
- Modify: `src/auto_code/contracts.py:426-442,2032-2192`
- Create: `src/auto_code/compatibility.py`
- Create: `tests/test_compatibility.py`

**Interfaces:**
- Consumes: `EvidenceRef`, `RunnerIdentity`, `hash_json`, canonical JSON helpers in `auto_code.state`, and `CatalogObservation` from Task 2.
- Produces: `CompatibilityComponentObservation`, `BrowserPreflightStatus`, `CompatibilityReceipt`, `CompatibilityReceiptAuthority`, and `CompatibilityReceiptAuthority.publish/load_verified_receipt`.
- Later tasks rely on: `CompatibilityReceipt.content_hash`, its `EvidenceRef`, and authority-backed reload before Task 3c binds `RunState.compatibility_receipt_hash` and `.compatibility_receipt_ref`.

- [ ] **Step 1: Write failing receipt authority tests**

  Cover canonical write/reload plus every trust-boundary rejection. Assert no untrusted or secret text crosses the public error:

  ```python
  def test_receipt_authority_publishes_once_and_reloads_matching_evidence(tmp_path: Path) -> None:
      authority = CompatibilityReceiptAuthority(tmp_path, "trusted-launcher", runner_identity())
      receipt = compatibility_receipt(authority, receipt_id="123e4567-e89b-12d3-a456-426614174000")

      evidence = authority.publish(receipt)

      assert evidence == EvidenceRef(
          relative_path="trusted-launcher/compatibility/123e4567-e89b-12d3-a456-426614174000.json",
          sha256=receipt.content_hash,
          media_type="application/json",
          creator="trusted-launcher",
      )
      assert authority.load_verified_receipt(evidence) == receipt


  @pytest.mark.parametrize("tamper", ("path", "hash", "launcher", "runner", "shape"))
  def test_receipt_authority_rejects_tampered_evidence_without_leaking_input(tmp_path: Path, tamper: str) -> None:
      authority = CompatibilityReceiptAuthority(tmp_path, "trusted-launcher", runner_identity())
      evidence = authority.publish(compatibility_receipt(authority))
      tamper_receipt_file_or_reference(tmp_path, evidence, tamper, "api_key=secret-value")

      with pytest.raises(CompatibilityReceiptError, match="compatibility receipt is invalid") as error:
          authority.load_verified_receipt(evidence)

      assert "secret-value" not in str(error.value)
  ```

- [ ] **Step 2: Run receipt tests to confirm failure**

  Run: `.venv/bin/python -m pytest tests/test_compatibility.py -q`

  Expected: FAIL because compatibility receipt contracts and their authority do not exist.

- [ ] **Step 3: Add frozen receipt contracts and root-owned authority**

  Add the remaining durable Pydantic contract models beside the `CatalogObservation` added in Task 2. Use `ContractModel` so extra fields are rejected and mapping fields are frozen. The receipt must include all required provenance and make its full canonical JSON hash its runtime identity:

  ```python
  class BrowserPreflightStatus(StrEnum):
      NOT_CONFIGURED = "not_configured"
      VERIFIED = "verified"


  class CompatibilityComponentObservation(ContractModel):
      component: Literal["python", "crewai", "openspec", "node", "ralph", "playwright"]
      expected_constraint: str
      observed_version: str
      verified_identity_hash: Sha256
      evidence_hashes: tuple[Sha256, ...]


  class CompatibilityReceipt(ContractModel):
      schema_version: Literal["v1"] = "v1"
      receipt_id: str
      issued_at: datetime
      launcher_identity: EffectReference
      runner_identity: RunnerIdentity
      runner_content_hash: Sha256
      project_policy_hash: Sha256
      selected_role_models_hash: Sha256
      profile_bundle_hash: Sha256
      catalog_receipt_hashes: Mapping[str, Sha256]
      catalog_observations: tuple[CatalogObservation, ...]
      browser_preflight_status: BrowserPreflightStatus
      component_observations: tuple[CompatibilityComponentObservation, ...]
      relative_path: EvidencePath

      @property
      def content_hash(self) -> str:
          return hash_json(self.model_dump(mode="json", round_trip=True))
  ```

  Validate canonical UUID receipt IDs, timezone-aware issuance timestamps, exactly one observation each for `python`, `crewai`, `openspec`, `node`, and `ralph`, and exactly one `playwright` observation only when `browser_preflight_status == "verified"`; `not_configured` receipts contain no Playwright observation. Also validate sorted/unique catalog providers, content-hash equality between each catalog observation and `catalog_receipt_hashes`, exact `trusted-launcher/compatibility/<uuid>.json` paths, `runner_content_hash == runner_identity.content_hash`, and safe fixed identifiers/observations only.

  In `compatibility.py`, implement the explicit authority API using `_normalize_state_root`, `_ensure_directory`, `_write_new_json`, and `_read_canonical_json`:

  ```python
  class CompatibilityReceiptError(RuntimeError):
      pass


  class CompatibilityReceiptAuthority:
      def __init__(self, state_root: Path, launcher_identity: str, runner_identity: RunnerIdentity) -> None: ...

      def publish(self, receipt: CompatibilityReceipt) -> EvidenceRef: ...

      def load_verified_receipt(self, evidence: EvidenceRef) -> CompatibilityReceipt: ...
  ```

  `publish()` validates the authority's launcher/runner identity and uses a write-once canonical file. On an existing path, reload it and return the same reference only if it is byte-for-byte/contract-equivalent; otherwise raise `CompatibilityReceiptError("compatibility receipt cannot be published")`. `load_verified_receipt()` accepts only `EvidenceRef(creator="trusted-launcher", media_type="application/json")`, validates path shape, canonical JSON, receipt path/hash/UUID/launcher/runner equality, and raises only `CompatibilityReceiptError("compatibility receipt is invalid")` on every failure.

- [ ] **Step 4: Run receipt authority regressions**

  Run: `.venv/bin/python -m pytest tests/test_compatibility.py -q`

  Expected: PASS for canonical write/load, idempotent same-content publication, conflicting publication rejection, path/hash/identity/shape tampering rejection, and secret-free error/serialization assertions.

- [ ] **Step 5: Record the task evidence without Git activity**

  Run: `.venv/bin/python -m compileall -q src tests`

  Expected: exit `0`. Do not run Git commands.

### Task 4: Verify The Baseline And Compose One Preflight Result

**Files:**
- Modify: `src/auto_code/compatibility.py`
- Modify: `tests/test_compatibility.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_project_config.py`

**Interfaces:**
- Consumes: `TrustedRuntimeConfig`, `ProjectConfig`, `CatalogPreflightPolicy`, `LiveCatalogPreflight`, `CatalogPreflightResult`, `CompatibilityReceiptAuthority`, `RoleModelConfig.models`, and `ModelCompatibilityRegistry.profile_bundle_hash`.
- Produces: `CompatibilityRuntime`, `RunnerPackageManifest`, `PreflightVersionVerifier.verify(runtime_config, role_config) -> CompatibilityPreflightResult`, and `load_descriptor_bound_policy(runtime_config)`.
- Later tasks rely on: `CompatibilityPreflightResult.receipt`, `.receipt_ref`, `.catalogs`, and `.resolved_models`; Task 3c must consume these values rather than accepting a receipt from CLI input or recomputing one.

- [ ] **Step 1: Write failing runtime baseline and failure-order tests**

  Build one fake launcher runtime from fixed trusted probes. It must count probes, catalog calls, receipt publications, and prohibited external-effect calls. Parametrize component mismatch coverage and verify no publication after every rejection:

  ```python
  @pytest.mark.parametrize(
      ("mutate", "expected_component"),
      [
          (lambda harness: harness.interpreter.set_version("3.11.9"), "python"),
          (lambda harness: harness.interpreter.set_distribution("crewai", "1.15.19"), "crewai"),
          (lambda harness: harness.tools.set_version("openspec", "1.11.0"), "openspec"),
          (lambda harness: harness.tools.set_version("node", "v20.19.0-rc.1"), "node"),
          (lambda harness: harness.manifest.set_ralph_version("1.0.9"), "ralph"),
      ],
  )
  def test_baseline_mismatch_rejects_before_catalog_or_receipt(mutate: Callable[[Harness], None], expected_component: str) -> None:
      harness = valid_harness(browser_configured=False)
      mutate(harness)

      with pytest.raises(CompatibilityPreflightError, match="compatibility baseline is invalid"):
          harness.verifier.verify(harness.runtime_config, harness.role_config)

      assert harness.catalog_client.calls == 0
      assert harness.receipt_authority.publish_calls == 0
      assert harness.prohibited_effects.calls == []


  def test_policy_drift_rejects_before_any_runtime_probe(tmp_path: Path) -> None:
      harness = valid_harness(project_root=tmp_path)
      harness.change_policy_after_descriptor_hash()

      with pytest.raises(CompatibilityPreflightError, match="compatibility policy is invalid"):
          harness.verifier.verify(harness.runtime_config, harness.role_config)

      assert harness.interpreter.calls == 0
      assert harness.catalog_client.calls == 0
  ```

  Add success tests that verify receipt fields, `receipt.content_hash == receipt_ref.sha256`, all selected role metadata, browser `not_configured` only for the absent/absent pair, and configured-browser failures for each exact Playwright package mismatch.

  Add a second explicit manifest parameterization so source/dependency/content/contract provenance cannot regress behind a valid version banner:

  ```python
  @pytest.mark.parametrize(
      "mutate_manifest",
      (
          lambda manifest: setattr(manifest, "openspec_schema_name", "other-schema"),
          lambda manifest: manifest.set_ralph_upstream("other-ralph", "1.0.10"),
          lambda manifest: manifest.set_identity_field("source_sha", "1" * 64),
          lambda manifest: manifest.set_identity_field("dependency_lock_hash", "2" * 64),
          lambda manifest: manifest.set_identity_field("content_hash", "3" * 64),
          lambda manifest: manifest.set_identity_field("contract_bundle_hash", "4" * 64),
          lambda manifest: manifest.set_package("@playwright/cli", "0.1.18"),
          lambda manifest: manifest.set_package("playwright", "1.63.0-alpha-2026-08-30"),
          lambda manifest: manifest.set_package("playwright-core", "1.63.0-alpha-2026-08-30"),
      ),
  )
  def test_runner_manifest_mismatch_never_publishes_a_receipt(mutate_manifest: Callable[[FakeManifest], None]) -> None:
      harness = valid_harness(browser_configured=True)
      mutate_manifest(harness.manifest)

      with pytest.raises(CompatibilityPreflightError, match="compatibility baseline is invalid"):
          harness.verifier.verify(harness.runtime_config, harness.role_config)

      assert harness.receipt_authority.publish_calls == 0
  ```

- [ ] **Step 2: Run the compatibility test module and confirm failure**

  Run: `.venv/bin/python -m pytest tests/test_compatibility.py -q`

  Expected: FAIL because `CompatibilityRuntime`, `RunnerPackageManifest`, bound-policy loading, and `PreflightVersionVerifier` do not exist.

- [ ] **Step 3: Implement capability-only verification and final receipt composition**

  Define these capability-oriented interfaces in `compatibility.py`; do not expose executable paths, credentials, raw command output, or provider endpoints in the descriptor or `ProjectConfig`:

  ```python
  class TrustedInterpreterProbe(Protocol):
      def python_observation(self) -> TrustedVersionObservation: ...
      def distribution_observation(self, distribution: str) -> TrustedVersionObservation: ...


  class TrustedToolProbe(Protocol):
      def version_observation(
          self,
          component: Literal["openspec", "node", "playwright"],
      ) -> TrustedVersionObservation: ...


  @dataclass(frozen=True)
  class TrustedVersionObservation:
      observed_version: str
      verified_identity_hash: str
      evidence_hashes: tuple[str, ...]


  @dataclass(frozen=True)
  class RunnerPackageManifest:
      runner_identity: RunnerIdentity
      openspec_schema_name: str
      openspec_schema_hash: str
      ralph_upstream_name: str
      ralph_upstream_version: str
      node_package_versions: Mapping[str, str]


  @dataclass(frozen=True)
  class CompatibilityPreflightResult:
      receipt: CompatibilityReceipt
      receipt_ref: EvidenceRef
      catalogs: Mapping[str, ModelCatalog]
      resolved_models: Mapping[RoleName, ModelMetadata]


  class CompatibilityPreflightError(RuntimeError):
      pass


  class PreflightVersionVerifier:
      def __init__(self, runtime: CompatibilityRuntime) -> None: ...

      def verify(
          self,
          runtime_config: TrustedRuntimeConfig,
          role_config: RoleModelConfig,
      ) -> CompatibilityPreflightResult: ...


  def load_descriptor_bound_policy(runtime_config: TrustedRuntimeConfig) -> ProjectConfig: ...


  def verify_python_crewai_openspec_node_and_ralph(
      runtime: CompatibilityRuntime,
      descriptor_runner_identity: RunnerIdentity,
      policy: ProjectConfig,
  ) -> tuple[CompatibilityComponentObservation, ...]: ...


  def verify_browser_if_configured(
      runtime: CompatibilityRuntime,
      browser_policy: BrowserPolicy,
  ) -> tuple[BrowserPreflightStatus, tuple[CompatibilityComponentObservation, ...]]: ...


  def build_compatibility_receipt(
      runtime: CompatibilityRuntime,
      runtime_config: TrustedRuntimeConfig,
      role_models: Mapping[RoleName, ModelRef],
      catalog_result: CatalogPreflightResult,
      observations: tuple[CompatibilityComponentObservation, ...],
      browser_status: BrowserPreflightStatus,
  ) -> CompatibilityReceipt: ...


  @dataclass(frozen=True)
  class CompatibilityRuntime:
      launcher_identity: str
      interpreter: TrustedInterpreterProbe
      tools: TrustedToolProbe
      runner_manifest: RunnerPackageManifest
      catalog_preflight: LiveCatalogPreflight
      receipt_authority: CompatibilityReceiptAuthority
      now: Callable[[], datetime]
      new_operation_id: Callable[[], str]
  ```

  `TrustedVersionObservation` contains only a safe observed version, a verified identity hash, and non-secret evidence hashes. `RunnerPackageManifest` must require `openspec_schema_name == "spec-driven"`, `ralph_upstream_name == "opencode-ralph-loop"`, a `runner_identity` equal to the descriptor's identity, and a frozen package-version mapping. The launcher implementation of `TrustedToolProbe` must use `ProcessRunner.run_with_trusted_output()` with hash-verified absolute executables and parse only the private trusted output; it must never use `PATH`, `npx`, a dynamic install, a mutable tag, or target-repository package data. The verifier only consumes the injected probe, so deterministic tests use fakes without subprocesses.

  Implement `load_descriptor_bound_policy()` to recheck containment, call `ProjectConfig.load(runtime_config.project_policy_path)`, and compare canonical hashes with `hmac.compare_digest`; convert every failure to `CompatibilityPreflightError("compatibility policy is invalid")` before any probe. `PreflightVersionVerifier.verify()` must then perform this exact ordering:

  ```python
  policy = load_descriptor_bound_policy(runtime_config)
  observations = verify_python_crewai_openspec_node_and_ralph(runtime, runtime_config.runner_identity, policy)
  browser_status, browser_observations = verify_browser_if_configured(runtime, policy.browser)
  catalog_result = runtime.catalog_preflight.resolve(
      role_config.models,
      policy.preflight,
      operation_id=runtime.new_operation_id(),
  )
  receipt = build_compatibility_receipt(
      runtime,
      runtime_config,
      role_config.models,
      catalog_result,
      (*observations, *browser_observations),
      browser_status,
  )
  receipt_ref = runtime.receipt_authority.publish(receipt)
  return CompatibilityPreflightResult(receipt, receipt_ref, catalog_result.catalogs, catalog_result.resolved_models)
  ```

  Build `selected_role_models_hash` with `hash_json({role.value: f"{ref.provider}/{ref.model_id}" for role, ref in sorted(role_config.models.items(), key=lambda item: item[0].value)})`. Require Python major/minor `3.12`, exact CrewAI/OpenSpec versions, final SemVer Node `>=20.19.0`, exact manifest schema/Ralph upstream/version and matching runner content/source/dependency/contract hashes. Treat browser as `not_configured` only for the absent/absent pair; otherwise require `TrustedToolProbe.version_observation("playwright").observed_version == "0.1.19"` and the exact three Playwright package versions in the injected runner manifest. Convert catalog failures to `CompatibilityPreflightError("compatibility catalog is invalid")`, baseline failures to `CompatibilityPreflightError("compatibility baseline is invalid")`, and authority failures to `CompatibilityPreflightError("compatibility receipt is invalid")`, always with `from None`.

- [ ] **Step 4: Run the complete compatibility/config/catalog regressions**

  Run: `.venv/bin/python -m pytest tests/test_cli.py tests/test_project_config.py tests/test_model_catalog.py tests/test_catalog_preflight.py tests/test_compatibility.py -q`

  Expected: PASS. Verify success composition, every baseline/package mismatch, browser conditionality, descriptor policy drift/containment, catalog failure ordering, no partial receipt, and unchanged injected-only `ModelFactory` behavior.

- [ ] **Step 5: Record the task evidence without Git activity**

  Run: `.venv/bin/python -m compileall -q src tests`

  Expected: exit `0`. Do not run Git commands.

### Task 5: Add Opt-In Provider Smoke Coverage And Final Verification

**Files:**
- Modify: `pyproject.toml:29-31`
- Create: `tests/conftest.py`
- Create: `tests/test_provider_smoke.py`

**Interfaces:**
- Consumes: `PreflightVersionVerifier`, `CompatibilityRuntime`, `RoleModelConfig`, and the launcher-owned `LiveCatalogPreflight` capability from Task 4.
- Produces: the registered `provider_smoke` marker, a `--provider-smoke` opt-in gate, and evidence that default tests remain offline.

- [ ] **Step 1: Write failing marker and harness-gate tests**

  Add one ordinary loader-contract test so the focused module has a passing default test, and a marked test that must never import or call an external harness during a default run. The opt-in test receives its harness through an explicit import path rather than credentials in policy or source:

  ```python
  class ProviderSmokeHarness(Protocol):
      verifier: PreflightVersionVerifier
      runtime_config: TrustedRuntimeConfig
      role_config: RoleModelConfig


  def load_launcher_smoke_harness() -> ProviderSmokeHarness: ...


  @pytest.mark.provider_smoke
  def test_launcher_composed_provider_smoke_contract() -> None:
      harness = load_launcher_smoke_harness()
      result = harness.verifier.verify(harness.runtime_config, harness.role_config)

      assert result.receipt_ref.sha256 == result.receipt.content_hash
      assert set(result.catalogs) == {ref.provider for ref in harness.role_config.models.values()}
      assert set(result.resolved_models) == set(RoleName)


  def test_launcher_smoke_loader_validates_a_fake_harness(monkeypatch: pytest.MonkeyPatch) -> None:
      fake = types.SimpleNamespace(
          build_provider_smoke_harness=lambda: types.SimpleNamespace(
              verifier=object(), runtime_config=object(), role_config=object()
          )
      )
      monkeypatch.setenv("AUTO_CODE_PROVIDER_SMOKE_HARNESS", "fake_launcher_harness")
      monkeypatch.setattr(importlib, "import_module", lambda _: fake)

      assert load_launcher_smoke_harness().verifier is not None
  ```

  In the default-test regression, invoke pytest for this module without `--provider-smoke` through a subprocess and assert the harness's sentinel file is not created. The ordinary loader test uses a fake module only to validate shape; no test asserts a static live model list.

- [ ] **Step 2: Run the smoke configuration tests and confirm failure**

  Run: `.venv/bin/python -m pytest tests/test_provider_smoke.py -q`

  Expected: FAIL because the marker, `--provider-smoke` option, and launcher-harness loader do not exist.

- [ ] **Step 3: Register and gate the smoke suite without making default pytest networked**

  Register the marker in `pyproject.toml`:

  ```toml
  [tool.pytest.ini_options]
  testpaths = ["tests"]
  pythonpath = ["src"]
  markers = [
      "provider_smoke: opt-in live provider catalog contract test; requires --provider-smoke and a launcher harness",
  ]
  ```

  In `tests/conftest.py`, add `--provider-smoke` and deselect marked items unless it is present:

  ```python
  def pytest_addoption(parser: pytest.Parser) -> None:
      parser.addoption("--provider-smoke", action="store_true", default=False)


  def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
      if config.getoption("--provider-smoke"):
          return
      items[:] = [item for item in items if "provider_smoke" not in item.keywords]
  ```

  Implement `load_launcher_smoke_harness()` in the test module only. It reads the non-secret `AUTO_CODE_PROVIDER_SMOKE_HARNESS` module path, imports `build_provider_smoke_harness()`, validates the returned object exposes `verifier`, `runtime_config`, and `role_config`, and otherwise skips with a fixed message. The externally supplied harness owns all provider endpoints and credentials; no production module, Project Policy, descriptor, run state, or test output may contain them.

- [ ] **Step 4: Run default, opt-in fake, and full regressions**

  Run: `.venv/bin/python -m pytest tests/test_provider_smoke.py -q`

  Expected: PASS with the live-marked test deselected and no network/harness import.

  Run: `.venv/bin/python -m pytest --provider-smoke -m provider_smoke tests/test_provider_smoke.py -q`

  Expected: SKIP with the fixed missing-harness message unless `AUTO_CODE_PROVIDER_SMOKE_HARNESS` is supplied. A real launcher smoke run uses the same command with that non-secret module path set by the launcher and must PASS without asserting a static catalog.

  Run: `.venv/bin/python -m pytest -q`

  Expected: PASS with all deterministic offline tests and no provider catalog network request.

- [ ] **Step 5: Run final static verification and record results**

  Run: `.venv/bin/python -m compileall -q src tests`

  Expected: exit `0`. Record focused/full/compile outputs in the Task 3b SDD evidence workspace, request independent review of the Task 3b diff and evidence, and do not run Git commands.

## Final Verification Checklist

- [ ] `.venv/bin/python -m pytest tests/test_cli.py tests/test_project_config.py tests/test_model_catalog.py tests/test_catalog_preflight.py tests/test_compatibility.py -q`
- [ ] `.venv/bin/python -m pytest tests/test_provider_smoke.py -q`
- [ ] `.venv/bin/python -m pytest -q`
- [ ] `.venv/bin/python -m compileall -q src tests`
- [ ] Confirm no provider smoke harness/network call occurs in default pytest.
- [ ] Confirm every failed preflight path leaves no compatibility receipt, Active Run, state generation, MCP/Linear request, Git invocation, or browser activity.
- [ ] Confirm all persisted compatibility/catalog data is canonical, secret-free, root-owned, and reloadable only through `CompatibilityReceiptAuthority`.
