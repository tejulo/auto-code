from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
from threading import Barrier, BrokenBarrierError, Event, Thread
from typing import Sequence

import pytest

import auto_code.openspec as openspec_module
from auto_code.openspec import (
    ArtifactDependencyError,
    ChangeOwnershipError,
    CheckpointMismatch,
    OpenSpecInputError,
    OpenSpecError,
    OpenSpecSchemaError,
    OpenSpecClient,
    StagedArtifactManifest,
    TaskDefinitionChanged,
    UnknownTaskId,
    _parse_trusted_json,
)
from auto_code.contracts import (
    ArtifactEnvelope,
    ArtifactFile,
    Checkpoint,
    TaskStatus,
    TaskStatusManifest,
    Stage,
    UnitStatus,
)
from auto_code.checkpoint import CheckpointAuthority
from auto_code.process import CommandExecution, CommandResult, TrustedCommandOutput


class RecordingProcessRunner:
    """Fake process boundary; it never starts a process."""

    def __init__(self) -> None:
        self.argvs: list[tuple[str, ...]] = []
        self.validation_cwds: list[Path] = []
        self.validation_trees: list[dict[str, str]] = []
        self.changes: set[str] = set()
        self.new_change_output: object = {
            "schema": "spec-driven",
            "change_id": "fabricated-change",
            "ticket_id": "ENG-99",
            "run_id": "foreign-run",
        }
        self.instructions_output: object = {
            "schema": "spec-driven",
            "change_id": "eng-1-change",
            "artifact": "proposal",
            "instructions": "Write the proposal.",
            "output_paths": ["proposal.md"],
            "requires": [],
        }
        self.instructions_outputs: dict[str, object] = {}
        self.validation_output: object = {
            "schema": "spec-driven",
            "change_id": "eng-1-change",
            "artifact": "proposal",
            "valid": True,
        }

    def run_with_trusted_output(
        self,
        argv: Sequence[str],
        cwd: Path,
        timeout: float,
        evidence_sink: object,
        environment: object,
        sandbox_policy: object,
        *,
        suppress_public_output: bool = False,
    ) -> CommandExecution:
        command = tuple(argv)
        self.argvs.append(command)
        if command[1:3] == ("new", "change"):
            change_id = command[3]
            if change_id in self.changes:
                return self._execution(command, {"error": "change exists"}, returncode=1)
            self.changes.add(change_id)
            body: object = self.new_change_output
        elif command[1] == "show":
            body = {"schema": "spec-driven", "change_id": command[2]}
        elif command[1] == "instructions":
            body = self.instructions_outputs.get(command[2], self.instructions_output)
        elif command[1] == "validate":
            self.validation_cwds.append(cwd)
            self.validation_trees.append(
                {
                    path.relative_to(cwd).as_posix(): path.read_text(encoding="utf-8")
                    for path in cwd.glob("openspec/changes/**/*.md")
                }
            )
            body = self.validation_output
        else:
            body = self.instructions_output
        return self._execution(command, body)

    @staticmethod
    def _execution(command: tuple[str, ...], body: object, *, returncode: int = 0) -> CommandExecution:
        if isinstance(body, bytes):
            raw = body
        elif isinstance(body, str):
            raw = body.encode("utf-8")
        else:
            raw = json.dumps(body).encode("utf-8")
        result = CommandResult(
            argv=command,
            returncode=returncode,
            stdout_text="[REDACTED]",
            stderr_text="",
            stdout_path=None,
            stderr_path=None,
            redacted=True,
        )
        return CommandExecution(
            result=result,
            output=TrustedCommandOutput(
                stdout_sha256=sha256(raw).hexdigest(),
                stderr_sha256=sha256(b"").hexdigest(),
                _stdout=raw,
                _stderr=b"",
            ),
        )


@pytest.fixture
def process() -> RecordingProcessRunner:
    return RecordingProcessRunner()


@pytest.fixture
def checkpoint_authority(tmp_path: Path) -> CheckpointAuthority:
    return CheckpointAuthority(tmp_path / "checkpoint-authority-root")


@pytest.fixture
def client(
    tmp_path: Path,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
) -> OpenSpecClient:
    return OpenSpecClient(
        root=tmp_path,
        process_runner=process,  # type: ignore[arg-type]
        openspec_executable="/trusted/bin/openspec",
        timeout=5,
        evidence_sink=object(),
        environment={},
        sandbox_policy=object(),
        checkpoint_authority=checkpoint_authority,
    )


def artifact_envelope(artifact: str, *files: tuple[str, str]) -> ArtifactEnvelope:
    return ArtifactEnvelope(
        artifact_id=artifact,
        files=tuple(
            ArtifactFile(relative_path=path, content=content, sha256=sha256(content.encode("utf-8")).hexdigest())
            for path, content in files
        ),
    )


def matching_checkpoint(
    authority: CheckpointAuthority,
    staged: object,
    receipt: object,
) -> Checkpoint:
    return authority.issue(
        stage={
            "proposal": Stage.ARCHITECT_PROPOSAL,
            "specs": Stage.ARCHITECT_SPECS,
            "design": Stage.ARCHITECT_DESIGN,
            "tasks": Stage.ARCHITECT_TASKS,
        }[staged.artifact],  # type: ignore[union-attr]
        contract_hash=staged.contract_hash,  # type: ignore[union-attr]
        input_hashes=dict(staged.input_hashes),  # type: ignore[union-attr]
        output_manifest_hash=staged.output_manifest_hash,  # type: ignore[union-attr]
        validator="openspec",
        validator_version="1.12.0",
        validation_receipt_hash=receipt.receipt_hash,  # type: ignore[union-attr]
    )


def publish(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
    staged: StagedArtifactManifest,
) -> None:
    process.validation_output = {
        "schema": "spec-driven",
        "change_id": staged.change_id,
        "artifact": staged.artifact,
        "valid": True,
    }
    receipt = client.validate_artifact(staged)
    client.publish_artifact(staged, matching_checkpoint(checkpoint_authority, staged, receipt))


def configure_full_change_instructions(process: RecordingProcessRunner) -> None:
    process.instructions_outputs = {
        "specs": {
            "schema": "spec-driven",
            "change_id": "eng-1-change",
            "artifact": "specs",
            "instructions": "Write the specs.",
            "output_paths": ["specs/api.md"],
            "requires": ["proposal"],
        },
        "design": {
            "schema": "spec-driven",
            "change_id": "eng-1-change",
            "artifact": "design",
            "instructions": "Write the design.",
            "output_paths": ["design.md"],
            "requires": ["proposal"],
        },
        "tasks": {
            "schema": "spec-driven",
            "change_id": "eng-1-change",
            "artifact": "tasks",
            "instructions": "Write the tasks.",
            "output_paths": ["tasks.md"],
            "requires": ["specs", "design"],
        },
    }


def publish_task_prerequisites(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    configure_full_change_instructions(process)
    proposal = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# Proposal\n")))
    publish(client, process, checkpoint_authority, proposal)
    specs = client.stage_artifact("eng-1-change", artifact_envelope("specs", ("specs/api.md", "# API\n")))
    publish(client, process, checkpoint_authority, specs)
    design = client.stage_artifact("eng-1-change", artifact_envelope("design", ("design.md", "# Design\n")))
    publish(client, process, checkpoint_authority, design)


@pytest.fixture
def tasks_envelope() -> ArtifactEnvelope:
    return artifact_envelope("tasks", ("tasks.md", "# Tasks\n"))


def test_tasks_require_published_specs_and_design(client: OpenSpecClient, tasks_envelope: ArtifactEnvelope) -> None:
    """Fails if tasks can stage without both published prerequisite artifacts."""
    with pytest.raises(OpenSpecError):
        client.stage_artifact("eng-1-change", tasks_envelope)


def test_stage_writes_an_immutable_proposal_without_making_it_visible(
    client: OpenSpecClient,
) -> None:
    """Fails if staging publishes output or produces a different version for the same envelope."""
    envelope = artifact_envelope("proposal", ("proposal.md", "# Proposal\n"))

    staged = client.stage_artifact("eng-1-change", envelope)

    assert staged.envelope == envelope
    assert client.visible_path(staged) is None
    assert client.stage_artifact("eng-1-change", envelope) == staged


def test_publish_requires_a_checkpoint_bound_to_the_staged_validation_receipt(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if a field-matched but unissued checkpoint can publish an artifact."""
    staged = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# Proposal\n")))
    receipt = client.validate_artifact(staged)
    forged_checkpoint = Checkpoint(
        stage=Stage.ARCHITECT_PROPOSAL,
        contract_hash=staged.contract_hash,
        input_hashes={},
        output_manifest_hash=staged.output_manifest_hash,
        validator="openspec",
        validator_version="1.12.0",
        validation_receipt_hash=receipt.receipt_hash,
    )
    genuine_checkpoint = matching_checkpoint(checkpoint_authority, staged, receipt)
    other_checkpoint = forged_checkpoint.model_copy(update={"output_manifest_hash": "0" * 64})
    other_receipt_checkpoint = forged_checkpoint.model_copy(update={"validation_receipt_hash": "0" * 64})

    with pytest.raises(CheckpointMismatch):
        client.publish_artifact(staged, other_checkpoint)
    with pytest.raises(CheckpointMismatch):
        client.publish_artifact(staged, other_receipt_checkpoint)
    with pytest.raises(CheckpointMismatch):
        client.publish_artifact(staged, forged_checkpoint)

    assert client.visible_path(staged) is None
    published = client.publish_artifact(staged, genuine_checkpoint)
    visible = client.visible_path(staged)
    assert visible is not None
    assert published == (visible / "proposal.md",)
    assert (visible / "proposal.md").read_text(encoding="utf-8") == "# Proposal\n"
    assert ("/trusted/bin/openspec", "validate", "--change", "eng-1-change", "--json") in process.argvs


def test_validator_observes_the_exact_complete_staged_change_tree(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
) -> None:
    """Fails if validation runs outside the private immutable change tree it attests."""
    process.instructions_output = {
        "schema": "spec-driven",
        "change_id": "eng-1-change",
        "artifact": "proposal",
        "instructions": "Write the proposal.",
        "output_paths": ["proposal.md", "notes.md"],
        "requires": [],
    }
    staged = client.stage_artifact(
        "eng-1-change",
        artifact_envelope("proposal", ("proposal.md", "# First\n"), ("notes.md", "# First notes\n")),
    )

    client.validate_artifact(staged)

    expected_tree = client.root / ".auto-code-openspec" / "versions" / "eng-1-change" / staged.output_manifest_hash / "tree"
    assert process.validation_cwds == [expected_tree]
    assert process.validation_trees == [
        {
            "openspec/changes/eng-1-change/notes.md": "# First notes\n",
            "openspec/changes/eng-1-change/proposal.md": "# First\n",
        }
    ]


def test_publish_replay_is_idempotent(
    client: OpenSpecClient,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if replaying an approved publication changes its visible artifact."""
    staged = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# Proposal\n")))
    receipt = client.validate_artifact(staged)
    checkpoint = matching_checkpoint(checkpoint_authority, staged, receipt)

    first = client.publish_artifact(staged, checkpoint)
    second = client.publish_artifact(staged, checkpoint)

    assert second == first
    assert first[0].read_text(encoding="utf-8") == "# Proposal\n"


def test_publish_rejects_stale_published_prerequisite_hashes(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if publication accepts a version staged against an old prerequisite pointer."""
    process.instructions_outputs = {
        "specs": {
            "schema": "spec-driven",
            "change_id": "eng-1-change",
            "artifact": "specs",
            "instructions": "Write the specs.",
            "output_paths": ["specs/api.md"],
            "requires": ["proposal"],
        }
    }
    first_proposal = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# First\n")))
    first_receipt = client.validate_artifact(first_proposal)
    client.publish_artifact(first_proposal, matching_checkpoint(checkpoint_authority, first_proposal, first_receipt))
    specs = client.stage_artifact("eng-1-change", artifact_envelope("specs", ("specs/api.md", "# API\n")))
    process.validation_output = {
        "schema": "spec-driven",
        "change_id": "eng-1-change",
        "artifact": "specs",
        "valid": True,
    }
    specs_receipt = client.validate_artifact(specs)
    second_proposal = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# Second\n")))
    process.validation_output = {
        "schema": "spec-driven",
        "change_id": "eng-1-change",
        "artifact": "proposal",
        "valid": True,
    }
    second_receipt = client.validate_artifact(second_proposal)
    client.publish_artifact(second_proposal, matching_checkpoint(checkpoint_authority, second_proposal, second_receipt))

    with pytest.raises(ArtifactDependencyError):
        client.publish_artifact(specs, matching_checkpoint(checkpoint_authority, specs, specs_receipt))


def test_publish_replay_cannot_move_a_newer_pointer_to_an_older_version(
    client: OpenSpecClient,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if replaying an old checkpoint can regress the visible change tree."""
    first = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# First\n")))
    first_receipt = client.validate_artifact(first)
    client.publish_artifact(first, matching_checkpoint(checkpoint_authority, first, first_receipt))
    second = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# Second\n")))
    second_receipt = client.validate_artifact(second)
    client.publish_artifact(second, matching_checkpoint(checkpoint_authority, second, second_receipt))

    with pytest.raises(CheckpointMismatch):
        client.publish_artifact(first, matching_checkpoint(checkpoint_authority, first, first_receipt))

    visible = client.visible_path(second)
    assert visible is not None
    assert (visible / "proposal.md").read_text(encoding="utf-8") == "# Second\n"


def test_interrupted_hashed_revision_remains_unpointed_and_invisible(
    client: OpenSpecClient,
    monkeypatch: pytest.MonkeyPatch,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if an interrupted real revision becomes visible without its current pointer."""
    staged = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# Proposal\n")))
    receipt = client.validate_artifact(staged)

    monkeypatch.setattr(
        openspec_module,
        "_atomic_replace_json",
        lambda path, payload: (_ for _ in ()).throw(OSError("injected pointer failure")),
    )

    with pytest.raises(OpenSpecError):
        client.publish_artifact(staged, matching_checkpoint(checkpoint_authority, staged, receipt))

    revisions = client.root / ".auto-code-openspec" / "revisions" / "eng-1-change"
    assert any(len(path.name) == 64 for path in revisions.iterdir())
    assert not client._current_pointer_path("eng-1-change").exists()
    assert client.visible_path(staged) is None


def test_publish_syncs_revision_parent_before_replacing_current_pointer(
    client: OpenSpecClient,
    monkeypatch: pytest.MonkeyPatch,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if the revision-root directory entry can remain volatile at pointer publication."""
    staged = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# Proposal\n")))
    receipt = client.validate_artifact(staged)
    events: list[tuple[str, Path | None]] = []
    original_fsync = openspec_module._fsync_directory_fd
    original_replace = openspec_module._atomic_replace_json
    revision_parent = client.root / ".auto-code-openspec" / "revisions" / "eng-1-change"

    def record_fsync(descriptor: int) -> None:
        events.append(("fsync", Path(os.readlink(f"/proc/self/fd/{descriptor}"))))
        original_fsync(descriptor)

    def record_pointer_replacement(path: Path, payload: object) -> None:
        events.append(("replace", path))
        original_replace(path, payload)

    monkeypatch.setattr(openspec_module, "_fsync_directory_fd", record_fsync)
    monkeypatch.setattr(openspec_module, "_atomic_replace_json", record_pointer_replacement)

    client.publish_artifact(staged, matching_checkpoint(checkpoint_authority, staged, receipt))

    parent_fsync = next(index for index, event in enumerate(events) if event == ("fsync", revision_parent))
    pointer_replacement = next(
        index
        for index, event in enumerate(events)
        if event == ("replace", client._current_pointer_path("eng-1-change"))
    )
    assert parent_fsync < pointer_replacement


def test_atomic_pointer_transition_retains_only_complete_old_or_new_tree(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    monkeypatch: pytest.MonkeyPatch,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if a failed pointer advance can expose a private or partially assembled tree."""
    process.instructions_output = {
        "schema": "spec-driven",
        "change_id": "eng-1-change",
        "artifact": "proposal",
        "instructions": "Write the proposal.",
        "output_paths": ["proposal.md", "notes.md"],
        "requires": [],
    }
    first = client.stage_artifact(
        "eng-1-change",
        artifact_envelope("proposal", ("proposal.md", "# First\n"), ("notes.md", "# First notes\n")),
    )
    first_receipt = client.validate_artifact(first)
    client.publish_artifact(first, matching_checkpoint(checkpoint_authority, first, first_receipt))
    first_visible = client.visible_path(first)
    assert first_visible is not None
    second = client.stage_artifact(
        "eng-1-change",
        artifact_envelope("proposal", ("proposal.md", "# Second\n"), ("notes.md", "# Second notes\n")),
    )
    assert (
        client.root / ".auto-code-openspec" / "versions" / "eng-1-change" / second.output_manifest_hash / "tree"
    ).is_dir()
    second_receipt = client.validate_artifact(second)
    original_replace = openspec_module._atomic_replace_json

    def fail_pointer_advance(path: Path, payload: object) -> None:
        raise OSError("injected pointer failure")

    monkeypatch.setattr(openspec_module, "_atomic_replace_json", fail_pointer_advance)

    with pytest.raises(OpenSpecError):
        client.publish_artifact(second, matching_checkpoint(checkpoint_authority, second, second_receipt))

    assert client.visible_path(second) == first_visible
    assert (first_visible / "proposal.md").read_text(encoding="utf-8") == "# First\n"
    assert (first_visible / "notes.md").read_text(encoding="utf-8") == "# First notes\n"
    monkeypatch.setattr(openspec_module, "_atomic_replace_json", original_replace)
    client.publish_artifact(second, matching_checkpoint(checkpoint_authority, second, second_receipt))
    second_visible = client.visible_path(second)

    assert second_visible is not None
    assert (second_visible / "proposal.md").read_text(encoding="utf-8") == "# Second\n"
    assert (second_visible / "notes.md").read_text(encoding="utf-8") == "# Second notes\n"


def test_publish_rejects_prerequisite_replacement_that_stales_published_successors(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if proposal B can leave published specs bound to proposal A visible."""
    process.instructions_outputs = {
        "specs": {
            "schema": "spec-driven",
            "change_id": "eng-1-change",
            "artifact": "specs",
            "instructions": "Write the specs.",
            "output_paths": ["specs/api.md"],
            "requires": ["proposal"],
        }
    }
    proposal_a = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# A\n")))
    proposal_a_receipt = client.validate_artifact(proposal_a)
    client.publish_artifact(proposal_a, matching_checkpoint(checkpoint_authority, proposal_a, proposal_a_receipt))
    specs_a = client.stage_artifact("eng-1-change", artifact_envelope("specs", ("specs/api.md", "# API\n")))
    process.validation_output = {
        "schema": "spec-driven",
        "change_id": "eng-1-change",
        "artifact": "specs",
        "valid": True,
    }
    specs_a_receipt = client.validate_artifact(specs_a)
    client.publish_artifact(specs_a, matching_checkpoint(checkpoint_authority, specs_a, specs_a_receipt))
    proposal_b = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# B\n")))
    process.validation_output = {
        "schema": "spec-driven",
        "change_id": "eng-1-change",
        "artifact": "proposal",
        "valid": True,
    }
    proposal_b_receipt = client.validate_artifact(proposal_b)
    current_path = client._current_pointer_path("eng-1-change")
    before = current_path.read_bytes()

    with pytest.raises(ArtifactDependencyError, match="OpenSpec published dependents would become stale"):
        client.publish_artifact(proposal_b, matching_checkpoint(checkpoint_authority, proposal_b, proposal_b_receipt))

    assert current_path.read_bytes() == before


def test_concurrent_descendants_cannot_both_advance_the_visible_pointer(
    client: OpenSpecClient,
    monkeypatch: pytest.MonkeyPatch,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if two siblings staged from one parent can both report publication success."""
    first = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# First\n")))
    first_receipt = client.validate_artifact(first)
    client.publish_artifact(first, matching_checkpoint(checkpoint_authority, first, first_receipt))
    second = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# Second\n")))
    third = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# Third\n")))
    second_receipt = client.validate_artifact(second)
    third_receipt = client.validate_artifact(third)
    original_replace = openspec_module._atomic_replace_json
    barrier = Barrier(2)
    outcomes: list[object] = []

    def delay_pointer_replacement(path: Path, payload: object) -> None:
        try:
            barrier.wait(timeout=0.1)
        except BrokenBarrierError:
            pass
        original_replace(path, payload)

    def publish(staged: object, receipt: object) -> None:
        try:
            outcomes.append(client.publish_artifact(staged, matching_checkpoint(checkpoint_authority, staged, receipt)))
        except Exception as error:
            outcomes.append(error)

    monkeypatch.setattr(openspec_module, "_atomic_replace_json", delay_pointer_replacement)
    second_thread = Thread(target=publish, args=(second, second_receipt))
    third_thread = Thread(target=publish, args=(third, third_receipt))
    second_thread.start()
    third_thread.start()
    second_thread.join(timeout=2)
    third_thread.join(timeout=2)

    assert not second_thread.is_alive()
    assert not third_thread.is_alive()
    assert len([outcome for outcome in outcomes if isinstance(outcome, tuple)]) == 1
    assert len([outcome for outcome in outcomes if isinstance(outcome, CheckpointMismatch)]) == 1


def test_publish_rejects_a_corrupt_visible_pointer(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if publication can replace an unreadable pointer without proving monotonicity."""
    process.instructions_output = {
        "schema": "spec-driven",
        "change_id": "eng-1-change",
        "artifact": "proposal",
        "instructions": "Write the proposal.",
        "output_paths": ["proposal.md", "notes.md"],
        "requires": [],
    }
    staged = client.stage_artifact(
        "eng-1-change",
        artifact_envelope("proposal", ("proposal.md", "# Proposal\n"), ("notes.md", "# Notes\n")),
    )
    receipt = client.validate_artifact(staged)
    publication = client._current_pointer_path("eng-1-change")
    publication.parent.mkdir(parents=True, exist_ok=True)
    publication.write_text("{corrupt", encoding="ascii")

    with pytest.raises(OpenSpecError):
        client.publish_artifact(staged, matching_checkpoint(checkpoint_authority, staged, receipt))


def test_validate_rejects_a_persisted_manifest_with_a_forged_contract_hash(client: OpenSpecClient) -> None:
    """Fails if a forged staged manifest can reach CLI validation with matching caller data."""
    staged = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# Proposal\n")))
    forged_payload = staged.model_dump(mode="json", round_trip=True)
    forged_payload["contract_hash"] = "0" * 64
    manifest_path = client._staged_root(staged) / "manifest.json"
    manifest_path.write_text(json.dumps(forged_payload, sort_keys=True, separators=(",", ":")), encoding="ascii")
    forged = StagedArtifactManifest.model_construct(
        change_id=staged.change_id,
        artifact=staged.artifact,
        envelope=staged.envelope,
        contract_hash="0" * 64,
        input_hashes=staged.input_hashes,
        output_manifest_hash=staged.output_manifest_hash,
        output_paths=staged.output_paths,
    )

    with pytest.raises(OpenSpecError):
        client.validate_artifact(forged)


def test_validate_rejects_a_persisted_manifest_with_a_forged_output_hash(client: OpenSpecClient) -> None:
    """Fails if a self-consistent staged directory can bypass output-manifest hash verification."""
    staged = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# Proposal\n")))
    forged = StagedArtifactManifest.model_construct(
        change_id=staged.change_id,
        artifact=staged.artifact,
        envelope=staged.envelope,
        contract_hash=staged.contract_hash,
        input_hashes=staged.input_hashes,
        output_manifest_hash="0" * 64,
        output_paths=staged.output_paths,
    )
    forged_root = client._staged_root(forged)
    forged_root.mkdir(parents=True)
    (forged_root / "proposal.md").write_text("# Proposal\n", encoding="utf-8")
    (forged_root / "manifest.json").write_text(
        json.dumps(
            {
                **staged.model_dump(mode="json", round_trip=True),
                "output_manifest_hash": "0" * 64,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )

    with pytest.raises(OpenSpecError):
        client.validate_artifact(forged)


def test_dependency_graph_requires_published_artifacts_and_allows_multifile_specs(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if prerequisite staging substitutes for publication or specs are limited to one file."""
    process.instructions_outputs = {
        "specs": {
            "schema": "spec-driven",
            "change_id": "eng-1-change",
            "artifact": "specs",
            "instructions": "Write the specs.",
            "output_paths": ["specs/api/spec.md", "specs/cli/spec.md"],
            "requires": ["proposal"],
        },
        "design": {
            "schema": "spec-driven",
            "change_id": "eng-1-change",
            "artifact": "design",
            "instructions": "Write the design.",
            "output_paths": ["design.md"],
            "requires": ["proposal"],
        },
        "tasks": {
            "schema": "spec-driven",
            "change_id": "eng-1-change",
            "artifact": "tasks",
            "instructions": "Write the tasks.",
            "output_paths": ["tasks.md"],
            "requires": ["specs", "design"],
        },
    }
    specs = artifact_envelope("specs", ("specs/api/spec.md", "# API\n"), ("specs/cli/spec.md", "# CLI\n"))

    with pytest.raises(ArtifactDependencyError):
        client.stage_artifact("eng-1-change", specs)

    proposal = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# Proposal\n")))
    proposal_receipt = client.validate_artifact(proposal)
    client.publish_artifact(
        proposal,
        matching_checkpoint(checkpoint_authority, proposal, proposal_receipt),
    )

    staged_specs = client.stage_artifact("eng-1-change", specs)

    assert staged_specs.output_paths == ("specs/api/spec.md", "specs/cli/spec.md")
    assert dict(staged_specs.input_hashes) == {"proposal": proposal.output_manifest_hash}

    process.validation_output = {
        "schema": "spec-driven",
        "change_id": "eng-1-change",
        "artifact": "specs",
        "valid": True,
    }
    specs_receipt = client.validate_artifact(staged_specs)
    client.publish_artifact(
        staged_specs,
        matching_checkpoint(checkpoint_authority, staged_specs, specs_receipt),
    )
    staged_design = client.stage_artifact("eng-1-change", artifact_envelope("design", ("design.md", "# Design\n")))
    process.validation_output = {
        "schema": "spec-driven",
        "change_id": "eng-1-change",
        "artifact": "design",
        "valid": True,
    }
    design_receipt = client.validate_artifact(staged_design)
    client.publish_artifact(
        staged_design,
        matching_checkpoint(checkpoint_authority, staged_design, design_receipt),
    )

    staged_tasks = client.stage_artifact("eng-1-change", artifact_envelope("tasks", ("tasks.md", "# Tasks\n")))

    assert dict(staged_tasks.input_hashes) == {
        "specs": staged_specs.output_manifest_hash,
        "design": staged_design.output_manifest_hash,
    }


def test_proposal_then_specs_publish_one_complete_current_revision(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if a successor revision omits an already approved artifact."""
    process.instructions_outputs = {
        "specs": {
            "schema": "spec-driven",
            "change_id": "eng-1-change",
            "artifact": "specs",
            "instructions": "Write the specs.",
            "output_paths": ["specs/api.md"],
            "requires": ["proposal"],
        }
    }
    proposal = client.stage_artifact(
        "eng-1-change",
        artifact_envelope("proposal", ("proposal.md", "# Proposal\n")),
    )
    proposal_receipt = client.validate_artifact(proposal)
    client.publish_artifact(proposal, matching_checkpoint(checkpoint_authority, proposal, proposal_receipt))
    specs = client.stage_artifact(
        "eng-1-change",
        artifact_envelope("specs", ("specs/api.md", "# API\n")),
    )
    process.validation_output = {
        "schema": "spec-driven",
        "change_id": "eng-1-change",
        "artifact": "specs",
        "valid": True,
    }
    specs_receipt = client.validate_artifact(specs)
    published = client.publish_artifact(specs, matching_checkpoint(checkpoint_authority, specs, specs_receipt))

    current = json.loads(client._current_pointer_path("eng-1-change").read_text(encoding="utf-8"))
    proposal_root = client.visible_path(proposal)
    specs_root = client.visible_path(specs)

    assert current["revision"] == 2
    assert current["artifacts"] == {
        "proposal": proposal.output_manifest_hash,
        "specs": specs.output_manifest_hash,
    }
    assert proposal_root == specs_root
    assert proposal_root is not None
    assert published == (proposal_root / "specs/api.md",)
    assert (proposal_root / "proposal.md").read_text(encoding="utf-8") == "# Proposal\n"
    assert (specs_root / "specs/api.md").read_text(encoding="utf-8") == "# API\n"
    assert not (client.root / ".auto-code-openspec" / "visible-pointers").exists()


@pytest.mark.parametrize(
    "files",
    (
        (
            ArtifactFile.model_construct(relative_path="../outside.md", content="# Proposal\n", sha256=sha256(b"# Proposal\n").hexdigest()),
        ),
        (
            ArtifactFile.model_construct(relative_path="proposal.md", content="# Proposal\n", sha256=sha256(b"# Proposal\n").hexdigest()),
            ArtifactFile.model_construct(relative_path="proposal.md", content="# Other\n", sha256=sha256(b"# Other\n").hexdigest()),
        ),
        (
            ArtifactFile.model_construct(relative_path="proposal.md", content="# Proposal\n", sha256="0" * 64),
        ),
    ),
)
def test_stage_revalidates_traversal_duplicate_and_mismatched_file_hashes(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    files: tuple[ArtifactFile, ...],
) -> None:
    """Fails if constructed contracts can bypass safe-path or content-integrity checks."""
    envelope = ArtifactEnvelope.model_construct(artifact_id="proposal", files=files)

    with pytest.raises(OpenSpecSchemaError):
        client.stage_artifact("eng-1-change", envelope)

    assert process.argvs == []


def test_client_rejects_a_symlinked_external_adapter_root(
    tmp_path: Path,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if adapter writes can escape through a configured root symlink."""
    external_root = tmp_path / "external"
    external_root.mkdir()
    unsafe_root = tmp_path / "unsafe-root"
    unsafe_root.symlink_to(external_root, target_is_directory=True)

    with pytest.raises(OpenSpecInputError):
        OpenSpecClient(
            root=unsafe_root,
            process_runner=process,  # type: ignore[arg-type]
            openspec_executable="/trusted/bin/openspec",
            timeout=5,
            evidence_sink=object(),
            environment={},
            sandbox_policy=object(),
            checkpoint_authority=checkpoint_authority,
        )


def test_ensure_change_is_idempotent_and_rejects_foreign_collision(
    client: OpenSpecClient, process: RecordingProcessRunner
) -> None:
    """Fails if a fabricated create response can claim an existing change's owner."""
    client.ensure_change("eng-1-change", "ENG-1", "run-1")
    client.ensure_change("eng-1-change", "ENG-1", "run-1")
    client.ensure_change("eng-2-change", "ENG-2", "run-2")

    with pytest.raises(ChangeOwnershipError):
        client.ensure_change("eng-2-change", "ENG-1", "run-1")

    assert ("/trusted/bin/openspec", "show", "eng-1-change", "--type", "change", "--json") in process.argvs


def test_instructions_use_trusted_json_and_never_archive(client: OpenSpecClient, process: RecordingProcessRunner) -> None:
    """Fails if instructions are not JSON-bound or the archive command is introduced."""
    instructions = client.instructions("eng-1-change", "proposal")

    assert instructions.output_paths == ("proposal.md",)
    assert (
        "/trusted/bin/openspec",
        "instructions",
        "proposal",
        "--change",
        "eng-1-change",
        "--json",
    ) in process.argvs
    assert all("archive" not in argv for argv in process.argvs)


def test_rejects_unsafe_change_and_artifact_before_invoking_process(
    client: OpenSpecClient, process: RecordingProcessRunner
) -> None:
    """Fails if unsafe input can become a process argument."""
    with pytest.raises(OpenSpecInputError):
        client.instructions("../foreign-change", "proposal")
    with pytest.raises(OpenSpecInputError):
        client.instructions("eng-1-change", "archive")

    assert process.argvs == []


def test_rejects_malformed_trusted_instruction_json(client: OpenSpecClient, process: RecordingProcessRunner) -> None:
    """Fails if malformed structured output is accepted as an instruction contract."""
    process.instructions_output = "{not-json"

    with pytest.raises(OpenSpecSchemaError):
        client.instructions("eng-1-change", "proposal")


@pytest.mark.parametrize(
    "payload",
    (
        '{"schema":"spec-driven","schema":"other"}',
        "NaN",
        "Infinity",
        "-Infinity",
        "[]",
        '"not-an-object"',
    ),
)
def test_trusted_json_rejects_duplicate_nonfinite_and_nonobject_payloads(payload: str) -> None:
    """Fails if the decoder accepts JSON that cannot be a typed object boundary."""
    with pytest.raises(OpenSpecSchemaError):
        _parse_trusted_json(payload)


def test_instructions_reject_malformed_utf8_before_typed_validation(
    client: OpenSpecClient, process: RecordingProcessRunner
) -> None:
    """Fails if replacement decoding can turn malformed command bytes into an instruction."""
    process.instructions_output = (
        b'{"schema":"spec-driven","change_id":"eng-1-change","artifact":"proposal",'
        b'"instructions":"\xff","output_paths":["proposal.md"],"requires":[]}'
    )

    with pytest.raises(OpenSpecSchemaError):
        client.instructions("eng-1-change", "proposal")


def test_parse_task_definitions_rejects_duplicate_or_textless_checklist_ids(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if a task manifest silently accepts duplicate IDs or blank task text."""
    publish_task_prerequisites(client, process, checkpoint_authority)
    duplicate = client.stage_artifact(
        "eng-1-change",
        artifact_envelope("tasks", ("tasks.md", "# Tasks\n- [ ] 1.1 Implement parsing\n- [x] 1.1 Keep status\n")),
    )
    textless = client.stage_artifact(
        "eng-1-change",
        artifact_envelope("tasks", ("tasks.md", "# Tasks\n- [ ] 1.1\n")),
    )

    with pytest.raises(OpenSpecSchemaError):
        client.parse_task_definitions(duplicate)
    with pytest.raises(OpenSpecSchemaError):
        client.parse_task_definitions(textless)


def test_parse_task_definitions_preserves_explicit_numeric_ids_and_text(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if task extraction drops, renumbers, or rewrites explicit checklist definitions."""
    publish_task_prerequisites(client, process, checkpoint_authority)
    staged = client.stage_artifact(
        "eng-1-change",
        artifact_envelope(
            "tasks",
            ("tasks.md", "# Tasks\nContext only.\n- [ ] 1.1 Parse task definitions\n- [x] 2.3 Preserve checked status\n"),
        ),
    )

    definitions = client.parse_task_definitions(staged)

    assert tuple((task.task_id, task.text) for task in definitions.tasks) == (
        ("1.1", "Parse task definitions"),
        ("2.3", "Preserve checked status"),
    )


def test_initial_task_status_preserves_checked_task_markers(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if parsing task definitions discards the authored checkbox status."""
    publish_task_prerequisites(client, process, checkpoint_authority)
    staged = client.stage_artifact(
        "eng-1-change",
        artifact_envelope("tasks", ("tasks.md", "# Tasks\n- [x] 1.1 Keep completed work\n- [ ] 1.2 Implement new work\n")),
    )
    definitions = client.parse_task_definitions(staged)

    initial = client.parse_initial_task_status(staged, definitions)

    assert initial.definition_hash == definitions.definition_hash
    assert initial.statuses == (
        TaskStatus(task_id="1.1", status=UnitStatus.CHECKED),
        TaskStatus(task_id="1.2", status=UnitStatus.UNCHECKED),
    )


def test_definitions_are_immutable_and_status_is_monotonic(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if checked status can be lost, drift to new definitions, or cite an unknown task."""
    publish_task_prerequisites(client, process, checkpoint_authority)
    definitions = client.parse_task_definitions(
        client.stage_artifact(
            "eng-1-change",
            artifact_envelope("tasks", ("tasks.md", "# Tasks\n- [ ] 1.1 Parse tasks\n- [ ] 1.2 Preserve checks\n")),
        )
    )
    changed = client.parse_task_definitions(
        client.stage_artifact(
            "eng-1-change",
            artifact_envelope("tasks", ("tasks.md", "# Tasks\n- [ ] 1.1 Parse changed tasks\n- [ ] 1.2 Preserve checks\n")),
        )
    )
    empty_status = TaskStatusManifest(
        definition_hash=definitions.definition_hash,
        statuses=tuple(TaskStatus(task_id=task.task_id, status=UnitStatus.UNCHECKED) for task in definitions.tasks),
    )

    checked = client.transition_task_status(definitions, empty_status, ("1.1",))

    assert checked.statuses == (
        TaskStatus(task_id="1.1", status=UnitStatus.CHECKED),
        TaskStatus(task_id="1.2", status=UnitStatus.UNCHECKED),
    )
    assert client.transition_task_status(definitions, checked, ()) == checked
    with pytest.raises(TaskDefinitionChanged):
        client.transition_task_status(changed, checked, ())
    with pytest.raises(UnknownTaskId):
        client.transition_task_status(definitions, checked, ("9.9",))


def test_complete_change_validation_requires_every_published_artifact(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    """Fails if a partial change can receive a full-change validation receipt."""
    proposal = client.stage_artifact("eng-1-change", artifact_envelope("proposal", ("proposal.md", "# Proposal\n")))
    publish(client, process, checkpoint_authority, proposal)
    validation_count = len(process.validation_cwds)

    with pytest.raises(ArtifactDependencyError):
        client.validate_complete_change("eng-1-change")

    assert len(process.validation_cwds) == validation_count
    publish_task_prerequisites(client, process, checkpoint_authority)
    tasks = client.stage_artifact("eng-1-change", artifact_envelope("tasks", ("tasks.md", "# Tasks\n- [ ] 1.1 Complete validation\n")))
    publish(client, process, checkpoint_authority, tasks)

    receipt = client.validate_complete_change("eng-1-change")

    assert receipt.artifact == "tasks"
    assert receipt.output_manifest_hash == tasks.output_manifest_hash
    assert process.validation_cwds[-1] == client._revision_root(client._visible_change_pointer("eng-1-change")) / "tree"  # type: ignore[union-attr]


def test_complete_change_validation_binds_the_tasks_manifest_and_cli_to_one_revision(
    client: OpenSpecClient,
    process: RecordingProcessRunner,
    checkpoint_authority: CheckpointAuthority,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fails if a task publication between validation reads can mix a receipt with a newer CLI tree."""
    publish_task_prerequisites(client, process, checkpoint_authority)
    first_tasks = client.stage_artifact(
        "eng-1-change",
        artifact_envelope("tasks", ("tasks.md", "# Tasks\n- [ ] 1.1 Validate revision A\n")),
    )
    publish(client, process, checkpoint_authority, first_tasks)
    first_pointer = client._visible_change_pointer("eng-1-change")
    assert first_pointer is not None
    second_tasks = client.stage_artifact(
        "eng-1-change",
        artifact_envelope("tasks", ("tasks.md", "# Tasks\n- [ ] 1.1 Validate revision B\n")),
    )
    original_published_artifacts = OpenSpecClient._published_artifacts
    publication_done = Event()
    publication_errors: list[BaseException] = []
    publication_thread: Thread | None = None

    def advance_pointer() -> None:
        try:
            publish(client, process, checkpoint_authority, second_tasks)
        except BaseException as error:
            publication_errors.append(error)
        finally:
            publication_done.set()

    def published_artifacts_then_advance(
        bound_client: OpenSpecClient,
        change_id: str,
        pointer: object | None = None,
    ) -> dict[str, StagedArtifactManifest]:
        nonlocal publication_thread
        if pointer is None:
            artifacts = original_published_artifacts(bound_client, change_id)
        else:
            artifacts = original_published_artifacts(bound_client, change_id, pointer)
        if bound_client is client and publication_thread is None:
            publication_thread = Thread(target=advance_pointer)
            publication_thread.start()
            publication_done.wait(timeout=1)
        return artifacts

    monkeypatch.setattr(OpenSpecClient, "_published_artifacts", published_artifacts_then_advance)

    receipt = client.validate_complete_change("eng-1-change")

    assert publication_thread is not None
    assert receipt.output_manifest_hash == first_tasks.output_manifest_hash
    assert process.validation_cwds[-1] == client._revision_root(first_pointer) / "tree"
    publication_thread.join(timeout=2)
    assert not publication_thread.is_alive()
    assert publication_errors == []
