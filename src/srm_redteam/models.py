from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from pydantic import BaseModel, Field


class AttackFamily(StrEnum):
    ontology_poisoning = "ontology_poisoning"
    memory_smuggling = "memory_smuggling"
    graph_walk_injection = "graph_walk_injection"
    drift_probe = "drift_probe"
    avatar_jailbreak = "avatar_jailbreak"


class Modality(StrEnum):
    transcript = "transcript"
    avatar = "avatar"


class AttackCase(BaseModel):
    case_id: str
    family: AttackFamily
    modality: Modality = Modality.transcript
    tenant: str
    payload: str
    annex_control: str
    expected_finding: bool
    invariant: str
    evidence: str


class GraphDelta(BaseModel):
    added_edges: list[str] = Field(default_factory=list)
    removed_edges: list[str] = Field(default_factory=list)
    weight_flips: list[str] = Field(default_factory=list)
    traversal_shift: list[str] = Field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.added_edges or self.removed_edges or self.weight_flips or self.traversal_shift)


class AttackRun(BaseModel):
    run_id: str
    case_id: str
    family: AttackFamily
    modality: Modality
    tenant: str
    status: str
    severity: int
    annex_control: str
    invariant: str
    evidence_id: str
    transcript_path: str
    graph_delta: GraphDelta
    finding_key: str | None
    observed: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: float


class Finding(BaseModel):
    finding_id: str
    finding_key: str
    family: AttackFamily
    annex_control: str
    title: str
    severity: int
    run_ids: list[str]
    evidence_ids: list[str]
    graph_fragment: list[str]
    transcript_excerpt: str
    mitigation: str


class VerificationReport(BaseModel):
    project: str
    checks: dict[str, bool]
    run_count: int
    unique_findings: int
    recall: float
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def passed(self) -> bool:
        return all(self.checks.values())


class Paths(BaseModel):
    root: Path
    configs: Path
    suites: Path
    runs: Path
    data: Path
    outputs: Path
    dashboard: Path
