"""Validated policy and result models."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PureWindowsPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Status(StrEnum):
    proposed = "proposed"
    approved = "approved"
    rejected = "rejected"
    deprecated = "deprecated"


class Enforcement(StrictModel):
    strategy: Literal["python_no_call", "python_required_call", "text_not_contain", "path_exists"]
    # For call strategies, target is a qualified Python call. For text, a literal string.
    # For path_exists, a repository-relative path.
    target: str = Field(min_length=1, max_length=200)
    keyword: str | None = Field(default=None, max_length=80)
    keyword_value: bool | str | None = None
    function: str | None = Field(default=None, max_length=100)

    @model_validator(mode="after")
    def check_shape(self) -> Enforcement:
        if self.strategy == "path_exists" and (
            self.target.startswith("/")
            or ".." in self.target.split("/")
            or "\\" in self.target
            or PureWindowsPath(self.target).is_absolute()
        ):
            raise ValueError("path_exists target must be relative and contained")
        if self.strategy not in {"python_no_call", "python_required_call"} and (
            self.keyword is not None or self.keyword_value is not None or self.function is not None
        ):
            raise ValueError("call options require a Python call strategy")
        if self.keyword_value is not None and self.keyword is None:
            raise ValueError("keyword_value requires keyword")
        return self


class Invariant(StrictModel):
    schema_version: Literal[1] = 1
    id: str = Field(pattern=r"^INV-[0-9]{3,}$")
    title: str = Field(min_length=8, max_length=180)
    description: str = Field(min_length=10, max_length=2000)
    category: str = Field(min_length=2, max_length=80)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    status: Status = Status.proposed
    confidence: Literal["low", "medium", "high"] = "medium"
    sources: list[str] = Field(default_factory=list, max_length=30)
    scope: list[str] = Field(min_length=1, max_length=30)
    statement: str = Field(min_length=10, max_length=2000)
    enforcement: Enforcement | None = None
    enforcement_strength: Literal["strong", "partial", "advisory"] = "partial"
    boundaries: list[str] = Field(default_factory=list, max_length=20)
    attacker: str | None = Field(default=None, max_length=500)
    bypasses: list[str] = Field(default_factory=list, max_length=10)
    rationale: str | None = Field(default=None, max_length=1500)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    approval_digest: str | None = None

    @model_validator(mode="after")
    def honest_strength(self) -> Invariant:
        if (
            self.enforcement is not None
            and self.enforcement.strategy.startswith("python_")
            and self.enforcement_strength == "strong"
        ):
            raise ValueError("Python syntax checks cannot claim strong enforcement")
        return self

    @field_validator("scope", "sources", "boundaries")
    @classmethod
    def safe_paths(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value or len(value) > 240 or "\\" in value or value.startswith("/"):
                raise ValueError("paths and labels must be bounded and relative")
            if any(part == ".." for part in value.split("/")):
                raise ValueError("parent traversal is forbidden")
        return values

    def rule_digest(self) -> str:
        data = self.model_dump(
            mode="json", exclude={"status", "created_at", "updated_at", "approval_digest"}
        )
        blob = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(blob).hexdigest()

    def approved_and_intact(self) -> bool:
        return self.status == Status.approved and self.approval_digest == self.rule_digest()


class Proposal(StrictModel):
    title: str = Field(min_length=8, max_length=180)
    description: str = Field(min_length=10, max_length=2000)
    category: str = Field(min_length=2, max_length=80)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    confidence: Literal["low", "medium", "high"] = "medium"
    sources: list[str] = Field(default_factory=list, max_length=30)
    scope: list[str] = Field(min_length=1, max_length=30)
    statement: str = Field(min_length=10, max_length=2000)
    enforcement: Enforcement | None = None
    enforcement_strength: Literal["strong", "partial", "advisory"] = "partial"
    boundaries: list[str] = Field(default_factory=list, max_length=20)
    attacker: str | None = Field(default=None, max_length=500)
    bypasses: list[str] = Field(default_factory=list, max_length=10)
    rationale: str | None = Field(default=None, max_length=1500)

    @field_validator("scope", "sources", "boundaries")
    @classmethod
    def safe_paths(cls, values: list[str]) -> list[str]:
        return Invariant.safe_paths(values)

    @model_validator(mode="after")
    def honest_strength(self) -> Proposal:
        if (
            self.enforcement is not None
            and self.enforcement.strategy.startswith("python_")
            and self.enforcement_strength == "strong"
        ):
            raise ValueError("Python syntax checks cannot claim strong enforcement")
        return self


class ProposalBatch(StrictModel):
    proposals: list[Proposal] = Field(max_length=12)


class BoundaryReview(StrictModel):
    path: str = Field(min_length=1, max_length=240)
    certainty: Literal["confirmed", "likely", "possible", "unknown"]
    summary: str = Field(min_length=1, max_length=500)
    reason: str = Field(min_length=1, max_length=1000)
    affected_invariants: list[str] = Field(max_length=30)
    test_ideas: list[str] = Field(max_length=10)


class BoundaryReviewBatch(StrictModel):
    reviews: list[BoundaryReview] = Field(max_length=30)


class CheckResult(StrictModel):
    id: str
    outcome: Literal["pass", "fail", "partial", "unenforced", "not_assessed"]
    detail: str
    files_checked: int = 0


class CheckReport(StrictModel):
    schema_version: Literal[1] = 1
    revision: str | None
    dirty: bool
    results: list[CheckResult]

    @property
    def failed(self) -> bool:
        return not self.results or any(
            item.outcome in {"fail", "unenforced", "not_assessed"} for item in self.results
        )
