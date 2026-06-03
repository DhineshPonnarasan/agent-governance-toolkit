# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Typed data quality evidence for policy-readable dataset trust signals.

This is an example-level artifact, not a core AGT package model.

It shows how data quality tool output can be mapped into a small typed
evidence object and used alongside AGT policy evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


VALIDATION_STATUSES = {"pass", "warn", "fail"}


@dataclass(frozen=True)
class DataQualityEvidence:
    """Dataset quality state at the time an agent attempts access."""

    dataset_id: str
    freshness_at: datetime
    validation_status: str
    failed_tests: tuple[str, ...]

    quality_score: float | None = None
    quality_profile_id: str | None = None
    dataset_owner_did: str | None = None
    classification: str | None = None
    source_tool: str | None = None

    def __post_init__(self) -> None:
        if not self.dataset_id:
            raise ValueError("dataset_id must not be empty")

        if self.validation_status not in VALIDATION_STATUSES:
            raise ValueError(
                f"validation_status must be one of {sorted(VALIDATION_STATUSES)}"
            )

        if self.quality_score is not None and not 0.0 <= self.quality_score <= 1.0:
            raise ValueError("quality_score must be between 0.0 and 1.0")

    def is_fresh_at(self, reference_time: datetime, max_age_hours: float = 6.0) -> bool:
        """Return true when the evidence is fresh relative to a fixed reference time."""
        age_seconds = (reference_time - self.freshness_at).total_seconds()
        return 0 <= age_seconds <= max_age_hours * 3600

    @property
    def is_passing(self) -> bool:
        return self.validation_status == "pass"

    @property
    def has_failures(self) -> bool:
        return len(self.failed_tests) > 0

    def to_audit_dict(self) -> dict:
        """Serialize the evidence for audit log inclusion."""
        return {
            "dataset_id": self.dataset_id,
            "freshness_at": self.freshness_at.isoformat(),
            "validation_status": self.validation_status,
            "quality_score": self.quality_score,
            "quality_profile_id": self.quality_profile_id,
            "dataset_owner_did": self.dataset_owner_did,
            "classification": self.classification,
            "failed_tests": list(self.failed_tests),
            "source_tool": self.source_tool,
        }