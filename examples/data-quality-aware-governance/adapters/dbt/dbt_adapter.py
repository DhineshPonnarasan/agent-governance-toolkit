# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
dbt adapter for example-level DataQualityEvidence.

Reads a dbt run_results.json artifact and maps it into typed evidence.
"""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path

from data_quality_evidence import DataQualityEvidence


def load_from_dbt_run_results(
    run_results_path: str | Path,
    dataset_id: str,
    dataset_owner_did: str | None = None,
    classification: str | None = None,
    quality_profile_id: str | None = None,
) -> DataQualityEvidence:
    """Load example-level data quality evidence from a dbt run_results.json artifact.

The adapter derives freshness from metadata.generated_at, computes validation
status from dbt test result statuses, collects failed test names, and returns
a DataQualityEvidence object that can be evaluated alongside AGT policy checks.
"""
    path = Path(run_results_path)
    if not path.exists():
        raise FileNotFoundError(f"dbt run_results.json not found: {path}")

    with path.open(encoding="utf-8") as file:
        run_results = json.load(file)

    generated_at = run_results.get("metadata", {}).get("generated_at")
    if generated_at is None:
        raise ValueError("dbt run_results.json missing metadata.generated_at")

    freshness_at = _parse_timestamp(generated_at)

    results = run_results.get("results", [])
    total_tests = len(results)

    failed_tests: list[str] = []
    warning_tests: list[str] = []

    for result in results:
        status = result.get("status", "pass")
        test_name = _test_name_from_unique_id(result.get("unique_id", "unknown"))

        if status in {"fail", "error"}:
            failed_tests.append(test_name)
        elif status == "warn":
            warning_tests.append(test_name)

    if failed_tests:
        validation_status = "fail"
    elif warning_tests:
        validation_status = "warn"
    else:
        validation_status = "pass"

    passing_tests = total_tests - len(failed_tests) - len(warning_tests)
    quality_score = round(passing_tests / total_tests, 4) if total_tests else 1.0

    return DataQualityEvidence(
        dataset_id=dataset_id,
        freshness_at=freshness_at,
        validation_status=validation_status,
        failed_tests=tuple(failed_tests),
        quality_score=quality_score,
        quality_profile_id=quality_profile_id,
        dataset_owner_did=dataset_owner_did,
        classification=classification,
        source_tool="dbt",
    )


def _parse_timestamp(value: str) -> datetime:
    """Parse dbt timestamps with or without trailing Z / fractional seconds."""
    # This example intentionally normalizes UTC-style timestamps to naive
    # datetimes so they can be compared against the fixed reference time.
    cleaned = value.rstrip("Z")
    return datetime.fromisoformat(cleaned)


def _test_name_from_unique_id(unique_id: str) -> str:
    """Extract a readable dbt test name from a dbt unique_id."""
    parts = unique_id.split(".")
    if len(parts) >= 3:
        return parts[-2]
    return unique_id