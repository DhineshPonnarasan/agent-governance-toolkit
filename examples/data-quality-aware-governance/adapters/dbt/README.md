# dbt Data Quality Evidence Adapter

This adapter extends the generic `examples/data-quality-aware-governance/` pattern with a concrete dbt-backed evidence flow.

The root example remains tool-agnostic. This folder shows one possible adapter implementation using dbt `run_results.json` output as input.

## What This Adapter Shows

This dbt adapter demonstrates how to:

1. Read dbt `run_results.json` output.
2. Map dbt test results into an example-local `DataQualityEvidence` object.
3. Evaluate the evidence alongside AGT policy decisions.
4. Produce an audit-friendly allow/block decision.

This is intentionally example-level code. It does not add a core AGT package model, require dbt as a dependency, or standardize a universal data quality schema.

## Files

```text
examples/data-quality-aware-governance/adapters/dbt/
├── README.md
├── data_quality_evidence.py
├── dbt_adapter.py
└── fixtures/
    ├── dbt_run_results_pass.json
    └── dbt_run_results_fail.json
```

## DataQualityEvidence

`DataQualityEvidence` is a small frozen dataclass that carries dataset trust state at the time an agent attempts access.

Fields include:

| Field | Purpose |
|---|---|
| `dataset_id` | Logical dataset identifier |
| `freshness_at` | Timestamp from dbt `metadata.generated_at` |
| `validation_status` | `pass`, `warn`, or `fail` |
| `failed_tests` | Failed dbt test names |
| `quality_score` | Ratio of passing tests from `0.0` to `1.0` |
| `quality_profile_id` | Optional quality profile name |
| `dataset_owner_did` | Optional dataset owner identifier |
| `classification` | Optional data classification |
| `source_tool` | Source quality tool, here `dbt` |

## dbt Mapping

The adapter maps dbt output as follows:

| dbt artifact field | Evidence field |
|---|---|
| `metadata.generated_at` | `freshness_at` |
| `results[].status` | `validation_status` |
| failing `results[].unique_id` values | `failed_tests` |
| pass ratio across `results[]` | `quality_score` |

## Example Usage

```python
from dbt_adapter import load_from_dbt_run_results

evidence = load_from_dbt_run_results(
    "fixtures/dbt_run_results_pass.json",
    dataset_id="user_events",
    dataset_owner_did="did:web:analytics.example.com",
    classification="regulated",
    quality_profile_id="strict",
)
```

The resulting evidence can then be used with AGT policy evaluation:

```text
AGT policy allows the agent
        +
dbt evidence says the dataset is fresh and passing
        =
allow the action
```

or:

```text
AGT policy allows the agent
        +
dbt evidence says validation failed
        =
block the action at the data quality layer
```

## Non-Goals

This adapter does not:

- change AGT core behavior
- add a package-level schema
- require dbt as an AGT dependency
- prescribe dbt as the only data quality system
- define a universal quality threshold
- implement external receipt or protocol semantics

## Relationship to the Root Example

The root `data-quality-aware-governance` example stays generic and tool-agnostic.

This adapter is one concrete implementation path. Future adapters could follow the same structure, for example:

```text
adapters/great-expectations/
adapters/soda/
adapters/custom-catalog/
```
