# Data Collection Pipeline

This folder contains the end-to-end data preparation pipeline for collecting vulnerability reports, extracting Solidity code artifacts, and validating extracted artifacts with LLM-based checks.

## Overview

The usual workflow is:

1. Download findings from Solodit API.
2. Extract Solidity artifacts from report content and linked GitHub sources.
3. Validate extracted artifacts and enrich metadata with consistency checks and vulnerability classifications.

Main scripts:

- `download.py`: fetch report data and persist it as batch JSON + markdown files.
- `analyze_data.py`: inspect markdown coverage and estimate extraction quality before extraction.
- `extract_contracts.py`: produce tiered Solidity artifacts and metadata.
- `validate_with_openai.py`: validate extracted artifacts and append classification/quality fields.

## Script Details

### 1) `download.py`

Purpose:
- Pull findings from Solodit API using pagination.
- Resume safely across runs with a state file.
- Deduplicate against prior batch JSON files.
- Save findings JSON and per-finding markdown files.

Key behavior:
- Uses `.env` values like `SOLODIT_API_KEY`, `PAGE_SIZE`, `TARGET_RUNS`, `STATE_FILE`, and `OUTPUT_FILE`.
- Stops cleanly when an API page returns zero findings.
- If the run stops mid-page (target reached), marks the page as incomplete and resumes from the same page on the next run.

Outputs:
- Batch findings JSON (for example under `downloaded_findings/`).
- Markdown files in a folder named from `OUTPUT_FILE` stem.
- Updated download state JSON.

### 2) `analyze_data.py`

Purpose:
- Survey all markdown files under `downloaded_findings/`.
- Report how many files contain GitHub `.sol` links, code blocks, inline snippets, and no extractable code.

When to use:
- Run before extraction to understand expected Tier 1/2/3 yield.

### 3) `extract_contracts.py`

Purpose:
- Extract Solidity code artifacts using a 3-tier priority system.

Tier priority:

```
Tier 1: GitHub .sol files (highest quality)
    -> fallback if unavailable
Tier 2: Solidity code blocks from markdown
    -> fallback if unavailable
Tier 3: Combined snippets from remaining inline content
```

Current default configuration in this script points to batch 4 paths:
- `downloaded_findings/batch_4_solodit_findings/`
- `batch_4_extracted_contracts/`

Extraction notes:
- Tier 1 downloads full `.sol` files from GitHub, ignoring line-anchor fragments for retrieval.
- Tier 2 keeps stronger Solidity code blocks that satisfy quality checks.
- Tier 3 combines multiple snippet fragments from one finding into one output artifact.

Outputs (under output batch directory):
- `tier_1_complete/`
- `tier_2_code_blocks/`
- `tier_3_snippets/`
- `extraction_stats.json`
- `shared_github_files.json`
- `failed_extractions.log`

### 4) `validate_with_openai.py`

Purpose:
- Validate extracted artifacts against their source finding.
- Enrich each metadata JSON with consistency checks, tag checks, and vulnerability classification.

Validation responsibilities:
- Content-code consistency validation.
- Existing tag correctness checks and suggested corrections.
- Classification into MANDO categories and SCSVS categories.
- Fix-code handling (use provided recommendation fix blocks or generate when needed).

Current default configuration points to batch 4 paths:
- Input extracted dir: `batch_4_extracted_contracts`
- Output validation dir: `batch_4_extracted_contracts/validation_results`

Detailed validation flow is documented in `README_VALIDATION.md`.

## Configuration

Use `.env` to configure API, rate limits, model settings, file names, and confidence thresholds.

Common fields used across scripts:

- Solodit/API fields:
    - `SOLODIT_API_KEY`
    - `PAGE_SIZE`
    - `TARGET_RUNS`
    - `STATE_FILE`
    - `OUTPUT_FILE`
- OpenAI validation fields:
    - `OPENAI_API_KEY`
    - `OPENAI_MODEL`
    - `OPENAI_TEMPERATURE`
    - `OPENAI_RATE_LIMIT_DELAY`
    - `OPENAI_RETRY_ATTEMPTS`
    - `CONFIDENCE_HIGH`
    - `CONFIDENCE_MEDIUM`
    - `CONFIDENCE_LOW`

See `.env.example` for baseline variable names.

## Typical Run Order

From this folder:

```bash
python download.py
python analyze_data.py
python extract_contracts.py
python validate_with_openai.py
```

Optional quick validation run:

```bash
python validate_with_openai.py --test
```

## Batch-Oriented Layout

This repository uses batch folders (for example `batch_1_extracted_contracts`, `batch_2_extracted_contracts`, etc.) to keep runs isolated and reproducible.

Recommended practice:

1. Keep each download/extract/validate cycle scoped to one batch folder.
2. Avoid mixing outputs from different batches in the same extraction directory.
3. Keep `OUTPUT_FILE` and extraction/validation directories aligned to the same batch.

## Notes

- Some scripts currently hardcode batch-specific paths (especially extraction and validation scripts). Update path constants before running a different batch.
- Downloading and validation are designed to be resumable and robust to partial failures; reruns should continue from saved state and existing outputs.

