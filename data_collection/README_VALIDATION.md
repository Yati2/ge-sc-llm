# OpenAI Validation Guide

This document explains how `validate_with_openai.py` works end-to-end.

## What the script does

`validate_with_openai.py` validates extracted Solidity artifacts against Solodit finding reports and augments each metadata JSON with:

1. Content-to-code consistency checks
2. Report tag validation (correct/missing/incorrect)
3. Vulnerability classification in both MANDO and SCSVS
4. Fix-code handling:
   - Uses provided recommendation fix blocks when available
   - Generates fixes when recommendation text exists but no fix blocks exist

It also writes project-level reports to `validation_results/`.

## Inputs

The script expects these inputs in `data_collection/`:

1. Findings JSON from `.env` variable `OUTPUT_FILE` (for example `solodit_findings.json`)
2. Extracted metadata/code under:
   - `extracted_contracts/tier_1_complete/*.json`
   - `extracted_contracts/tier_2_code_blocks/*.json`
   - `extracted_contracts/tier_3_snippets/*.json`

## Tier coverage behavior

By default, validation runs on all three tiers.

Collection order is:

1. `tier_1_complete`
2. `tier_2_code_blocks`
3. `tier_3_snippets`

If you run with `--test`, the script validates only the first 5 collected files, so test mode is often biased toward tier 1 because tier 1 is collected first.

## Configuration (.env)

Required and commonly used environment variables:

1. `OPENAI_API_KEY`
2. `OPENAI_MODEL`
3. `OPENAI_TEMPERATURE`
4. `OPENAI_RATE_LIMIT_DELAY`
5. `OPENAI_RETRY_ATTEMPTS`
6. `CONFIDENCE_HIGH`
7. `CONFIDENCE_MEDIUM`
8. `CONFIDENCE_LOW`
9. `OUTPUT_FILE`

If `OPENAI_API_KEY` is missing, the script exits early with an error message.

## Run commands

From `data_collection/`:

```bash
python validate_with_openai.py
```

Test mode (quick smoke run):

```bash
python validate_with_openai.py --test
```

## Validation pipeline (step-by-step)

For each metadata JSON:

1. Load metadata and find matching report by `id` in `OUTPUT_FILE`.
2. Build problem-code input with fallback priority:
   1. `metadata.problem_code.snippets` (preferred)
   2. `metadata.problem_code` if it is plain text
   3. Full `.sol` file beside metadata JSON
3. Build provided fix-code input from `recommendation.fix_code_blocks`.
   - Supports blocks as dict (`{"code": ...}`) or plain string.
4. Ask OpenAI to perform:
   1. Content/code consistency
   2. Tag validation
   3. MANDO + SCSVS classification
5. Decide fix source:
   1. `provided` if recommendation already has fix blocks
   2. `generated` if recommendation text exists but no fix blocks
   3. `none` otherwise
6. If generation is needed, create snippet-aware fix requests and normalize response.
7. Write `validation` back into the same metadata JSON.
8. Update aggregate statistics and issue buckets.

## Generated fix behavior (current)

When fix generation is triggered, the prompt enforces:

1. One full fixed function per problem snippet
2. Multiple problem snippets -> multiple fixed function blocks
3. No language indicator in code output fields

The script normalizes generated output into `generated_fix.fixed_code_blocks` and keeps a compatibility field `generated_fix.fix_code` (concatenated text of all blocks).

It also records block cardinality checks:

1. `generated_fix.expected_fixed_blocks`
2. `generated_fix.returned_fixed_blocks`
3. `generated_fix.block_count_match`

## Augmented metadata structure

Each metadata JSON gets a `validation` object similar to:

```json
{
  "validation": {
    "validated_at": "2026-03-20T10:20:30",
    "model": "gpt-4o",
    "code_input_source": "problem_code",
    "fix_code_source": "generated",
    "content_code_consistency": {
      "consistent": true,
      "confidence": 91,
      "summary_matches": true,
      "content_matches": true,
      "summary_reasoning": "...",
      "content_reasoning": "...",
      "functions_found": ["withdraw"],
      "variables_found": ["balances"],
      "patterns_found": ["state update after external call"],
      "issues": []
    },
    "report_tag_validation": {
      "existing_tag": "Reentrancy",
      "tag_present": true,
      "tag_correct": true,
      "confidence": 95,
      "reasoning": "...",
      "suggested_tag": "reentrancy",
      "alternative_tags": [],
      "correction_explanation": "..."
    },
    "mando_classification": {
      "primary_category": "reentrancy",
      "secondary_categories": [],
      "confidence": 93,
      "mando_applicable": true,
      "reasoning": "..."
    },
    "scsvs_classification": {
      "primary_category": "G6",
      "primary_category_name": "Communications",
      "secondary_categories": [],
      "confidence": 90,
      "use_scsvs_instead": false,
      "reasoning": "...",
      "vulnerability_type": "reentrancy"
    },
    "generated_fix": {
      "has_fix": true,
      "fix_approach": "checks-effects-interactions",
      "fixed_code_blocks": [
        {
          "snippet_index": 1,
          "function_name": "withdraw",
          "fixed_function_code": "function withdraw(...) { ... }",
          "reasoning": "moves state update before external call"
        }
      ],
      "fix_code": "function withdraw(...) { ... }",
      "expected_fixed_blocks": 1,
      "returned_fixed_blocks": 1,
      "block_count_match": true,
      "key_changes": ["state update ordering"],
      "security_improvements": ["reentrancy resistance"],
      "additional_recommendations": "consider ReentrancyGuard",
      "confidence": 88,
      "generated_by": "openai",
      "generation_date": "2026-03-20T10:20:35"
    }
  }
}
```

## Output files

The script generates these files under `validation_results/`:

1. `validation_summary.json`
   - Totals, confidence buckets, classification distribution, fix-source stats
2. `validation_issues.json`
   - Incorrect tags, missing tags, mismatches, high-confidence list, generated-fix entries
3. `category_mapping.json`
   - Lightweight map for high-confidence items

It also updates every processed metadata JSON in place.

## Confidence interpretation

Confidence buckets are controlled by env thresholds:

1. High: `>= CONFIDENCE_HIGH`
2. Medium: `>= CONFIDENCE_MEDIUM` and `< CONFIDENCE_HIGH`
3. Low: `< CONFIDENCE_MEDIUM`

## Common troubleshooting

1. `No report found for ID ...`
   - The finding ID does not exist in `OUTPUT_FILE`.
2. `No code found for ...`
   - Metadata had no usable problem code and no fallback `.sol` file.
3. API retry warnings / JSON parse warnings
   - Handled via `OPENAI_RETRY_ATTEMPTS`; if retries exhaust, the file fails and processing continues.
4. Schema mismatch in recommendation blocks
   - The script supports both dict and string fix blocks; malformed block items are skipped.

## MANDO categories used by validator

1. `access_control`
2. `arithmetic`
3. `denial_of_service`
4. `front_running`
5. `reentrancy`
6. `time_manipulation`
7. `unchecked_low_level_calls`

