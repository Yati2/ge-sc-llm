## Output Files

### 1. Augmented Metadata (`*.json`)

Each metadata JSON file gets a `validation` section:

```json
{
  "id": "64974",
  "tier": "tier_1",
  "filename": "CollateralManager.sol",
  
  "validation": {
    "validated_at": "2026-03-06T12:34:56",
    "model": "gpt-4o-2024-11-20",
    
    "content_code_consistency": {
      "consistent": true,
      "confidence": 95,
      "summary_reasoning": "Summary accurately describes the issue...",
      "content_reasoning": "Content correctly identifies vulnerable functions...",
      "functions_found": ["_computeNewRevenue", "_realizeRevenue"],
      "patterns_found": ["Only accumulates positive yield"],
      "issues": []
    },
    
    "report_tag_validation": {
      "existing_tag": "Access Control",
      "tag_correct": false,
      "reasoning": "Existing tag is incorrect. The vulnerability is arithmetic...",
      "suggested_tag": "Arithmetic",
      "correction_explanation": "Should be Arithmetic - violates G7.1..."
    },
    
    "mando_classification": {
      "primary_category": "arithmetic",
      "confidence": 92,
      "scsvs_mapping": {"G7": "Arithmetic - G7.1, G7.3"},
      "reasoning": "Core issue is incorrect calculation logic..."
    }
  }
}
```

### 2. Summary Report (`validation_summary.json`)

Overall statistics:

```json
{
  "total_validated": 96,
  "consistency": {
    "high": 78,
    "medium": 12,
    "low": 6
  },
  "tag_validation": {
    "correct": 0,
    "incorrect": 1,
    "missing": 95
  },
  "mando_distribution": {
    "arithmetic": 15,
    "reentrancy": 12,
    "access_control": 18
  }
}
```

### 3. Issues Report (`validation_issues.json`)

Detailed issues for manual review:

```json
{
  "incorrect_tags": [
    {
      "id": "64974",
      "existing_tag": "Access Control",
      "suggested_tag": "Arithmetic",
      "reasoning": "Existing tag is incorrect...",
      "correction_explanation": "Should be Arithmetic because..."
    }
  ],
  "content_mismatches": [
    {
      "id": "64888",
      "issues": ["Summary mentions functions not in code"],
      "summary_reasoning": "Summary describes withdraw but not in snippet",
      "recommendation": "Manual review required"
    }
  ],
  "missing_tags": [...]
}
```

### 4. Category Mapping (`category_mapping.json`)

Quick lookup for high-confidence validations:

```json
{
  "64974": {
    "filename": "CollateralManager.sol",
    "tier": "tier_1",
    "confidence": 95
  }
}
```
## MANDO Categories

The system maps vulnerabilities to these 7 categories:

1. **access_control** (G5) - Authorization, permissions
2. **arithmetic** (G7) - Math operations, overflow/underflow
3. **denial_of_service** (G8) - Resource exhaustion
4. **front_running** (G4) - Transaction ordering
5. **reentrancy** (G6) - Cross-contract calls
6. **time_manipulation** (G9) - Block data dependency
7. **unchecked_low_level_calls** (G6/I1) - Failed call handling

## Understanding Validation Results

### High Confidence (>80%)
Ready for model training. Code clearly demonstrates the vulnerability.

### Medium Confidence (50-80%)
Partial match. May need human review or code is incomplete.

### Low Confidence (<50%)
Significant issues. Code doesn't match report or is too incomplete.  
Should be flagged for manual review.

