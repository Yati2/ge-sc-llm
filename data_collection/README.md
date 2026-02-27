# Work Summary

### 1. Data Collection System ([download.py](download.py))
- **Random sampling strategy**: Selects random pages from Solodit API to ensure diverse, unbiased dataset
- Filters to keep only findings with populated summaries
- Continues sampling until exactly 100 valid findings collected
- Ensures data randomness across thousands of available vulnerabilities

### 2. Validation Module ([validate_summary.py](validate_summary.py))
- Uses OpenAI API to verify if vulnerability summaries match actual code
- Extracts Solidity code snippets from markdown
- Returns validity status + reason for mismatches
- Configurable model via `.env` file

### 3. Testing Script ([test_validation.py](test_validation.py))
- Tests validation on sample vulnerabilities
- Saves results as JSON files in `validation_results/` folder

## Tech Stack:
Python, OpenAI API (GPT-4o-mini), Solodit API
