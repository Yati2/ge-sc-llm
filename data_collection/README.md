## Overview

Two main scripts work together to analyze and extract Solidity code:

1. **`analyze_data.py`** - Pre-extraction analysis and statistics
2. **`extract_contracts.py`** - Full extraction with 3-tier quality system

---

## 📊 Script 1: `analyze_data.py`

### Purpose
Survey markdown files before extraction to understand data quality and predict extraction success rates.

### What It Does
- Scans all markdown files in `markdown_files/`
- Detects GitHub .sol links
- Identifies code blocks (```solidity, ```sol, or plain ``` with Solidity code)
- Finds inline function snippets
- Tracks unique GitHub files vs total links
- Provides extraction predictions based on tier characteristics

### Usage
```bash
cd data_collection
python analyze_data.py
```

### Output Example
```
📊 ANALYSIS RESULTS
Total files: 100

🔗 GitHub Links:
  Files with GitHub .sol links: 123 (123.0%)
  Total .sol links found: 123
  Unique .sol files: 44 (Tier 1 will deduplicate)
  Files with GitHub line refs (#L): 116 (116.0%)

📝 Code Blocks:
  Files with code blocks: 87 (87.0%)
  Code block sizes: avg=13.7, min=1, max=392 lines

📊 EXPECTED RESULTS
  ~44 Tier 1 files (unique GitHub .sol files)
  ~87 Tier 2 files (good code blocks)
  Expected successful extractions: ~96/100 files (96.0%)
```

### Key Features
- **Deduplication detection**: Shows unique GitHub files vs total links
- **Quality assessment**: Analyzes code block sizes and completeness
- **Accurate predictions**: Estimates tier distribution before extraction

---

## 🔧 Script 2: `extract_contracts.py`

### Purpose
Extract Solidity contracts from markdown files using a 3-tier priority system.

### Extraction Priority System

The script follows a **decision tree** to extract the highest quality code:

```
PRIORITY 1: GitHub .sol Files (Tier 1)
    ↓ (if download fails or no GitHub links)
PRIORITY 2: Code Blocks from Markdown (Tier 2)
    ↓ (if no quality code blocks)
PRIORITY 3: Inline Snippets (Tier 3)
```

---

## 📁 Tier System Explained

### **Tier 1: Complete GitHub Files** 
**Source**: GitHub raw URLs

**Characteristics**:
- Complete, production-ready Solidity files
- Downloaded from GitHub repositories
- **Deduplication**: Each unique .sol file downloaded only ONCE
- **Smart handling**: Ignores line numbers (`#L97-L100`) and downloads full file
- **Stops early**: First successful download per finding
- **Retry logic**: Handles 404s, rate limits with exponential backoff

**Quality Requirements**: 
- ✅ Successfully downloaded from GitHub (HTTP 200)
- ✅ Valid .sol file

**Metadata Includes**:
- `source_url`: Original GitHub link
- `vulnerable_lines`: Line numbers mentioned (informational)
- `filename`: Original GitHub filename
- Quality metrics (pragma, contract, functions, etc.)

**Example**:
```
64660.md → Oracle.sol (Tier 1)
- URL: https://github.com/.../Oracle.sol#L97-L100
- Downloaded complete file (17,656 bytes)
- Vulnerable lines: [97, 100] (metadata only)
```

---

### **Tier 2: Code Blocks** 
**Source**: Markdown code blocks (```solidity, ```sol, or ``` with Solidity)

**Characteristics**:
- High-quality code blocks from markdown
- Near-complete contract implementations
- Multiple blocks from same file kept separate

**Quality Requirements**:
- ✅ Has `pragma solidity`
- ✅ Has `contract`, `interface`, or `library` declaration
- ✅ Balanced braces `{}`
- ✅ More than 20 lines

**Example**:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    // Complete contract code from markdown
    function vulnerable() external { ... }
}
```

---

### **Tier 3: Combined Snippets** 
**Source**: Inline code and function snippets

**Characteristics**:
- **COMBINED**: All snippets from same finding merged into ONE .sol file
- Separated by clear dividers: `// ========== Code Block N ==========`
- Marked with `"is_combined": true` in metadata
- Useful for context and analysis
- May be incomplete (missing imports, pragma, etc.)

**Quality Requirements**:
- ✅ Contains function definitions or Solidity keywords
- ✅ More than 5 lines OR has recognizable function signature
- ⚠️ May not compile standalone

**Metadata Includes**:
- `is_combined`: true
- `num_blocks`: Number of snippets merged
- `block_sources`: Array showing origin of each snippet

**Example**:
```solidity
// ========== Code Block 1 ==========
// Source: markdown_code_block
function vulnerable(uint amount) external {
    balance += amount;  // Integer overflow
}

// ========== Code Block 2 ==========
// Source: inline_content
function withdraw() external {
    msg.sender.call{value: balance}("");  // Reentrancy
}
```

---

## 🚀 Usage

### Basic Usage
```bash
cd data_collection
python extract_contracts.py
```

### Full Workflow
```bash
# Step 1: Analyze data first (optional but recommended)
python analyze_data.py

# Step 2: Run extraction
python extract_contracts.py

# Step 3: Review results
cat extracted_contracts/extraction_stats.json
ls extracted_contracts/tier_1_complete/
ls extracted_contracts/tier_2_code_blocks/
ls extracted_contracts/tier_3_snippets/
```

---

## 📂 Output Structure

```
extracted_contracts/
├── tier_1_complete/          # Complete GitHub files (unique)
│   ├── Oracle.sol
│   ├── Oracle.json           # Metadata
│   ├── PerpManager.sol
│   └── PerpManager.json
│
├── tier_2_code_blocks/       # High-quality code blocks
│   ├── 64660_contract.sol
│   ├── 64660_contract.json
│   └── ...
│
├── tier_3_snippets/          # Combined snippets (ONE file per finding)
│   ├── 64681_contract.sol    # Combined snippets from 64681
│   ├── 64681_contract.json   # is_combined: true
│   └── ...
│
├── extraction_stats.json     # Overall statistics
└── failed_extractions.log    # Failed files and reasons
```

---

## 📊 Statistics File

`extraction_stats.json` contains:

```json
{
  "total_processed": 100,
  "successful_extractions": 96,
  "github_attempted": 123,
  "github_successful": 44,
  "by_tier": {
    "tier_1_github_complete": 44,
    "tier_2_code_blocks": 30,
    "tier_3_snippets": 22
  },
  "by_extraction_type": {
    "github_direct": 44,
    "markdown_code_block": 30,
    "content_snippet": 22
  },
  "failed": 4,
  "failure_reasons": {
    "no_code_found": 4
  }
}
```

---

## 🗂️ Metadata Files

Each `.sol` file has a corresponding `.json` metadata file:

### Tier 1 Metadata Example
```json
{
  "id": "64660",
  "extraction_type": "github_with_lines",
  "source_url": "https://github.com/.../Oracle.sol#L97-L100",
  "is_complete": true,
  "tier": "tier_1",
  "vulnerable_lines": [97, 100],
  "filename": "Oracle.sol",
  "has_pragma": true,
  "has_contract": true,
  "has_function": true,
  "balanced_braces": true,
  "num_lines": 433,
  "extraction_date": "2026-03-05T01:23:45.678901"
}
```

### Tier 3 Combined Metadata Example
```json
{
  "id": "64681",
  "extraction_type": "combined",
  "source": "multiple_blocks",
  "is_combined": true,
  "num_blocks": 2,
  "block_sources": [
    {"type": "markdown_code_block", "index": 0},
    {"type": "markdown_code_block", "index": 1}
  ],
  "tier": "tier_3",
  "has_pragma": false,
  "has_contract": false,
  "has_function": true,
  "num_lines": 45,
  "extraction_date": "2026-03-05T01:23:45.678901"
}
```