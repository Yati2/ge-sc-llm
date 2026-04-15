## 🔧  `extract_contracts.py`

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

