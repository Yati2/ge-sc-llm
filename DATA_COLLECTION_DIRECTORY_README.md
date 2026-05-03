# Pipeline Overview: Directory Structure, Flow, and Environments

This document explains where key files/folders live, the end-to-end workflow, and which conda environments to use for each step.

---

## Directory Structure at a Glance

```
ge-sc-llm/
├── data_collection/              # Data collection pipeline (download, extract, validate)
│   ├── download.py               # Download findings from Solodit API
│   ├── analyze_data.py            # Analyze markdown coverage
│   ├── extract_contracts.py       # Extract Solidity artifacts (Tier 1/2/3)
│   ├── validate_with_openai.py    # Validate and classify vulnerabilities
│   ├── README.md                  # Detailed data collection docs
│   ├── README_OVERVIEW.md         # Quick stats and overview
│   ├── downloaded_findings/       # ← Solodit findings (JSON + markdown)
│   └── batch_*_extracted_contracts/  # ← Extracted Solidity artifacts
│       ├── tier_1_complete/
│       ├── tier_2_code_blocks/
│       ├── tier_3_snippets/
│       ├── validation_results/
│       └── [extraction stats, shared files, etc.]
│
├── process_graphs/               # Graph generation helpers
│   ├── slither_reader.py
│   └── tree_sitter_codeviews/
│
├── test/                         # Testing/inference scripts
│   ├── generate_cfg_graphs.py    # Generate CFG graphs from Solidity
│   ├── run_cfg_only_all_checkpoints.py  # Graph-level inference
│   ├── run_node_inference.py     # Node-level inference (multi-category)
│   └── verify_node_consistency.py  # Verify predictions vs audit findings
│
├── graphs/                       # ← Generated and test graphs
│   ├── graph_detection/          # Graph-level predictions
│   ├── node_detection/           # Node-level predictions
│   └── testing/
│       ├── batch_1/
│       ├── batch_2/
│       ├── batch_3/
│       └── batch_4/
│           ├── tier_1_cfg_graphs/
│           ├── tier_3_cfg_graphs/
│           ├── node_level_predictions_by_nodetype/
│           └── consistency_reports/
│
├── checkpoints/                  # ← Pre-trained model weights
│   ├── graph_detection/nodetype/
│   └── node_detection/nodetype/
│
├── sco_models/                   # Model architecture and utilities
│   ├── model_hgt.py
│   ├── model_hgt_with_guardrails.py
│   └── [utilities, tools, etc.]
│
└── experiments/                  # Training and batch experiments
    ├── graph_classification.py
    └── node_classification.py
```

---

## Conda Environments

| Stage | Environment | Purpose |
|-------|-------------|---------|
| **Data Collection** | `mando37` | Download findings, extract contracts, validate with LLM |
| **Graph Generation & Inference** | `mando_graph` | Generate CFG graphs, run node/graph inference, verify results |

### Activate Environments

```bash
# For data collection
conda activate mando37

# For graph generation and inference
conda activate mando_graph
```

---

## End-to-End Workflow

### Stage 1: Data Collection (Environment: `mando37`)

**Location:** `data_collection/`

**Flow:**
1. **Download findings** → Run `data_collection/download.py`
   - Fetches audit findings from Solodit API
   - Output: `data_collection/downloaded_findings/batch_X_solodit_findings.json` + markdown files

2. **Analyze data** (optional) → Run `data_collection/analyze_data.py`
   - Survey markdown files to estimate Tier 1/2/3 yield before extraction
   - Output: Console summary only

3. **Extract contracts** → Run `data_collection/extract_contracts.py`
   - Extract Solidity code using 3-tier fallback:
     - Tier 1: Full `.sol` files from GitHub
     - Tier 2: Code blocks from markdown
     - Tier 3: Snippets and combined code
   - Output: `data_collection/batch_*_extracted_contracts/tier_{1,2,3}_{complete,code_blocks,snippets}/`

4. **Validate artifacts** → Run `data_collection/validate_with_openai.py`
   - Validate extracted code
   - Classify vulnerabilities (MANDO + SCSVS categories)
   - Enrich metadata with classifications
   - Output: Updated metadata JSON files + validation results

**Output Data:** Extracted Solidity files organized by tier, each with metadata including vulnerability classifications

---

### Stage 2: Graph Generation & Inference (Environment: `mando_graph`)

**Locations:** `test/`, `graphs/`, `checkpoints/`

**Flow:**

#### A) Generate CFG Graphs
- **Script:** `test/generate_cfg_graphs.py`
- **Input:** Extracted Solidity files from `data_collection/batch_*_extracted_contracts/tier_*/`
- **Process:** Build control-flow graphs (CFG) from Solidity source using tree-sitter
- **Output:** `graphs/testing/batch_*/tier_*_cfg_graphs/*.gpickle`

#### B) Run Graph-Level Inference (Contract Detection)
- **Script:** `test/run_cfg_only_all_checkpoints.py`
- **Input:** Generated CFG graphs + checkpoints from `checkpoints/graph_detection/nodetype/*.pth`
- **Process:** Run graph classifiers across all checkpoint categories
- **Output:** `graphs/testing/batch_*/cfg_only_all_checkpoint_predictions.json`

#### C) Run Node-Level Inference (Fine-Grained Detection)
- **Script:** `test/run_node_inference.py`
- **Input:** Generated CFG graphs + checkpoints from `checkpoints/node_detection/nodetype/*.pth`
- **Process:**
  - Discover available checkpoint categories (reentrancy, access_control, arithmetic, etc.)
  - Normalize category names
  - Generate per-tier per-category predictions
- **Output:**
  - `graphs/testing/batch_*/node_level_predictions_by_nodetype/tier_*_node_level_predictions_{category}.json`
  - `graphs/testing/batch_*/node_level_predictions_by_nodetype/manifest_all_nodetypes.json`

#### D) Verify Predictions
- **Script:** `test/verify_node_consistency.py`
- **Input:**
  - Node predictions from step C
  - Extracted audit findings from data collection stage
- **Process:**
  - Read predictions grouped by vulnerability category
  - Filter audit findings by matching category
  - Compare predicted vulnerable methods/lines vs audit ground truth
  - Generate per-category consistency reports
- **Output:**
  - `graphs/testing/batch_*/consistency_reports/node_detection/{category}/*_detailed_report.json`
  - `graphs/testing/batch_*/consistency_reports/node_detection/{category}/*_summary_report.json`
  - `graphs/testing/batch_*/consistency_reports/node_detection/node_detection_all_nodetypes_master_summary.json`

---

## Quick Command Reference

### Data Collection (in `mando37` environment)

```bash
conda activate mando37
cd /data/sue/ge-sc-llm

# Download findings
python data_collection/download.py

# (Optional) Analyze markdown coverage
python data_collection/analyze_data.py

# Extract contracts
python data_collection/extract_contracts.py

# Validate and classify
python data_collection/validate_with_openai.py
```

### Graph Generation & Inference (in `mando_graph` environment)

```bash
conda activate mando_graph
cd /data/sue/ge-sc-llm

# Generate CFG graphs
python test/generate_cfg_graphs.py

# Run graph-level inference
python test/run_cfg_only_all_checkpoints.py

# Run node-level inference (all categories)
python test/run_node_inference.py

# Verify predictions
python test/verify_node_consistency.py
```

---

## Data and Model Locations

| Artifact | Location |
|----------|----------|
| **Downloaded findings** | `data_collection/downloaded_findings/batch_*.json` |
| **Extracted Solidity** | `data_collection/batch_*_extracted_contracts/tier_{1,2,3}_*` |
| **Generated CFG graphs** | `graphs/testing/batch_*/tier_*_cfg_graphs/*.gpickle` |
| **Node predictions** | `graphs/testing/batch_*/node_level_predictions_by_nodetype/` |
| **Graph predictions** | `graphs/testing/batch_*/cfg_only_all_checkpoint_predictions.json` |
| **Consistency reports** | `graphs/testing/batch_*/consistency_reports/` |
| **Pre-trained checkpoints** | `checkpoints/graph_detection/nodetype/*.pth`, `checkpoints/node_detection/nodetype/*.pth` |
| **Model code** | `sco_models/*.py` |

---

## Key Notes

1. **Environment switching is critical:** Data collection uses `mando37`, graph generation/inference uses `mando_graph`.
2. **Batch paths:** Batch 4 is the main dataset (19,327 findings → 13,150 extracted artifacts). Batches 1-3 are smaller validation sets.
3. **Category normalization:** Node inference and verification both normalize checkpoint filenames to extract base vulnerability categories (e.g., `reentrancy_tree_sitter_cfg_cg_hgt.pth` → `reentrancy`).
4. **Configuration:** Most scripts use a `SETTINGS` dictionary at the top for configurable paths and parameters.
5. **See also:**
   - [Data Collection README](data_collection/README_OVERVIEW.md) — Extraction stats and details
   - [Graph Testing README](graphs/testing/README.md) — Inference and verification workflows
   - [Validation Details](data_collection/README_VALIDATION.md) — LLM validation logic

---

## Detailed Reference: Script-by-Script Breakdown

### Data Collection Scripts (mando37)

**Location:** `data_collection/`

**Workflow order:**
1. `download.py`
2. `analyze_data.py` (optional but recommended)
3. `extract_contracts.py`
4. `validate_with_openai.py`

**Details:**

#### `data_collection/download.py`
- Purpose: Downloads Solidity findings from Solodit API, deduplicates across batches, and saves batch JSON plus per-finding markdown files.
- Process:
  - Reads API/config values from `.env`.
  - Loads prior state from `STATE_FILE`.
  - Fetches paginated results from Solodit.
  - Filters/deduplicates findings.
  - Writes findings JSON and markdown outputs.
- Inputs:
  - `.env`: `SOLODIT_API_KEY`, `PAGE_SIZE`, `TARGET_RUNS`, `STATE_FILE`, `OUTPUT_FILE`.
  - Solodit API response.
- Outputs:
  - `data_collection/downloaded_findings/<batch>_solodit_findings.json`
  - `data_collection/downloaded_findings/<batch>_solodit_findings/` (markdown files)
  - Updated download state JSON (`STATE_FILE`).

#### `data_collection/analyze_data.py`
- Purpose: Surveys downloaded markdown files to estimate extraction quality before contract extraction.
- Process:
  - Scans all markdown files under `downloaded_findings/`.
  - Reports coverage of GitHub `.sol` links, code blocks, inline snippets, and files with no extractable code.
- Inputs:
  - Markdown files under `data_collection/downloaded_findings/`.
- Outputs:
  - Console summary only (no major artifact file).

#### `data_collection/extract_contracts.py`
- Purpose: Extracts Solidity artifacts from reports using a 3-tier fallback strategy.
- Process:
  - Tier 1: download full `.sol` files from GitHub links.
  - Tier 2: extract Solidity code blocks from markdown.
  - Tier 3: combine snippets when Tier 1/2 are not available.
  - Writes extraction statistics and metadata.
- Inputs:
  - Markdown findings folder (configured in script).
  - Findings JSON (configured in script).
  - GitHub raw `.sol` URLs.
- Outputs:
  - `batch_*_extracted_contracts/tier_1_complete/`
  - `batch_*_extracted_contracts/tier_2_code_blocks/`
  - `batch_*_extracted_contracts/tier_3_snippets/`
  - `batch_*_extracted_contracts/extraction_stats.json`
  - `batch_*_extracted_contracts/shared_github_files.json`
  - `batch_*_extracted_contracts/failed_extractions.log`

#### `data_collection/validate_with_openai.py`
- Purpose: Validates extracted artifacts and enriches metadata with consistency checks and security categorization.
- Process:
  - Loads extraction outputs and original finding metadata.
  - Validates content-to-code consistency.
  - Validates/adjusts report tags.
  - Classifies vulnerabilities into MANDO and SCSVS categories.
  - Handles fix code (provided or generated).
  - Writes updated metadata and summary reports.
- Inputs:
  - `OUTPUT_FILE` findings JSON from `.env`.
  - `batch_*_extracted_contracts/tier_1_complete/*.json`
  - `batch_*_extracted_contracts/tier_2_code_blocks/*.json`
  - `batch_*_extracted_contracts/tier_3_snippets/*.json`
  - `.env`: `OPENAI_API_KEY`, model/retry/rate-limit settings.
- Outputs:
  - Updated metadata JSON files in tier folders.
  - `batch_*_extracted_contracts/validation_results/validation_summary.json`
  - `batch_*_extracted_contracts/validation_results/validation_issues.json`
  - `batch_*_extracted_contracts/validation_results/category_mapping.json`

---

### Graph Generation & Testing Scripts (mando_graph)

**Locations:**
- `test/generate_cfg_graphs.py`
- `process_graphs/`
- `graphs/`

#### `test/generate_cfg_graphs.py`
- Purpose: Generates CFG graphs from Solidity files using tree-sitter parser and exports `.gpickle` graph artifacts.
- Process:
  - Reads `.sol` files from configured `SETTINGS["input_dir"]`.
  - Builds/loads tree-sitter Solidity language library.
  - Generates CFG graph for each source.
  - Saves graph as `.gpickle` and summary JSON.
- Inputs:
  - Solidity files from an extracted tier folder (for example `data_collection/batch_3_extracted_contracts/tier_1_complete`).
  - Parser assets under `process_graphs/tree_sitter_codeviews/`.
- Outputs:
  - `graphs/testing/.../*.gpickle`
  - `graphs/testing/.../*.dot`
  - `graphs/testing/.../generation_summary.json`

#### `process_graphs/slither_reader.py`
- Purpose: Helper for Solidity version parsing from pragma statements during graph tooling.
- Input:
  - Solidity source text/file.
- Output:
  - Compiler version information used by graph tooling.

#### Graph artifact locations used by models
- Contract-level detection graphs:
  - `graphs/graph_detection/*_compressed_graphs.gpickle`
- Node-level detection graphs:
  - `graphs/node_detection/*_compressed_graphs.gpickle`

---

### Inference and Model Training (mando_graph)

**Primary files:**
- `graph_classifier.py` (contract-level prediction)
- `node_classifier.py` (line/node-level prediction)
- `checkpoints/` (pretrained model weights)
- `experiments/graph_classification.py` and `experiments/node_classification.py` (batch experiment drivers)

#### `graph_classifier.py` (Contract-level)
- Purpose: Train/test whole-contract vulnerability classification using hetero graph models.
- Core inputs:
  - `--compressed_graph` -> graph `.gpickle` (typically from `graphs/graph_detection/`).
  - `--label` -> labels JSON for graphs.
  - `--node_feature` -> feature mode (`nodetype`, `metapath2vec`, `han`, `gae`, `line`, `node2vec`).
  - Optional `--feature_extractor` / `--checkpoint`.
- Core outputs:
  - Checkpoint `.pth` at `--output_models` path.
  - Training/validation metrics in console.
  - Logs in `--log_dir`.

#### `node_classifier.py` (Node/line-level)
- Purpose: Train/test vulnerable node prediction for fine-grained localization.
- Core inputs:
  - `--compressed_graph` -> node graph `.gpickle` (typically from `graphs/node_detection/`).
  - `--dataset`, `--testset` -> source folders for split logic.
  - `--node_feature` and optional extractors (`--feature_extractor`, `--feature_compressed_graph`, `--cfg_feature_extractor`).
- Core outputs:
  - Checkpoint `.pth` at `--output_models` path.
  - Node-level classification metrics and confusion/classification reports.

#### Checkpoints and model code
- Pretrained checkpoints:
  - `checkpoints/graph_detection/nodetype/*.pth`
  - `checkpoints/node_detection/nodetype/*.pth`
- Model definitions used by classifiers:
  - `sco_models/model_hgt.py`
  - Supporting utilities in `sco_models/dataloader.py`, `sco_models/utils.py`

#### Experiment runners
- `experiments/graph_classification.py`:
  - Runs repeated contract-level experiments across vulnerability types and feature methods.
- `experiments/node_classification.py`:
  - Runs repeated node-level experiments and baselines.

---

## Important Notes

### Configuration & Paths
- **`extract_contracts.py` and `validate_with_openai.py`**: Currently use batch-specific default paths in script constants (e.g., batch 4). Update these constants when switching batches.
- **`test/generate_cfg_graphs.py`**: Uses the `SETTINGS` dictionary at the top of the script for input/output/build directories.
- **Tree-sitter dependencies**: Located under `process_graphs/tree_sitter_codeviews/`. The generator script prepares the expected vendor symlink path under `app/sco/process_graphs/tree_sitter_codeviews/vendor`.

### Environment Management
- Always activate the correct conda environment before running scripts
- Data collection work → `conda activate mando37`
- Graph generation and inference → `conda activate mando_graph`

---

## Related Documentation

- **Root README**: [README.md](README.md) — Training and evaluation overview
- **Repository guide**: [REPOSITORY_GUIDE.md](REPOSITORY_GUIDE.md) — Full repository walkthrough
- **Data collection details**: [data_collection/README.md](data_collection/README.md) — Detailed workflow
- **Data collection stats**: [data_collection/README_OVERVIEW.md](data_collection/README_OVERVIEW.md) — Quick extraction statistics
- **Validation logic**: [data_collection/README_VALIDATION.md](data_collection/README_VALIDATION.md) — LLM validation details
- **Graph testing guide**: [graphs/testing/README.md](graphs/testing/README.md) — Inference and verification workflows
