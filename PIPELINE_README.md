# Pipeline File Guide (Data Collection -> Graph Generation -> Inference)

This document explains where the main pipeline files live, what each file does, and the expected input/output for each step.

## 1) Data Collection Files

Location: `data_collection/`

### Workflow order
1. `download.py`
2. `analyze_data.py` (optional but recommended)
3. `extract_contracts.py`
4. `validate_with_openai.py`

### File-by-file details

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

## 2) Graph Generation Files

Primary locations:
- `test/generate_cfg_graphs.py`
- `process_graphs/`
- `graphs/`

### `test/generate_cfg_graphs.py`
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

### `process_graphs/slither_reader.py`
- Purpose: Helper for Solidity version parsing from pragma statements during graph tooling.
- Input:
  - Solidity source text/file.
- Output:
  - Compiler version information used by graph tooling.

### Graph artifact locations used by models
- Contract-level detection graphs:
  - `graphs/graph_detection/*_compressed_graphs.gpickle`
- Node-level detection graphs:
  - `graphs/node_detection/*_compressed_graphs.gpickle`

---

## 3) Inference and Classification Files

Primary files:
- `graph_classifier.py` (contract-level prediction)
- `node_classifier.py` (line/node-level prediction)
- `checkpoints/` (pretrained model weights)
- `experiments/graph_classification.py` and `experiments/node_classification.py` (batch experiment drivers)

### `graph_classifier.py` (Contract-level)
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

### `node_classifier.py` (Node/line-level)
- Purpose: Train/test vulnerable node prediction for fine-grained localization.
- Core inputs:
  - `--compressed_graph` -> node graph `.gpickle` (typically from `graphs/node_detection/`).
  - `--dataset`, `--testset` -> source folders for split logic.
  - `--node_feature` and optional extractors (`--feature_extractor`, `--feature_compressed_graph`, `--cfg_feature_extractor`).
- Core outputs:
  - Checkpoint `.pth` at `--output_models` path.
  - Node-level classification metrics and confusion/classification reports.

### Checkpoints and model code
- Pretrained checkpoints:
  - `checkpoints/graph_detection/nodetype/*.pth`
  - `checkpoints/node_detection/nodetype/*.pth`
- Model definitions used by classifiers:
  - `sco_models/model_hgt.py`
  - Supporting utilities in `sco_models/dataloader.py`, `sco_models/utils.py`

### Experiment runners
- `experiments/graph_classification.py`:
  - Runs repeated contract-level experiments across vulnerability types and feature methods.
- `experiments/node_classification.py`:
  - Runs repeated node-level experiments and baselines.

---

## 4) End-to-End Pipeline Summary

1. Data collection
- Run `data_collection/download.py` to fetch findings.
- Run `data_collection/extract_contracts.py` to produce tiered Solidity artifacts.
- Run `data_collection/validate_with_openai.py` to validate and categorize.

2. Graph generation
- Run `test/generate_cfg_graphs.py` with the extracted tier folder as input.
- Produce `.gpickle` graph files for model consumption.

3. Inference/training
- Use `graph_classifier.py` for contract-level prediction.
- Use `node_classifier.py` for line/node-level prediction.
- Load/save checkpoints under `checkpoints/` (or your chosen output path).

---

## 5) Notes for this repository

- `extract_contracts.py` and `validate_with_openai.py` currently use batch-specific default paths in the script constants (for example batch 4). Update those constants when switching batches.
- `test/generate_cfg_graphs.py` uses the `SETTINGS` dictionary for input/output/build directories.
- Tree-sitter parser/vendor dependencies are under `process_graphs/tree_sitter_codeviews/`, and the generator script prepares the expected vendor symlink path under `app/sco/process_graphs/tree_sitter_codeviews/vendor`.

---

## 6) Related existing docs

- Root training/evaluation README: `README.md`
- Existing repository walkthrough: `REPOSITORY_GUIDE.md`
- Data collection workflow details: `data_collection/README.md`
- Validation logic details: `data_collection/README_VALIDATION.md`
