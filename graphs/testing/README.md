# Graph Testing README

This folder stores test-time graph artifacts, checkpoint prediction outputs, and consistency reports for the MANDO graph/node detection pipeline.

## Scope

The testing flow here is used to:

1. Generate CFG test graphs from extracted Solidity files.
2. Run graph-detection checkpoints across those generated graphs.
3. Compare prediction tags with report metadata and validation outputs.

## Scripts Used

These scripts live in `test/` and operate on paths under `graphs/testing/`.

### 1) Graph generation

- Script: `test/generate_cfg_graphs.py`
- What it does:
   - Reads Solidity files from a selected batch input folder.
   - Uses tree-sitter CFG generation.
   - Writes `.dot` and `.gpickle` per input contract.
   - Writes `generation_summary.json` in the output graph folder.
- Default settings are controlled in the `SETTINGS` block inside the script.

### 2) All-checkpoint graph inference (CFG-only test mode)

- Script: `test/run_cfg_only_all_checkpoints.py`
- What it does:
   - Loads all `.gpickle` files from a target testing folder.
   - Iterates all matching checkpoints (default: `checkpoints/graph_detection/nodetype/*_tree_sitter_cfg_cg_hgt.pth`).
   - Runs graph classifier inference for each graph/checkpoint pair.
   - Uses partial state-dict loading to tolerate schema mismatches.
   - Writes one aggregated predictions JSON file.

### 3) Node-level detection inference

- Script: `test/run_node_inference.py`
- What it does:
   - Discovers available vulnerability checkpoints from `checkpoints/node_detection/nodetype/` directory
   - Normalizes checkpoint category names by stripping suffixes (`_hgt`, `_tree_sitter_cfg_cg_hgt`, etc.) to map to base vulnerability categories (reentrancy, access_control, arithmetic, front_running, etc.)
   - Loads CFG graphs from all tiers (tier_1_cfg_graphs, tier_3_cfg_graphs, etc.)
   - For each discovered category, runs node-level classifier inference on all graph/tier combinations
   - Generates per-tier per-category predictions JSON files in `node_level_predictions_by_nodetype/` with format: `tier_X_cfg_graphs_node_level_predictions_{category}.json`
   - Creates manifest file `manifest_all_nodetypes.json` tracking all categories tested and their results
   - Outputs confidence scores via softmax probabilities for each predicted vulnerable node
- Key parameters: defined in `SETTINGS` (checkpoint path, device, node_feature attribute, etc.)
- Output: `node_level_predictions_by_nodetype/{tier_X_cfg_graphs_node_level_predictions_{category}.json}` files + `manifest_all_nodetypes.json`

### 4) Node-level consistency verification

- Script: `test/verify_node_consistency.py`
- What it does:
   - Reads all per-tier per-category node predictions from `node_level_predictions_by_nodetype/` directory
   - Extracts tier and category (nodetype) from each prediction filename and normalizes category names using same suffix-stripping logic as inference
   - Groups predictions by category for organized per-vulnerability-type reporting
   - For each category, compares predicted methods and line numbers against extracted audit findings
   - Filters extracted audit findings by category: checks `validation.mando_classification.primary_category` for exact match (case-insensitive), falls back to substring match in `validation.scsvs_classification.primary_category_name` if primary is absent
   - Classifies each prediction as MATCH (perfect line overlap), PARTIAL_MATCH (some overlap), or NOT_FOUND_IN_EXTRACTED
   - Tracks `contracts_skipped_non_matching_category` for contracts that don't have audit findings for the current category
   - Generates detailed report per tier per category in `consistency_reports/node_detection/{category}/`
   - Generates per-category summary report and master summary across all categories
   - Outputs organized under `consistency_reports/node_detection/` with per-category subfolders

### 3) Tag consistency report generation (Graph-level)

- Script: `test/compare_checkpoint_tags.py`
- What it does:
   - Reads predictions JSON from step 2.
   - Reads finding validation JSON files from a batch `tier_1_complete` folder.
   - Compares predicted checkpoint tag vs selected suitable tag from metadata.
   - Writes report JSON files under `consistency_reports/`.

## Current Batch-Oriented Layout

Typical folder pattern in `graphs/testing/`:

- `batch_1/`
- `batch_2/`
- `batch_3/`
- `batch_4/`

### Standardized Batch Structure

Each batch folder follows this standardized layout:

```
batch_X/
├── tier_1_cfg_graphs/               (tier 1 complete contracts - CFG graphs)
├── tier_2_cfg_graphs/               (tier 2 code blocks - CFG graphs) [optional]
├── tier_3_cfg_graphs/               (tier 3 snippets - CFG graphs)
├── cfg_only_all_checkpoint_predictions.json
├── node_level_predictions_by_nodetype/
│   ├── tier_1_cfg_graphs_node_level_predictions_nodetype1.json
│   ├── tier_1_cfg_graphs_node_level_predictions_nodetype2.json
│   ├── tier_3_cfg_graphs_node_level_predictions_nodetype1.json
│   ├── tier_3_cfg_graphs_node_level_predictions_nodetype2.json
│   └── manifest_all_nodetypes.json
└── consistency_reports/
    ├── graph_detection/
    │   ├── tier_1_checkpoint_tag_comparison_per_file.json
    │   ├── tier_1_checkpoint_tag_excluded_error_records.json
    │   ├── tier_1_checkpoint_tag_no_prediction_files.json
    │   ├── tier_3_checkpoint_tag_comparison_per_file.json
    │   ├── tier_3_checkpoint_tag_excluded_error_records.json
    │   └── tier_3_checkpoint_tag_no_prediction_files.json
    └── node_detection/
        ├── nodetype1/
        │   ├── node_detection_tier_1_detailed_report.json
        │   ├── node_detection_tier_3_detailed_report.json
        │   └── node_detection_nodetype1_summary_report.json
        ├── nodetype2/
        │   ├── node_detection_tier_1_detailed_report.json
        │   ├── node_detection_tier_3_detailed_report.json
        │   └── node_detection_nodetype2_summary_report.json
        └── node_detection_all_nodetypes_master_summary.json
```

**Note:** All batches follow this structure. Per-tier files are consolidated under single folders.

## Recent Changes and Implementation Details

### Checkpoint-Based Category Discovery

- **Before:** Node inference (`run_node_inference.py`) discovered "nodetypes" by reading unique `node_type` values from the first graph.
- **After:** Now discovers vulnerability categories by enumerating checkpoint files in `checkpoints/node_detection/nodetype/`.
- **Why:** Checkpoints are the source of truth for what categories are supported. Graph node attributes may vary or be incomplete.

### Category Normalization

- **Implementation:** Both `run_node_inference.py` and `verify_node_consistency.py` use identical regex to strip checkpoint filename suffixes and extract base category names.
- **Suffixes stripped:** `_tree_sitter_cfg_cg_hgt`, `_tree_sitter_cfg_cg`, `_tree_sitter`, `_hgt`
- **Result:** Checkpoint filenames like `reentrancy_tree_sitter_cfg_cg_hgt.pth` map to category `reentrancy`.
- **Why:** Ensures consistent naming across all scripts and tools, and makes category names human-readable and audit-friendly.

### Unified Output Organization

- **Predictions location:** All per-tier per-category predictions write to `node_level_predictions_by_nodetype/` with filenames `{tier}_node_level_predictions_{category}.json`.
- **Manifest:** `manifest_all_nodetypes.json` tracks all categories tested and their inference results with keys `results_by_category` and `categories_tested`.
- **Reports:** Consistency reports organized under `consistency_reports/node_detection/{category}/` with per-category subfolders and a master summary.
- **Why:** Consolidation prevents scattered outputs and makes it easy to locate and track results for specific vulnerability types.

### Category-Aware Verification Filtering

- **Filtering logic:** Verification compares predictions against extracted audit findings using vulnerability category matching.
- **Primary filter:** Matches `validation.mando_classification.primary_category` exactly (case-insensitive).
- **Fallback filter:** If primary is absent, checks substring match in `validation.scsvs_classification.primary_category_name`.
- **Skipping:** Contracts without matching category classification are skipped and counted separately.
- **Why:** Enables accurate comparison between detectors and ground truth for each vulnerability type independently.

## Model and Checkpoint Notes

### Checkpoint families

Graph checkpoints in this repo are under:

- `checkpoints/graph_detection/nodetype/`

Node checkpoints are under:

- `checkpoints/node_detection/nodetype/`

Both are generally binary detectors per vulnerability type:

- class `0`: not vulnerable for that detector type
- class `1`: vulnerable for that detector type

### Schema compatibility

Model architecture is inferred from graph schema (node/edge types and feature expectations). Full checkpoint loading requires compatible schema.

When schema differs, common failures include:

- missing/unexpected keys
- shape mismatch

The CFG-only all-checkpoint script intentionally uses partial loading to avoid hard failures for exploratory testing.

## Node Detection Notes

### Category-Aware Filtering

Node consistency verification (`verify_node_consistency.py`) filters extracted contracts to match the current vulnerability category being verified. For each category:

1. **Primary check:** `validation.mando_classification.primary_category` == `{category}` (case-insensitive)
2. **Fallback check:** If primary is empty/null, check `validation.scsvs_classification.primary_category_name` contains `{category}` as substring (case-insensitive)
3. **Skip:** If neither classification matches the category, contract is skipped with status SKIPPED and counted in `contracts_skipped_non_matching_category`

This category-aware filtering ensures verification compares model predictions only against relevant ground truth vulnerabilities for the specific detector being tested.

### Multi-Category Architecture

Node-level detection automatically discovers and processes all available vulnerability detection checkpoints:

- Node inference (`run_node_inference.py`) scans the `checkpoints/node_detection/nodetype/` directory to enumerate all available checkpoint files
- Normalizes checkpoint filenames to extract base category names (reentrancy, access_control, arithmetic, front_running, etc.) by stripping common suffixes
- Iterates through each discovered category, generating separate predictions per tier per category
- Each category produces its own set of predictions that can be analyzed independently
- Master manifest aggregates results across all categories for comparative analysis

### Node Feature Extraction

- Predictions include confidence scores via softmax probabilities (0-1 range)
- Line numbers are extracted and consolidated into minimal contiguous spans
- Vulnerable nodes are grouped by (source_file, method) for summary reporting
- Vulnerability summary includes: method name, node count, line count, individual lines, and aggregated line spans

## Node Detection Implementation Details

### Checkpoint Discovery and Category Normalization

The inference and verification scripts use a unified category naming convention:

- **Discovery:** `run_node_inference.py` enumerates checkpoint files in `checkpoints/node_detection/nodetype/` and normalizes their basenames
- **Normalization:** Strips common suffixes (`_tree_sitter_cfg_cg_hgt`, `_tree_sitter_cfg_cg`, `_tree_sitter`, `_hgt`) from checkpoint filenames to extract base category names
- **Example:** Checkpoint `reentrancy_tree_sitter_cfg_cg_hgt.pth` → category `reentrancy`
- **Verification:** `verify_node_consistency.py` applies identical normalization when extracting categories from prediction filenames
- **Consistency:** Both scripts use normalized category names for file naming, filtering, and reporting to ensure alignment

## Output Interpretation

### Graph-Level Predictions

In predictions JSON rows from `run_cfg_only_all_checkpoints.py`:

1. Check `status` first.
2. If `status == "ok"`:
    - `predicted_label == "1"` means vulnerable for that checkpoint type.
    - `prob_class_1` is the class-1 probability-like score.
3. If `status == "error"`, inspect `error` text for schema/runtime details.

Consistency report outputs classify each contract as match/mismatch/no-positive-prediction/errors-only based on predicted positives and selected metadata tag.

### Node-Level Predictions

In node predictions JSON:

1. Structure: `{"summary": {...}, "rows": [...]}`
2. Each row represents a graph analysis result:
   - `graph`: Path to the GPPickle file analyzed
   - `vulnerable_nodes_count`: Number of CFG nodes predicted as vulnerable
   - `total_nodes`: Total nodes in the graph
   - `vulnerability_summary`: Aggregated list of vulnerable methods with line ranges
   - `vulnerable_nodes`: Detailed list with node IDs, confidence scores, source files, methods
3. Confidence score in `vulnerable_nodes`: Softmax probability (0-1) for vulnerability class

### Consistency Report Outputs

Node consistency reports classify each prediction as:

- **MATCH**: Predicted lines perfectly align with extracted audit range
- **PARTIAL_MATCH**: Some predicted lines overlap with audit range (partial coverage)
- **NOT_FOUND_IN_EXTRACTED**: Method predicted by model but not in extracted audit findings
- **SKIPPED**: Contract skipped (not classified as reentrancy)
- **NOT_FOUND**: Extracted JSON file not found for contract

Each report includes: contract ID, method name, status, predicted lines, actual audit lines, and overlap statistics.

## Recommended Workflow

### Graph-Level Detection (CFG-only)
1. Generate CFG graphs for a target batch with `test/generate_cfg_graphs.py`.
2. Run graph checkpoints with `test/run_cfg_only_all_checkpoints.py`.
3. Run `test/compare_checkpoint_tags.py` to summarize alignment with metadata tags.
4. Consistency reports appear in `consistency_reports/graph_detection/`.

### Node-Level Detection (Multi-Category)
1. Ensure CFG graphs have been generated (step 1 above).
2. Run node inference with `test/run_node_inference.py` to discover all available checkpoint categories and generate per-tier per-category predictions.
   - Outputs go to `node_level_predictions_by_nodetype/{tier}_node_level_predictions_{category}.json`
   - Manifest: `node_level_predictions_by_nodetype/manifest_all_nodetypes.json`
3. Run `test/verify_node_consistency.py` to verify predictions against extracted audit findings, filtering by category.
   - Generates per-category detailed reports and summary
   - Consistency reports organized as `consistency_reports/node_detection/{category}/`
   - Master summary: `consistency_reports/node_detection/node_detection_all_nodetypes_master_summary.json`
4. Review results per category to analyze detection accuracy across all vulnerability types.

## Practical Guidance

- Use CFG-only all-checkpoint runs for comparative/triage analysis.
- Use schema-matched graph/checkpoint pairs for production-quality inference.
- Treat partial-load results as exploratory, not strict benchmark-equivalent.
- For node detection, always run node inference before verification to ensure predictions exist.
- Node consistency verification automatically filters contracts by category, so `contracts_skipped_non_matching_category` counts reflect contracts without audit findings for that specific vulnerability type.
- Review `contracts_skipped_non_matching_category` in each category summary to understand coverage.

## Troubleshooting

### Node Inference Issues

- **No prediction files found**: Verify that graphs exist in tier folders (tier_1_cfg_graphs, tier_3_cfg_graphs) and that checkpoints exist in `checkpoints/node_detection/nodetype/`.
- **Shape mismatch errors**: Ensure checkpoint matches graph schema (node types, feature dimensions). Verify checkpoint path in SETTINGS.
- **Missing node_info_vulnerabilities**: This is expected for CFG-generated graphs. Node inference auto-patches graphs to add this attribute.
- **No categories discovered**: Check that checkpoint directory `checkpoints/node_detection/nodetype/` contains `.pth` files. Verify file permissions and path.

### Consistency Verification Issues

- **0% match rate for a category**: Expected if contracts don't have that specific vulnerability type. Check `contracts_skipped_non_matching_category` and category summary report.
- **All contracts skipped for all categories**: Verify extracted JSON files contain proper `validation.mando_classification.primary_category` or `validation.scsvs_classification.primary_category_name` data.
- **None handling errors in reports**: Ensure node predictions include `vulnerability_summary` field (required for line extraction). Run node inference first if verification fails.

### Report Organization

- Graph reports save to: `consistency_reports/graph_detection/`
- Node reports save to: `consistency_reports/node_detection/{nodetype}/`
- Always separate graph and node results to avoid confusion.