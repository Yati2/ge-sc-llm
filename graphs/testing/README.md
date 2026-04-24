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

### 3) Tag consistency report generation

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

Inside each batch folder, common subfolders/files include:

- `tier_1_cfg_graphs/` (generated `.gpickle` and `.dot` files)
- `cfg_only_all_checkpoint_predictions.json`
- `consistency_reports/`

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

## Node Detection Caveat (Important)

For node-level runs, graph nodes are expected to include attributes used for label handling, including `node_info_vulnerabilities`.

If generated test graphs do not contain expected node attributes, node classifier initialization or labeling may fail.

In this workspace, a known issue is that CFG generation flow may set line fields but not persist `node_info_vulnerabilities` onto nodes in output graphs, which blocks straightforward node-detection inference on those generated test graphs.

## Output Interpretation

In predictions JSON rows from `run_cfg_only_all_checkpoints.py`:

1. Check `status` first.
2. If `status == "ok"`:
    - `predicted_label == "1"` means vulnerable for that checkpoint type.
    - `prob_class_1` is the class-1 probability-like score.
3. If `status == "error"`, inspect `error` text for schema/runtime details.

Consistency report outputs classify each contract as match/mismatch/no-positive-prediction/errors-only based on predicted positives and selected metadata tag.

## Recommended Workflow

1. Generate CFG graphs for a target batch with `test/generate_cfg_graphs.py`.
2. Run graph checkpoints with `test/run_cfg_only_all_checkpoints.py`.
3. Run `test/compare_checkpoint_tags.py` to summarize alignment with metadata tags.
4. For node-level localization, ensure generated graph schema includes required node attributes before running node checkpoints.

## Practical Guidance

- Use CFG-only all-checkpoint runs for comparative/triage analysis.
- Use schema-matched graph/checkpoint pairs for production-quality inference.
- Treat partial-load results as exploratory, not strict benchmark-equivalent.