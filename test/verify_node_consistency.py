#!/usr/bin/env python3
"""
Verify node-level predictions consistency against extracted JSON files.
Compares line numbers and method names for accuracy.
Processes all tier-level prediction files.
"""

import json
import sys
import re
from pathlib import Path
from collections import defaultdict

# Setup repo root
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent if _HERE.name == "test" else _HERE

# Paths
BATCH_DIR = _REPO_ROOT / "graphs/testing/batch_1"
EXTRACTED_BASE_DIR = _REPO_ROOT / "data_collection/batch_1_extracted_contracts"
REPORTS_DIR = BATCH_DIR / "consistency_reports" / "node_detection"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def find_tier_prediction_files():
    """Find all tier_*_node_level_predictions_*.json files from node_level_predictions_by_nodetype directory."""
    predictions_dir = BATCH_DIR / "node_level_predictions_by_nodetype"
    if not predictions_dir.exists():
        return []
    return sorted(predictions_dir.glob("tier_*_node_level_predictions_*.json"))


def extract_tier_from_path(file_path):
    """Extract tier number and nodetype from file path.

    Expected format: tier_1_cfg_graphs_node_level_predictions_nodetype.json
    Returns: tuple of (tier, nodetype) e.g., ('tier_1_cfg_graphs', 'nodetype')
    """
    stem = file_path.stem
    # Extract tier part (e.g., "tier_1_cfg_graphs")
    tier_match = re.search(r"(tier_\d+_cfg_graphs)", stem)
    # Extract nodetype part (e.g., "nodetype")
    nodetype_match = re.search(r"_node_level_predictions_(.+)$", stem)

    tier = tier_match.group(1) if tier_match else "tier_unknown"
    nodetype = nodetype_match.group(1) if nodetype_match else "unknown"

    # Normalize nodetype names to vulnerability category base names.
    # Examples: 'reentrancy_tree_sitter_cfg_cg_hgt' -> 'reentrancy',
    # 'access_control_hgt' -> 'access_control',
    # strip common suffixes used in checkpoint filenames.
    nodetype = re.sub(
        r"(_tree_sitter_cfg_cg_hgt|_tree_sitter_cfg_cg|_tree_sitter|_hgt)$",
        "",
        nodetype,
    )

    return tier, nodetype


def load_predictions(predictions_file):
    """Load predictions from JSON file."""
    with open(predictions_file) as f:
        data = json.load(f)
    return data.get("rows", [])


def load_extracted_json(contract_id, extracted_dir):
    """Load extracted JSON for a contract."""
    json_file = extracted_dir / f"{contract_id}.json"
    if not json_file.exists():
        return None
    with open(json_file) as f:
        return json.load(f)


def extract_methods_from_extracted(extracted_json, nodetype=None):
    """Extract method names and line ranges from extracted JSON.

    If `nodetype` is provided, only return methods when the extracted
    contract is classified as that vulnerability type. Classification is
    checked first via `validation.mando_classification.primary_category` and
    then via `validation.scsvs_classification.primary_category_name` as a
    fallback. Matching is case-insensitive and performs substring checks for
    the SCSVS field.

    Args:
        extracted_json: The extracted contract JSON
        nodetype: Optional string name of vulnerability to filter by (e.g. "reentrancy")

    Returns:
        dict: Methods with their line ranges, or empty dict if filtered out
    """
    methods = {}

    if not extracted_json:
        return methods

    # If a nodetype filter was provided, check classifications
    if nodetype:
        required = (nodetype or "").lower()
        validation = extracted_json.get("validation", {})
        mando_classification = validation.get("mando_classification") or {}
        primary_category = (mando_classification.get("primary_category") or "").lower()

        # Primary equality match
        if primary_category != required:
            scsvs_classification = validation.get("scsvs_classification") or {}
            scsvs_primary_name = (
                scsvs_classification.get("primary_category_name") or ""
            ).lower()
            # substring match for SCSVS fallback
            if required not in scsvs_primary_name:
                return methods

    problem_code = extracted_json.get("problem_code", {})
    snippets = problem_code.get("snippets", [])

    for snippet in snippets:
        func_name = snippet.get("function_name", "unknown")
        start_line = snippet.get("start_line")
        end_line = snippet.get("end_line")

        if func_name and start_line is not None and end_line is not None:
            methods[func_name] = {
                "start_line": start_line,
                "end_line": end_line,
                "line_range": list(range(start_line, end_line + 1)),
            }

    return methods


def check_line_consistency(pred_lines, actual_range):
    """Check if predicted lines fall within actual range."""
    actual_set = set(actual_range)
    pred_set = set(pred_lines)

    overlap = pred_set & actual_set
    missing = pred_set - actual_set
    extra_actual = actual_set - pred_set

    return {
        "overlap_count": len(overlap),
        "missing_count": len(missing),
        "extra_count": len(extra_actual),
        "overlap_percentage": (len(overlap) / len(pred_set) * 100) if pred_set else 0,
        "is_consistent": len(missing) == 0 and len(overlap) > 0,
    }


def generate_report(predictions, extracted_dir, nodetype=None):
    """Generate consistency report for a given nodetype (optional)."""
    report = {
        "total_predictions": 0,
        "total_contracts": 0,
        "contracts_checked": 0,
        "contracts_skipped_non_matching_category": 0,
        "matches": 0,
        "partial_matches": 0,
        "mismatches": 0,
        "not_found": 0,
        "flagged_in_audit": 0,
        "not_flagged_in_audit": 0,
        "details": [],
        "audit_vs_model": [],
    }

    # Group predictions by graph file
    graphs_by_contract = defaultdict(list)
    for pred in predictions:
        graph_path = pred.get("graph", "")
        # Extract contract ID from graph path (e.g., "64837_Market" from the path)
        contract_id = Path(graph_path).stem.rsplit("_patched", 1)[0]
        graphs_by_contract[contract_id].append(pred)

    report["total_contracts"] = len(graphs_by_contract)

    # Check each contract
    for contract_id, contract_preds in sorted(graphs_by_contract.items()):
        extracted_json = load_extracted_json(contract_id, extracted_dir)

        if not extracted_json:
            report["not_found"] += 1
            report["details"].append(
                {
                    "contract_id": contract_id,
                    "status": "NOT_FOUND",
                    "message": f"Extracted JSON not found for {contract_id}",
                }
            )
            continue

        # Extract methods filtered by nodetype (if provided)
        methods_in_extracted = extract_methods_from_extracted(
            extracted_json, nodetype=nodetype
        )

        # If no matching vulnerabilities found in extracted file, skip it
        if not methods_in_extracted:
            report["contracts_skipped_non_matching_category"] += 1
            report["details"].append(
                {
                    "contract_id": contract_id,
                    "status": "SKIPPED",
                    "message": (
                        f"Extracted JSON exists but does not classify as {nodetype} vulnerability"
                        if nodetype
                        else "Extracted JSON has no problem code snippets"
                    ),
                }
            )
            continue

        report["contracts_checked"] += 1

        for pred in contract_preds:
            vulnerability_summary = pred.get("vulnerability_summary", [])

            for vuln in vulnerability_summary:
                report["total_predictions"] += 1

                method_name = vuln.get("method", "")
                pred_lines = vuln.get("lines", [])

                # Try to match with extracted methods
                matching_method = None
                if method_name in methods_in_extracted:
                    matching_method = method_name

                if matching_method:
                    report["flagged_in_audit"] += 1
                    actual_range = methods_in_extracted[matching_method]["line_range"]
                    consistency = check_line_consistency(pred_lines, actual_range)

                    if consistency["is_consistent"]:
                        report["matches"] += 1
                        status = "MATCH"
                    else:
                        report["partial_matches"] += 1
                        status = "PARTIAL_MATCH"

                    report["details"].append(
                        {
                            "contract_id": contract_id,
                            "method": method_name,
                            "status": status,
                            "predicted_lines": pred_lines,
                            "predicted_line_range": (
                                f"{pred_lines[0]}-{pred_lines[-1]}"
                                if pred_lines
                                else "N/A"
                            ),
                            "actual_line_range": (
                                f"{actual_range[0]}-{actual_range[-1]}"
                                if actual_range
                                else "N/A"
                            ),
                            "consistency": consistency,
                        }
                    )
                else:
                    report["mismatches"] += 1
                    report["not_flagged_in_audit"] += 1
                    report["details"].append(
                        {
                            "contract_id": contract_id,
                            "method": method_name,
                            "status": "NOT_FOUND_IN_EXTRACTED",
                            "predicted_lines": pred_lines,
                            "message": f"Method '{method_name}' not found in extracted JSON",
                        }
                    )
                    # Add to audit vs model comparison
                    report["audit_vs_model"].append(
                        {
                            "contract_id": contract_id,
                            "method": method_name,
                            "in_audit": False,
                            "predicted_lines": pred_lines,
                            "predicted_line_range": (
                                f"{pred_lines[0]}-{pred_lines[-1]}"
                                if pred_lines
                                else "N/A"
                            ),
                        }
                    )

    return report


def save_reports(report, tier, nodetype=None):
    """Save detailed and summary reports for a specific tier and nodetype."""
    # Organize reports by nodetype if provided
    if nodetype:
        report_dir = REPORTS_DIR / nodetype
        report_dir.mkdir(parents=True, exist_ok=True)
    else:
        report_dir = REPORTS_DIR

    # Summary report
    summary = {
        "tier": tier,
        "nodetype": nodetype or "all",
        "total_predictions": report["total_predictions"],
        "total_contracts": report["total_contracts"],
        "contracts_skipped_non_matching_category": report.get(
            "contracts_skipped_non_matching_category", 0
        ),
        "contracts_checked": report["contracts_checked"],
        "matches": report["matches"],
        "partial_matches": report["partial_matches"],
        "mismatches": report["mismatches"],
        "not_found": report["not_found"],
        "flagged_in_audit": report["flagged_in_audit"],
        "not_flagged_in_audit": report["not_flagged_in_audit"],
        "match_rate_percentage": (
            (report["matches"] / report["total_predictions"] * 100)
            if report["total_predictions"]
            else 0
        ),
        "consistency_rate_percentage": (
            (
                (report["matches"] + report["partial_matches"])
                / report["total_predictions"]
                * 100
            )
            if report["total_predictions"]
            else 0
        ),
        "audit_coverage_percentage": (
            (report["flagged_in_audit"] / report["total_predictions"] * 100)
            if report["total_predictions"]
            else 0
        ),
    }

    # Detailed report
    tier_part = tier.replace("_cfg_graphs", "") if tier else "tier_unknown"
    detailed_filename = f"node_detection_{tier_part}_detailed_report.json"
    with open(report_dir / detailed_filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n✅ Report generated for {tier}:")
    print(f"   - Details: {report_dir / detailed_filename}")


def get_extracted_dir_for_tier(tier):
    """Map tier to correct extracted directory.

    Handles both old format (tier_1) and new format (tier_1_cfg_graphs).
    """
    # Extract just the tier number (e.g., "1" from "tier_1_cfg_graphs")
    tier_match = re.search(r"tier_(\d+)", tier)
    if not tier_match:
        return EXTRACTED_BASE_DIR / f"{tier}_complete"

    tier_num = tier_match.group(1)
    tier_map = {
        "1": "tier_1_complete",
        "2": "tier_2_code_blocks",
        "3": "tier_3_snippets",
    }
    extracted_subdir = tier_map.get(tier_num, f"tier_{tier_num}_complete")
    return EXTRACTED_BASE_DIR / extracted_subdir


def load_tier_summary(report_file):
    """Load tier summary JSON from a report file."""
    with open(report_file) as f:
        return json.load(f)


def main():
    # Find all tier prediction files
    pred_files = find_tier_prediction_files()

    if not pred_files:
        print("❌ No tier_*_node_level_predictions_*.json files found!")
        return

    print(f"🔍 Found {len(pred_files)} tier prediction files\n")

    # Group files by nodetype
    files_by_nodetype = defaultdict(list)
    for pred_file in pred_files:
        tier, nodetype = extract_tier_from_path(pred_file)
        files_by_nodetype[nodetype].append((pred_file, tier))

    print(f"📊 Discovered nodetypes: {sorted(files_by_nodetype.keys())}\n")

    all_nodetype_summaries = {}

    # Process each nodetype
    for nodetype in sorted(files_by_nodetype.keys()):
        print(f"\n{'='*70}")
        print(f"🔍 Processing nodetype: {nodetype}")
        print(f"{'='*70}")

        tier_summaries = []
        nodetype_files = files_by_nodetype[nodetype]
        print(f"   Found {len(nodetype_files)} tier predictions for this nodetype\n")

        for pred_file, tier in sorted(nodetype_files):
            extracted_dir = get_extracted_dir_for_tier(tier)

            # Validate extracted directory exists
            if not extracted_dir.exists():
                print(
                    f"   ⚠️  Skipping {tier}: extracted directory not found at {extracted_dir}"
                )
                continue

            print(f"   Processing {tier}...")

            # Load predictions
            predictions = load_predictions(pred_file)
            print(f"      Found {len(predictions)} prediction entries")

            # Generate report for this nodetype
            report = generate_report(predictions, extracted_dir, nodetype=nodetype)

            # Save reports organized by nodetype
            save_reports(report, tier, nodetype=nodetype)

            # Collect tier stats
            tier_stats = {
                "tier": tier,
                "total_predictions": report["total_predictions"],
                "contracts_skipped_non_matching_category": report.get(
                    "contracts_skipped_non_matching_category", 0
                ),
                "matches": report["matches"],
                "partial_matches": report["partial_matches"],
                "mismatches": report["mismatches"],
                "flagged_in_audit": report["flagged_in_audit"],
                "not_flagged_in_audit": report["not_flagged_in_audit"],
            }
            tier_summaries.append(tier_stats)

        # Create nodetype summary
        if tier_summaries:
            nodetype_summary = {
                "nodetype": nodetype,
                "tier_count": len(tier_summaries),
                "tier_summaries": tier_summaries,
                "combined_stats": {
                    "total_predictions": sum(
                        t["total_predictions"] for t in tier_summaries
                    ),
                    "total_matches": sum(t["matches"] for t in tier_summaries),
                    "total_partial_matches": sum(
                        t["partial_matches"] for t in tier_summaries
                    ),
                    "total_mismatches": sum(t["mismatches"] for t in tier_summaries),
                    "total_flagged_in_audit": sum(
                        t["flagged_in_audit"] for t in tier_summaries
                    ),
                    "total_not_flagged_in_audit": sum(
                        t["not_flagged_in_audit"] for t in tier_summaries
                    ),
                },
            }
            all_nodetype_summaries[nodetype] = nodetype_summary

            # Save nodetype summary
            nodetype_dir = REPORTS_DIR / nodetype
            nodetype_summary_file = (
                nodetype_dir / f"node_detection_{nodetype}_summary_report.json"
            )
            with open(nodetype_summary_file, "w") as f:
                json.dump(nodetype_summary, f, indent=2)
            print(f"\n   ✅ Nodetype summary saved to: {nodetype_summary_file}")

    # Create master summary across all nodetypes
    if all_nodetype_summaries:
        print(f"\n{'='*70}")
        print(f"📊 Creating master summary for all nodetypes...")
        print(f"{'='*70}")

        master_summary = {
            "description": "Summary statistics for all node_detection consistency checks across all nodetypes",
            "nodetype_count": len(all_nodetype_summaries),
            "nodetypes": all_nodetype_summaries,
            "overall_stats": {
                "total_predictions": sum(
                    s["combined_stats"]["total_predictions"]
                    for s in all_nodetype_summaries.values()
                ),
                "total_matches": sum(
                    s["combined_stats"]["total_matches"]
                    for s in all_nodetype_summaries.values()
                ),
                "total_flagged_in_audit": sum(
                    s["combined_stats"]["total_flagged_in_audit"]
                    for s in all_nodetype_summaries.values()
                ),
            },
        }
        master_summary_file = (
            REPORTS_DIR / "node_detection_all_nodetypes_master_summary.json"
        )
        with open(master_summary_file, "w") as f:
            json.dump(master_summary, f, indent=2)
        print(f"\n✅ Master summary saved to: {master_summary_file}")

    print(f"\n{'='*70}")
    print(f"✨ All nodetype verification reports completed!")
    print(f"{'='*70}")
    print("✅ All tier consistency checks complete!")
    print(f"{'='*60}")
    print(f"\n📁 All reports saved to: {REPORTS_DIR}")


if __name__ == "__main__":
    main()
