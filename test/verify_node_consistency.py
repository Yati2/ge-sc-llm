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
REPORTS_DIR = BATCH_DIR / "consistency_reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def find_tier_prediction_files():
    """Find all tier_*_cfg_graphs_node_level_predictions.json files."""
    return sorted(BATCH_DIR.glob("tier_*_cfg_graphs_node_level_predictions.json"))


def extract_tier_from_path(file_path):
    """Extract tier number from file path."""
    stem = file_path.stem
    match = re.search(r"(tier_\d+)", stem)
    if match:
        return match.group(1)
    return "tier_unknown"


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


def extract_methods_from_extracted(extracted_json):
    """Extract method names and line ranges from extracted JSON."""
    methods = {}

    if not extracted_json:
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


def generate_report(predictions, extracted_dir):
    """Generate consistency report."""
    report = {
        "total_predictions": 0,
        "total_contracts": 0,
        "contracts_checked": 0,
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

        report["contracts_checked"] += 1

        methods_in_extracted = extract_methods_from_extracted(extracted_json)

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


def save_reports(report, tier):
    """Save detailed and summary reports for a specific tier."""
    # Summary report
    summary = {
        "tier": tier,
        "total_predictions": report["total_predictions"],
        "total_contracts": report["total_contracts"],
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

    with open(REPORTS_DIR / f"node_detection_{tier}_summary_report.json", "w") as f:
        json.dump(summary, f, indent=2)

    # Detailed report
    with open(REPORTS_DIR / f"node_detection_{tier}_detailed_report.json", "w") as f:
        json.dump(report, f, indent=2)

    # Model-only predictions (not in audit)
    with open(
        REPORTS_DIR / f"node_detection_{tier}_model_only_predictions.json", "w"
    ) as f:
        model_only = {
            "description": "Methods flagged by model that were NOT in original audit report",
            "total_model_only": len(report["audit_vs_model"]),
            "by_contract": defaultdict(list),
        }
        for item in report["audit_vs_model"]:
            contract_id = item["contract_id"]
            model_only["by_contract"][contract_id].append(
                {
                    "method": item["method"],
                    "predicted_lines": item["predicted_lines"],
                    "line_range": item["predicted_line_range"],
                }
            )
        json.dump(model_only, f, indent=2)

    print(f"\n✅ Reports generated for {tier}:")
    print(f"   - Summary: {REPORTS_DIR / f'node_detection_{tier}_summary_report.json'}")
    print(
        f"   - Details: {REPORTS_DIR / f'node_detection_{tier}_detailed_report.json'}"
    )
    print(
        f"   - Model-only predictions: {REPORTS_DIR / f'node_detection_{tier}_model_only_predictions.json'}"
    )
    print(f"\n📊 Summary for {tier}:")
    for key, value in summary.items():
        if isinstance(value, float):
            print(f"   {key}: {value:.2f}")
        else:
            print(f"   {key}: {value}")


def get_extracted_dir_for_tier(tier):
    """Map tier to correct extracted directory."""
    tier_map = {
        "tier_1": "tier_1_complete",
        "tier_2": "tier_2_code_blocks",
        "tier_3": "tier_3_snippets",
    }
    extracted_subdir = tier_map.get(tier, f"{tier}_complete")
    return EXTRACTED_BASE_DIR / extracted_subdir


def load_tier_summary(report_file):
    """Load tier summary JSON from a report file."""
    with open(report_file) as f:
        return json.load(f)


def main():
    # Find all tier prediction files
    pred_files = find_tier_prediction_files()

    if not pred_files:
        print("❌ No tier_*_cfg_graphs_node_level_predictions.json files found!")
        return

    print(f"🔍 Found {len(pred_files)} tier prediction files:\n")

    all_tier_summaries = []

    for pred_file in pred_files:
        tier = extract_tier_from_path(pred_file)
        extracted_dir = get_extracted_dir_for_tier(tier)

        # Validate extracted directory exists
        if not extracted_dir.exists():
            print(
                f"⚠️  Skipping {tier}: extracted directory not found at {extracted_dir}"
            )
            continue

        print(f"\n{'='*60}")
        print(f"Processing {tier}...")
        print(f"{'='*60}")

        # Load predictions
        print(f"🔍 Loading predictions from {pred_file.name}...")
        predictions = load_predictions(pred_file)
        print(f"   Found {len(predictions)} prediction entries")

        # Generate report
        print(f"🔄 Generating consistency report for {tier}...")
        report = generate_report(predictions, extracted_dir)

        # Save reports
        print(f"💾 Saving reports for {tier}...")
        save_reports(report, tier)

        tier_summary_file = REPORTS_DIR / f"node_detection_{tier}_summary_report.json"
        if tier_summary_file.exists():
            all_tier_summaries.append(load_tier_summary(tier_summary_file))

    if all_tier_summaries:
        combined_report = {
            "description": "Summary statistics for all node_detection tier consistency checks",
            "tier_count": len(all_tier_summaries),
            "tiers": all_tier_summaries,
        }
        with open(
            REPORTS_DIR / "node_detection_all_tiers_summary_report.json", "w"
        ) as f:
            json.dump(combined_report, f, indent=2)
        print(
            f"\n📁 Combined tier summary saved to: {REPORTS_DIR / 'node_detection_all_tiers_summary_report.json'}"
        )

    print(f"\n{'='*60}")
    print("✅ All tier consistency checks complete!")
    print(f"{'='*60}")
    print(f"\n📁 All reports saved to: {REPORTS_DIR}")


if __name__ == "__main__":
    main()
