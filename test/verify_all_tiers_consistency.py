#!/usr/bin/env python3
"""
Verify node-level predictions consistency for ALL tiers.
Generates per-tier reports and a master summary.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

# Setup repo root
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent if _HERE.name == "test" else _HERE

# Paths
GRAPHS_DIR = _REPO_ROOT / "graphs/testing/batch_1"
EXTRACTED_BASE = _REPO_ROOT / "data_collection/batch_1_extracted_contracts"
REPORTS_DIR = GRAPHS_DIR / "consistency_reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def find_prediction_files():
    """Find all tier_*_cfg_graphs_node_level_predictions.json files."""
    prediction_files = sorted(
        GRAPHS_DIR.glob("tier_*_cfg_graphs_node_level_predictions.json")
    )
    return prediction_files


def extract_tier_from_file(filepath):
    """Extract tier number from file path."""
    stem = filepath.stem
    for part in stem.split("_"):
        if part.startswith("tier"):
            return part
    return "unknown"


def get_extracted_dir_for_tier(tier):
    """Get the appropriate extracted contracts directory for a tier."""
    # tier_1 uses tier_1_complete, tier_3 uses tier_3_snippets, etc.
    if tier == "tier_1":
        return EXTRACTED_BASE / "tier_1_complete"
    else:
        # For tier_3, use tier_3_snippets, etc.
        tier_num = tier.replace("tier_", "")
        return EXTRACTED_BASE / f"tier_{tier_num}_snippets"


def load_predictions(filepath):
    """Load predictions from JSON file."""
    with open(filepath) as f:
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

    return {
        "overlap_count": len(overlap),
        "missing_count": len(missing),
        "overlap_percentage": (len(overlap) / len(pred_set) * 100) if pred_set else 0,
        "is_consistent": len(missing) == 0 and len(overlap) > 0,
    }


def generate_report(predictions, tier, extracted_dir):
    """Generate consistency report for a tier."""
    report = {
        "tier": tier,
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


def save_tier_reports(report, tier):
    """Save per-tier reports."""
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

    with open(REPORTS_DIR / f"node_detection_{tier}_detailed_report.json", "w") as f:
        json.dump(report, f, indent=2)

    model_only = {
        "tier": tier,
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

    with open(
        REPORTS_DIR / f"node_detection_{tier}_model_only_predictions.json", "w"
    ) as f:
        json.dump(model_only, f, indent=2)

    return summary


def main():
    print("🔍 Finding all tier prediction files...")
    prediction_files = find_prediction_files()
    print(f"   Found {len(prediction_files)} tier files: {[f.stem for f in prediction_files]}")

    all_summaries = []

    for pred_file in prediction_files:
        tier = extract_tier_from_file(pred_file)
        extracted_dir = get_extracted_dir_for_tier(tier)

        print(f"\n{'='*60}")
        print(f"Processing {tier}...")
        print(f"   Predictions file: {pred_file.name}")
        print(f"   Extracted dir: {extracted_dir}")

        if not extracted_dir.exists():
            print(f"   ⚠️  Extracted directory not found, skipping")
            continue

        print(f"🔍 Loading predictions for {tier}...")
        predictions = load_predictions(pred_file)
        print(f"   Found {len(predictions)} prediction entries")

        print(f"🔄 Generating consistency report for {tier}...")
        report = generate_report(predictions, tier, extracted_dir)

        print(f"💾 Saving {tier} reports...")
        summary = save_tier_reports(report, tier)
        all_summaries.append(summary)

        print(f"✅ Reports generated for {tier}:")
        print(f"   - Summary: node_detection_{tier}_summary_report.json")
        print(f"   - Details: node_detection_{tier}_detailed_report.json")
        print(f"   - Model-only: node_detection_{tier}_model_only_predictions.json")

    # Generate master summary
    print(f"\n{'='*60}")
    print("📊 Generating master summary for all tiers...")
    master_summary = {
        "report_name": "Node Detection Consistency - All Tiers",
        "total_tiers": len(all_summaries),
        "tier_summaries": all_summaries,
        "combined_stats": {
            "total_predictions": sum(s["total_predictions"] for s in all_summaries),
            "total_contracts": sum(s["total_contracts"] for s in all_summaries),
            "total_matches": sum(s["matches"] for s in all_summaries),
            "total_partial_matches": sum(s["partial_matches"] for s in all_summaries),
            "total_mismatches": sum(s["mismatches"] for s in all_summaries),
            "total_flagged_in_audit": sum(s["flagged_in_audit"] for s in all_summaries),
            "total_not_flagged_in_audit": sum(
                s["not_flagged_in_audit"] for s in all_summaries
            ),
        },
    }

    with open(REPORTS_DIR / "node_detection_all_tiers_master_summary.json", "w") as f:
        json.dump(master_summary, f, indent=2)

    print("\n" + "="*60)
    print("✅ ALL REPORTS GENERATED")
    print("="*60)
    print(f"\nMaster Summary: node_detection_all_tiers_master_summary.json")
    print(f"\nPer-Tier Reports:")
    for summary in all_summaries:
        tier = summary["tier"]
        print(
            f"\n  {tier}:"
        )
        print(f"    - Predictions: {summary['total_predictions']}")
        print(f"    - Contracts: {summary['total_contracts']}")
        print(f"    - Matches: {summary['matches']}")
        print(f"    - Mismatches: {summary['mismatches']}")
        print(f"    - Not flagged in audit: {summary['not_flagged_in_audit']}")


if __name__ == "__main__":
    main()
