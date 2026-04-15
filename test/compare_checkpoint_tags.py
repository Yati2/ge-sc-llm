#!/usr/bin/env python3
"""Compare checkpoint predictions against JSON tag metadata.

Default inputs:
- Predictions JSON: graphs/testing/cfg_only_all_checkpoint_predictions.json
- JSON directory: data_collection/extracted_contracts/tier_1_complete
- Output directory: graphs/testing/consistency_reports

Tag metadata extracted per contract:
- existing_tag, tag_present, tag_correct
- suggested_tag and confidence
- mando/scsvs primary categories and confidences

consistency_status derivation:
- errors_only_excluded: no successful checkpoint rows and at least one error row
- no_prediction_rows: no checkpoint rows for the contract in predictions JSON
- no_positive_prediction: has successful rows, but none with predicted_label == "1"
- match: has at least one positive prediction and suitable_tag == pred_highest_prob
- mismatch: has at least one positive prediction and suitable_tag != pred_highest_prob,
    or either value is missing

Notes:
- pred_highest_prob is the checkpoint_tag with maximum prob_class_1 among rows where
    predicted_label == "1".
- suitable_tag uses existing_tag only when tag_correct is true; otherwise it picks the
    highest-confidence tag among suggested_tag, mando_primary_category, and
    scsvs_primary_category_name.

Core comparison excludes rows with runtime errors, but errors are reported
separately in a dedicated audit file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional


SETTINGS = {
    "predictions_json": "graphs/testing/cfg_only_all_checkpoint_predictions.json",
    "json_dir": "data_collection/extracted_contracts/tier_1_complete",
    "output_dir": "graphs/testing/consistency_reports",
}


def _repo_root() -> Path:
    here = Path(__file__).resolve().parent
    # Script may live under test/, while inputs/outputs are repo-root relative.
    return here.parent if here.name == "test" else here


def _resolve(path_value: str) -> Path:
    p = Path(path_value)
    if p.is_absolute():
        return p
    return (_repo_root() / p).resolve()


def _to_bool(value) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v == "true":
            return True
        if v == "false":
            return False
    return None


def _clean_tag(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.lower() in {"null", "none", "false", "n/a", "na"}:
        return None
    return text


def _as_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _checkpoint_to_tag(checkpoint_path: str) -> str:
    base = Path(checkpoint_path).name
    if base.endswith(".pth"):
        base = base[:-4]
    if "_tree_sitter_" in base:
        return base.split("_tree_sitter_")[0]
    if base.endswith("_hgt"):
        return base[: -len("_hgt")]
    return base


def _normalize_tag(value: Optional[str]) -> str:
    tag = _clean_tag(value)
    if not tag:
        return ""
    tag = tag.lower().replace("-", "_").replace("/", "_")
    tag = re.sub(r"\s+", "_", tag)
    tag = re.sub(r"[^a-z0-9_]", "", tag)
    return re.sub(r"_+", "_", tag).strip("_")


def _extract_tag_metadata(json_obj: Dict) -> Dict[str, str]:
    validation = json_obj.get("validation", {}) if isinstance(json_obj, dict) else {}
    report_tag = validation.get("report_tag_validation", {}) if isinstance(validation, dict) else {}
    mando = validation.get("mando_classification", {}) if isinstance(validation, dict) else {}
    scsvs = validation.get("scsvs_classification", {}) if isinstance(validation, dict) else {}

    existing_tag = _clean_tag(report_tag.get("existing_tag"))
    tag_correct = _to_bool(report_tag.get("tag_correct"))
    tag_present = _to_bool(report_tag.get("tag_present"))

    suggested_tag = _clean_tag(report_tag.get("suggested_tag"))
    suggested_conf = _as_float(report_tag.get("confidence"))

    mando_primary = _clean_tag(mando.get("primary_category"))
    mando_conf = _as_float(mando.get("confidence"))

    scsvs_primary = _clean_tag(scsvs.get("primary_category_name"))
    scsvs_conf = _as_float(scsvs.get("confidence"))

    if existing_tag and tag_correct is True:
        suitable_tag = _normalize_tag(existing_tag)
    else:
        candidates = [
            (_normalize_tag(suggested_tag), suggested_conf),
            (_normalize_tag(mando_primary), mando_conf),
            (_normalize_tag(scsvs_primary), scsvs_conf),
        ]
        valid_candidates = [(tag, conf) for tag, conf in candidates if tag]
        suitable_tag = max(valid_candidates, key=lambda x: x[1])[0] if valid_candidates else ""


    return {
        "existing_tag": existing_tag or "",
        "tag_present": "" if tag_present is None else str(tag_present),
        "tag_correct": "" if tag_correct is None else str(tag_correct),
        "suggested_tag": suggested_tag or "",
        "suggested_confidence": f"{suggested_conf:.2f}",
        "mando_primary_category": mando_primary or "",
        "mando_confidence": f"{mando_conf:.2f}",
        "scsvs_primary_category": scsvs_primary or "",
        "scsvs_confidence": f"{scsvs_conf:.2f}",
        "suitable_tag": suitable_tag,
    }


def _load_json_map(json_dir: Path) -> Dict[str, Dict]:
    data: Dict[str, Dict] = {}
    for json_path in sorted(json_dir.glob("*.json")):
        try:
            obj = json.loads(json_path.read_text(encoding="utf-8"))
            filename = obj.get("filename") if isinstance(obj, dict) else None
            key = filename if isinstance(filename, str) and filename else json_path.stem + ".sol"
            data[key] = obj
        except Exception:
            continue
    return data


def _write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _base_file_row(contract_name: str, selection: Dict[str, str]) -> Dict[str, str]:
    return {
        "contract_name": contract_name,
        "existing_tag": selection["existing_tag"],
        "tag_present": selection["tag_present"],
        "tag_correct": selection["tag_correct"],
        "suggested_tag": selection["suggested_tag"],
        "suggested_confidence": selection["suggested_confidence"],
        "mando_primary_category": selection["mando_primary_category"],
        "mando_confidence": selection["mando_confidence"],
        "scsvs_primary_category": selection["scsvs_primary_category"],
        "scsvs_confidence": selection["scsvs_confidence"],
        "suitable_tag": selection["suitable_tag"],
    }


def _checkpoint_prediction_entry(
    checkpoint_name: str,
    checkpoint_tag: str,
    pred_label: str,
    prob0: str,
    prob1: str,
) -> Dict[str, str]:
    return {
        "checkpoint_name": checkpoint_name,
        "checkpoint_tag": checkpoint_tag,
        "predicted_label": pred_label,
        "prob_class_0": prob0,
        "prob_class_1": prob1,
    }


def build_reports(predictions_json: Path, json_dir: Path, output_dir: Path) -> Dict[str, Path]:
    json_map = _load_json_map(json_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    per_file: Dict[str, Dict] = {}
    checkpoint_rows: List[Dict[str, str]] = []

    payload = json.loads(predictions_json.read_text(encoding="utf-8"))
    rows_input = payload.get("rows", []) if isinstance(payload, dict) else []

    for row in rows_input:
        if not isinstance(row, dict):
            continue

        contract_name = (row.get("contract_name") or "").strip()
        if not contract_name:
            continue

        status = (row.get("status") or "").strip().lower()
        checkpoint_path = (row.get("checkpoint") or "").strip()
        checkpoint_name = Path(checkpoint_path).name
        checkpoint_tag = _checkpoint_to_tag(checkpoint_path)
        pred_label = (row.get("predicted_label") or "").strip()

        file_entry = per_file.setdefault(
            contract_name,
            {
                "rows_total": 0,
                "rows_ok": 0,
                "rows_error": 0,
                "all_checkpoint_tags": set(),
                "error_messages": set(),
                "positive_checkpoints": [],
                "positive_tags": set(),
                "all_checkpoint_predictions": [],
                "positive_checkpoint_predictions": [],
            },
        )

        file_entry["rows_total"] += 1
        file_entry["all_checkpoint_tags"].add(checkpoint_tag)

        if status == "ok":
            file_entry["rows_ok"] += 1
            prob0 = (row.get("prob_class_0") or "").strip()
            prob1 = (row.get("prob_class_1") or "").strip()

            checkpoint_prediction = _checkpoint_prediction_entry(
                checkpoint_name,
                checkpoint_tag,
                pred_label,
                prob0,
                prob1,
            )
            file_entry["all_checkpoint_predictions"].append(checkpoint_prediction)

            if pred_label == "1":
                file_entry["positive_checkpoints"].append(checkpoint_name)
                file_entry["positive_tags"].add(checkpoint_tag)
                file_entry["positive_checkpoint_predictions"].append(checkpoint_prediction)
        else:
            file_entry["rows_error"] += 1
            err = (row.get("error") or "").strip()
            if err:
                file_entry["error_messages"].add(err)

        checkpoint_rows.append(
            {
                "contract_name": contract_name,
                "checkpoint_name": checkpoint_name,
                "checkpoint_tag": checkpoint_tag,
                "status": status,
                "predicted_label": pred_label,
                "prob_class_0": (row.get("prob_class_0") or "").strip(),
                "prob_class_1": (row.get("prob_class_1") or "").strip(),
                "match_ratio": (row.get("match_ratio") or "").strip(),
                "error": (row.get("error") or "").strip(),
            }
        )

    all_contracts = sorted(set(json_map.keys()) | set(per_file.keys()))
    full_file_rows: List[Dict[str, str]] = []
    filtered_file_rows: List[Dict[str, str]] = []
    no_prediction_rows: List[Dict[str, str]] = []
    filtered_checkpoint_rows: List[Dict[str, str]] = []
    error_checkpoint_rows: List[Dict[str, str]] = []

    summary = {
        "total_files_in_universe": 0,
        "files_with_predictions": 0,
        "files_with_no_predictions": 0,
        "files_with_json": 0,
        "files_with_positive_predictions": 0,
        "files_tag_evaluated": 0,
        "files_tag_match": 0,
        "files_tag_mismatch": 0,
        "files_no_positive_prediction": 0,
        "files_excluded_errors_only": 0,
        "checkpoint_rows_total": 0,
        "checkpoint_rows_included": 0,
        "checkpoint_rows_excluded_error": 0,
    }

    for contract_name in all_contracts:
        summary["total_files_in_universe"] += 1

        json_obj = json_map.get(contract_name)

        selection = _extract_tag_metadata(json_obj or {})

        file_entry = per_file.get(
            contract_name,
            {
                "rows_total": 0,
                "rows_ok": 0,
                "rows_error": 0,
                "all_checkpoint_tags": set(),
                "error_messages": set(),
                "positive_checkpoints": [],
                "positive_tags": set(),
                "all_checkpoint_predictions": [],
                "positive_checkpoint_predictions": [],
          
            },
        )

        rows_total = int(file_entry["rows_total"])
        rows_ok = int(file_entry["rows_ok"])
        rows_error = int(file_entry["rows_error"])
        positive_tags = sorted(file_entry["positive_tags"])

        pred_highest_prob = ""
        highest_prob = -1.0
        for pred in file_entry["all_checkpoint_predictions"]:
            if pred.get("predicted_label") != "1":
                continue
            prob1 = _as_float(pred.get("prob_class_1"), default=-1.0)
            if prob1 > highest_prob:
                highest_prob = prob1
                pred_highest_prob = pred.get("checkpoint_tag", "")

        if rows_total > 0:
            summary["files_with_predictions"] += 1
        else:
            summary["files_with_no_predictions"] += 1


        if rows_ok > 0 and positive_tags:
            summary["files_with_positive_predictions"] += 1

        if rows_total == 0:
            consistency_status = "no_prediction_rows"
        elif rows_ok == 0 and rows_error > 0:
            consistency_status = "errors_only_excluded"
            summary["files_excluded_errors_only"] += 1

        elif not positive_tags:
            consistency_status = "no_positive_prediction"
            summary["files_tag_evaluated"] += 1
            summary["files_no_positive_prediction"] += 1

        else:
            suitable_tag = selection["suitable_tag"]
            if suitable_tag and pred_highest_prob and suitable_tag == pred_highest_prob:
                consistency_status = "match"
                summary["files_tag_match"] += 1
            else:
                consistency_status = "mismatch"
                summary["files_tag_mismatch"] += 1
            summary["files_tag_evaluated"] += 1

        row = {
            "consistency_status": consistency_status,
            **_base_file_row(contract_name, selection),
            "total_checkpoints": str(rows_total),
            "ok_rows": str(rows_ok),
            "error_rows": str(rows_error),
            "pred_highest_prob": pred_highest_prob,
            "error_messages": "|".join(sorted(file_entry["error_messages"])),
            "all_checkpoint_predictions": file_entry["all_checkpoint_predictions"],
        }
        full_file_rows.append(row)

        if rows_ok > 0:
            filtered_file_rows.append(row)

        if rows_total == 0:
            no_prediction_rows.append(
                {
                    **_base_file_row(contract_name, selection ),
                    "audit_status": "no_predictions_found_in_json",
                }
            )

    for row in checkpoint_rows:
        summary["checkpoint_rows_total"] += 1

        if row["status"] != "ok":
            summary["checkpoint_rows_excluded_error"] += 1
            error_checkpoint_rows.append(
                {
                    **row,
                    "row_interpretation": "runtime_error_excluded",
                }
            )
            continue

        summary["checkpoint_rows_included"] += 1
        pred = row["predicted_label"]
        if pred == "1":
            interpretation = "positive_prediction"
        elif pred == "0":
            interpretation = "negative_prediction"
        else:
            interpretation = "unknown"

        filtered_checkpoint_rows.append(
            {
                **row,
                "row_interpretation": interpretation,
            }
        )

    file_headers = [
        "contract_name",

        "existing_tag",
        "tag_present",
        "tag_correct",
        "suggested_tag",
        "suggested_confidence",
        "mando_primary_category",
        "mando_confidence",
        "scsvs_primary_category",
        "scsvs_confidence",
        "suitable_tag",
        "total_checkpoints",
        "ok_rows",
        "error_rows",
        "pred_highest_prob",
        "error_messages",
        "consistency_status",
        "all_checkpoint_predictions",
    ]

    no_prediction_headers = [
        "contract_name",
        "existing_tag",
        "tag_present",
        "tag_correct",
        "suggested_tag",
        "suggested_confidence",
        "mando_primary_category",
        "mando_confidence",
        "scsvs_primary_category",
        "scsvs_confidence",
        "suitable_tag",
        "audit_status",
    ]

    

    # JSON reports for easier human review.
    per_file_json = output_dir / "checkpoint_tag_comparison_per_file.json"
    _write_json(
        per_file_json,
        {
            "meta": {
                "predictions_json": str(predictions_json),
                "json_dir": str(json_dir),
            },
            "summary": summary,
            "files_included_for_tag_comparison": filtered_file_rows,
            "all_files": full_file_rows,
        },
    )

    excluded_errors_json = output_dir / "checkpoint_tag_excluded_error_records.json"
    _write_json(
        excluded_errors_json,
        {
            "meta": {
                "predictions_json": str(predictions_json),
                "json_dir": str(json_dir),
            },
            "excluded_error_checkpoint_rows": error_checkpoint_rows,
        },
    )

    no_predictions_json = output_dir / "checkpoint_tag_no_prediction_files.json"
    _write_json(
        no_predictions_json,
        {
            "meta": {
                "predictions_json": str(predictions_json),
                "json_dir": str(json_dir),
            },
            "no_prediction_files": no_prediction_rows,
        },
    )

    return {
        "per_file_report_json": per_file_json,
        "excluded_error_checkpoints_json": excluded_errors_json,
        "no_prediction_files_json": no_predictions_json,
    }


def main() -> int:
    predictions_json = _resolve(SETTINGS["predictions_json"])
    json_dir = _resolve(SETTINGS["json_dir"])
    output_dir = _resolve(SETTINGS["output_dir"])

    if not predictions_json.exists():
        print(f"Missing predictions JSON: {predictions_json}")
        return 1
    if not json_dir.exists():
        print(f"Missing JSON directory: {json_dir}")
        return 1

    outputs = build_reports(predictions_json=predictions_json, json_dir=json_dir, output_dir=output_dir)

    preferred_order = [
        "per_file_report_json",
        "excluded_error_checkpoints_json",
        "no_prediction_files_json",
    ]

    for key in preferred_order:
        if key in outputs:
            print(f"Generated ({key}): {outputs[key]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
