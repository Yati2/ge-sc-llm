#!/usr/bin/env python3
"""Run CFG-only inference for all generated gpickles against all checkpoints.

Because checkpoints were trained on richer schemas (often CFG+CG), this script
uses partial state-dict loading: only parameters with matching names and shapes
are loaded. This allows execution on CFG-only graphs without crashing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple


_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent if _HERE.name == "test" else _HERE
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import torch

from sco_models.model_hgt_with_guardrails import HGTVulGraphClassifier


SETTINGS = {
    "gpickle_dir": "graphs/testing/batch_3/tier_1_cfg_graphs",
    "checkpoint_dir": "checkpoints/graph_detection/nodetype",
    "checkpoint_glob": "*_tree_sitter_cfg_cg_hgt.pth",
    "device": "cpu",
    "output_json": "graphs/testing/batch_3/cfg_only_all_checkpoint_predictions.json",
}


def _repo_root() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent if here.name == "test" else here


def _resolve(path_value: str) -> Path:
    p = Path(path_value)
    if p.is_absolute():
        return p
    return (_repo_root() / p).resolve()


def _partial_load_checkpoint(model: torch.nn.Module, checkpoint_path: Path, device: str) -> Tuple[int, int]:
    state = torch.load(str(checkpoint_path), map_location=device)
    model_state = model.state_dict()

    matched: Dict[str, torch.Tensor] = {}
    for key, tensor in state.items():
        if key in model_state and model_state[key].shape == tensor.shape:
            matched[key] = tensor

    model.load_state_dict(matched, strict=False)
    return len(matched), len(model_state)


def main() -> int:
    gpickle_dir = _resolve(SETTINGS["gpickle_dir"])
    checkpoint_dir = _resolve(SETTINGS["checkpoint_dir"])
    output_json = _resolve(SETTINGS["output_json"])
    checkpoint_glob = SETTINGS["checkpoint_glob"]
    device = SETTINGS["device"]

    if not gpickle_dir.exists():
        print(f"Missing gpickle dir: {gpickle_dir}")
        return 1
    if not checkpoint_dir.exists():
        print(f"Missing checkpoint dir: {checkpoint_dir}")
        return 1

    gpickles = sorted(gpickle_dir.glob("*.gpickle"))
    checkpoints = sorted(checkpoint_dir.glob(checkpoint_glob))

    if not gpickles:
        print(f"No gpickle files found in: {gpickle_dir}")
        return 1
    if not checkpoints:
        print(f"No checkpoint files found in: {checkpoint_dir}")
        return 1

    output_json.parent.mkdir(parents=True, exist_ok=True)

    rows: List[Dict[str, str]] = []
    total_jobs = len(gpickles) * len(checkpoints)
    done = 0
    ok = 0
    err = 0

    for gp in gpickles:
        contract_name = gp.stem + ".sol"
        for ckpt in checkpoints:
            done += 1
            row = {
                "gpickle": str(gp),
                "contract_name": contract_name,
                "checkpoint": str(ckpt),
                "matched_params": "0",
                "total_model_params": "0",
                "match_ratio": "0.0000",
                "predicted_label": "",
                "prob_class_0": "",
                "prob_class_1": "",
                "status": "ok",
                "error": "",
            }

            try:
                model = HGTVulGraphClassifier(
                    str(gp),
                    feature_extractor=None,
                    node_feature="nodetype",
                    device=device,
                )

                matched, total_model = _partial_load_checkpoint(model, ckpt, device)
                ratio = (matched / total_model) if total_model else 0.0
                row["matched_params"] = str(matched)
                row["total_model_params"] = str(total_model)
                row["match_ratio"] = f"{ratio:.4f}"

                model.to(device)
                model.eval()

                with torch.no_grad():
                    logits, _ = model([contract_name])
                    probs = torch.softmax(logits, dim=1)
                    pred = int(torch.argmax(probs, dim=1).item())

                row["predicted_label"] = str(pred)
                row["prob_class_0"] = f"{float(probs[0, 0]):.6f}"
                row["prob_class_1"] = f"{float(probs[0, 1]):.6f}"
                ok += 1
            except Exception as exc:  # pylint: disable=broad-except
                row["status"] = "error"
                row["error"] = f"{type(exc).__name__}: {exc}"
                err += 1

            rows.append(row)

            if done % 25 == 0 or done == total_jobs:
                print(f"Progress {done}/{total_jobs} | ok={ok} | error={err}")

    summary_payload = {
        "gpickle_dir": str(gpickle_dir),
        "checkpoint_dir": str(checkpoint_dir),
        "checkpoint_glob": checkpoint_glob,
        "device": device,
        "total_gpickles": len(gpickles),
        "total_checkpoints": len(checkpoints),
        "total_jobs": total_jobs,
        "ok": ok,
        "error": err,
        "output_json": str(output_json),
    }

    predictions_payload = {
        "summary": summary_payload,
        "meta": {
            "gpickle_dir": str(gpickle_dir),
            "checkpoint_dir": str(checkpoint_dir),
            "checkpoint_glob": checkpoint_glob,
            "device": device,
            "total_gpickles": len(gpickles),
            "total_checkpoints": len(checkpoints),
            "total_jobs": total_jobs,
        },
        "rows": rows,
    }
    output_json.write_text(json.dumps(predictions_payload, indent=2), encoding="utf-8")

    print("Done")
    print(json.dumps(summary_payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
