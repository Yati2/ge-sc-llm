#!/usr/bin/env python3
"""Run node-level inference and map vulnerable nodes to source line ranges.

Edit SETTINGS dict below to configure a single graph or a batch directory,
checkpoint, and node feature type. Outputs JSON with detected vulnerable
nodes and their line ranges.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import torch

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent if _HERE.name == "test" else _HERE
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sco_models.model_hgt_with_guardrails import HGTVulNodeClassifier
from sco_models.graph_utils import load_hetero_nx_graph

SETTINGS = {
    "batch_dir": str(_REPO_ROOT / "graphs/testing/batch_1"),
    "checkpoint": str(
        _REPO_ROOT
        / "checkpoints/node_detection/nodetype/reentrancy_tree_sitter_cfg_cg_hgt.pth"
    ),
    "node_feature": "nodetype",
    "device": "cpu",
}


def compact_spans(values):
    """Convert a sorted list of line numbers into contiguous spans."""
    if not values:
        return []
    spans = []
    start = prev = values[0]
    for value in values[1:]:
        if value == prev + 1:
            prev = value
            continue
        spans.append([start, prev] if start != prev else [start])
        start = prev = value
    spans.append([start, prev] if start != prev else [start])
    return spans


def summarize_vulnerabilities(vulnerable_nodes):
    """Summarize vulnerable nodes by file and method with compact line spans."""
    grouped = {}
    for item in vulnerable_nodes:
        key = (item.get("source_file"), item.get("method"))
        grouped.setdefault(key, set())
        lines = item.get("lines") or []
        if isinstance(lines, int):
            grouped[key].add(lines)
        else:
            for line in lines:
                try:
                    grouped[key].add(int(line))
                except Exception:
                    continue

    summary = []
    for (source_file, method), lines in sorted(
        grouped.items(), key=lambda x: (x[0][0] or "", x[0][1] or "")
    ):
        sorted_lines = sorted(lines)
        summary.append(
            {
                "source_file": source_file,
                "method": method,
                "node_count": sum(
                    1
                    for item in vulnerable_nodes
                    if item.get("source_file") == source_file
                    and item.get("method") == method
                ),
                "line_count": len(sorted_lines),
                "lines": sorted_lines,
                "line_spans": compact_spans(sorted_lines),
            }
        )

    return summary


def safe_lines(node_data):
    lines = node_data.get("node_source_code_lines")
    if lines is None:
        return None
    if isinstance(lines, str):
        try:
            return ast.literal_eval(lines)
        except Exception:
            return None
    return lines


def patch_graph(graph_path: Path):
    """Load a graph and ensure required node attributes exist."""
    import networkx as nx

    try:
        nxg = nx.read_gpickle(str(graph_path))
    except Exception:
        nxg = load_hetero_nx_graph(str(graph_path))

    missing = False
    for _, node_data in nxg.nodes(data=True):
        if "node_info_vulnerabilities" not in node_data:
            node_data["node_info_vulnerabilities"] = None
            missing = True

    if missing:
        patched_graph_path = Path(
            str(graph_path).replace(".gpickle", "_patched.gpickle")
        )
        nx.write_gpickle(nxg, str(patched_graph_path))
        print(f"ℹ️  Patched graph written to: {patched_graph_path}")
        return patched_graph_path

    return graph_path


def load_checkpoint(model, ckpt_path: Path, device: str):
    state = torch.load(str(ckpt_path), map_location=device)
    # accept OrderedDict/state_dict or a checkpoint dict containing 'state_dict'
    if isinstance(state, dict):
        sd = state.get("state_dict", state)
        # try strict load first
        try:
            model.load_state_dict(sd)
            return
        except Exception:
            pass

        # try non-strict load
        try:
            model.load_state_dict(sd, strict=False)
            print(
                f"⚠️  Loaded checkpoint {ckpt_path} with strict=False (missing/extra keys tolerated)"
            )
            return
        except Exception:
            pass

        # helper to remap keys
        def remap_keys(d, strip_prefix=None, add_prefix=None):
            new = {}
            for k, v in d.items():
                nk = k
                if strip_prefix and nk.startswith(strip_prefix):
                    nk = nk[len(strip_prefix) :]
                if add_prefix:
                    nk = add_prefix + nk
                new[nk] = v
            return new

        # try stripping a common 'module.' prefix
        try:
            sd2 = remap_keys(sd, strip_prefix="module.")
            model.load_state_dict(sd2, strict=False)
            print(f"⚠️  Loaded checkpoint {ckpt_path} after stripping 'module.' prefix")
            return
        except Exception:
            pass

        # try adding 'module.' prefix
        try:
            sd3 = remap_keys(sd, add_prefix="module.")
            model.load_state_dict(sd3, strict=False)
            print(f"⚠️  Loaded checkpoint {ckpt_path} after adding 'module.' prefix")
            return
        except Exception:
            pass

    raise RuntimeError(
        f"Couldn't load checkpoint {ckpt_path} - unsupported format or incompatible state_dict"
    )


def run_for_graph(graph_path: Path, ckpt_path: Path, node_feature: str, device: str):
    model_graph_path = patch_graph(graph_path)
    nxg = load_hetero_nx_graph(str(model_graph_path))

    print(f"🤖 Loading checkpoint: {ckpt_path}")
    model = HGTVulNodeClassifier(
        str(model_graph_path),
        feature_extractor=None,
        node_feature=node_feature,
        device=device,
    )
    load_checkpoint(model, ckpt_path, device)
    model.to(device)
    model.eval()

    print(f"🔍 Running inference on {len(nxg)} nodes...")
    with torch.no_grad():
        logits = model()
        probs = torch.softmax(logits, dim=1)
        preds = torch.argmax(probs, dim=1).cpu().numpy()

    vulnerable = []
    for node_id, node_data in nxg.nodes(data=True):
        try:
            pred = int(preds[int(node_id)])
        except Exception:
            pred = None
        if pred == 1:
            vulnerable.append(
                {
                    "node_id": int(node_id),
                    "lines": safe_lines(node_data),
                    "source_file": node_data.get("source_file"),
                    "method": node_data.get("method"),
                }
            )

    return {
        "graph": str(graph_path),
        "checkpoint": str(ckpt_path),
        "node_feature": node_feature,
        "device": device,
        "total_nodes": len(nxg),
        "vulnerable_nodes_count": len(vulnerable),
        "vulnerability_summary": summarize_vulnerabilities(vulnerable),
        "vulnerable_nodes": vulnerable,
    }


def main() -> int:
    graph_path = SETTINGS.get("graph")
    batch_dir = SETTINGS.get("batch_dir")
    ckpt_path = Path(SETTINGS["checkpoint"])
    node_feature = SETTINGS["node_feature"]
    device = SETTINGS["device"]
    if not ckpt_path.exists():
        print(f"❌ Missing checkpoint: {ckpt_path}")
        return 1

    if graph_path:
        graph_path = Path(graph_path)
        if not graph_path.exists():
            print(f"❌ Missing graph: {graph_path}")
            return 1
        print(f"📊 Loading graph: {graph_path}")
        out = run_for_graph(graph_path, ckpt_path, node_feature, device)
        print(f"\n✅ Found {out['vulnerable_nodes_count']} vulnerable nodes")
        print(json.dumps(out, indent=2))
        return 0

    batch_dir = Path(batch_dir) if batch_dir else None
    if not batch_dir or not batch_dir.exists():
        print(f"❌ Missing batch directory: {batch_dir}")
        return 1

    graph_files = sorted(batch_dir.glob("tier_*_cfg_graphs/*.gpickle"))
    if not graph_files:
        print(f"❌ No gpickle graphs found under: {batch_dir}")
        return 1

    print(f"📊 Running batch inference under: {batch_dir}")
    print(f"📁 Found {len(graph_files)} graphs across all tiers")

    tier_groups = {}
    for graph_file in graph_files:
        tier_name = graph_file.parent.name
        tier_groups.setdefault(tier_name, []).append(graph_file)

    summary_rows = []
    for tier_name, tier_graphs in sorted(tier_groups.items()):
        print(f"\n📦 Tier {tier_name}: {len(tier_graphs)} graphs")
        tier_rows = []
        for index, graph_file in enumerate(tier_graphs, start=1):
            print(f"[{index}/{len(tier_graphs)}] {graph_file.name}")
            try:
                tier_rows.append(
                    run_for_graph(graph_file, ckpt_path, node_feature, device)
                )
            except Exception as exc:
                tier_rows.append(
                    {
                        "graph": str(graph_file),
                        "checkpoint": str(ckpt_path),
                        "node_feature": node_feature,
                        "device": device,
                        "total_nodes": 0,
                        "vulnerable_nodes_count": 0,
                        "vulnerable_nodes": [],
                        "error": str(exc),
                    }
                )

        tier_output_json = batch_dir / f"{tier_name}_node_level_predictions.json"
        tier_out = {
            "summary": {
                "batch_dir": str(batch_dir),
                "tier": tier_name,
                "checkpoint": str(ckpt_path),
                "node_feature": node_feature,
                "device": device,
                "total_graphs": len(tier_graphs),
                "ok": sum(1 for row in tier_rows if not row.get("error")),
                "error": sum(1 for row in tier_rows if row.get("error")),
                "output_json": str(tier_output_json),
            },
            "rows": tier_rows,
        }
        tier_output_json.write_text(json.dumps(tier_out, indent=2), encoding="utf-8")
        summary_rows.append(tier_out["summary"])
        print(f"✅ Wrote tier output to {tier_output_json}")

    out = {
        "summary": {
            "batch_dir": str(batch_dir),
            "checkpoint": str(ckpt_path),
            "node_feature": node_feature,
            "device": device,
            "tiers": len(tier_groups),
            "total_graphs": len(graph_files),
        },
        "tier_summaries": summary_rows,
    }

    manifest_json = batch_dir / "node_level_predictions_manifest.json"
    manifest_json.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\n✅ Wrote batch manifest to {manifest_json}")
    print(json.dumps(out["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
