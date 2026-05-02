#!/usr/bin/env python3
"""Generate CFG graphs for Solidity files and print summary metrics.

This script is designed for the ge-sc-llm workspace and defaults to:
- Input: data_collection/extracted_contracts/tier_1_complete
- Output: graphs/testing/tier_1_complete_cfg_tree_sitter
- Tree-sitter build dir: graphs/testing/tree_sitter_build
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import Dict, List

import networkx as nx


# Edit these values directly when you want to change input/output locations.
SETTINGS = {
    "input_dir": "../data_collection/batch_4_extracted_contracts/tier_1_complete",
    "output_dir": "../graphs/testing/batch_4/tier_1_complete_cfg_graphs",
    "tree_sitter_build_dir": "../graphs/testing/tree_sitter_build",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parent


def _workspace_root() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent if here.name == "test" else here


def _resolve_setting_path(repo_root: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (repo_root / path).resolve()


def _ensure_import_path(repo_root: Path) -> None:
    repo_root_str = str(repo_root)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)


def _ensure_vendor_symlink(repo_root: Path) -> None:
    """Match expected parser vendor path used by custom_parser._get_vendor_paths."""
    target_vendor = repo_root / "process_graphs" / "tree_sitter_codeviews" / "vendor"
    expected_vendor = repo_root / "app" / "sco" / "process_graphs" / "tree_sitter_codeviews" / "vendor"

    expected_vendor.parent.mkdir(parents=True, exist_ok=True)
    if expected_vendor.exists() or expected_vendor.is_symlink():
        return
    expected_vendor.symlink_to(target_vendor)


def _build_language_library(repo_root: Path, build_dir: Path) -> str:
    """Build and/or load tree-sitter library for Solidity."""
    _ensure_import_path(repo_root)
    _ensure_vendor_symlink(repo_root)

    build_dir.mkdir(parents=True, exist_ok=True)
    os.environ["TREE_SITTER_LIB_DIR"] = str(build_dir)

    from process_graphs.tree_sitter_codeviews.tree_parser.custom_parser import (  # pylint: disable=import-outside-toplevel
        _initialize_languages,
    )

    lib_path, _ = _initialize_languages()
    return lib_path


def _is_parser_side_cfg_bug(error_msg: str) -> bool:
    return "update_node_id" in error_msg and "UnboundLocalError" in error_msg


def generate_graphs(input_dir: Path, output_dir: Path) -> Dict[str, object]:
    from process_graphs.tree_sitter_codeviews.control_flow_graph_tree_sitter_generator import (  # pylint: disable=import-outside-toplevel
        tree_sitter_generate_cfg,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    sol_files = sorted(input_dir.rglob("*.sol"))

    summary: Dict[str, object] = {
        "input_dir": str(input_dir),
        "output_dir": str(output_dir),
        "total_sol_files": len(sol_files),
        "success": 0,
        "failed": 0,
        "parser_side_cfg_bug_files": [],
        "results": [],
    }

    parser_bug_files: List[str] = []

    for idx, sol in enumerate(sol_files, 1):
        rel = sol.relative_to(input_dir)
        stem = rel.with_suffix("")
        dot_path = output_dir / f"{stem}.dot"
        gpickle_path = output_dir / f"{stem}.gpickle"
        dot_path.parent.mkdir(parents=True, exist_ok=True)

        item: Dict[str, object] = {
            "source": str(sol),
            "dot": str(dot_path),
            "gpickle": str(gpickle_path),
            "status": "ok",
            "nodes": 0,
            "edges": 0,
        }

        try:
            src = sol.read_text(encoding="utf-8", errors="ignore")
            graph = tree_sitter_generate_cfg(
                src,
                ori_name=sol.name,
                src_language="solidity",
                CFG_output=str(dot_path),
            )
            nx.write_gpickle(graph, gpickle_path)
            item["nodes"] = int(graph.number_of_nodes())
            item["edges"] = int(graph.number_of_edges())
            summary["success"] = int(summary["success"]) + 1
        except Exception as exc:  # pylint: disable=broad-except
            err = f"{type(exc).__name__}: {exc}"
            item["status"] = "error"
            item["error"] = err
            item["traceback"] = traceback.format_exc(limit=2)
            summary["failed"] = int(summary["failed"]) + 1

            if _is_parser_side_cfg_bug(err):
                parser_bug_files.append(sol.name)

        cast_results = summary["results"]
        assert isinstance(cast_results, list)
        cast_results.append(item)

        if idx % 10 == 0:
            print(f"Processed {idx}/{len(sol_files)}")

    summary["parser_side_cfg_bug_files"] = sorted(parser_bug_files)
    return summary


def main() -> int:
    repo_root = _repo_root()
    workspace_root = _workspace_root()

    input_dir = _resolve_setting_path(repo_root, SETTINGS["input_dir"])
    output_dir = _resolve_setting_path(repo_root, SETTINGS["output_dir"])
    build_dir = _resolve_setting_path(repo_root, SETTINGS["tree_sitter_build_dir"])

    if not input_dir.exists():
        print(f"Input directory not found: {input_dir}")
        return 1

    _ensure_import_path(workspace_root)
    lib_path = _build_language_library(workspace_root, build_dir)
    print(f"Using tree-sitter library: {lib_path}")

    summary = generate_graphs(input_dir, output_dir)

    summary_path = output_dir / "generation_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    total = int(summary["total_sol_files"])
    success = int(summary["success"])
    failed = int(summary["failed"])
    parser_bug_files = summary.get("parser_side_cfg_bug_files", [])
    parser_bug_count = len(parser_bug_files) if isinstance(parser_bug_files, list) else 0

    print(f"Processed {total} files")
    print(f"Success: {success} | Failed: {failed}")
    if parser_bug_count:
        print(f"Parser-side CFG bug file count: {parser_bug_count}")
    print(f"Summary: {summary_path}")

    if failed == parser_bug_count and failed > 0:
        print(f"{total} processed, {success} success, {failed} failed due to parser-side CFG bug on specific files.")
    else:
        print(f"{total} processed, {success} success, {failed} failed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())