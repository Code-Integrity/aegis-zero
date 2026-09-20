# utils/formatter.py

import json
from typing import List, Dict, Any

def format_depth4_tree(tree_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Standardizes the structural properties of raw depth4 nodes into clear serializable telemetry blocks.
    """
    formatted = []
    for idx, node in enumerate(tree_data):
        formatted.append({
            "index": idx,
            "category": node.get("category", "Other"),
            "tab": node.get("source_tab", "Unknown"),
            "flow": {
                "depth1_event": node.get("depth1_event"),
                "depth2_surface_cause": node.get("depth2_surface_cause", []),
                "depth3_structural_cause": node.get("depth3_structural_cause", []),
                "depth4_responsibility_drift": node.get("depth4_responsibility_drift", [])
            },
            "flow_correlations": node.get("flow_correlations", [])
        })
    return formatted

def format_llama_payload(prompt_file: str, model_path: str, tree: List[Dict[str, Any]], scoring: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Assembles a unified, structured context payload tracking ledger.
    This creates the definitive target file that the inference engine reads.
    """
    return {
        "metadata": {
            "target_model_tag": model_path,
            "instruction_source_prompt": prompt_file,
            "total_nodes_ingested": len(tree)
        },
        "prioritized_threat_map": scoring,
        "complete_behavioral_tree": tree
    }
