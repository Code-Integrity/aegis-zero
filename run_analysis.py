import json
import os
import sys
from typing import List, Dict, Any

# ---------------------------------------------------------
# Utilities & I/O Components
# ---------------------------------------------------------
from utils.file_io import load_json, save_json, save_text
from utils.logger import log
from utils.formatter import format_depth4_tree, format_llama_payload

# ---------------------------------------------------------
# Recon & Analysis Core Modules
# ---------------------------------------------------------
from recon.depth4_tree import preprocess_devtools_logs_depth4
from recon.scoring import preprocess_and_score_logs

# ---------------------------------------------------------
# Vulnerability Static Auditors
# ---------------------------------------------------------
from auditors.js_domxss_auditor import aegis_js_scan

# ---------------------------------------------------------
# LLM Inference Orchestration
# ---------------------------------------------------------
from models.inference_engine import run_llama_inference


def load_config() -> Dict[str, Any]:
    """
    Loads unified configuration JSON files from the config directory.
    """
    config_dir = "config"

    def load(name: str) -> Dict[str, Any]:
        path = os.path.join(config_dir, name)
        return load_json(path) or {}

    return {
        "model": load("model.json"),
        "paths": load("paths.json"),
        "settings": load("settings.json")
    }


def main() -> None:
    """
    Main entry point for Aegis-Zero Self-Driven Security Analysis Framework.
    Orchestrates DevTools log ingestion, Depth4 tree construction, 
    vulnerability scoring, AI inference, and targeted auditor feedback loop.
    """
    log("=== AEGIS-ZERO Recon Engine (Optimized Auto-Inference Mode) ===")

    # [Step 1] Configuration Ingestion
    log("[1] Loading configuration schemas...")
    cfg = load_config()
    model_cfg = cfg["model"]
    paths = cfg["paths"]
    settings = cfg["settings"]

    # [Step 1.5] Enforce Output Directory Tree Existence
    # Ensure all target output directories exist on the local file system before writing artifacts
    for path_key, path_val in paths.items():
        if path_key.endswith("_output") or path_key in ["llama_payload", "llama_output"]:
            if path_val:  # Defensive guard for None/empty values
                os.makedirs(os.path.dirname(path_val), exist_ok=True)

    # [Step 2] DevTools Raw Log Ingestion
    log("[2] Loading raw DevTools trace logs from target browser session...")
    network_logs = load_json(paths.get("network_file")) or []
    console_logs = load_json(paths.get("console_file")) or []
    storage_logs = load_json(paths.get("storage_file")) or []
    sources_logs = load_json(paths.get("sources_file")) or []

    # [Step 3] Depth4 Structural Tree Generation
    log("[3] Normalizing logs and constructing Depth4 structural tree...")
    # Leveraging the enhanced depth4_tree module with correlational flow tracing
    depth4_tree_json = preprocess_devtools_logs_depth4(
        network_logs, console_logs, storage_logs, sources_logs
    )
    depth4_tree = json.loads(depth4_tree_json)

    # Export structured depth4 analysis artifacts
    formatted_tree = format_depth4_tree(depth4_tree)
    save_json(paths.get("depth4_output"), formatted_tree)
    log(f"[OK] Depth4 structural tree successfully exported -> {paths.get('depth4_output')}")

    # [Step 4] Risk Scoring & Prioritization
    scored_tree = []
    if settings.get("enable_scoring", True):
        log("[4] Executing tactical vulnerability scoring and threat sorting...")
        # Generates prioritized nodes sorted in descending order of risk score
        scored_tree = preprocess_and_score_logs(
            network_logs, console_logs, storage_logs, sources_logs
        )
        save_json(paths.get("scoring_output"), scored_tree)
        log(f"[OK] Scoring and sorting metrics exported -> {paths.get('scoring_output')}")

    # [Step 5] LLM Prompt & Context Payload Assembly
    if settings.get("enable_llama_payload", True):
        log("[5] Formulating structured context payload for LLM inference backend...")
        llama_payload = format_llama_payload(
            model_cfg.get("prompt_file"),
            model_cfg.get("llama_model_path"),
            depth4_tree,
            scored_tree
        )
        save_json(paths.get("llama_payload"), llama_payload)
        log(f"[OK] LLM-ready prompt context successfully serialized -> {paths.get('llama_payload')}")

    # [Step 6] Automated AI Structural Reasoning
    if settings.get("enable_llama_inference", True):
        log("[6] Launching autonomous LLM structural inference engine...")
        llama_output = run_llama_inference()
        save_text(paths.get("llama_output"), llama_output)
        log(f"[OK] Autonomous security reasoning complete -> {paths.get('llama_output')}")

    # [Step 7] Smart Feedback Loop: Targeted Static Auditing (Recon-to-Audit Link)
    if settings.get("enable_targeted_auditor", True) and scored_tree:
        log("[7] Evaluating 'High/Medium' priority nodes to trigger precision Auditors...")
        
        # Extract high-confidence static auditing targets (URLs / endpoints) from prioritized recon nodes
        audit_targets = set()
        for node in scored_tree:
            if node.get("vuln_level") in ["High", "Medium"]:
                # Isolate target asset identifiers (e.g., source file URLs or target endpoints)
                raw_event = node.get("raw", {}).get("event")
                source_tab = node.get("source_tab")
                
                if source_tab in ["Network", "Sources"] and raw_event:
                    # Filter for legitimate web URLs to analyze
                    if raw_event.startswith("http://") or raw_event.startswith("https://"):
                        audit_targets.add(raw_event)

        # Automatically deploy JavaScript Static Auditors on high-suspicion surface targets
        if audit_targets:
            log(f"[!] Isolated {len(audit_targets)} high-suspicion attack vectors for specialized verification.")
            for target_url in audit_targets:
                log(f"[+] Deploying DOM-Based XSS Auditor against target: {target_url}")
                try:
                    # Trigger the static audit layer seamlessly
                    aegis_js_scan(target_url)
                except Exception as audit_error:
                    log(f"[ERROR] Auditor execution failed for target {target_url}: {str(audit_error)}")
        else:
            log("[INFO] No critical application drift targets met the threshold for auto-auditing.")

    log("=== Finalized: AEGIS-ZERO Complete End-to-End Execution Sequence ===")


if __name__ == "__main__":
    main()
