# run_analysis.py

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
# Vulnerability Static Auditors (Polymorphic Registry)
# ---------------------------------------------------------
from auditors.js_domxss_auditor import aegis_js_scan
from auditors.cookie_auditor import aegis_cookie_scan
from auditors.cors_auditor import aegis_cors_scan
from auditors.csp_auditor import aegis_csp_scan

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
    llama_output = ""
    if settings.get("enable_llama_inference", True):
        log("[6] Launching autonomous LLM structural inference engine...")
        llama_output = run_llama_inference()
        save_text(paths.get("llama_output"), llama_output)
        log(f"[OK] Autonomous security reasoning complete -> {paths.get('llama_output')}")

    # [Step 7] Smart Feedback Loop: Polymorphic Trigger Routing (Recon-to-Audit Link)
    if settings.get("enable_targeted_auditor", True) and scored_tree:
        log("[7] Evaluating 'High/Medium' priority nodes to trigger specific polymorphic Auditors...")
        
        # 7.1 Pre-scan AI's cognitive inference text to build dynamic global tags
        ai_focus_tags = []
        if llama_output:
            upper_output = llama_output.upper()
            if "CORS" in upper_output: ai_focus_tags.append("CORS")
            if "COOKIE" in upper_output or "SET-COOKIE" in upper_output: ai_focus_tags.append("COOKIE")
            if "CSP" in upper_output or "CONTENT-SECURITY-POLICY" in upper_output: ai_focus_tags.append("CSP")
            if "XSS" in upper_output or "DOM-XSS" in upper_output: ai_focus_tags.append("XSS")
            log(f"[INFO] AI Cognitive Layer signaled high-suspicion tags: {ai_focus_tags}")

                # 7.2 Core routing matrix iterating over prioritized recon data
        for node in scored_tree:
            
            if True: 
                raw_event = node.get("raw", {}).get("event", "")
                source_tab = node.get("source_tab")
                vuln_reasons = str(node.get("vuln_reasons", "")).upper()
                
                
                target_url = raw_event if (str(raw_event).startswith("http://") or str(raw_event).startswith("https://")) else settings.get("fallback_target_url", f"https://{settings.get('fallback_target_url', 'motel6.com')}")

                # --- ROUTE ENTRYPOINT 1: DOM-Based XSS Asset Checking ---
                
                if ("XSS" in ai_focus_tags or "XSS" in vuln_reasons or "EVAL" in vuln_reasons or "INNERHTML" in vuln_reasons):
                    log(f"[+] Polymorphic Trigger: Deploying DOM-Based XSS Auditor against: {target_url}")
                    try:
                        aegis_js_scan(target_url)
                    except Exception as e:
                        log(f"[ERROR] DOMXSS Auditor crash: {str(e)}")

                    log("[INFO] Target achieved. Breaking loop to protect local PC resources.")
                    break    

                # --- ROUTE ENTRYPOINT 2: Cookie Transport Security Hardening ---
                
                if True: 
                    injected_cookie_str = node.get("raw", {}).get("cookie_header") or node.get("raw", {}).get("response_headers", {}).get("Set-Cookie")
                    log(f"[+] Polymorphic Trigger: Deploying Specialized Cookie Auditor against: {target_url}")
                    try:
                        aegis_cookie_scan(target_url, custom_cookie_header=injected_cookie_str)
                    except Exception as e:
                        log(f"[ERROR] Cookie Auditor crash: {str(e)}")

                    log("[INFO] Target achieved. Breaking loop to protect local PC resources.")
                    break    


                # --- ROUTE ENTRYPOINT 3: Permissive CORS Leakage Checking ---
                if "CORS" in ai_focus_tags or "CORS" in vuln_reasons or "ACCESS-CONTROL-ALLOW" in vuln_reasons:
                    injected_cors_str = node.get("raw", {}).get("cors_header") or node.get("raw", {}).get("response_headers", {})
                    if isinstance(injected_cors_str, dict):
                        # Convert dict headers to standardized string blocks for the prompt template
                        injected_cors_str = "\n".join([f"{k}: {v}" for k, v in injected_cors_str.items() if k.lower().startswith("access-control-")])
                    
                    log(f"[+] Polymorphic Trigger: Deploying Specialized CORS Auditor against: {target_url}")
                    try:
                        aegis_cors_scan(target_url, custom_cors_headers=injected_cors_str if injected_cors_str else None)
                    except Exception as e:
                        log(f"[ERROR] CORS Auditor crash: {str(e)}")

                    log("[INFO] Target achieved. Breaking loop to protect local PC resources.")
                    break    

                # --- ROUTE ENTRYPOINT 4: Structural CSP Bypass Tracking ---
                if "CSP" in ai_focus_tags or "CSP" in vuln_reasons or "CONTENT-SECURITY-POLICY" in vuln_reasons:
                    injected_csp_str = node.get("raw", {}).get("csp_header") or node.get("raw", {}).get("response_headers", {}).get("Content-Security-Policy")
                    log(f"[+] Polymorphic Trigger: Deploying Specialized CSP Auditor against: {target_url}")
                    try:
                        aegis_csp_scan(target_url, custom_csp_header=injected_csp_str)
                    except Exception as e:
                        log(f"[ERROR] CSP Auditor crash: {str(e)}")

                    log("[INFO] Target achieved. Breaking loop to protect local PC resources.")
                    break    

    else:
        log("[INFO] No critical application drift targets met the threshold for dynamic auto-auditing.")

    log("=== Finalized: AEGIS-ZERO Complete End-to-End Execution Sequence ===")


if __name__ == "__main__":
    main()
