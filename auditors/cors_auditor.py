# auditors/cors_auditor.py

import os
import subprocess
import requests
import re
from string import Template
from typing import List, Dict, Any, Optional
from utils.logger import log
from utils.file_io import load_json

PROMPT_PATH: str = "prompts/js_cors_prompt.txt"
CONFIG_MODEL_PATH: str = "config/model.json"
H1_REPORT_OUTPUT_DIR: str = "output/reports"


def load_model_config() -> Dict[str, Any]:
    """
    Loads model deployment schemas from the centralized config mapping profile.
    """
    if not os.path.exists(CONFIG_MODEL_PATH):
        return {"llama_model_path": "llama3.2"}
    return load_json(CONFIG_MODEL_PATH) or {}


def load_prompt_template() -> Template:
    """
    Loads prompts/js_cors_prompt.txt and returns it as a string Template.
    Prevents syntax crashes on curly braces.
    """
    if not os.path.exists(PROMPT_PATH):
        raise FileNotFoundError(f"Configuration profile prompt file missing: {PROMPT_PATH}")
    with open(PROMPT_PATH, "r", encoding="utf-8") as f:
        return Template(f.read())


def build_prompt(template: Template, cors_context: str, source_type: str) -> str:
    """
    Safely embeds CORS telemetry data into the template using string.Template mapping.
    """
    return template.safe_substitute(
        source_type=source_type,
        cors_context=cors_context,
    )


def call_model_with_prompt(prompt: str) -> str:
    """
    Orchestrates subprocess execution to query local Ollama container.
    Enforces strict 300s execution timeout and JSON formatting.
    """
    model_cfg = load_model_config()
    model_tag = model_cfg.get("llama_model_path", "llama3.2")

    try:
        result = subprocess.run(
            ["ollama", "run", model_tag, "--format", "json"],
            input=prompt,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=300,
        )
        
        if result.returncode != 0:
            error_msg = result.stderr or "Unknown terminal execution fault."
            return f"[ERROR] Ollama daemon runtime fault: {error_msg}"
            
        raw_output = result.stdout or ""
        
        # Clean up terminal control codes & Ollama progress indicators
        clean_output = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]\vert{}\x1b\][0-9;]*[a-zA-Z]', '', raw_output)
        clean_output = re.sub(r'\[\d+[D|K]', '', clean_output)
        
        return clean_output.strip() or "[INFO] Model execution completed with empty token feedback."
        
    except subprocess.TimeoutExpired:
        return f"[ERROR] AI inference pipeline execution halted due to timeout exhaustion (300s) for model [{model_tag}]."
    except Exception as e:
        return f"[ERROR] AI orchestrator pipeline initialization fault: {str(e)}"


def export_hackerone_report(target_url: str, index_label: str, ai_feedback: str) -> None:
    """
    Automated Reporter Layer. Compiles CORS static analysis findings into a 
    production-ready HackerOne markdown document template.
    """
    os.makedirs(H1_REPORT_OUTPUT_DIR, exist_ok=True)
    
    safe_filename_suffix = index_label.lower().replace(" ", "_").replace("#", "")
    report_file_path = os.path.join(H1_REPORT_OUTPUT_DIR, f"h1_report_cors_{safe_filename_suffix}.md")
    
    markdown_blueprint = f"""# [HackerOne Vulnerability Report] Permissive CORS Access-Control Policy
## 1. Vulnerability Ingress Target
* **Target Asset Vector Identification:** {target_url}
* **Analysis Inspection Scope:** {index_label}
* **Automated Scanner Perimeter:** Aegis-Zero CORS Security Auditor Component

## 2. Core Strategic Threat Analysis (AI Security Feedback Engine Output)
The following technical diagnostics and security posture analysis streams were 
extracted autonomously from the local containerized inference runtime layer:

```json
{ai_feedback.strip()}
```

## 3. Standard Operational Proof of Concept (PoC) & Exploitation Blueprints
1. Review the exploit block payload enclosed within the AI security feedback data stream.
2. Setup a local mock attacker perimeter (e.g., `http://attacker.com`) and host the provided cross-origin fetch script.
3. Observe if authenticated user context (session tokens, profiles) is successfully read and leaked into the attacker logs due to loose dynamic origin reflection policies.

---
*Generated Autonomously via Aegis-Zero Security Framework Security Orchestrator System.*
"""
    try:
        with open(report_file_path, "w", encoding="utf-8") as rep_file:
            rep_file.write(markdown_blueprint)
        log(f"[OK] Premium HackerOne CORS report compiled and successfully exported -> {report_file_path}")
    except Exception as io_err:
        log(f"[ERROR] Failed to write markdown report to storage: {str(io_err)}")


def scan_cors_telemetry(cors_data: str, index_label: str, template: Template, source_type: str, target_url: str) -> None:
    """
    Evaluates raw header combinations against typical CORS bug indicators and passes to AI if flaws exist.
    """
    if not cors_data or not cors_data.strip():
        return

    # Insecure baseline indicator: Allowing credentials while reflecting wildcards or loose boundaries
    lower_data = cors_data.lower()
    has_credentials = "allow-credentials: true" in lower_data
    has_wildcard = "allow-origin: *" in lower_data
    has_null = "allow-origin: null" in lower_data
    
    # If credentials are true alongside insecure origins, or if the Recon layer explicitly tagged this block
    if (has_credentials and has_wildcard) or has_null or "allow-origin:" in lower_data:
        log(f"🚨 Target {index_label}: Loose CORS architecture isolated. Initiating precise AI audit...")
        
        prompt = build_prompt(template, cors_context=cors_data, source_type=source_type)
        ai_report = call_model_with_prompt(prompt)
        
        print("\n" + "-" * 60)
        print(f"[{index_label} Strategic CORS AI Report]")
        print(ai_report)
        print("-" * 60)
        
        export_hackerone_report(target_url, index_label, ai_report)
    else:
        log(f"[INFO] CORS layout [{index_label}] seems restricted. Skipping deep audit.")


def aegis_cors_scan(target_url: str, custom_cors_headers: Optional[str] = None) -> None:
    """
    Main CORS Auditor ingress vector. Scans HTTP response headers extracted from Recon or live sources.
    """
    log(f"--- 🏹 Aegis-Zero CORS Auditor: Initiating Analysis Pipeline [{target_url}] ---")

    try:
        template = load_prompt_template()
    except Exception as e:
        log(f"[ERROR] Prompt schema ingestion failure: {str(e)}")
        return

    # Ingress Scenario A: Direct injection from Recon Layer (Passed correlation header logs)
    if custom_cors_headers:
        log("[INFO] Processing injected CORS response metadata stream from automated Recon telemetry...")
        scan_cors_telemetry(custom_cors_headers, "Injected Telemetry Headers", template, "Recon-Injected-Headers", target_url)
        return

    # Ingress Scenario B: Dynamic live verification fallback
    try:
        # Simulate cross-origin trigger request by injecting an untrusted Origin header
        response = requests.get(
            target_url,
            timeout=10,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisZero/1.0",
                "Origin": "https://evil-attacker-perimeter.com"
            },
        )
        
        # Gather relevant CORS access control tracking headers
        cors_indicators = []
        for header_name, header_val in response.headers.items():
            if header_name.lower().startswith("access-control-allow-"):
                cors_indicators.append(f"{header_name}: {header_val}")
        
        if not cors_indicators:
            log("[INFO] No active Access-Control-Allow-* headers reflected during external origin validation.")
            return

        compiled_cors_block = "\n".join(cors_indicators)
        log(f"[INFO] Live CORS response blocks captured from external origin simulation.")
        scan_cors_telemetry(compiled_cors_block, "Live Simulated Response", template, "Live-Simulated-CORS", target_url)

    except Exception as e:
        log(f"[ERROR] Live asset CORS verification failed for endpoint: {str(e)}")


if __name__ == "__main__":
    # Test stub representing a critical CORS reflection flaw with credentials enabled
    test_url = "https://example.com"
    mock_leaky_cors = (
        "Access-Control-Allow-Origin: https://evil-attacker-perimeter.com\n" # Reflected blindly!
        "Access-Control-Allow-Credentials: true\n"
        "Access-Control-Allow-Methods: GET, POST"
    )
    aegis_cors_scan(test_url, custom_cors_headers=mock_leaky_cors)
