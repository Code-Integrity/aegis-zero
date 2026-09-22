# auditors/csp_auditor.py

import os
import subprocess
import requests
import re
from string import Template
from typing import List, Dict, Any, Optional
from utils.logger import log
from utils.file_io import load_json

PROMPT_PATH: str = "prompts/js_csp_prompt.txt"
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
    Loads prompts/js_csp_prompt.txt and returns it as a string Template.
    Prevents syntax crashes on curly braces.
    """
    if not os.path.exists(PROMPT_PATH):
        raise FileNotFoundError(f"Configuration profile prompt file missing: {PROMPT_PATH}")
    with open(PROMPT_PATH, "r", encoding="utf-8") as f:
        return Template(f.read())


def build_prompt(template: Template, csp_context: str, source_type: str) -> str:
    """
    Safely embeds CSP metadata into the template using string.Template mapping.
    """
    return template.safe_substitute(
        source_type=source_type,
        csp_context=csp_context,
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
    Automated Reporter Layer. Compiles CSP structural analysis findings into a 
    production-ready HackerOne markdown document template.
    """
    os.makedirs(H1_REPORT_OUTPUT_DIR, exist_ok=True)
    
    safe_filename_suffix = index_label.lower().replace(" ", "_").replace("#", "")
    report_file_path = os.path.join(H1_REPORT_OUTPUT_DIR, f"h1_report_csp_{safe_filename_suffix}.md")
    
    markdown_blueprint = f"""# [HackerOne Vulnerability Report] Structural Content Security Policy (CSP) Bypass
## 1. Vulnerability Ingress Target
* **Target Asset Vector Identification:** {target_url}
* **Analysis Inspection Scope:** {index_label}
* **Automated Scanner Perimeter:** Aegis-Zero CSP Security Auditor Component

## 2. Core Strategic Threat Analysis (AI Security Feedback Engine Output)
The following technical diagnostics and policy bypass vectors were 
extracted autonomously from the local containerized inference runtime layer:

```json
{ai_feedback.strip()}
```

## 3. Standard Operational Proof of Concept (PoC) & Exploitation Blueprints
1. Review the structural policy omissions highlighted in the AI diagnostics data block.
2. Identify endpoints on the whitelisted CDN or script destinations that support JSONP or AngularJS-style client-side template injections.
3. Inject the synthesized payload blueprint on the target parameter and observe if arbitrary JavaScript execution triggers, invalidating the target perimeter's core defensive assumptions.

---
*Generated Autonomously via Aegis-Zero Security Framework Security Orchestrator System.*
"""
    try:
        with open(report_file_path, "w", encoding="utf-8") as rep_file:
            rep_file.write(markdown_blueprint)
        log(f"[OK] Premium HackerOne CSP report compiled and successfully exported -> {report_file_path}")
    except Exception as io_err:
        log(f"[ERROR] Failed to write markdown report to storage: {str(io_err)}")


def scan_csp_telemetry(csp_data: str, index_label: str, template: Template, source_type: str, target_url: str) -> None:
    """
    Evaluates raw CSP directives against common structural flaws and triggers AI audit if weak spots trip.
    """
    if not csp_data or not csp_data.strip():
        return

    lower_data = csp_data.lower()
    
    # Static triage indicators: common flags that increase the odds of a structural bypass
    has_unsafe_inline = "'unsafe-inline'" in lower_data
    has_wildcard = "script-src *" in lower_data or "default-src *" in lower_data
    missing_object_src = "object-src" not in lower_data

    if has_unsafe_inline or has_wildcard or missing_object_src:
        log(f"🚨 Target {index_label}: Fragile CSP architecture isolated. Initiating precise AI audit...")
        
        prompt = build_prompt(template, csp_context=csp_data, source_type=source_type)
        ai_report = call_model_with_prompt(prompt)
        
        print("\n" + "-" * 60)
        print(f"[{index_label} Strategic CSP AI Report]")
        print(ai_report)
        print("-" * 60)
        
        export_hackerone_report(target_url, index_label, ai_report)
    else:
        log(f"[INFO] CSP architecture [{index_label}] meets strict baseline definitions. Skipping deep audit.")


def aegis_csp_scan(target_url: str, custom_csp_header: Optional[str] = None) -> None:
    """
    Main CSP Auditor ingress vector. Evaluates Content-Security-Policy headers from Recon logs or live endpoints.
    """
    log(f"--- 🏹 Aegis-Zero CSP Auditor: Initiating Analysis Pipeline [{target_url}] ---")

    try:
        template = load_prompt_template()
    except Exception as e:
        log(f"[ERROR] Prompt schema ingestion failure: {str(e)}")
        return

    # Ingress Scenario A: Direct injection from Recon Layer (Passed telemetry policy logs)
    if custom_csp_header:
        log("[INFO] Processing injected CSP metadata stream from automated Recon telemetry...")
        scan_csp_telemetry(custom_csp_header, "Injected Telemetry Policy", template, "Recon-Injected-Policy", target_url)
        return

    # Ingress Scenario B: Dynamic live network verification fallback
    try:
        response = requests.get(
            target_url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisZero/1.0"},
        )
        
        csp_header = response.headers.get("Content-Security-Policy") or response.headers.get("X-Content-Security-Policy")
        
        if not csp_header:
            log("[INFO] No active Content-Security-Policy headers reflected on the target live domain.")
            return

        log(f"[INFO] Live response processed. Active CSP policy block successfully captured.")
        scan_csp_telemetry(csp_header, "Live Response Policy", template, "Live-Response-CSP", target_url)

    except Exception as e:
        log(f"[ERROR] Live asset CSP header acquisition failed for endpoint: {str(e)}")


if __name__ == "__main__":
    # Test stub representing a weak CSP with unsafe-inline enabled and object-src omitted
    test_url = "https://target-app.com"
    mock_weak_csp = "default-src 'self'; script-src 'self' 'unsafe-inline' ://cloudflare.com;"
    aegis_csp_scan(test_url, custom_csp_header=mock_weak_csp)
