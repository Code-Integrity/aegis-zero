# auditors/cookie_auditor.py

import os
import subprocess
import requests
import re
from string import Template
from typing import List, Dict, Any
from utils.logger import log
from utils.file_io import load_json

PROMPT_PATH: str = "prompts/js_cookie_prompt.txt"
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
    Loads prompts/js_cookie_prompt.txt and returns it as a string Template.
    Prevents syntax crashes on curly braces.
    """
    if not os.path.exists(PROMPT_PATH):
        raise FileNotFoundError(f"Configuration profile prompt file missing: {PROMPT_PATH}")
    with open(PROMPT_PATH, "r", encoding="utf-8") as f:
        return Template(f.read())


def build_prompt(template: Template, cookie_context: str, source_type: str) -> str:
    """
    Safely embeds Cookie data into the template using string.Template mapping.
    """
    return template.safe_substitute(
        source_type=source_type,
        cookie_context=cookie_context,
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
        
        return clean_output.strip() or "[INFO] Model execution completed with empty payload feedback."
        
    except subprocess.TimeoutExpired:
        return f"[ERROR] AI inference pipeline execution halted due to timeout exhaustion (300s) for model [{model_tag}]."
    except Exception as e:
        return f"[ERROR] AI orchestrator pipeline initialization fault: {str(e)}"


def export_hackerone_report(target_url: str, index_label: str, ai_feedback: str) -> None:
    """
    Automated Reporter Layer. Compiles Cookie static analysis findings into a 
    production-ready HackerOne markdown document template.
    """
    os.makedirs(H1_REPORT_OUTPUT_DIR, exist_ok=True)
    
    safe_filename_suffix = index_label.lower().replace(" ", "_").replace("#", "")
    report_file_path = os.path.join(H1_REPORT_OUTPUT_DIR, f"h1_report_cookie_{safe_filename_suffix}.md")
    
    markdown_blueprint = f"""# [HackerOne Vulnerability Report] Cookie Flag Hardening Inconsistency
## 1. Vulnerability Ingress Target
* **Target Asset Vector Identification:** {target_url}
* **Analysis Inspection Scope:** {index_label}
* **Automated Scanner Perimeter:** Aegis-Zero Cookie Security Auditor Component

## 2. Core Strategic Threat Analysis (AI Security Feedback Engine Output)
The following technical diagnostics and security posture analysis streams were 
extracted autonomously from the local containerized inference runtime layer:

```json
{ai_feedback.strip()}
```

## 3. Standard Operational Proof of Concept (PoC) & Exploitation Blueprints
1. Verify the absence of the identified transport or security flags via intercepted HTTP response headers.
2. In the case of missing `HttpOnly` on sensitive session identifiers, evaluate client-side accessibility using console hooks (`document.cookie`).
3. Construct cross-site attack vectors (CSRF/Session Fixation) where loose `SameSite` topologies allow unauthenticated context injection.

---
*Generated Autonomously via Aegis-Zero Security Framework Security Orchestrator System.*
"""
    try:
        with open(report_file_path, "w", encoding="utf-8") as rep_file:
            rep_file.write(markdown_blueprint)
        log(f"[OK] Premium HackerOne Cookie report compiled and successfully exported -> {report_file_path}")
    except Exception as io_err:
        log(f"[ERROR] Failed to write markdown report to storage: {str(io_err)}")


def scan_cookie_telemetry(cookie_data: str, index_label: str, template: Template, source_type: str, target_url: str) -> None:
    """
    Evaluates raw cookie strings against security flag omissions and passes to AI if flaws are detected.
    """
    if not cookie_data or not cookie_data.strip():
        return

    # Basic static check to flag potential omission immediately before invoking deep LLM reasoning
    lower_data = cookie_data.lower()
    has_httponly = "httponly" in lower_data
    has_secure = "secure" in lower_data
    
    # If it looks like a sensitive tracking/auth header but missing key flags, trigger AI analysis
    if not (has_httponly and has_secure):
        log(f"🚨 Target {index_label}: Potential Cookie flag omission isolated. Initiating precise AI audit...")
        
        prompt = build_prompt(template, cookie_context=cookie_data, source_type=source_type)
        ai_report = call_model_with_prompt(prompt)
        
        print("\n" + "-" * 60)
        print(f"[{index_label} Strategic Cookie AI Report]")
        print(ai_report)
        print("-" * 60)
        
        export_hackerone_report(target_url, index_label, ai_report)
    else:
        log(f"[INFO] Cookie asset [{index_label}] contains baseline transport protections. Skipping deep audit.")


def aegis_cookie_scan(target_url: str, custom_cookie_header: Optional[str] = None) -> None:
    """
    Main Cookie Auditor ingress vector. Scans Set-Cookie response headers or raw session context.
    """
    log(f"--- 🍪 Aegis-Zero Cookie Auditor: Initiating Analysis Pipeline [{target_url}] ---")

    try:
        template = load_prompt_template()
    except Exception as e:
        log(f"[ERROR] Prompt schema ingestion failure: {str(e)}")
        return

    # Ingress Scenario A: Direct injection from Recon Layer (Passed telemetry header strings)
    if custom_cookie_header:
        log("[INFO] Processing injected cookie metadata stream from automated Recon telemetry...")
        scan_cookie_telemetry(custom_cookie_header, "Injected Telemetry Header", template, "Recon-Injected-Header", target_url)
        return

    # Ingress Scenario B: Dynamic live network fallback verification
    try:
        response = requests.get(
            target_url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisZero/1.0"},
        )
        
        cookie_headers = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else response.headers.get('Set-Cookie', '').split(',')
        cookie_headers = [c.strip() for c in cookie_headers if c.strip()]
        
        if not cookie_headers:
            log("[INFO] No live Set-Cookie headers identified during automated endpoint validation.")
            return

        log(f"[INFO] Live response processed. Identified {len(cookie_headers)} target Cookie vector(s).")
        for i, raw_cookie in enumerate(cookie_headers, 1):
            scan_cookie_telemetry(raw_cookie, f"Set-Cookie Header #{i}", template, "Live-Response-Header", target_url)

    except Exception as e:
        log(f"[ERROR] Live asset header verification failed for endpoint: {str(e)}")


if __name__ == "__main__":
    # Test stub representing an insecure session token leak scenario
    test_url = "https://example.com"
    mock_bad_cookie = "session_id=auth_token_xyz123; Path=/; SameSite=None;" # Missing HttpOnly & Secure!
    aegis_cookie_scan(test_url, custom_cookie_header=mock_bad_cookie)
