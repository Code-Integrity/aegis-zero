# auditors/js_domxss_auditor.py

import os
import subprocess
import requests
from bs4 import BeautifulSoup
from string import Template
from typing import List, Optional
from utils.logger import log

# Dangerous dynamic evaluation sinks often targeted in bug bounty reconnaissance
SINK_KEYWORDS: List[str] = [
    "document.write",
    "innerHTML",
    "eval(",
    "location.href",
]

PROMPT_PATH: str = "prompts/js_domxss_prompt.txt"
# Standardized location to save the synthesized hackerone vulnerability document
H1_REPORT_OUTPUT_DIR: str = "output/reports"


def load_prompt_template() -> Template:
    """
    Loads prompts/js_domxss_prompt.txt and returns it as a string Template.
    Uses string.Template instead of .format() to prevent KeyError crashes 
    caused by curly braces '{}' inherent to JavaScript syntax.
    """
    if not os.path.exists(PROMPT_PATH):
        raise FileNotFoundError(f"Configuration profile prompt file missing: {PROMPT_PATH}")
    with open(PROMPT_PATH, "r", encoding="utf-8") as f:
        return Template(f.read())


def build_prompt(template: Template, js_code: str, source_type: str) -> str:
    """
    Safely embeds the target JavaScript payload into the template placeholder 
    using explicit key mapping substitution.
    """
    return template.safe_substitute(
        source_type=source_type,
        js_code=js_code,
    )


def call_llama_with_prompt(prompt: str) -> str:
    """
    Orchestrates subprocess execution to query local Ollama container.
    Enforces strict execution timeout boundaries to prevent execution lock.
    Uses target JSON restriction parameters if specified.
    """
    try:
        result = subprocess.run(
            ["ollama", "run", "llama3.2"],
            input=prompt,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
        return result.stdout or "[INFO] Model execution completed with empty payload feedback."
    except subprocess.TimeoutExpired:
        return "[ERROR] AI inference pipeline execution halted due to timeout exhaustion."
    except Exception as e:
        return f"[ERROR] AI orchestrator pipeline initialization fault: {str(e)}"


def export_hackerone_report(target_url: str, index_label: str, ai_feedback: str) -> None:
    """
    Automated Reporter Layer. Compiles raw AI static analysis findings into a 
    production-ready HackerOne markdown document template ('h1_report.md') 
    inside the output report pipeline registry.
    """
    os.makedirs(H1_REPORT_OUTPUT_DIR, exist_ok=True)
    
    # Cleans up specific asset target tags for the output filename mapping
    safe_filename_suffix = index_label.lower().replace(" ", "_").replace("#", "")
    report_file_path = os.path.join(H1_REPORT_OUTPUT_DIR, f"h1_report_{safe_filename_suffix}.md")
    
    markdown_blueprint = f"""# [HackerOne Vulnerability Report] Targeted Static Analysis Breakdown

## 1. Vulnerability Ingress Target
* **Target Asset Vector Identification:** `{target_url}`
* **Analysis Inspection Scope:** `{index_label}`
* **Automated Scanner Perimeter:** Aegis-Zero JavaScript Static Auditor Component

## 2. Core Strategic Threat Analysis (AI Security Feedback Engine Output)
The following technical diagnostics and contextual architectural analysis streams were 
extracted autonomously from the local containerized inference runtime layer:

```text
{ai_feedback.strip()}
```

## 3. Standard Operational Proof of Concept (PoC) & Exploitation Blueprints
1. Review the targeted code snippet context inside the telemetry tracking history maps.
2. Formulate explicit execution injections corresponding to the dynamic evaluation sink identified above.
3. Test variable containment inputs to trace the full flow sequence boundary from untrusted Sources directly to the compromised destination Sink properties.

---
*Generated Autonomously via Aegis-Zero Security Framework Security Orchestrator System.*
"""
    try:
        with open(report_file_path, "w", encoding="utf-8") as rep_file:
            rep_file.write(markdown_blueprint)
        log(f"[OK] Premium HackerOne structural report compiled and successfully exported -> {report_file_path}")
    except Exception as io_err:
        log(f"[ERROR] Failed to stream and commit compiled markdown vulnerabilities to storage: {str(io_err)}")


def scan_raw_javascript_payload(js_code: str, index_label: str, template: Template, source_type: str, target_url: str) -> None:
    """
    Analyzes raw text JS payload against sink metrics and dispatches to AI if suspicious indicators trip.
    Automatically generates standardized security files if successful.
    """
    if not js_code or not js_code.strip():
        return

    detected_sinks = [sink for sink in SINK_KEYWORDS if sink in js_code]
    if not detected_sinks:
        return

    log(f"🚨 Target {index_label}: Dangerous perimeter sinks isolated {detected_sinks}. Initiating precise AI audit...")

    prompt = build_prompt(template, js_code=js_code, source_type=source_type)
    ai_report = call_llama_with_prompt(prompt)

    print("\n" + "-" * 60)
    print(f"[{index_label} Strategic AI Security Report]")
    print(ai_report)
    print("-" * 60)
    
    # Trigger the automated report compiler sequence seamlessly
    export_hackerone_report(target_url, index_label, ai_report)


def aegis_js_scan(target_url: str) -> None:
    """
    Main Auditor ingress vector. Scans inline scripts inside HTML endpoints or
    directly parses target raw remote JS assets intercepted from structural Recon.
    """
    log(f"--- 🏹 Aegis-Zero JS Auditor: Initiating Static Analysis Pipeline [{target_url}] ---")

    try:
        response = requests.get(
            target_url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisZero/1.0"},
        )
        response.raise_for_status()
    except Exception as e:
        log(f"[ERROR] Asset data acquisition failed for endpoint: {str(e)}")
        return

    try:
        template = load_prompt_template()
    except Exception as e:
        log(f"[ERROR] Prompt schema ingestion failure: {str(e)}")
        return

    # Check if the target asset URL is a raw standalone JavaScript file
    if target_url.endswith(".js") or "javascript" in response.headers.get("Content-Type", "").lower():
        log("[INFO] Target isolated as raw script resource. Running global payload telemetry...")
        scan_raw_javascript_payload(response.text, "Standalone Script Asset", template, "External-JS-File", target_url)
        return

    # Fallback to HTML DOM script block processing structure
    soup = BeautifulSoup(response.text, "html.parser")
    scripts = soup.find_all("script")
    log(f"[INFO] DOM tree layout processed. Identified {len(scripts)} target script vectors.")

    for i, script in enumerate(scripts, 1):
        js_payload = script.string
        scan_raw_javascript_payload(js_payload, f"Inline Block #{i}", template, "Inline-Script", target_url)


if __name__ == "__main__":
    test_url = "https://example.com"
    aegis_js_scan(test_url)
