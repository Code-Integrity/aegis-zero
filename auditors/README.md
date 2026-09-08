# Aegis-Zero Auditors

JavaScript Static Analysis Module (DOM-Based XSS Auditor)

Aegis-Zero provides not only DevTools log analysis (SAFE recon) but also a dedicated
static analysis module for client-side JavaScript.
The `auditors/` directory contains independent analysis modules designed to detect
vulnerabilities using LLM-assisted reasoning.

The current implementation focuses on the **DOM-Based XSS Auditor**.

---

## 1. Module Overview

### `js_domxss_auditor.py`

This module performs static analysis on inline JavaScript code and determines whether
a **DOM-Based XSS** vulnerability exists.

Key features:

- Inline `<script>` extraction using BeautifulSoup
- Lightweight detection of dangerous sinks (document.write, innerHTML, eval, location.href)
- LLM-powered static analysis (LLaMA3 / DeepSeek / Qwen)
- HackerOne-style prompt that generates realistic PoC payloads
- Operates independently from SAFE recon (DevTools analysis)

---

## 2. Analysis Flow

1. **Fetch HTML**
   The target page is retrieved using `requests.get()`.

2. **Extract Inline JavaScript**
   BeautifulSoup scans all `<script>` tags.

3. **Detect Dangerous Sinks**
   If any of the following keywords appear, AI analysis is triggered:

- `document.write`
- `innerHTML`
- `eval(`
- `location.href`

4. **Prompt Generation**
   The template `prompts/js_domxss_prompt.txt` is loaded and populated with
   `{js_code}` and `{source_type}`.

5. **LLM Inference**
   The module uses `run_llama_inference(prompt)` from
   `models/llama3/inference.py`.

6. **Structured Output (JSON)**

- verdict (VULNERABLE / SAFE)
- sources (external input)
- sinks (dangerous functions)
- poc_payload (attack payload)
- root_cause (reason for vulnerability)

---

## 3. Usage

### From Python

```python
from auditors.js_domxss_auditor import aegis_js_scan

aegis_js_scan("https://example.com")


Manual Testing (CLI)

python auditors/js_domxss_auditor.py


```

## 4. Prompt File

`prompts/js_domxss_prompt.txt`

This is the HackerOne-style prompt used for LLM analysis.
It determines DOM-XSS presence, identifies sinks/sources, and generates PoC payloads.

The template uses {js_code} and {source_type} placeholders.

---

## 5. Model Configuration

The model used for analysis is defined in config/model.json.

```
Example:

{
"llama_model_path": "/models/llama3.1-70b-q4_k_m",
"prompt_file": "prompts/js_domxss_prompt.txt",
"context_length": 8192,
"temperature": 0.1,
"top_p": 0.9,
"max_tokens": 4096
}

```

Switching to DeepSeek or Qwen only requires updating
llama_model_path and prompt_file.

---

## 6. Extensibility

This directory is designed to support additional modules in the future:

• Cookie Auditor
• CSP Auditor
• CORS Auditor
• Storage Access Auditor
• Script Injection Auditor

Aegis-Zero is built as a multi-module, self-driven security analysis framework.

---

## 7. Notes

• External JavaScript file analysis will be added later
• Dynamically generated JS (eval / new Function) may require deeper LLM assistance
• PoC payloads should be manually validated
• This module performs static analysis; runtime behavior must be verified separately

---

## 8. Summary

auditors/ contains independent analysis modules that complement SAFE recon.
The DOM-Based XSS Auditor provides a powerful LLM-assisted static analysis engine
for client-side vulnerabilities.

Combined with DevTools analysis, Aegis-Zero offers a dual-perspective approach
to browser security: structural behavior + JavaScript logic.

---
