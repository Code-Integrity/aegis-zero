# Aegis-Zero

Self-Driven Browser Security Analysis Framework
DevTools Log Analysis (SAFE recon) + JavaScript Static Analysis (Auditors)

Aegis-Zero is a multi-module, self-driven security analysis framework designed to analyze
browser behavior and client-side JavaScript using structured reasoning and LLM-assisted inference.

It combines two powerful perspectives:

1. **SAFE recon** — Deep structural analysis of browser DevTools logs
2. **Auditors** — Static analysis of JavaScript for DOM-Based XSS and other vulnerabilities

Together, these modules provide a dual-layer understanding of browser security:
**runtime behavior + code-level logic**.

---

## 1. Core Concepts

### SAFE recon (DevTools Log Analysis)

SAFE recon transforms raw DevTools logs into a structured Depth4 binary tree, enabling:

- Event flow reconstruction
- Structural anomaly detection
- Responsibility mismatch analysis
- Timing and dependency evaluation
- LLM-assisted reasoning for hidden causes
- Re-observation loop (iterative refinement)

This module is ideal for analyzing:

- Network requests
- Storage access
- Console events
- Script execution
- Browser subsystem interactions

---

### JavaScript Auditors (Static Analysis)

The `auditors/` directory contains independent modules for client-side JS analysis.

Current implementation:

#### **DOM-Based XSS Auditor**

- Extracts inline JavaScript from HTML
- Detects dangerous sinks (document.write, innerHTML, eval, location.href)
- Uses LLM reasoning to identify sources → sinks data flow
- Generates realistic PoC payloads
- HackerOne-style vulnerability reporting

Future modules may include:

- Cookie Auditor
- CSP Auditor
- CORS Auditor
- Storage Access Auditor
- Script Injection Auditor

---

## 2. Directory Structure

aegis-zero/ recon/ devtools_extract.py depth4_tree.py scoring.py

auditors/ js_domxss_auditor.py

models/ llama3/ inference.py

prompts/ llama3_depth4_prompt.txt deepseek_prompt.txt qwen_prompt.txt js_domxss_prompt.txt

utils/ file_io.py formatter.py logger.py

config/ model.json paths.json settings.json

run_analysis.py README.md

This structure ensures strict responsibility separation and high extensibility.

---

## 3. SAFE recon Workflow

1. Extract DevTools logs
2. Normalize logs into structured JSON
3. Build Depth4 binary tree
4. Score nodes for anomaly likelihood
5. Generate LLM prompt
6. Infer structural causes and mismatches
7. Identify nodes requiring re-observation
8. Iterate (SAFE recon loop)

LLM models supported:

- LLaMA3
- DeepSeek-R1
- Qwen2.5
- Any Ollama-compatible model

---

## 4. Auditor Workflow (DOM-Based XSS)

1. Fetch HTML
2. Extract inline `<script>` blocks
3. Detect dangerous sinks
4. Build HackerOne-style prompt
5. Run LLM inference
6. Output structured JSON report:

- verdict
- sources
- sinks
- poc_payload
- root_cause

---

## 5. Model Configuration

All modules share a unified configuration file:

### `config/model.json`

```json
{
  "llama_model_path": "/models/llama3.1-70b-q4_k_m",
  "prompt_file": "prompts/llama3_depth4_prompt.txt",
  "context_length": 8192,
  "temperature": 0.1,
  "top_p": 0.9,
  "max_tokens": 4096
}
```

Switching models only requires updating:

• llama_model_path
• prompt_file

---

## 6. Usage

SAFE recon (DevTools Analysis)

python run_analysis.py

DOM-Based XSS Auditor

from auditors.js_domxss_auditor import aegis_js_scan
aegis_js_scan("https://example.com")

---

## 7. Extensibility

Aegis-Zero is designed for long-term growth:

• Add new auditors easily
• Swap LLM models without code changes
• Extend Depth4 logic safely
• Integrate new browser subsystems
• Build custom scoring modules

The framework is intentionally modular and future-proof.

---

## 8. Philosophy

Aegis-Zero is built on three principles:

1. Structural Reasoning

Security issues often emerge from structural inconsistencies, not isolated events.

2. Responsibility Separation

Each module has a clear, isolated responsibility to prevent logic leakage.

3. Iterative Observation

Security analysis is a loop: observe → infer → re-observe → refine.

---

## 9. Summary

Aegis-Zero is a self-driven security analysis framework combining:

• Depth4 structural analysis of browser behavior
• LLM-assisted reasoning for hidden causes
• Static JavaScript vulnerability detection

It provides a powerful dual perspective for modern web security research and bug bounty workflows.

## License

This project is licensed under the Apache License 2.0.

You may use, modify, and distribute this software under the terms of the Apache License.
A full copy of the license is available at:

https://www.apache.org/licenses/LICENSE-2.0

## Contributing

Contributions are welcome.
Feel free to open issues or submit pull requests.

## Additional Author Notice (Non‑Legal)

This project includes original analysis logic, structural reasoning patterns,
and security workflow designs created by **Code‑Integrity**.

While the Apache License permits reuse and modification, the author requests the following:

- Please provide proper attribution when using or extending the structural reasoning concepts
  (Depth4, SAFE recon workflow, anomaly scoring philosophy, auditor inference design).
- Do not misrepresent these methodologies as your own original invention.
- When used in corporate training, academic material, or security frameworks,
  please include clear credit to **Code‑Integrity**.

These courtesy guidelines do not alter the Apache License terms.
