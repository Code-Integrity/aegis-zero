# Aegis-Zero

### Self-Driven Browser Security Analysis Framework

**DevTools Log Correlation (SAFE recon) + Precision JavaScript Static Analysis (Auditors)**

Aegis-Zero is a multi-module, self-driven security reconnaissance and analysis framework designed to isolate client-side browser behavior vulnerabilities using data-driven correlation and LLM-assisted structural inference.
Unlike flat scanner blueprints, Aegis-Zero models runtime state logs into an integrated, causal-linked binary tree mapping matrix, flags high-suspicion code vectors, and automatically coordinates targeted static analysis checks to output turn-key HackerOne-style triage document artifacts.

---

## 1. Core Architecture & Philosophy

The framework operates on a dual-layer, zero-trust perimeter analysis approach: Runtime Context Modeling + Automated Targeted Code Verification.

```text
[Raw DevTools Traces]
│ (Network, Console, Storage, Sources)
▼
┌────────────────────────────────────────┐
│ 1. SAFE recon Layer (Depth4 Mapping)   │
│ - Generates structural logic tree      │
│ - Traces cross-tab causal relations    │
└────────────────────────────────────────┘
│
▼
┌────────────────────────────────────────┐
│ 2. Tactical Risk Scoring Engine        │
│ - Weighted bounty risk validation      │
│ - Priority sorting (High -> Low)       │
└────────────────────────────────────────┘
│
▼
┌────────────────────────────────────────┐
│ 3. Abstracted Cognitive Layer          │
│ - Decoupled Local LLM Orchestrator     │
│ - Isolates Responsibility Drifts      │
└────────────────────────────────────────┘
│ (High/Medium Suspicion Targets Verified)
▼
┌────────────────────────────────────────┐
│ 4. Polymorphic Static Auditors Registry│
│ - Secure string template engine scan   │
│ - Automatic HackerOne Markdown Output  │
└────────────────────────────────────────┘
```

### 🧠 Causal-Linked Depth4 Trees

Rather than auditing source files blindly in a vacuum, Aegis-Zero dynamically links disparate browser events (e.g., an unhardened response header mapping to an immediate localStorage transaction which flows into a source code script execution context).
The engine synthesizes these cross-layer paths into four explicit dimensional scopes:

- **Depth 1 (Observed Event):** Raw operational perimeter capture telemetry.
- **Depth 2 (Surface Cause):** Evident technical boundary failures (e.g., Non-2xx redirects, raw exceptions).
- **Depth 3 (Structural Cause):** Systemic architecture patterns (e.g., Wildcard CORS settings, raw token processing scopes).
- **Depth 4 (Responsibility Drift):** Severe data access delegation slippages indicating high exploitability.

---

## 2. Directory Structure

```text
aegis-zero/
├── auditors/
│   ├── js_domxss_auditor.py   # Precision JS sink checking & H1 compiler
│   ├── cookie_auditor.py      # Transport security flag verification
│   ├── cors_auditor.py        # Permissive cross-origin leak analyzer
│   └── csp_auditor.py         # Structural policy bypass tracker
├── config/
│   ├── model.json             # Abstracted LLM execution schemas
│   ├── paths.json             # Application file system maps
│   └── settings.json          # Functional execution toggle configuration
├── logs/
│   └── devtools/              # Target ingestion area for raw JSON dumps
├── models/
│   └── inference_engine.py    # Abstracted Polymorphic LLM orchestrator
├── output/
│   ├── analysis/              # Serialized payloads and raw AI reason traces
│   ├── reports/               # Production-ready HackerOne markdown outputs
│   └── trees/                 # Compiled relational Depth4 structural trees
├── prompts/
│   ├── llama3_depth4_prompt.txt # Architecture mapping prompt (Japanese output configuration)
│   ├── js_domxss_prompt.txt   # DOM-XSS evaluation prompt (string.Template optimized)
│   ├── js_cookie_prompt.txt   # Cookie flag hardening prompt (string.Template optimized)
│   ├── js_cors_prompt.txt     # CORS policy reflection prompt (string.Template optimized)
│   └── js_csp_prompt.txt      # CSP structural bypass prompt (string.Template optimized)
├── requirements.txt           # System dependency configuration definitions
└── run_analysis.py            # Core automation controller & router entry point
```

---

## 3. Advanced Refactoring & Engine Hardening

### ⚡ Robust Variable Interpolation Layer (`string.Template`)

- **Anti-Crash Guardrails:** All prompt ingestion engines (`inference_engine.py` and all standalone auditors) utilize `string.Template` structures instead of raw Python `.format()` calls.
- **Syntax Collision Immunity:** This isolates and sanitizes JavaScript curly braces (`{}`) and explicit target JSON template boundaries (`$${}$$`) from prompt templates, eliminating structural `ValueError` and `KeyError` exceptions during active runtime reasoning.

### 🧠 Automated Polymorphic Trigger Routing (Cognitive Feedback Loop)

Step 7 in `run_analysis.py` operates as an intelligent router that dynamically connects the Recon Layer to the Specialized Auditor Registry:

1. **AI Output Pre-scanning:** Autonomously scans local LLM reasoning logs for contextual threat profile tags (`XSS`, `COOKIE`, `CORS`, `CSP`).
2. **Multi-Ingress Data Injection:** Automatically extracts raw telemetry assets (e.g., loose `Set-Cookie` blocks or reflected CORS header fields) out of the Depth4 binary tree and dispatches them straight into the targeted Auditor plugin via `custom_*` parameters.
3. **Reasoning-Model Optimization:** Built-in subprocess handling features a strict 300-second execution boundary and ANSI character stripping to safely accommodate deep analytical thinking cycles (e.g., DeepSeek-R1) without truncation or data mojibake.

---

## 4. Configuration Management

### Centralized Engine Model Configuration (`config/model.json`)

The cognitive stack utilizes a polymorphic model wrapper layer. Easily hot-swap between high-performance local variants via your local Ollama instance registry without modifying script definitions:

```json
{
  "llama_model_path": "deepseek-r1:14b",
  "prompt_file": "prompts/llama3_depth4_prompt.txt",
  "context_length": 16384,
  "temperature": 0.1,
  "top_p": 0.9,
  "max_tokens": 4096
}
```

---

## 5. Operation & Ingestion Sequence

### 1. Ingestion Setup

Drop your target browser session trace files directly into the configuration deployment paths:

- `logs/devtools/network.json`
- `logs/devtools/console.json`
- `logs/devtools/storage.json`
- `logs/devtools/sources.json`

### 2. Core Automation Runtime Execution

Deploy the orchestrator loop. The system automatically handles target output file system generation, threat validation weights sorting, AI reasoning loops, and precision targeted code scanner injections:

```bash
python3 run_analysis.py
```

### 3. Triage Report Collection

Review high-suspicion artifacts and turn-key bug bounty document templates compiled automatically into the designated workspace reports cache:

- **Relational Threat Maps:** `output/analysis/scoring_result.json` (Sorted cleanly by high-priority risk weight indexes).
- **AI Cognitive Reports:** `output/analysis/llama_output.txt` (Structured structural analysis mapping).
- **Bounty Triage Markdown:** `output/reports/h1_report_*.md` (Ready-to-submit security report structures outlining full causal chains, impacts, verification PoCs, and remediation advice for DOMXSS, Cookies, CORS, and CSP).

---

## 6. Security & Isolation Management (`.gitignore`)

Aegis-Zero strictly safeguards highly sensitive target telemetry details, tokens, and local infrastructure paths during open repository control management. Ensure the production `.gitignore` layout is accurately established:

```text
/*
!/auditors/
!/prompts/
!/config/
!/utils/
!/README.md
!/run_analysis.py
!/.gitignore
!/LICENSE

/logs/devtools/**
/output/**
/models/__*
**__pycache__/
*.pyc
.venv/
```

---

Developed autonomously for modern high-velocity bug bounty reconnaissance workflows.

## 6. License

This project is licensed under the Apache License 2.0.

You may use, modify, and distribute this software under the terms of the Apache License.
A full copy of the license is available at:

https://www.apache.org/licenses/LICENSE-2.0

## 7. Contributing

Contributions are welcome.
Feel free to open issues or submit pull requests.

## 8. Additional Author Notice (Non‑Legal)

This project includes original analysis logic, structural reasoning patterns,
and security workflow designs created by **Code‑Integrity**.

While the Apache License permits reuse and modification, the author requests the following:

- Please provide proper attribution when using or extending the structural reasoning concepts
  (Depth4, SAFE recon workflow, anomaly scoring philosophy, auditor inference design).
- Do not misrepresent these methodologies as your own original invention.
- When used in corporate training, academic material, or security frameworks,
  please include clear credit to **Code‑Integrity**.

These courtesy guidelines do not alter the Apache License terms.
