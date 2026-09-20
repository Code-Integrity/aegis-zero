# Aegis-Zero Auditors## Precision JavaScript Static Analysis Module (Targeted Vulnerability Verification)

The auditors/ directory encompasses independent, pluggable static analysis utility modules designed to dissect client-side source code, locate injection vectors, and synthesize deterministic exploit proofs via localized LLM pipeline queries.
The primary operational engine deployed within this registry is the DOM-Based XSS & Dynamic Code Execution Auditor.

---

## 1. Module Overview: js_domxss_auditor.py

This engine performs fine-grained static dataflow tracing against isolated JavaScript targets, determining the precise link between untrusted input entries (Sources) and unshielded runtime evaluation primitives (Sinks).

## 🛠️ Key Architectural Enhancements

- Polymorphic Ingress Ingestion: Automatically toggles processing behaviors between parsing inner HTML inline <script> scopes and directly orchestrating network fetches to swallow standalone remote static assets (e.g., auth.js) passed directly from the recon phase.
- Crash-Resilient Template Parsing: Utilizes strict string.Template key-substitution bindings rather than basic Python .format() calls, completely eliminating runtime crashes triggered by the native curly-brace {} structures inherent to JavaScript logic.
- Automated Triage Compilation: Dynamically captures successful AI telemetry outputs and auto-compiles ready-to-submit HackerOne vulnerability advisories directly onto the persistent markdown repository storage path.

---

## 2. Ingress Analysis Sequence Flow

[Target URL Ingress]
│
▼
┌───────────────────────┐
│ 1. Data Fetch │ ──► Enforces strict requests client User-Agent masking
└───────────────────────┘
│
▼
┌───────────────────────┐
│ 2. Telemetry Routing │ ──► Identifies content types (HTML DOM vs Standalone Script File)
└───────────────────────┘
│
▼
┌───────────────────────┐
│ 3. Sink Telemetry │ ──► Isolates keywords: innerHTML, document.write, eval(, location.href
└───────────────────────┘
│
▼
┌───────────────────────┐
│ 4. Prompt Synthesis │ ──► Mapped safely via string.Template keys ($js*code, $source_type)
└───────────────────────┘
│
▼
┌───────────────────────┐
│ 5. Core Inference │ ──► Interfaces seamlessly via the centralized models/inference_engine
└───────────────────────┘
│
▼
┌───────────────────────┐
│ 6. Auto-Compilation │ ──► Exports complete triage document maps to output/reports/h1_report*\*.md
└───────────────────────┘

---

## 3. Usage & Execution Integration## Automated Execution (Pipeline Orchestration Mode)

The Auditor layer triggers automatically when run_analysis.py flags an asset URL meeting the threat boundary scoring metrics inside config/settings.json:

"enable_targeted_auditor": true

## Manual Sandbox Verification (CLI Mode)

To standalone-audit a targeted online asset or script path independently of the global DevTools tracking logs, query the script endpoint directly:

python3 auditors/js_domxss_auditor.py

## Script API Ingress Integration

from auditors.js_domxss_auditor import aegis_js_scan

# Scans HTML endpoints for inline blocks, or standalone JS links directly

aegis_js_scan("https://target-app.com")

---

## 4. Unified Artifact Dependencies## Centralized Reasoning Prompt (prompts/js_domxss_prompt.txt)

Contains the definitive, highly structured HackerOne simulation logic rules. Configured to output comprehensive vulnerability breakdowns, execution flow tracking, and precise context payloads in Japanese (日本語) to maximize hunter triage efficiency.

## System Path Registry Definitions (config/paths.json)

The output report directories are fully mapped into the unified path scheme. Generated Markdown documents are cleanly committed to:

output/reports/h1*report*[target_identifier_suffix].md

---

## 5. Extensibility Framework

The auditors/ ecosystem architecture is deliberately isolated and decoupled (疎結合). You can expand the analytical perimeter by simply dropping independent auditing scripts into this directory without modifying the core recon logging logic:

- 🛡️ cookie_auditor.py: Hardening evaluation of SameSite, Secure, and HttpOnly attributes.
- 🌐 cors_auditor.py: Verification of cross-origin state leakage controls.
- 🔒 csp_auditor.py: Structural review of active layout restriction policies.

---

## Maintained under proprietary security engineering standards by Code‑Integrity.
