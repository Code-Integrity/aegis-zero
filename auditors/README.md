# Aegis-Zero Auditors

## Precision JavaScript & Header Static Analysis Modules (Targeted Vulnerability Verification)

The `auditors/` directory encompasses independent, pluggable analysis utility modules designed to dissect client-side source code, investigate dangerous response headers, locate injection vectors, and synthesize deterministic exploit proofs via localized LLM pipeline queries.

Rather than executing generic scans, these engines are dynamically deployed by the core orchestrator based on threat profiles generated during the reconnaissance phase.

---

## 1. Complete Auditor Registry

Aegis-Zero deploys four specialized standalone verification engines, each utilizing crash-resilient `string.Template` engines and auto-compiling ready-to-submit **HackerOne triage markdown advisories** directly inside `output/reports/`:

### 🏹 1. DOM-Based XSS Auditor (`js_domxss_auditor.py`)

- **Perimeter:** Analyzes raw standalone JS assets (`.js` files) or inner HTML inline `<script>` scopes.
- **Sinks Targeted:** `innerHTML`, `document.write`, `eval(`, `location.href`.
- **Prompt Map:** `prompts/js_domxss_prompt.txt` (`$js_code`, `$source_type`).

### 🍪 2. Cookie Security Auditor (`cookie_auditor.py`)

- **Perimeter:** Evaluates live `Set-Cookie` response headers or raw session context injected from Recon telemetry.
- **Flags Targeted:** Missing or weak `HttpOnly`, `Secure`, and `SameSite` attributes on sensitive session identifiers.
- **Prompt Map:** `prompts/js_cookie_prompt.txt` (`$cookie_context`, `$source_type`).

### 📡 3. Permissive CORS Leakage Auditor (`cors_auditor.py`)

- **Perimeter:** Verifies Cross-Origin Resource Sharing controls. Features an **automated origin reflection simulator** that injects untrusted origins (`Origin: https://evil-attacker-perimeter.com`) to catch dynamic response reflections.
- **Flaws Targeted:** Credential disclosures (`Credentials: true`) combined with wildcards or unvalidated origin reflection.
- **Prompt Map:** `prompts/js_cors_prompt.txt` (`$cors_context`, `$source_type`).

### 🛡️ 4. Structural CSP Bypass Auditor (`csp_auditor.py`)

- **Perimeter:** Reviews active Content Security Policy layout restriction headers.
- **Bypasses Targeted:** Presence of `'unsafe-inline'` without nonces, unsafe CDN white-lists allowing JSONP bypasses, or missing `object-src`.
- **Prompt Map:** `prompts/js_csp_prompt.txt` (`$csp_context`, `$source_type`).

---

## 2. Ingress Analysis & Routing Sequence Flow

The core `run_analysis.py` controller driving Step 7 executes an **Automated Polymorphic Trigger Routing** loop:

```text
       [Recon Depth4 Tree / Scored Nodes]
                       │
                       ▼
         [Step 6: AI Cognitive Inference] ──► Pre-scans logs for tags (XSS, COOKIE, CORS, CSP)
                       │
                       ▼
      ┌─────────────────────────────────┐
      │  Step 7: Smart Feedback Router  │
      └─────────────────────────────────┘
         │          │          │          │
         ▼          ▼          ▼          ▼
     [DOM-XSS]   [Cookie]    [CORS]     [CSP]   ──► (300s deep reasoning boundaries enforced)
         │          │          │          │
         └──────────┴──────────┴──────────┘
                       │
                       ▼
         [Automated Triage Compilation]   ──► Compiles definitive report payload in Japanese (日本語)
                       │
                       ▼
          [output/reports/h1_report_*.md] ──► Turn-key HackerOne advisory templates complete with PoCs
```

---

## 3. Usage & Execution Integration

### Automated Execution (Pipeline Orchestration Mode)

The Auditor layer triggers automatically when `run_analysis.py` flags an asset URL or telemetry context meeting the threat boundary scoring metrics inside `config/settings.json`:

```json
"enable_targeted_auditor": true
```

### Manual Sandbox Verification (CLI / API Mode)

To standalone-audit targeted online assets or raw telemetry blocks independently of the global DevTools tracking logs, you can call the modules directly or import them into custom test vectors.

#### A. DOM-Based XSS Audit

```python
from auditors.js_domxss_auditor import aegis_js_scan
aegis_js_scan("https://target-perimeter.local")
```

#### B. Cookie Flag Omission Audit

```python
from auditors.cookie_auditor import aegis_cookie_scan
# Inject loose cookie strings to compile an instant H1 report
aegis_cookie_scan("https://target-perimeter.local", custom_cookie_header="session_token=xyz; SameSite=None;")
```

#### C. Permissive CORS Reflection Audit

```python
from auditors.cors_auditor import aegis_cors_scan
# Simulates active origin reflection checks natively or passes logs
aegis_cors_scan("https://target-perimeter.local")
```

#### D. Content Security Policy Bypass Audit

```python
from auditors.csp_auditor import aegis_csp_scan
aegis_csp_scan("https://target-perimeter.local", custom_csp_header="script-src 'self' 'unsafe-inline';")
```

---

## 4. System Artifact Deliverables

All generated Markdown documents are cleanly committed to:

```text
output/reports/h1_report_[vuln_type]_[target_identifier_suffix].md
```

_Every advisory output contains highly structured vulnerability breakdowns, execution data-flow tracing, impact summaries, and fully executable verification exploit/bypass PoC blueprints._

---

Maintained under elite security engineering standards by Code‑Integrity.
