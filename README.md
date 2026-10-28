# CodeGuard AI

AI-powered static code analysis and security vulnerability scanner for Python projects.

CodeGuard AI provides automated security scanning for Python source code using [Semgrep](https://semgrep.dev/) static analysis combined with specialized security rules. It pinpoints vulnerabilities, categorizes risk levels, offers actionable remediation guidance, and exports structured reports for auditing and CI/CD pipelines.

---

## Table of Contents

- [Features](#features)
- [System Architecture](#system-architecture)
- [Supported Vulnerability Rules](#supported-vulnerability-rules)
- [Finding Quality & Reliability](#finding-quality--reliability)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Backend Setup](#backend-setup)
  - [Frontend Setup](#frontend-setup)
- [Testing](#testing)
- [API Reference](#api-reference)
  - [GET /](#get-)
  - [GET /health](#get-health)
  - [POST /scan](#post-scan)
  - [POST /scan/report](#post-scanreport)
- [Scan Report Schema](#scan-report-schema)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

- **Static Security Scanning** — Analyzes Python code directly without execution, identifying risks safely in isolated temp directories.
- **Precision Detection** — Six purpose-built rules targeting high-frequency security pitfalls in Python applications.
- **Actionable Remediation** — Every finding includes a concrete explanation, line numbers, affected code snippet, and actionable guidance for remediation.
- **Deduplication Engine** — Eliminates redundant findings sharing the same rule ID, line boundaries, and code snippet.
- **JSON Report Export** — Download complete audit reports containing metadata, summary counts by severity, and detailed findings.
- **Interactive Web Dashboard** — Modern React interface featuring real-time connection health checks, code editor, summary metric cards, and responsive finding views.
- **Comprehensive Test Suite** — Test-driven test suite with true-positive and false-positive test cases for every supported rule.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       React Frontend                        │
│   (Vite + React 19: Code Editor, Metrics, Report Exporter)  │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / JSON
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                      FastAPI Backend                        │
│   - POST /scan        -> returns structured findings        │
│   - POST /scan/report -> returns downloadable JSON report   │
│   - GET /health       -> liveness probe                     │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    Semgrep Scanner Core                     │
│   - Resolves executable dynamically across environments     │
│   - Sandboxed temp workspace execution                      │
│   - Deduplication filter & schema normalizer                │
│   - Rule definitions: semgrep-rules/python-security.yml     │
└─────────────────────────────────────────────────────────────┘
```

---

## Supported Vulnerability Rules

CodeGuard AI detects six critical vulnerability patterns:

| Rule ID | Category | Severity | Description |
|---|---|---|---|
| `python-dangerous-eval` | Code Injection | `WARNING` | Detects arbitrary code execution via `eval()`. Safe patterns like `ast.literal_eval()` and type casting (`int()`, `float()`) are excluded. |
| `python-hardcoded-secret` | Hardcoded Secrets | `WARNING` | Detects hardcoded API keys, passwords, and JWT tokens. Excludes placeholder names like `"changeme"` or `"your_api_key_here"`. |
| `python-sql-injection-fstring` | SQL Injection | `WARNING` | Identifies SQL queries constructed via f-strings or raw string formatting. Recommends parameterized database queries. |
| `python-unsafe-pickle` | Unsafe Deserialization | `ERROR` | Flags untrusted object deserialization via `pickle.loads()`. Recommends secure serialization formats such as JSON or Protocol Buffers. |
| `python-command-injection` | Command Injection | `ERROR` | Detects shell executions with user input (`os.system()`, `subprocess.run(..., shell=True)`). Safe list arguments (`subprocess.run(["cmd", "arg"])`) are not flagged. |
| `python-unsafe-tempfile` | Insecure File Handling | `WARNING` | Catches insecure temporary file creation via `tempfile.mktemp()`. Recommends `NamedTemporaryFile` or `TemporaryDirectory`. |

---

## Finding Quality & Reliability

CodeGuard AI enforces strict data quality guarantees:

1. **False-Positive Resistance**: Safe standard library equivalents (`ast.literal_eval`, `json.loads`, parameterized DB calls, list-based `subprocess.run`) pass the scanner cleanly.
2. **Deterministic Deduplication**: Findings are deduplicated based on `(rule_id, start_line, end_line, code_snippet)` to prevent noisy multi-match reports.
3. **Consistent Severity Levels**: Severities strictly align with risk (`ERROR` for remote code execution and deserialization exploits, `WARNING` for injection and secret hygiene).
4. **Normalized Findings**: Every finding guarantees valid integer line numbers, non-empty snippets, category taxonomy, and human-readable remediation advice.

---

## Technology Stack

- **Frontend**: React 19, Vite 8, Plain CSS
- **Backend**: Python 3.10+, FastAPI, Uvicorn, Pydantic v2
- **Static Analysis Engine**: Semgrep 1.x
- **Testing**: pytest, FastAPI TestClient, HTTPX

---

## Project Structure

```
codeguard-ai/
├── backend/
│   ├── main.py              # FastAPI application, routing, and CORS
│   ├── scanner.py           # Scanner core, Semgrep executor, report builder
│   ├── test_scanner.py      # Security rule validation test suite (TDD)
│   ├── test_api.py          # FastAPI endpoint integration tests
│   └── requirements.txt     # Locked backend dependency specifications
├── frontend/
│   ├── src/
│   │   ├── App.jsx          # Dashboard, code input, metrics, export button
│   │   ├── main.jsx         # React DOM mount point
│   │   ├── index.css        # Base styling
│   │   └── App.css          # Application layout styles
│   ├── index.html           # Single-page application entry HTML
│   └── package.json         # Frontend scripts and dependencies
├── semgrep-rules/
│   └── python-security.yml  # Semgrep YAML rule definitions
├── .gitignore               # Ignored artifacts, virtual environments, caches
└── README.md                # Project documentation
```

---

## Getting Started

### Prerequisites

- **Python**: 3.10 or higher
- **Node.js**: 18.0 or higher
- **npm**: 9.0 or higher

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create and activate a virtual environment:
   ```bash
   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1

   # macOS / Linux
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Start the development server:
   ```bash
   uvicorn main:app --reload --port 8001
   ```

The backend server will run at `http://127.0.0.1:8001`.

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install Node dependencies:
   ```bash
   npm install
   ```

3. Start the Vite development server:
   ```bash
   npm run dev
   ```

4. Open `http://localhost:5173` in your browser.

---

## Testing

The project uses `pytest` for rigorous test-driven validation, covering individual rules, false-positive resistance, deduplication, and full HTTP endpoint integration.

Run the complete test suite:

```bash
cd backend
pytest test_scanner.py test_api.py -v
```

All 48 test cases test against real Semgrep execution and FastAPI endpoints.

---

## API Reference

### `GET /`

Root status endpoint verifying backend connectivity.

**Response:**
```json
{
  "message": "CodeGuard AI backend is running!"
}
```

---

### `GET /health`

Liveness and health monitoring check.

**Response:**
```json
{
  "status": "healthy"
}
```

---

### `POST /scan`

Executes static analysis on the submitted Python source code.

**Request Body:**
```json
{
  "code": "user_input = input('Command: ')\nos.system(user_input)"
}
```

**Response:**
```json
{
  "findings": [
    {
      "rule_id": "python-command-injection",
      "severity": "ERROR",
      "category": "Command Injection",
      "message": "Dynamic input executed in shell command can lead to command injection.",
      "remediation": "Avoid building shell commands from user-controlled input. Prefer direct API calls and avoid shell=True unless absolutely necessary.",
      "file_path": "sample.py",
      "start_line": 2,
      "end_line": 2,
      "code_snippet": "os.system(user_input)"
    }
  ],
  "total_findings": 1
}
```

---

### `POST /scan/report`

Generates and serves a downloadable JSON security report with aggregate summary statistics.

**Headers Returned:**
`Content-Disposition: attachment; filename="codeguard-report.json"`

**Response Body:**
```json
{
  "report_version": "1.0",
  "generated_at": "2026-10-28T14:40:00+00:00",
  "scanner": "CodeGuard AI / Semgrep",
  "summary": {
    "total_findings": 1,
    "severity_counts": {
      "ERROR": 1
    }
  },
  "findings": [
    {
      "rule_id": "python-command-injection",
      "severity": "ERROR",
      "category": "Command Injection",
      "message": "Dynamic input executed in shell command can lead to command injection.",
      "remediation": "Avoid building shell commands from user-controlled input. Prefer direct API calls and avoid shell=True unless absolutely necessary.",
      "file_path": "sample.py",
      "start_line": 2,
      "end_line": 2,
      "code_snippet": "os.system(user_input)"
    }
  ]
}
```

---

## Scan Report Schema

Exported reports adhere to the following contract:

```typescript
interface ScanReport {
  report_version: string;       // Schema version, e.g., "1.0"
  generated_at: string;         // ISO 8601 UTC timestamp
  scanner: string;              // Scanner engine identifier
  summary: {
    total_findings: number;
    severity_counts: Record<"ERROR" | "WARNING" | "INFO", number>;
  };
  findings: Array<{
    rule_id: string;
    severity: "ERROR" | "WARNING" | "INFO";
    category: string;
    message: string;
    remediation: string;
    file_path: string;
    start_line: number;
    end_line: number;
    code_snippet: string;
  }>;
}
```

---

## Roadmap

- [ ] **AI-Assisted Autofix**: Integration with LLM APIs to generate syntax-accurate pull requests and remediation diffs.
- [ ] **Multi-File & Repository Scanning**: Upload ZIP archives or point to GitHub repositories for project-wide scans.
- [ ] **SARIF & PDF Exports**: Export findings to GitHub Code Scanning SARIF format and downloadable audit PDFs.
- [ ] **Custom Rule Builder**: In-browser YAML rule creation with immediate syntax validation.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
