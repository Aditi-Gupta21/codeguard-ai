# CodeGuard AI

> Automated static code analysis and security vulnerability scanner for Python applications.

CodeGuard AI inspects Python source code for security vulnerabilities, insecure design patterns, and exposed secrets using [Semgrep](https://semgrep.dev/) static analysis with tailored rule sets. Findings include actionable remediation advice, line-by-line code context, severity indicators, and downloadable audit reports.

---

## Features

- **Static Analysis**: Scans source code safely in isolated temporary workspaces without executing untrusted code.
- **Vulnerability Detection**: Identifies critical vulnerability classes including SQL injection, command execution, unsafe deserialization, insecure temporary files, hardcoded secrets, and dangerous `eval()` usage.
- **Actionable Remediation**: Every detection includes step-by-step guidance and recommended secure alternatives.
- **Deduplication Filter**: Eliminates redundant findings sharing identical rule IDs, line boundaries, and code snippets.
- **Audit Report Export**: Downloads complete security reports formatted as structured JSON with summary counts by severity.
- **Live Web Dashboard**: Interactive React frontend featuring real-time health checks, code editor, summary cards, and responsive finding views.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       React Frontend                        │
│   (Vite + React 19: Code Editor, Metrics, Report Exporter)  │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / JSON
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                      FastAPI Backend                        │
│   - POST /scan        -> Returns structured findings        │
│   - POST /scan/report -> Returns downloadable JSON report   │
│   - GET  /health      -> Health probe                       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    Semgrep Scanner Engine                   │
│   - Sandboxed temporary workspace execution                 │
│   - Rule definitions: semgrep-rules/python-security.yml     │
│   - Parse warning tolerance & deduplication normalizer      │
└─────────────────────────────────────────────────────────────┘
```

---

## Supported Security Rules

| Rule ID | Category | Severity | Description | Recommended Remediation |
|---|---|---|---|---|
| `python-dangerous-eval` | Code Injection | `WARNING` | Detects arbitrary code execution via `eval()`. | Avoid `eval()` on untrusted input. Use `ast.literal_eval()` for literals or parse structured data explicitly. |
| `python-hardcoded-secret` | Hardcoded Secrets | `WARNING` | Detects hardcoded API keys, passwords, and tokens. | Store credentials in environment variables or a dedicated secrets manager. Rotate exposed credentials. |
| `python-sql-injection-fstring` | SQL Injection | `WARNING` | Detects raw SQL queries constructed via f-strings. | Use parameterized database queries supported by your database driver. Never format user strings directly into SQL. |
| `python-unsafe-pickle` | Unsafe Deserialization | `ERROR` | Flags deserialization of untrusted payloads with `pickle`. | Avoid `pickle` on untrusted data. Use safer interchange formats such as JSON or Protocol Buffers. |
| `python-command-injection` | Command Injection | `ERROR` | Detects shell executions constructed from user input. | Avoid dynamic shell commands. Prefer list-based execution (`subprocess.run(["cmd", "arg"])`) and avoid `shell=True`. |
| `python-unsafe-tempfile` | Insecure File Handling | `WARNING` | Catches insecure temporary file paths via `mktemp()`. | Use `tempfile.NamedTemporaryFile` or `tempfile.TemporaryDirectory` to prevent predictable path collisions. |

---

## Technology Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn, Pydantic v2
- **Scanner Engine**: Semgrep 1.x
- **Frontend**: React 19, Vite 8, Plain CSS

---

## Project Structure

```
codeguard-ai/
├── backend/
│   ├── main.py              # FastAPI application, routing, and CORS
│   ├── scanner.py           # Scanner core, Semgrep integration, report builder
│   └── requirements.txt     # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── App.jsx          # Dashboard, code input, metrics, export button
│   │   ├── main.jsx         # React application entry point
│   │   ├── index.css        # Base styling
│   │   └── App.css          # Application layout styles
│   ├── index.html           # HTML shell
│   └── package.json         # Frontend dependencies and scripts
├── semgrep-rules/
│   └── python-security.yml  # Semgrep YAML security rules
├── .gitignore               # Ignored environments, caches, and build outputs
└── README.md                # Project documentation
```

---

## Getting Started

### Prerequisites

- **Python**: 3.10 or higher
- **Node.js**: 18.0 or higher
- **npm**: 9.0 or higher

### 1. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# macOS / Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the API server
uvicorn main:app --reload --port 8001
```

The API will be accessible at `http://127.0.0.1:8001`.

### 2. Frontend Setup

In a separate terminal:

```bash
cd frontend

# Install Node dependencies
npm install

# Start development server
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## API Reference

### `GET /`

Root connectivity probe.

```bash
curl http://127.0.0.1:8001/
```

**Response (`200 OK`):**
```json
{
  "message": "CodeGuard AI backend is running!"
}
```

---

### `GET /health`

Health check endpoint.

```bash
curl http://127.0.0.1:8001/health
```

**Response (`200 OK`):**
```json
{
  "status": "healthy"
}
```

---

### `POST /scan`

Scans Python code and returns individual findings.

```bash
curl -X POST http://127.0.0.1:8001/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "import os\nos.system(\"rm -rf \" + user_input)"}'
```

**Response (`200 OK`):**
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
      "code_snippet": "os.system(\"rm -rf \" + user_input)"
    }
  ],
  "total_findings": 1
}
```

---

### `POST /scan/report`

Scans Python code and returns a complete downloadable JSON report with summary statistics.

```bash
curl -X POST http://127.0.0.1:8001/scan/report \
  -H "Content-Type: application/json" \
  -d '{"code": "eval(input())"}'
```

**Response Headers:**
```
Content-Disposition: attachment; filename="codeguard-report.json"
```

**Response Body (`200 OK`):**
```json
{
  "report_version": "1.0",
  "generated_at": "2026-10-28T14:50:00+00:00",
  "scanner": "CodeGuard AI / Semgrep",
  "summary": {
    "total_findings": 1,
    "severity_counts": {
      "WARNING": 1
    }
  },
  "findings": [
    {
      "rule_id": "python-dangerous-eval",
      "severity": "WARNING",
      "category": "Code Injection",
      "message": "Use of eval() can execute arbitrary code with the current process privileges.",
      "remediation": "Avoid eval() on untrusted input. Use safer alternatives such as ast.literal_eval() for supported Python literals, or parse the specific input format explicitly.",
      "file_path": "sample.py",
      "start_line": 1,
      "end_line": 1,
      "code_snippet": "eval(input())"
    }
  ]
}
```

---

## Scan Report Schema

Exported reports adhere to the following structure:

```json
{
  "report_version": "1.0",
  "generated_at": "ISO-8601 UTC Timestamp",
  "scanner": "CodeGuard AI / Semgrep",
  "summary": {
    "total_findings": 0,
    "severity_counts": {
      "ERROR": 0,
      "WARNING": 0,
      "INFO": 0
    }
  },
  "findings": [
    {
      "rule_id": "string",
      "severity": "ERROR | WARNING | INFO",
      "category": "string",
      "message": "string",
      "remediation": "string",
      "file_path": "string",
      "start_line": 1,
      "end_line": 1,
      "code_snippet": "string"
    }
  ]
}
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
