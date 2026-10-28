"""Semgrep-based Python security scanner for CodeGuard AI."""

import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Project root: the directory containing backend/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_FILE = PROJECT_ROOT / "semgrep-rules" / "python-security.yml"

# ── Remediation guidance keyed by rule ID ──────────────────────────────────

REMEDIATION_GUIDANCE: dict[str, str] = {
    "python-dangerous-eval": (
        "Avoid eval() on untrusted input. Use safer alternatives such as "
        "ast.literal_eval() for supported Python literals, or parse the "
        "specific input format explicitly."
    ),
    "python-hardcoded-secret": (
        "Move passwords, API keys, and tokens into environment variables "
        "or a dedicated secrets manager. Rotate any real exposed credentials."
    ),
    "python-sql-injection-fstring": (
        "Use parameterized SQL queries supported by your database driver. "
        "Do not insert untrusted input directly into SQL strings."
    ),
    "python-unsafe-pickle": (
        "Avoid deserializing untrusted data with pickle. Prefer a safer "
        "format such as JSON and validate the parsed data."
    ),
    "python-command-injection": (
        "Avoid building shell commands from user-controlled input. Prefer direct "
        "API calls and avoid shell=True unless absolutely necessary."
    ),
    "python-unsafe-tempfile": (
        "Use secure temporary-file APIs or create files only in trusted directories; "
        "avoid mktemp() and other predictable temporary paths."
    ),
}

# ── Category labels keyed by rule ID ───────────────────────────────────────

SECURITY_CATEGORIES: dict[str, str] = {
    "python-dangerous-eval": "Code Injection",
    "python-hardcoded-secret": "Hardcoded Secrets",
    "python-sql-injection-fstring": "SQL Injection",
    "python-unsafe-pickle": "Unsafe Deserialization",
    "python-command-injection": "Command Injection",
    "python-unsafe-tempfile": "Insecure File Handling",
}

# ── Helpers ────────────────────────────────────────────────────────────────


def _resolve_semgrep_command() -> list[str]:
    """Resolve the active Semgrep executable without relying on a user-specific path."""
    candidates = []

    semgrep_path = shutil.which("semgrep")
    if semgrep_path:
        candidates.append(semgrep_path)

    venv_scripts = Path(sys.executable).resolve().parent
    for candidate_name in ("semgrep.exe", "pysemgrep.exe"):
        local_script = venv_scripts / candidate_name
        if local_script.exists():
            candidates.append(str(local_script))

    if candidates:
        return [candidates[0]]

    return [str(venv_scripts / "semgrep.exe")]


def _deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Remove exact-duplicate findings that share the same rule, line range, and snippet."""
    seen: set[tuple] = set()
    unique: list[dict] = []
    for finding in findings:
        key = (
            finding.get("rule_id"),
            finding.get("start_line"),
            finding.get("end_line"),
            finding.get("code_snippet"),
        )
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


# ── Core scanner ───────────────────────────────────────────────────────────


def scan_code(source_code: str) -> list[dict]:
    """Scan Python source code with Semgrep and return structured findings."""

    if not RULES_FILE.is_file():
        raise RuntimeError(f"Semgrep rules file not found: {RULES_FILE}")

    with tempfile.TemporaryDirectory(prefix="codeguard-") as temp_dir:
        source_file = Path(temp_dir) / "sample.py"
        source_file.write_text(source_code, encoding="utf-8")

        command = _resolve_semgrep_command() + [
            "scan",
            "--config",
            str(RULES_FILE),
            "--json",
            "--no-git-ignore",
            str(source_file),
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Semgrep scan timed out.") from exc
        except OSError as exc:
            raise RuntimeError(
                "Could not start Semgrep. Install it in the active Python environment or add it to PATH."
            ) from exc

        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Semgrep could not run."
            if "No module named semgrep" in detail or "not recognized" in detail.lower():
                raise RuntimeError(
                    "Semgrep is not installed in the active Python environment. Install it with: "
                    f"{sys.executable} -m pip install semgrep"
                )
            raise RuntimeError(f"Semgrep scan failed: {detail}")

        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            detail = result.stderr.strip() or "No diagnostic output available."
            raise RuntimeError(f"Semgrep returned invalid JSON: {detail}") from exc

        fatal_errors = []
        for error in report.get("errors", []):
            error_level = str(error.get("level", "")).lower()
            error_type = error.get("type")
            # Semgrep reports file parse/syntax issues with level="warn" or type containing "Parsing"
            is_parse_issue = (
                error_level == "warn"
                or (isinstance(error_type, list) and len(error_type) > 0 and "parsing" in str(error_type[0]).lower())
                or "syntax error" in str(error.get("message", "")).lower()
                or "parse error" in str(error.get("message", "")).lower()
            )
            if not is_parse_issue:
                fatal_errors.append(error)

        if fatal_errors:
            details = "; ".join(
                error.get("message", error.get("short_msg", "Unknown error"))
                for error in fatal_errors
            )
            raise RuntimeError(f"Semgrep scan failed: {details}")

        findings = []
        source_lines = source_code.splitlines()

        for finding in report.get("results", []):
            extra = finding.get("extra", {})
            start = finding.get("start", {})
            end = finding.get("end", {})

            start_line = start.get("line")
            end_line = end.get("line")

            snippet = ""
            if isinstance(start_line, int) and 1 <= start_line <= len(source_lines):
                snippet = source_lines[start_line - 1]

            rule_id = finding.get("check_id", "").split(".")[-1]

            findings.append(
                {
                    "rule_id": rule_id,
                    "severity": extra.get("severity", "INFO"),
                    "category": SECURITY_CATEGORIES.get(rule_id, "Security"),
                    "message": extra.get("message", ""),
                    "remediation": REMEDIATION_GUIDANCE.get(
                        rule_id,
                        "Review this finding and follow secure coding practices.",
                    ),
                    "file_path": "sample.py",
                    "start_line": start_line,
                    "end_line": end_line,
                    "code_snippet": snippet,
                }
            )

        return _deduplicate_findings(findings)


# ── Report builder ─────────────────────────────────────────────────────────


def build_report(findings: list[dict]) -> dict:
    """Build a structured scan report suitable for JSON export."""
    severity_counts: dict[str, int] = {}
    for finding in findings:
        sev = (finding.get("severity") or "INFO").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "report_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner": "CodeGuard AI / Semgrep",
        "summary": {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
        },
        "findings": findings,
    }
