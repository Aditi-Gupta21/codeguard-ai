import json
import subprocess
import tempfile
from pathlib import Path

# Project root: the directory containing backend/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_FILE = PROJECT_ROOT / "semgrep-rules" / "python-security.yml"
SEMGREP_EXECUTABLE = (
    Path.home()
    / "AppData"
    / "Local"
    / "CodeGuardSemgrep"
    / "Scripts"
    / "pysemgrep.exe"
)


def scan_code(source_code: str) -> list[dict]:
    """Scan Python source code with Semgrep and return structured findings."""

    if not RULES_FILE.is_file():
        raise RuntimeError(f"Semgrep rules file not found: {RULES_FILE}")

    # Create a temporary Python file. The submitted code is never executed.
    with tempfile.TemporaryDirectory(prefix="codeguard-") as temp_dir:
        source_file = Path(temp_dir) / "sample.py"
        source_file.write_text(source_code, encoding="utf-8")

        command = [
            str(SEMGREP_EXECUTABLE),
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
                "Could not start Semgrep. Check that it is installed "
                "in the active Python environment."
            ) from exc

        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            detail = result.stderr.strip() or "No diagnostic output available."
            raise RuntimeError(f"Semgrep returned invalid JSON: {detail}") from exc

        if result.returncode != 0 or report.get("errors"):
            details = "; ".join(
                error.get("message", error.get("short_msg", "Unknown error"))
                for error in report.get("errors", [])
            )
            raise RuntimeError(
                f"Semgrep scan failed: {details or result.stderr.strip()}"
            )

        findings = []
        source_lines = source_code.splitlines()

        for finding in report.get("results", []):
            extra = finding.get("extra", {})
            start = finding.get("start", {})
            end = finding.get("end", {})

            start_line = start.get("line")
            end_line = end.get("line")

            # Use the submitted source instead of Semgrep's unavailable snippet.
            snippet = ""
            if isinstance(start_line, int) and 1 <= start_line <= len(source_lines):
                snippet = source_lines[start_line - 1]


            rule_id = finding.get("check_id", "").split(".")[-1]

            remediation_guidance = {
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
            }

            security_categories = {
                "python-dangerous-eval": "Code Injection",
                "python-hardcoded-secret": "Hardcoded Secrets",
                "python-sql-injection-fstring": "SQL Injection",
                "python-unsafe-pickle": "Unsafe Deserialization",
            }

            findings.append(
                {
                    "rule_id": rule_id,
                    "severity": extra.get("severity", "INFO"),
                    "category": security_categories.get(rule_id, "Security"),
                    "message": extra.get("message", ""),
                    "remediation": remediation_guidance.get(
                        rule_id,
                        "Review this finding and follow secure coding practices."
                    ),
                    "file_path": "sample.py",
                    "start_line": start_line,
                    "end_line": end_line,
                    "code_snippet": snippet,
                }
            )


        return findings
