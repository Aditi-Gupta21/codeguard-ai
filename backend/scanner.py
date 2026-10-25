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

            findings.append(
                {
                    "rule_id": finding.get("check_id", "").split(".")[-1],
                    "severity": extra.get("severity", "INFO"),
                    "message": extra.get("message", ""),
                    "file_path": "sample.py",
                    "start_line": start_line,
                    "end_line": end_line,
                    "code_snippet": snippet,
                }
            )

        return findings