"""Security scanner test suite for CodeGuard AI.

Covers:
  - True-positive detection for every supported rule
  - False-positive suppression for safe alternatives
  - Duplicate finding elimination
  - Severity and remediation consistency
  - Finding metadata completeness
  - Report export structure
"""

import json

import pytest

from scanner import (
    REMEDIATION_GUIDANCE,
    SECURITY_CATEGORIES,
    build_report,
    scan_code,
)


# ── Helpers ────────────────────────────────────────────────────────────────


def get_rule_ids(code: str) -> set[str]:
    findings = scan_code(code)
    return {finding["rule_id"] for finding in findings}


def get_findings_for_rule(code: str, rule_id: str) -> list[dict]:
    return [f for f in scan_code(code) if f["rule_id"] == rule_id]


# ═══════════════════════════════════════════════════════════════════════════
# Vulnerability Detection Test Suite
# ═══════════════════════════════════════════════════════════════════════════


# ── python-dangerous-eval ──────────────────────────────────────────────────

class TestDangerousEval:
    def test_detects_eval_with_user_input(self):
        code = "user_input = input('Enter expression: ')\nresult = eval(user_input)\nprint(result)"
        assert "python-dangerous-eval" in get_rule_ids(code)

    def test_detects_eval_with_variable(self):
        code = "data = get_data()\neval(data)"
        assert "python-dangerous-eval" in get_rule_ids(code)

    def test_safe_literal_eval_not_flagged(self):
        code = "import ast\nvalue = ast.literal_eval('[1, 2, 3]')\nprint(value)"
        assert "python-dangerous-eval" not in get_rule_ids(code)

    def test_safe_int_conversion_not_flagged(self):
        code = "user_input = input('Enter number: ')\nresult = int(user_input)\nprint(result)"
        assert "python-dangerous-eval" not in get_rule_ids(code)


# ── python-hardcoded-secret ────────────────────────────────────────────────

class TestHardcodedSecret:
    def test_detects_password_assignment(self):
        code = 'DB_PASSWORD = "super-secret-123!"'
        assert "python-hardcoded-secret" in get_rule_ids(code)

    def test_detects_api_key_assignment(self):
        code = 'API_KEY = "sk-abc123456789xyz"'
        assert "python-hardcoded-secret" in get_rule_ids(code)

    def test_detects_token_assignment(self):
        code = 'AUTH_TOKEN = "eyJhbGciOiJIUzI1NiJ9.abc"'
        assert "python-hardcoded-secret" in get_rule_ids(code)

    def test_ignores_placeholder_values(self):
        code = 'API_KEY = "your_api_key_here"\nPASSWORD = "changeme"'
        assert "python-hardcoded-secret" not in get_rule_ids(code)

    def test_ignores_short_values(self):
        code = 'PASSWORD = "short"'
        assert "python-hardcoded-secret" not in get_rule_ids(code)

    def test_ignores_non_secret_variable_names(self):
        code = 'USERNAME = "administrator-account"'
        assert "python-hardcoded-secret" not in get_rule_ids(code)


# ── python-sql-injection-fstring ───────────────────────────────────────────

class TestSqlInjection:
    def test_detects_fstring_select_query(self):
        code = 'user = "admin\' OR \'1\'=\'1"\nquery = f"SELECT * FROM users WHERE username = \'{user}\'"'
        assert "python-sql-injection-fstring" in get_rule_ids(code)

    def test_detects_direct_execute_fstring(self):
        code = 'user = "alice"\ncursor.execute(f"SELECT * FROM users WHERE username = \'{user}\'")'
        assert "python-sql-injection-fstring" in get_rule_ids(code)

    def test_detects_fstring_insert_query(self):
        code = 'name = "alice"\nquery = f"INSERT INTO users (name) VALUES (\'{name}\')"'
        assert "python-sql-injection-fstring" in get_rule_ids(code)

    def test_detects_fstring_delete_query(self):
        code = 'uid = "42"\nquery = f"DELETE FROM sessions WHERE user_id = {uid}"'
        assert "python-sql-injection-fstring" in get_rule_ids(code)

    def test_parameterized_query_not_flagged(self):
        code = 'user = "alice"\nquery = "SELECT * FROM users WHERE username = %s"\ncursor.execute(query, (user,))'
        assert "python-sql-injection-fstring" not in get_rule_ids(code)

    def test_non_sql_fstring_not_flagged(self):
        code = 'name = "alice"\nmessage = f"Hello {name}!"\nprint(message)'
        assert "python-sql-injection-fstring" not in get_rule_ids(code)


# ── python-unsafe-pickle ──────────────────────────────────────────────────

class TestUnsafePickle:
    def test_detects_pickle_loads(self):
        code = "import pickle\npayload = b'\\x80\\x04\\x95\\x00....'\nvalue = pickle.loads(payload)"
        assert "python-unsafe-pickle" in get_rule_ids(code)

    def test_json_loads_not_flagged(self):
        code = 'import json\nvalue = json.loads(\'{"user": "alice"}\')\nprint(value)'
        assert "python-unsafe-pickle" not in get_rule_ids(code)


# ── python-command-injection ──────────────────────────────────────────────

class TestCommandInjection:
    def test_detects_os_system(self):
        code = 'import os\ncmd = "ls -l " + user_input\nos.system(cmd)'
        assert "python-command-injection" in get_rule_ids(code)

    def test_detects_subprocess_shell_true(self):
        code = 'import subprocess\nsubprocess.run(f"echo {user_input}", shell=True)'
        assert "python-command-injection" in get_rule_ids(code)

    def test_detects_popen_shell_true(self):
        code = 'import subprocess\nsubprocess.Popen("ls", shell=True)'
        assert "python-command-injection" in get_rule_ids(code)

    def test_safe_subprocess_list_not_flagged(self):
        code = 'import subprocess\nsubprocess.run(["ls", "-l"])'
        assert "python-command-injection" not in get_rule_ids(code)

    def test_safe_subprocess_without_shell_not_flagged(self):
        code = 'import subprocess\nsubprocess.run(["git", "status"], check=True)'
        assert "python-command-injection" not in get_rule_ids(code)


# ── python-unsafe-tempfile ────────────────────────────────────────────────

class TestUnsafeTempfile:
    def test_detects_mktemp(self):
        code = "import tempfile\npath = tempfile.mktemp()\nprint(path)"
        assert "python-unsafe-tempfile" in get_rule_ids(code)

    def test_safe_named_tempfile_not_flagged(self):
        code = "import tempfile\nwith tempfile.NamedTemporaryFile(delete=True) as tmp:\n    print(tmp.name)"
        assert "python-unsafe-tempfile" not in get_rule_ids(code)

    def test_safe_tempdir_not_flagged(self):
        code = "import tempfile\nwith tempfile.TemporaryDirectory() as d:\n    print(d)"
        assert "python-unsafe-tempfile" not in get_rule_ids(code)


# ═══════════════════════════════════════════════════════════════════════════
# Finding Quality and Consistency Checks
# ═══════════════════════════════════════════════════════════════════════════


class TestFindingQuality:
    """Verify no duplicates, correct severity, and matching remediation."""

    def _findings(self) -> list[dict]:
        """Return findings from a snippet that triggers multiple rules."""
        code = (
            "import os, pickle, tempfile\n"
            'DB_PASSWORD = "super-secret-123!"\n'
            "os.system('echo hello')\n"
            "pickle.loads(b'data')\n"
            "tempfile.mktemp()\n"
            "user_input = input('>')\n"
            "eval(user_input)\n"
            'query = f"SELECT * FROM users WHERE id = {user_input}"\n'
        )
        return scan_code(code)

    def test_no_duplicate_findings(self):
        findings = self._findings()
        keys = [
            (f["rule_id"], f["start_line"], f["end_line"], f["code_snippet"])
            for f in findings
        ]
        assert len(keys) == len(set(keys)), "Duplicate findings detected"

    def test_severity_matches_known_rules(self):
        """Verify ERROR and WARNING severity values match what the rules define."""
        findings = self._findings()
        error_rules = {"python-unsafe-pickle", "python-command-injection"}
        warning_rules = {
            "python-dangerous-eval",
            "python-hardcoded-secret",
            "python-sql-injection-fstring",
            "python-unsafe-tempfile",
        }
        for finding in findings:
            rid = finding["rule_id"]
            sev = finding["severity"].upper()
            if rid in error_rules:
                assert sev == "ERROR", f"{rid} should be ERROR, got {sev}"
            elif rid in warning_rules:
                assert sev == "WARNING", f"{rid} should be WARNING, got {sev}"

    def test_remediation_matches_rule(self):
        """Every known rule must include the correct remediation text."""
        findings = self._findings()
        for finding in findings:
            rid = finding["rule_id"]
            if rid in REMEDIATION_GUIDANCE:
                assert finding["remediation"] == REMEDIATION_GUIDANCE[rid], (
                    f"Remediation mismatch for {rid}"
                )

    def test_category_matches_rule(self):
        """Every known rule must include the correct category label."""
        findings = self._findings()
        for finding in findings:
            rid = finding["rule_id"]
            if rid in SECURITY_CATEGORIES:
                assert finding["category"] == SECURITY_CATEGORIES[rid], (
                    f"Category mismatch for {rid}"
                )


# ═══════════════════════════════════════════════════════════════════════════
# Finding Metadata Completeness
# ═══════════════════════════════════════════════════════════════════════════


class TestFindingMetadata:
    def test_every_finding_has_required_fields(self):
        code = "import os\nos.system('echo hello')"
        findings = scan_code(code)
        assert findings, "Expected at least one finding"
        required = {"rule_id", "severity", "category", "message", "remediation", "file_path", "start_line", "end_line", "code_snippet"}
        for finding in findings:
            missing = required - set(finding.keys())
            assert not missing, f"Missing fields: {missing}"

    def test_start_line_is_positive_integer(self):
        code = "import os\nos.system('echo hello')"
        findings = scan_code(code)
        for finding in findings:
            assert isinstance(finding["start_line"], int)
            assert finding["start_line"] >= 1

    def test_code_snippet_is_nonempty(self):
        code = "import os\nos.system('echo hello')"
        findings = scan_code(code)
        for finding in findings:
            assert finding["code_snippet"], "Code snippet should not be empty"


# ═══════════════════════════════════════════════════════════════════════════
# Report Export Structure
# ═══════════════════════════════════════════════════════════════════════════


class TestReportExport:
    def test_report_structure(self):
        findings = scan_code("import os\nos.system('ls')")
        report = build_report(findings)

        assert report["report_version"] == "1.0"
        assert "generated_at" in report
        assert report["scanner"] == "CodeGuard AI / Semgrep"
        assert "summary" in report
        assert "findings" in report

    def test_report_summary_counts(self):
        code = (
            "import os, pickle\n"
            "os.system('echo hi')\n"
            "pickle.loads(b'x')\n"
            "eval(input())\n"
        )
        findings = scan_code(code)
        report = build_report(findings)

        summary = report["summary"]
        assert summary["total_findings"] == len(findings)
        assert isinstance(summary["severity_counts"], dict)
        total_from_counts = sum(summary["severity_counts"].values())
        assert total_from_counts == summary["total_findings"]

    def test_report_is_json_serializable(self):
        findings = scan_code("eval(input())")
        report = build_report(findings)
        serialized = json.dumps(report)
        assert isinstance(serialized, str)
        roundtrip = json.loads(serialized)
        assert roundtrip == report

    def test_report_generated_at_is_iso_format(self):
        findings = scan_code("eval(input())")
        report = build_report(findings)
        ts = report["generated_at"]
        # Should parse without error
        from datetime import datetime
        dt = datetime.fromisoformat(ts)
        assert dt is not None

    def test_empty_scan_produces_valid_report(self):
        findings = scan_code("x = 1 + 2\nprint(x)")
        report = build_report(findings)
        assert report["summary"]["total_findings"] == 0
        assert report["findings"] == []
        assert report["summary"]["severity_counts"] == {}
