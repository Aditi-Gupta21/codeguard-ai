import pytest

from scanner import scan_code


def get_rule_ids(code: str):
    findings = scan_code(code)
    return {finding["rule_id"] for finding in findings}


def test_dangerous_eval_detects_vulnerable_input():
    code = """
user_input = input('Enter expression: ')
result = eval(user_input)
print(result)
"""
    assert "python-dangerous-eval" in get_rule_ids(code)


def test_dangerous_eval_safe_alternative_does_not_trigger():
    code = """
import ast
value = ast.literal_eval("[1, 2, 3]")
print(value)
"""
    assert "python-dangerous-eval" not in get_rule_ids(code)


def test_hardcoded_secret_detects_credentials():
    code = """
DB_PASSWORD = "super-secret-123!"
print(DB_PASSWORD)
"""
    assert "python-hardcoded-secret" in get_rule_ids(code)


def test_hardcoded_secret_ignores_placeholder_values():
    code = """
API_KEY = "your_api_key_here"
PASSWORD = "changeme"
"""
    assert "python-hardcoded-secret" not in get_rule_ids(code)


def test_sql_injection_fstring_detects_vulnerable_query():
    code = """
user = "admin' OR '1'='1"
query = f"SELECT * FROM users WHERE username = '{user}'"
cursor.execute(query)
"""
    assert "python-sql-injection-fstring" in get_rule_ids(code)


def test_sql_injection_direct_execute_fstring_detects_vulnerable_query():
    code = """
user = "alice"
cursor.execute(f"SELECT * FROM users WHERE username = '{user}'")
"""
    assert "python-sql-injection-fstring" in get_rule_ids(code)


def test_parameterized_sql_query_is_safe():
    code = """
user = "alice"
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (user,))
"""
    assert "python-sql-injection-fstring" not in get_rule_ids(code)


def test_non_sql_fstring_is_safe():
    code = """
name = "alice"
message = f"Hello {name}!"
print(message)
"""
    assert "python-sql-injection-fstring" not in get_rule_ids(code)


def test_pickle_loads_detects_unsafe_deserialization():
    code = """
import pickle
payload = b'\x80\x04\x95\x00....'
value = pickle.loads(payload)
print(value)
"""
    assert "python-unsafe-pickle" in get_rule_ids(code)


def test_json_deserialization_is_safe():
    code = """
import json
payload = '{"user": "alice"}'
value = json.loads(payload)
print(value)
"""
    assert "python-unsafe-pickle" not in get_rule_ids(code)


def test_command_injection_detects_shell_execution():
    code = """
import os
cmd = "ls -l " + user_input
os.system(cmd)
"""
    assert "python-command-injection" in get_rule_ids(code)


def test_safe_subprocess_call_is_not_flagged():
    code = """
import subprocess
subprocess.run(["ls", "-l"])
"""
    assert "python-command-injection" not in get_rule_ids(code)


def test_unsafe_tempfile_detects_mktemp():
    code = """
import tempfile
path = tempfile.mktemp()
print(path)
"""
    assert "python-unsafe-tempfile" in get_rule_ids(code)


def test_safe_named_tempfile_is_not_flagged():
    code = """
import tempfile
with tempfile.NamedTemporaryFile(delete=True) as tmp:
    print(tmp.name)
"""
    assert "python-unsafe-tempfile" not in get_rule_ids(code)


def test_scan_returns_expected_metadata_fields():
    code = """
import os
os.system("echo hello")
"""
    findings = scan_code(code)
    assert findings
    finding = findings[0]
    assert "rule_id" in finding
    assert "severity" in finding
    assert "category" in finding
    assert "message" in finding
    assert "remediation" in finding
    assert "start_line" in finding
