"""Integration tests for the CodeGuard AI FastAPI endpoints.

Validates the full workflow: HTTP request → FastAPI → Semgrep → response.
"""

import json

import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


class TestHealthEndpoints:
    def test_home_returns_message(self):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "running" in data["message"].lower()

    def test_health_returns_healthy(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}


class TestScanEndpoint:
    def test_scan_returns_findings(self):
        response = client.post("/scan", json={"code": "eval(input())"})
        assert response.status_code == 200
        data = response.json()
        assert "findings" in data
        assert "total_findings" in data
        assert data["total_findings"] >= 1

    def test_scan_clean_code_returns_zero_findings(self):
        response = client.post("/scan", json={"code": "x = 1 + 2\nprint(x)"})
        assert response.status_code == 200
        data = response.json()
        assert data["total_findings"] == 0
        assert data["findings"] == []

    def test_scan_rejects_empty_code(self):
        response = client.post("/scan", json={"code": ""})
        assert response.status_code == 422

    def test_scan_rejects_missing_code_field(self):
        response = client.post("/scan", json={})
        assert response.status_code == 422

    def test_scan_finding_has_expected_shape(self):
        response = client.post("/scan", json={"code": "eval(input())"})
        data = response.json()
        finding = data["findings"][0]
        required_keys = {"rule_id", "severity", "category", "message", "remediation", "file_path", "start_line", "end_line", "code_snippet"}
        assert required_keys.issubset(set(finding.keys()))


class TestReportEndpoint:
    def test_report_returns_downloadable_json(self):
        response = client.post("/scan/report", json={"code": "eval(input())"})
        assert response.status_code == 200
        assert "codeguard-report.json" in response.headers.get("content-disposition", "")

        report = response.json()
        assert report["report_version"] == "1.0"
        assert "generated_at" in report
        assert report["summary"]["total_findings"] >= 1
        assert len(report["findings"]) == report["summary"]["total_findings"]

    def test_report_clean_code(self):
        response = client.post("/scan/report", json={"code": "print('hello')"})
        assert response.status_code == 200
        report = response.json()
        assert report["summary"]["total_findings"] == 0

    def test_report_rejects_empty_code(self):
        response = client.post("/scan/report", json={"code": ""})
        assert response.status_code == 422
