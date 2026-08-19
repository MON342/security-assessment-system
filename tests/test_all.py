"""
Unit tests for Automated Security Misconfiguration Assessment System
"""
import os
import sys
import json
import tempfile
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import validate_url
import modules.whatweb_scanner as whatweb_scanner
import modules.nmap_scanner as nmap_scanner
import modules.gobuster_scanner as gobuster_scanner
import modules.nikto_scanner as nikto_scanner
import modules.testssl_scanner as testssl_scanner
import modules.risk_scorer as risk_scorer
import modules.report_generator as report_generator


def test_validate_url():
    assert validate_url("example.com") == "https://example.com"
    assert validate_url("http://example.com:8080") == "http://example.com:8080"
    assert validate_url("https://test.local/app") == "https://test.local/app"
    with pytest.raises(ValueError):
        validate_url("http://")


def test_nmap_parse_headers():
    raw_output = """
  00010: HTTP/1.1 200 OK
  00020: Date: Wed, 19 Aug 2026 14:00:00 GMT
  00030: Server: Apache/2.4.41 (Ubuntu)
  00040: X-Frame-Options: SAMEORIGIN
  00050: Content-Type: text/html
  (Request type: GET)
    """
    headers = nmap_scanner._parse_headers(raw_output)
    assert headers.get("server") == "Apache/2.4.41 (Ubuntu)"
    assert headers.get("x-frame-options") == "SAMEORIGIN"
    assert headers.get("content-type") == "text/html"
    assert "00010" not in headers


def test_whatweb_json_parse():
    sample_json = json.dumps([
        {
            "target": "https://example.com",
            "http_status": 200,
            "plugins": {
                "HTTPServer": {"string": ["cloudflare"]},
                "PHP": {"version": ["7.4.3"]},
                "Apache": {"version": ["2.4.41"]}
            }
        }
    ])
    with tempfile.TemporaryDirectory() as tmpdir:
        json_file = os.path.join(tmpdir, "whatweb_results.json")
        with open(json_file, "w") as f:
            f.write(sample_json)

        # Mock run_tool to avoid executing actual whatweb binary
        original_run = whatweb_scanner.run_tool
        try:
            whatweb_scanner.run_tool = lambda cmd, tool_name, timeout: (0, "", "")
            res = whatweb_scanner.scan("https://example.com", tmpdir)
            assert res["status"] == "success"
            tech_names = [t["name"] for t in res["technologies"]]
            assert "HTTPServer" in tech_names
            assert "PHP" in tech_names
            assert len(res["findings"]) >= 1
        finally:
            whatweb_scanner.run_tool = original_run


def test_gobuster_parse_output():
    raw_output = """
/admin                (Status: 200) [Size: 4096]
http://example.com/config.php (Status: 200) [Size: 123]
/secret.txt           (Status: 403) [Size: 0]
/notfound             (Status: 404) [Size: 50]
    """
    paths = gobuster_scanner._parse_gobuster_output(raw_output)
    path_names = [p["path"] for p in paths]
    assert "/admin" in path_names
    assert "/config.php" in path_names
    assert "/secret.txt" in path_names
    assert "/notfound" not in path_names


def test_nikto_json_parse():
    sample_data = {
        "host": "127.0.0.1",
        "vulnerabilities": [
            {
                "id": "999999",
                "msg": "X-Frame-Options header is missing.",
                "uri": "/",
                "method": "GET"
            },
            {
                "id": "999998",
                "msg": "SQL injection vulnerability in login parameter",
                "uri": "/login.php",
                "method": "POST"
            }
        ]
    }
    with tempfile.TemporaryDirectory() as tmpdir:
        json_file = os.path.join(tmpdir, "nikto_results.json")
        with open(json_file, "w") as f:
            f.write("Warning banner before JSON\n" + json.dumps(sample_data))

        findings = nikto_scanner._parse_nikto_json(json_file)
        assert len(findings) == 2
        severities = [f["severity"] for f in findings]
        assert "CRITICAL" in severities or "HIGH" in severities
        assert "LOW" in severities or "MEDIUM" in severities


def test_testssl_json_parse():
    sample_data = [
        {"id": "SSLv2", "severity": "OK", "finding": "not offered"},
        {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
        {"id": "cert_expired", "severity": "HIGH", "finding": "certificate expired"}
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        json_file = os.path.join(tmpdir, "testssl_results.json")
        with open(json_file, "w") as f:
            f.write("Some warning\n" + json.dumps(sample_data))

        parsed = testssl_scanner._parse_testssl_json(json_file)
        assert len(parsed["findings"]) >= 2


def test_risk_scorer():
    findings = [
        {
            "tool": "nmap",
            "title": "Docker API Exposed",
            "severity": "CRITICAL",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        },
        {
            "tool": "nmap",
            "title": "Missing HSTS Header",
            "severity": "MEDIUM",
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
        }
    ]
    scored = risk_scorer.score_all_findings(findings)
    assert scored[0]["severity"] == "CRITICAL"
    assert scored[0]["cvss_base_score"] >= 9.0

    overall = risk_scorer.calculate_overall_score(scored)
    assert overall["max_score"] >= 9.0
    assert overall["max_severity"] == "CRITICAL"
    assert overall["total_risks"] == 2


def test_report_generator():
    results = {"whatweb": {"status": "success", "findings": []}}
    summary = {
        "max_score": 7.5,
        "max_severity": "HIGH",
        "total_risks": 1,
        "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    }
    findings = [
        {
            "tool": "whatweb",
            "title": "Exposed PHP Version",
            "severity": "HIGH",
            "description": "PHP 7.4 version disclosed.",
            "evidence": "Detected: PHP v7.4.3",
            "category": "Information Disclosure",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_base_score": 7.5
        }
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        report_paths = report_generator.generate_report(
            "https://example.com", results, summary, findings, tmpdir, "2026-08-19_21-00-00"
        )
        assert os.path.exists(report_paths["pdf"])
        assert os.path.exists(report_paths["txt"])
        assert os.path.getsize(report_paths["pdf"]) > 0
        assert os.path.getsize(report_paths["txt"]) > 0
