import json

from execproof.rawrequest import parse_raw_request
from execproof.models import ScanConfig
from execproof.scanner import Scanner
from execproof.report import to_sarif


RAW_POST = (
    "POST /vuln/echo HTTP/1.1\n"
    "Host: target\n"
    "Content-Type: application/json\n"
    "\n"
    '{"name":"guest"}\n'
)


def test_parse_raw_request():
    parsed = parse_raw_request(RAW_POST, "http://127.0.0.1:1")
    assert parsed["method"] == "POST"
    assert parsed["url"].endswith("/vuln/echo")
    assert parsed["headers"]["Content-Type"] == "application/json"
    assert parsed["data"] == '{"name":"guest"}'


def test_parse_raw_rejects_garbage():
    import pytest
    with pytest.raises(ValueError):
        parse_raw_request("garbage", "http://127.0.0.1:1")


def test_scan_with_raw_request(vuln_base_url):
    import tempfile
    import os
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write(RAW_POST)
        raw_path = fh.name
    try:
        cfg = ScanConfig(
            url=vuln_base_url,
            raw_request=raw_path,
            rate=50.0,
            detectors=["echo"],
        )
        result = Scanner(cfg).scan()
        assert result.confirmed
        assert result.confirmed[0].injection_point == "json:name"
    finally:
        os.unlink(raw_path)


def test_both_mode_merges_dast_and_sast(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/vuln/echo?name=g",
        rate=50.0,
        mode="both",
        src_path="tests/fixtures/src",
        detectors=["echo"],
    )
    result = Scanner(cfg).scan()
    sources = {f.source for f in result.findings}
    assert "sast" in sources
    assert result.confirmed


def test_sarif_output(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/vuln/echo?name=g",
        rate=50.0,
        mode="both",
        src_path="tests/fixtures/src",
        detectors=["echo"],
    )
    result = Scanner(cfg).scan()
    sarif = json.loads(to_sarif(result))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert any(rid.startswith("sast:") for rid in rule_ids)
