import subprocess

from execproof.models import ScanConfig
from execproof.scanner import Scanner

from tests.vuln_app import run_cmd


def test_local_shell_is_safe_only():
    assert "hello" in run_cmd("echo hello")
    out = run_cmd("echo $((44*2))")
    assert "88" in out


def test_echo_detector_confirms_real_rce(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/vuln/echo?name=guest",
        rate=50.0,
        timeout=10.0,
        detectors=["echo"],
        confirmations=1,
    )
    result = Scanner(cfg).scan()
    assert result.confirmed, [f.to_dict() for f in result.findings]
    f = result.confirmed[0]
    assert f.detector == "echo"
    assert f.injection_point == "query:name"
    assert f.severity == "critical"


def test_arithmetic_probe_confirms_rce(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/vuln/echo?name=guest",
        rate=50.0,
        detectors=["echo"],
        confirmations=1,
    )
    result = Scanner(cfg).scan()
    payloads_used = [f.payload for f in result.confirmed]
    assert any("*2))" in p or "expr" in p for p in payloads_used), payloads_used


def test_quote_escape_context_detected(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/vuln/eval-quote?arg=x",
        rate=50.0,
        detectors=["echo"],
        confirmations=1,
    )
    result = Scanner(cfg).scan()
    assert result.confirmed


def test_time_detector_confirms_blind_rce(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/vuln/ping?host=127.0.0.1",
        rate=50.0,
        timeout=30.0,
        time_delay=3,
        time_threshold=2.5,
        confirmations=2,
        detectors=["time"],
    )
    result = Scanner(cfg).scan()
    assert result.confirmed, [f.to_dict() for f in result.findings]
    f = result.confirmed[0]
    assert f.detector == "time"


def test_safe_endpoint_produces_no_confirmations(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/safe?q=hello",
        rate=50.0,
        detectors=["echo", "time"],
        time_delay=2,
        time_threshold=1.5,
        confirmations=1,
    )
    result = Scanner(cfg).scan()
    assert not result.confirmed
    assert not result.candidates


def test_json_body_injection_detected(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/vuln/echo",
        method="POST",
        data='{"name":"guest"}',
        headers={"Content-Type": "application/json"},
        rate=50.0,
        detectors=["echo"],
        confirmations=1,
    )
    result = Scanner(cfg).scan()
    assert result.confirmed
    assert result.confirmed[0].injection_point == "json:name"


def test_scope_regex_blocks_out_of_scope(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/vuln/echo?name=x",
        rate=50.0,
        detectors=["echo"],
        scope_regex=r"^evil\.example$",
    )
    result = Scanner(cfg).scan()
    assert not result.findings


def test_report_outputs(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/vuln/echo?name=g",
        rate=50.0,
        detectors=["echo"],
        confirmations=1,
    )
    result = Scanner(cfg).scan()
    from execproof.report import to_json, to_markdown
    assert '"confirmed_count"' in to_json(result)
    assert "# ExecProof Report" in to_markdown(result)


def test_subprocess_probe_direct():
    out = subprocess.run(
        "echo rha_test_1$(echo rha_test_2)", shell=True, capture_output=True, text=True
    ).stdout
    assert "rha_test_1rha_test_2" in out
