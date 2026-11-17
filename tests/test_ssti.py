
from execproof.models import ScanConfig
from execproof.scanner import Scanner


def test_ssti_fingerprint_and_rce_confirmed(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/vuln/ssti?tpl=hello",
        rate=50.0,
        detectors=["ssti"],
    )
    result = Scanner(cfg).scan()
    confirmed = [f for f in result.findings if f.confidence == "confirmed"]
    assert confirmed, [f.to_dict() for f in result.findings]
    f = confirmed[0]
    assert f.detector == "ssti"
    assert "uid=" in f.evidence
    assert f.severity == "critical"


def test_ssti_candidate_when_sandboxed(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/vuln/ssti-sandbox?tpl=x",
        rate=50.0,
        detectors=["ssti"],
    )
    result = Scanner(cfg).scan()
    candidates = [f for f in result.findings if f.confidence == "candidate"]
    confirmed = [f for f in result.findings if f.confidence == "confirmed"]
    assert candidates and not confirmed, [f.to_dict() for f in result.findings]


def test_safe_template_no_ssti(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/safe/template?tpl={{7*7}}",
        rate=50.0,
        detectors=["ssti"],
    )
    result = Scanner(cfg).scan()
    assert not result.findings


def test_ssti_no_false_positive_on_plain_echo(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/safe?q={{7*7}}",
        rate=50.0,
        detectors=["ssti"],
    )
    result = Scanner(cfg).scan()
    assert not [f for f in result.findings if f.detector == "ssti" and f.confidence == "confirmed"]


def test_impact_stage_verifies_echo_rce(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/vuln/echo?name=guest",
        rate=50.0,
        detectors=["echo"],
    )
    result = Scanner(cfg).scan()
    verified = [f for f in result.findings if f.confidence == "impact-verified"]
    assert verified, [f.to_dict() for f in result.findings]
    f = verified[0]
    assert f.detector == "impact"
    assert "uid=" in f.evidence


def test_impact_stage_skipped_when_disabled(vuln_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/vuln/echo?name=guest",
        rate=50.0,
        detectors=["echo"],
        impact=False,
    )
    result = Scanner(cfg).scan()
    assert not [f for f in result.findings if f.confidence == "impact-verified"]
    assert [f for f in result.findings if f.confidence == "confirmed"]


def test_oob_poll_confirms_blind_rce(vuln_base_url, poll_base_url):
    cfg = ScanConfig(
        url=f"{vuln_base_url}/vuln/echo?name=guest",
        rate=50.0,
        detectors=["oob"],
        oob_domain="oob.example",
        oob_poll_url=poll_base_url,
    )
    result = Scanner(cfg).scan()
    confirmed = [f for f in result.findings if f.confidence == "confirmed"]
    assert confirmed, [f.to_dict() for f in result.findings]
    assert "OOB callback confirmed" in confirmed[0].evidence
