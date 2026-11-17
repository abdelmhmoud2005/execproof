import json

from execproof.cli import main


def test_cli_version(capsys):
    assert main(["version"]) == 0
    out = capsys.readouterr().out
    assert out.strip()


def test_cli_scan_vuln_target_json(vuln_base_url, capsys):
    rc = main([
        "scan", "-u", f"{vuln_base_url}/vuln/echo?name=guest",
        "--detectors", "echo", "--rate", "50", "--format", "json",
    ])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert rc == 1
    assert data["confirmed_count"] >= 1
    assert data["findings"][0]["confidence"] == "confirmed"


def test_cli_scan_safe_target_exit_zero(vuln_base_url, capsys):
    rc = main([
        "scan", "-u", f"{vuln_base_url}/safe?q=hi",
        "--detectors", "echo", "--rate", "50", "--format", "json",
    ])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert rc == 0
    assert data["confirmed_count"] == 0


def test_cli_scope_blocks_external(tmp_path, vuln_base_url, capsys):
    rc = main([
        "scan", "-u", f"{vuln_base_url}/vuln/echo?name=x",
        "--scope-regex", r"^internal\.corp$", "--detectors", "echo",
        "--format", "json",
    ])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["confirmed_count"] == 0


def test_cli_markdown_output_file(vuln_base_url, tmp_path):
    out_file = tmp_path / "report.md"
    main([
        "scan", "-u", f"{vuln_base_url}/vuln/echo?name=g",
        "--detectors", "echo", "--rate", "50", "-o", str(out_file), "--format", "md",
    ])
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "ExecProof Report" in content


def test_cli_invalid_url_errors(capsys):
    rc = main(["scan", "-u", "not-a-url"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "[!]" in err
