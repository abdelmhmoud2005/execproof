import os

from execproof.sast import scan_source_dir, scan_file, RULES

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "src")


def _ids(findings):
    return {f.detector for f in findings}


def test_scans_all_language_fixtures():
    findings = scan_source_dir(FIXTURES)
    assert findings
    sources = {f.source for f in findings}
    assert sources == {"sast"}
    for f in findings:
        assert f.confidence == "candidate"


def test_python_rules_fire():
    findings = scan_source_dir(FIXTURES)
    ids = _ids(findings)
    for rule in ["sast:py-os-system", "sast:py-shell-true", "sast:py-eval",
                 "sast:py-yaml-load", "sast:py-pickle"]:
        assert rule in ids, (rule, ids)


def test_yaml_load_without_loader_flagged_safe_load_not():
    findings = scan_file(os.path.join(FIXTURES, "vuln.py"), "python")
    ids = _ids(findings)
    assert "sast:py-yaml-load" in ids
    safe = scan_file(os.path.join(FIXTURES, "safe.py"), "python")
    assert "sast:py-yaml-load" not in _ids(safe)


def test_literal_command_not_flagged():
    safe = scan_file(os.path.join(FIXTURES, "safe.py"), "python")
    ids = _ids(safe)
    assert "sast:py-os-system" not in ids
    assert "sast:py-shell-true" not in ids


def test_node_rules_fire():
    findings = scan_file(os.path.join(FIXTURES, "vuln.js"), "node")
    ids = _ids(findings)
    assert "sast:node-cp-exec" in ids
    assert "sast:node-eval" in ids
    assert "sast:node-new-function" in ids


def test_php_rules_fire():
    findings = scan_file(os.path.join(FIXTURES, "vuln.php"), "php")
    ids = _ids(findings)
    assert "sast:php-system" in ids
    assert "sast:php-exec" in ids
    assert "sast:php-backtick" in ids
    assert "sast:php-eval" in ids
    assert "sast:php-unserialize" in ids


def test_java_rules_fire():
    findings = scan_file(os.path.join(FIXTURES, "vuln.java"), "java")
    ids = _ids(findings)
    assert "sast:java-runtime-exec" in ids
    assert "sast:java-processbuilder" in ids
    assert "sast:java-yaml" in ids
    assert "sast:java-scriptengine" in ids


def test_ruby_rules_fire():
    findings = scan_file(os.path.join(FIXTURES, "vuln.rb"), "ruby")
    ids = _ids(findings)
    assert "sast:rb-system" in ids
    assert "sast:rb-backtick" in ids
    assert "sast:rb-yaml-load" in ids
    assert "sast:rb-marshal" in ids
    assert "sast:rb-eval" in ids


def test_sast_findings_have_remediation_and_location():
    findings = scan_source_dir(FIXTURES)
    f = findings[0]
    assert "Remediation" in f.detail
    assert ":" in f.injection_point
    assert f.injection_point.endswith(".py") or "." in f.injection_point


def test_all_rules_compile():
    for lang, rules in RULES.items():
        for rule in rules:
            assert rule.pattern is not None
