import json
from .models import ScanResult

def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def to_markdown(result: ScanResult) -> str:
    lines = [
        "# ExecProof Report",
        "",
        f"- **Target:** {result.target}",
        f"- **Started:** {result.started_at}",
        f"- **Finished:** {result.finished_at}",
        f"- **Requests sent:** {result.requests_sent}",
        f"- **Confirmed:** {len(result.confirmed)} | **Candidates:** {len(result.candidates)}",
        "",
    ]
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"
    for f in result.findings:
        lines.append(f"## [{f.confidence.upper()}] {f.detector} @ {f.injection_point} ({f.severity})")
        lines.append("")
        lines.append(f"- **Payload:** `{f.payload}`")
        lines.append(f"- **Evidence:** {f.evidence}")
        if f.detail:
            lines.append(f"- **Detail:** {f.detail}")
        lines.append("")
    return "\n".join(lines)


SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def to_sarif(result: ScanResult) -> str:
    findings = result.findings
    rules = []
    seen = set()
    for f in findings:
        rule_id = f.detector if f.detector != "impact" else "impact-verification"
        if rule_id not in seen:
            seen.add(rule_id)
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": f.detector},
                "defaultConfiguration": {"level": SEVERITY_TO_LEVEL.get(f.severity, "warning")},
            })
    results = []
    for f in findings:
        rule_id = f.detector if f.detector != "impact" else "impact-verification"
        if f.source == "sast" and ":" in f.injection_point:
            path, _, line = f.injection_point.rpartition(":")
            location = {"physicalLocation": {
                "artifactLocation": {"uri": path},
                "region": {"startLine": int(line) if line.isdigit() else 1},
            }}
        else:
            location = {"physicalLocation": {"artifactLocation": {"uri": result.target}}}
        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_TO_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"[{f.confidence}] {f.evidence} | payload: {f.payload}"},
            "locations": [location],
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "execproof", "version": "0.2.0",
                                "informationUri": "https://github.com/abdelmhmoud2005/execproof"}},
            "rules": rules,
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)
