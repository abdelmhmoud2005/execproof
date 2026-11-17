from .. import payloads
from ..models import CONFIRMED, CANDIDATE, Finding
from ..injector import build_request


class EchoDetector:
    name = "echo"

    def run(self, client, cfg, url, point, baseline_body: str) -> list:
        findings = []
        findings.extend(self._arith_probe(client, cfg, url, point, baseline_body))
        findings.extend(self._echo_pair_probe(client, cfg, url, point, baseline_body))
        return findings

    def _send(self, client, cfg, url, point, raw_payload, url_encode=True):
        final_url, final_data = build_request(url, cfg.data, point, raw_payload, url_encode)
        return client.request(cfg.method, final_url, data=final_data)

    def _arith_probe(self, client, cfg, url, point, baseline_body):
        findings = []
        n, expected = payloads.arithmetic_token()
        if expected in (baseline_body or ""):
            return findings
        for tpl in payloads.build_arithmetic_payloads(n):
            resp, _ = self._send(client, cfg, url, point, tpl)
            if resp is None:
                continue
            if expected in resp.text and expected not in (baseline_body or ""):
                findings.append(Finding(
                    detector=self.name,
                    injection_point=f"{point['kind']}:{point['name']}",
                    payload=tpl,
                    evidence=f"arithmetic result {n}*2={expected} reflected in response",
                    confidence=CONFIRMED,
                    severity="critical",
                    detail="Server evaluated injected arithmetic expression; output reflected.",
                ))
                break
        return findings

    def _echo_pair_probe(self, client, cfg, url, point, baseline_body):
        findings = []
        built, (a, b) = payloads.build_echo_payloads()
        marker = a + b
        if marker in (baseline_body or ""):
            return findings
        for name, tpl in built:
            resp, _ = self._send(client, cfg, url, point, tpl)
            if resp is None:
                continue
            if marker in resp.text:
                findings.append(Finding(
                    detector=self.name,
                    injection_point=f"{point['kind']}:{point['name']}",
                    payload=tpl,
                    evidence=f"nested echo markers ({a}$(echo {b})) concatenated in response",
                    confidence=CONFIRMED,
                    severity="critical",
                    detail="Command executed and output reflected (nested substitution).",
                ))
                break
            if a in resp.text and b not in resp.text:
                findings.append(Finding(
                    detector=self.name,
                    injection_point=f"{point['kind']}:{point['name']}",
                    payload=tpl,
                    evidence=f"first echo marker {a} present, second missing",
                    confidence=CANDIDATE,
                    severity="high",
                    detail="Partial command execution signature; needs manual confirmation.",
                ))
        return findings
