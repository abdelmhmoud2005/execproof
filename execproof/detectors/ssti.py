
from .. import payloads
from ..models import CONFIRMED, CANDIDATE, Finding
from ..injector import build_request


class SstiDetector:
    name = "ssti"

    def run(self, client, cfg, url, point, baseline_body: str) -> list:
        findings = []
        engine = self._fingerprint(client, cfg, url, point, baseline_body)
        if engine is None:
            return findings
        findings.extend(self._rce(client, cfg, url, point, baseline_body, engine))
        return findings

    def _send(self, client, cfg, url, point, raw_payload):
        final_url, final_data = build_request(url, cfg.data, point, raw_payload)
        try:
            return client.request(cfg.method, final_url, data=final_data)
        except Exception:
            return None, 0.0

    def _fingerprint(self, client, cfg, url, point, baseline_body):
        engine_name = None
        for engine, payload, product in payloads.build_ssti_fingerprint_payloads():
            if str(product) in (baseline_body or ""):
                continue
            resp, _ = self._send(client, cfg, url, point, payload)
            if resp is not None and str(product) in resp.text:
                engine_name = engine
                break
        if engine_name == "jinja2_or_twig":
            resp, _ = self._send(client, cfg, url, point, payloads.SSTI_JINJA_TWIG_DIFF)
            if resp is not None:
                if "7777777" in resp.text:
                    return "jinja2"
                if "49" in resp.text:
                    return "twig"
            return "jinja2"
        return payloads.SSTI_ENGINE_BY_FINGERPRINT.get(engine_name)

    def _rce(self, client, cfg, url, point, baseline_body, engine):
        for payload in payloads.build_ssti_rce_payloads(engine):
            resp, _ = self._send(client, cfg, url, point, payload)
            if resp is None:
                continue
            m = payloads.SSTI_RCE_PROOF.search(resp.text)
            if m:
                return [Finding(
                    detector=self.name,
                    injection_point=f"{point['kind']}:{point['name']}",
                    payload=payload,
                    evidence=f"template engine '{engine}' executed OS command; captured: {m.group(0)}",
                    confidence=CONFIRMED,
                    severity="critical",
                    detail=f"SSTI in {engine} escalated to OS command execution (id output reflected).",
                )]
            if "root:x:0" in resp.text or "root:*:0" in resp.text:
                return [Finding(
                    detector=self.name,
                    injection_point=f"{point['kind']}:{point['name']}",
                    payload=payload,
                    evidence="file read executed through template engine",
                    confidence=CONFIRMED,
                    severity="critical",
                    detail=f"SSTI in {engine} executed code (file read reflected).",
                )]
        return [Finding(
            detector=self.name,
            injection_point=f"{point['kind']}:{point['name']}",
            payload=payloads.SSTI_JINJA_TWIG_DIFF if engine == "jinja2" else payload,
            evidence=f"template engine '{engine}' evaluated arithmetic (code evaluation confirmed)",
            confidence=CANDIDATE,
            severity="high",
            detail=(
                f"Code evaluation confirmed in {engine} but engine-specific RCE payloads "
                "did not reflect command output; sandboxed engine or output filtering likely. "
                "Manual review: try blind SSTI with OOB callback."
            ),
        )]
