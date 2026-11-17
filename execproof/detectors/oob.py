from .. import payloads
from ..models import CONFIRMED, CANDIDATE, Finding
from ..injector import build_request


class OobDetector:
    name = "oob"

    def run(self, client, cfg, url, point, baseline_body: str) -> list:
        if not cfg.oob_domain:
            return []
        token = payloads.random_token("rho")
        built = payloads.build_oob_payloads(cfg.oob_domain, token)
        findings = []
        for name, tpl in built:
            final_url, final_data = build_request(url, cfg.data, point, tpl)
            try:
                client.request(cfg.method, final_url, data=final_data)
            except Exception:
                continue
            if cfg.oob_poll_url and payloads.build_oob_poll_check(client, cfg.oob_poll_url, token):
                return [Finding(
                    detector=self.name,
                    injection_point=f"{point['kind']}:{point['name']}",
                    payload=tpl,
                    evidence=f"OOB callback confirmed: {token}.{cfg.oob_domain} polled from your endpoint",
                    confidence=CONFIRMED,
                    severity="critical",
                    detail="The target server performed a DNS/HTTP callback to your OOB domain. "
                           "Blind command execution confirmed.",
                )]
            findings.append(Finding(
                detector=self.name,
                injection_point=f"{point['kind']}:{point['name']}",
                payload=tpl,
                evidence=f"OOB token {token}.{cfg.oob_domain} sent; check your collaborator for this exact token",
                confidence=CANDIDATE,
                severity="high",
                detail=(
                    "Candidate blind RCE via DNS/HTTP callback. Confirm ONLY if your OOB "
                    "platform records a lookup for the exact token above. No callback = no finding."
                ),
            ))
            break
        return findings
