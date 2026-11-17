from .. import payloads
from ..models import CONFIRMED, CANDIDATE, Finding
from ..injector import build_request


class TimeDetector:
    name = "time"

    def run(self, client, cfg, url, point, baseline_body: str) -> list:
        built = payloads.build_time_payloads(cfg.time_delay)
        threshold = max(cfg.time_threshold, cfg.time_delay - 1.0)
        findings = []
        seen_syntaxes = set()
        for name, tpl in built:
            if name in seen_syntaxes:
                continue
            hits = self._measure(client, cfg, url, point, tpl, threshold)
            if hits >= cfg.confirmations:
                findings.append(Finding(
                    detector=self.name,
                    injection_point=f"{point['kind']}:{point['name']}",
                    payload=tpl,
                    evidence=f"response delayed {cfg.time_delay}s on {hits}/{hits} measurements",
                    confidence=CONFIRMED if hits >= 2 else CANDIDATE,
                    severity="critical" if hits >= 2 else "high",
                    detail="Blind command execution inferred from controlled sleep() delay.",
                ))
                break
            if hits == 1:
                findings.append(Finding(
                    detector=self.name,
                    injection_point=f"{point['kind']}:{point['name']}",
                    payload=tpl,
                    evidence=f"single delayed response >= {threshold:.1f}s (not reproducible)",
                    confidence=CANDIDATE,
                    severity="high",
                    detail="One-off delay observed; retry did not reproduce.",
                ))
            seen_syntaxes.add(name)
        return findings

    def _measure(self, client, cfg, url, point, tpl, threshold) -> int:
        hits = 0
        for _ in range(cfg.confirmations):
            final_url, final_data = build_request(url, cfg.data, point, tpl)
            try:
                _, elapsed = client.request(cfg.method, final_url, data=final_data)
            except Exception:
                return hits
            if elapsed >= threshold:
                hits += 1
            else:
                return hits
        return hits
