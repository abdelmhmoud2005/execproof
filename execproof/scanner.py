import datetime
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import payloads
from .config import is_safe_command
from .http_client import HttpClient
from .models import CONFIRMED, VERIFIED, ScanConfig, ScanResult, Finding
from .payloads import split_injection_points
from .sast import scan_source_dir
from .rawrequest import parse_raw_request
from .detectors import DETECTORS


class ScanError(Exception):
    pass


UID_RE = re.compile(r"uid=\d+\([^)]*\)")


class Scanner:
    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg
        self._validate()
        self.client = HttpClient(
            timeout=cfg.timeout,
            rate=cfg.rate,
            headers=cfg.headers,
            scope_regex=cfg.scope_regex,
        )

    def scan(self) -> ScanResult:
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = ScanResult(target=self.cfg.url, started_at=started)
        baseline_error = None
        points = []
        baseline_body = ""

        if self.cfg.mode in ("dast", "both"):
            self._apply_raw()
            try:
                resp, _ = self.client.request(self.cfg.method, self.cfg.url, data=self.cfg.data)
                baseline_body = resp.text if resp is not None else ""
            except Exception as exc:
                baseline_error = str(exc)
            points = split_injection_points(self.cfg.url, self.cfg.data, None)
            if baseline_error is None and not points:
                baseline_error = "no injectable parameters found (query string or body)"

        sast_findings = []
        if self.cfg.mode in ("sast", "both"):
            if not self.cfg.src_path:
                baseline_error = baseline_error or "--src required for sast/both mode"
            else:
                sast_findings = scan_source_dir(self.cfg.src_path)

        if self.cfg.mode in ("dast", "both") and baseline_error is None and points:
            self._run_dast(points, baseline_body, result)
        result.findings.extend(sast_findings)
        result.requests_sent = self.client.requests_sent
        result.finished_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.client.close()
        return result

    def _apply_raw(self):
        if not self.cfg.raw_request:
            return
        with open(self.cfg.raw_request, "r", encoding="utf-8") as fh:
            parsed = parse_raw_request(fh.read(), base_url=self.cfg.url)
        self.cfg.method = parsed["method"]
        self.cfg.url = parsed["url"]
        if parsed["headers"]:
            merged = dict(self.cfg.headers)
            merged.update(parsed["headers"])
            self.cfg.headers = merged
            self.client.session.headers.update(parsed["headers"])
        self.cfg.data = parsed["data"]

    def _run_dast(self, points, baseline_body, result):
        active = [n for n in self.cfg.detectors if n in DETECTORS]
        if self.cfg.threads <= 1:
            for point in points:
                result.findings.extend(self._scan_point(point, baseline_body, active))
        else:
            with ThreadPoolExecutor(max_workers=self.cfg.threads) as pool:
                futures = [pool.submit(self._scan_point, p, baseline_body, active) for p in points]
                for fut in as_completed(futures):
                    result.findings.extend(fut.result())

    def _scan_point(self, point, baseline_body, active):
        findings = []
        for det_name in active:
            findings.extend(DETECTORS[det_name]().run(
                self.client, self.cfg, self.cfg.url, point, baseline_body))
        if self.cfg.impact:
            findings.extend(self._impact_stage(point, findings))
        return findings

    def _impact_stage(self, point, findings) -> list:
        confirmed = [f for f in findings if f.confidence == CONFIRMED]
        if not confirmed:
            return []
        for payload in payloads.build_impact_payloads(self.cfg.os_type):
            if not is_safe_command(payload):
                continue
            final_url, final_data = None, None
            try:
                from .injector import build_request
                final_url, final_data = build_request(self.cfg.url, self.cfg.data, point, payload)
                resp, _ = self.client.request(self.cfg.method, final_url, data=final_data)
            except Exception:
                continue
            if resp is None:
                continue
            if self.cfg.os_type == "unix":
                m = UID_RE.search(resp.text)
                if m:
                    return [Finding(
                        detector="impact",
                        injection_point=f"{point['kind']}:{point['name']}",
                        payload=payload,
                        evidence=f"real OS execution proven: {m.group(0)}",
                        confidence=VERIFIED,
                        severity="critical",
                        detail="Executed `id` on the host and captured its output. This is "
                               "Gate-0-grade proof: the attacker can already run arbitrary commands.",
                    )]
            else:
                if re.search(r"(?im)^[a-z0-9_.-]+\\[a-z0-9_.-]+$", resp.text):
                    return [Finding(
                        detector="impact",
                        injection_point=f"{point['kind']}:{point['name']}",
                        payload=payload,
                        evidence="real OS execution proven: whoami output (DOMAIN\\user) in response",
                        confidence=VERIFIED,
                        severity="critical",
                        detail="Executed `whoami` on the Windows host and captured its output.",
                    )]
        return []

    def _validate(self):
        if self.cfg.mode in ("dast", "both"):
            parsed = urllib.parse.urlparse(self.cfg.url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ScanError("target must be a valid http(s) URL")
        if self.cfg.data and not is_safe_command(self.cfg.data):
            raise ScanError("user-provided body contains blocked destructive tokens")
