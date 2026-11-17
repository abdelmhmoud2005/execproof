from dataclasses import dataclass, field
from typing import Optional


CONFIRMED = "confirmed"
CANDIDATE = "candidate"
VERIFIED = "impact-verified"
INFO = "info"


@dataclass
class Finding:
    detector: str
    injection_point: str
    payload: str
    evidence: str
    confidence: str
    severity: str
    detail: str = ""
    source: str = "dast"

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "injection_point": self.injection_point,
            "payload": self.payload,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "severity": self.severity,
            "detail": self.detail,
            "source": self.source,
        }


@dataclass
class ScanConfig:
    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    data: Optional[str] = None
    timeout: float = 15.0
    rate: float = 5.0
    time_delay: int = 6
    time_threshold: float = 4.0
    oob_domain: Optional[str] = None
    oob_poll_url: Optional[str] = None
    scope_regex: Optional[str] = None
    safe_mode: bool = True
    confirmations: int = 2
    detectors: list = field(default_factory=lambda: ["echo", "time", "oob", "ssti"])
    mode: str = "dast"
    src_path: Optional[str] = None
    raw_request: Optional[str] = None
    threads: int = 1
    os_type: str = "unix"
    impact: bool = True

    def __post_init__(self):
        self.method = self.method.upper()
        if self.rate <= 0:
            self.rate = 5.0
        if self.confirmations < 1:
            self.confirmations = 1
        if self.threads < 1:
            self.threads = 1
        self.mode = self.mode.lower()
        if self.mode not in ("dast", "sast", "both"):
            self.mode = "dast"
        self.os_type = self.os_type.lower()
        if self.os_type not in ("unix", "windows"):
            self.os_type = "unix"


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str = ""
    requests_sent: int = 0
    findings: list = field(default_factory=list)

    @property
    def confirmed(self) -> list:
        return [f for f in self.findings if f.confidence in (CONFIRMED, VERIFIED)]

    @property
    def candidates(self) -> list:
        return [f for f in self.findings if f.confidence == CANDIDATE]

    @property
    def impact_verified(self) -> list:
        return [f for f in self.findings if f.confidence == VERIFIED]

    def to_dict(self) -> dict:
        return {
            "tool": "execproof",
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "requests_sent": self.requests_sent,
            "confirmed_count": len(self.confirmed),
            "candidate_count": len(self.candidates),
            "impact_verified_count": len(self.impact_verified),
            "findings": [f.to_dict() for f in self.findings],
        }
