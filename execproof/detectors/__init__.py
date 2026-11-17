from .echo import EchoDetector
from .time_based import TimeDetector
from .oob import OobDetector
from .ssti import SstiDetector

DETECTORS = {
    "echo": EchoDetector,
    "time": TimeDetector,
    "oob": OobDetector,
    "ssti": SstiDetector,
}

__all__ = ["DETECTORS", "EchoDetector", "TimeDetector", "OobDetector", "SstiDetector"]

