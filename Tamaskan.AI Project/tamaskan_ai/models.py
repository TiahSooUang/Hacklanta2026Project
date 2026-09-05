from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Flow:
    flow_id: str
    packets: int
    bytes_total: int
    duration_s: float
    bytes_per_sec: float
    pkts_per_sec: float
    avg_packet_size: float
    verdict: str = ""   # "Normal" or "ANOMALY"


@dataclass
class AnalysisResult:
    flows: list[Flow]
    total: int
    normal: int
    anomalies: int
    anomaly_pct: float
