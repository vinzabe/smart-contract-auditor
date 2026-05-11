"""Common finding schema across Slither and Mythril."""
from __future__ import annotations
import enum
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Sequence


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        s = (s or "").lower()
        mapping = {
            "info": cls.INFO, "informational": cls.INFO, "note": cls.INFO,
            "low": cls.LOW,
            "medium": cls.MEDIUM, "warning": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
        }
        return mapping.get(s, cls.LOW)

    def rank(self) -> int:
        order = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
                 Severity.HIGH: 3, Severity.CRITICAL: 4}
        return order[self]


@dataclass
class Finding:
    detector: str            # "reentrancy-eth", "integer_overflow"...
    title: str
    severity: Severity
    confidence: str          # "Low", "Medium", "High"
    contract: str
    function: str
    file_path: str
    lines: List[int] = field(default_factory=list)
    description: str = ""
    code_snippet: str = ""
    source: str = "unknown"  # "slither", "mythril", or "llm"
    swc_id: Optional[str] = None
    raw: Optional[Dict] = None

    def fingerprint(self) -> str:
        h = hashlib.sha256()
        h.update(self.detector.encode())
        h.update(b"|")
        h.update(self.contract.encode())
        h.update(b"|")
        h.update(self.function.encode())
        h.update(b"|")
        h.update(",".join(str(x) for x in sorted(self.lines)).encode())
        return h.hexdigest()[:16]

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d.pop("raw", None)
        return d


class FindingDB:
    """Deduplicating set keyed by fingerprint, with merge of source tags."""
    def __init__(self) -> None:
        self.by_fp: Dict[str, Finding] = {}
        self.sources_for: Dict[str, List[str]] = {}

    def add(self, f: Finding) -> None:
        fp = f.fingerprint()
        if fp in self.by_fp:
            existing = self.by_fp[fp]
            # promote severity to the higher one
            if f.severity.rank() > existing.severity.rank():
                existing.severity = f.severity
            if f.source not in self.sources_for[fp]:
                self.sources_for[fp].append(f.source)
        else:
            self.by_fp[fp] = f
            self.sources_for[fp] = [f.source]

    def all(self) -> List[Finding]:
        return list(self.by_fp.values())

    def by_severity(self) -> List[Finding]:
        return sorted(self.by_fp.values(),
                      key=lambda x: -x.severity.rank())

    def report(self) -> Dict:
        return {
            "total": len(self.by_fp),
            "by_severity": {
                sev.value: sum(1 for f in self.by_fp.values()
                                if f.severity == sev)
                for sev in Severity
            },
            "findings": [
                {**f.to_dict(),
                 "fingerprint": fp,
                 "sources": self.sources_for[fp]}
                for fp, f in self.by_fp.items()
            ],
        }
